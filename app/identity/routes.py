import base64
import hashlib
from secrets import compare_digest, token_urlsafe
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from app.identity.sessions import LOGIN_COOKIE, LOGIN_TTL, SESSION_COOKIE, SESSION_TTL, LoginAttempt
from app.identity.tokens import InvalidToken, KeycloakUnavailable

router = APIRouter(prefix="/auth")
CALLBACK_PATH = "/auth/callback"
PRIVATE_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


@router.get("/login")
def login(request: Request) -> Response:
    app = request.app.state
    settings = app.settings
    attempt = LoginAttempt(verifier=token_urlsafe(48), nonce=token_urlsafe(32))
    state = app.login_attempts.add(attempt)
    digest = hashlib.sha256(attempt.verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.keycloak_client_id,
            "redirect_uri": settings.keycloak_redirect_uri,
            "scope": "openid profile",
            "state": state,
            "nonce": attempt.nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    response = RedirectResponse(
        f"{settings.keycloak_issuer}/protocol/openid-connect/auth?{query}",
        status_code=303,
        headers=PRIVATE_HEADERS,
    )
    response.set_cookie(
        LOGIN_COOKIE, state, max_age=LOGIN_TTL, path=CALLBACK_PATH,
        secure=settings.secure_cookies, httponly=True, samesite="lax",
    )
    return response


@router.get("/callback")
def callback(request: Request) -> Response:
    app = request.app.state
    settings = app.settings
    query = request.query_params
    state = request.cookies.get(LOGIN_COOKIE, "")
    returned_states = query.getlist("state")
    if (
        not state
        or len(returned_states) != 1
        or not compare_digest(state.encode(), returned_states[0].encode())
    ):
        return JSONResponse({"detail": "Invalid login state"}, 400, headers=PRIVATE_HEADERS)
    attempt = app.login_attempts.get(state, consume=True)
    if attempt is None:
        return JSONResponse({"detail": "Invalid login state"}, 400, headers=PRIVATE_HEADERS)

    codes = query.getlist("code")
    issuers = query.getlist("iss")
    if "error" in query or len(codes) != 1 or not codes[0] or (
        issuers and issuers != [settings.keycloak_issuer]
    ):
        response = JSONResponse({"detail": "Login failed"}, 400, headers=PRIVATE_HEADERS)
    else:
        response = complete_login(request, codes[0], attempt)
    response.delete_cookie(
        LOGIN_COOKIE, path=CALLBACK_PATH, secure=settings.secure_cookies,
        httponly=True, samesite="lax",
    )
    return response


def complete_login(request: Request, code: str, attempt: LoginAttempt) -> Response:
    app = request.app.state
    settings = app.settings
    try:
        result = app.http.post(
            f"{settings.keycloak_issuer}/protocol/openid-connect/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.keycloak_redirect_uri,
                "client_id": settings.keycloak_client_id,
                "client_secret": settings.keycloak_client_secret.get_secret_value(),
                "code_verifier": attempt.verifier,
            },
        )
        if result.status_code == 400:
            return JSONResponse({"detail": "Login failed"}, 401, headers=PRIVATE_HEADERS)
        result.raise_for_status()
        tokens = result.json()
        if not isinstance(tokens, dict):
            raise InvalidToken
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")
        if not isinstance(access_token, str) or not isinstance(id_token, str):
            raise InvalidToken
        claims = app.verifier.decode(id_token, settings.keycloak_client_id, ["iat", "nonce"])
        nonce = claims["nonce"]
        if (
            claims.get("typ") != "ID"
            or not isinstance(nonce, str)
            or not compare_digest(nonce.encode(), attempt.nonce.encode())
        ):
            raise InvalidToken
        audiences = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
        if audiences != [settings.keycloak_client_id] or claims.get(
            "azp", settings.keycloak_client_id
        ) != settings.keycloak_client_id:
            raise InvalidToken
        if "at_hash" in claims:
            digest = hashlib.sha256(access_token.encode("ascii")).digest()
            expected_hash = base64.urlsafe_b64encode(digest[:16]).decode("ascii").rstrip("=")
            token_hash = claims["at_hash"]
            if not isinstance(token_hash, str) or not compare_digest(
                token_hash.encode(), expected_hash.encode()
            ):
                raise InvalidToken
        if app.verifier.access_user(access_token).subject != claims["sub"]:
            raise InvalidToken
    except (httpx.HTTPError, KeycloakUnavailable):
        return JSONResponse(
            {"detail": "Identity provider unavailable"}, 503, headers=PRIVATE_HEADERS,
        )
    except ValueError:
        return JSONResponse({"detail": "Login failed"}, 401, headers=PRIVATE_HEADERS)

    previous = request.cookies.get(SESSION_COOKIE)
    if previous:
        app.sessions.get(previous, consume=True)
    handle = app.sessions.add(access_token)
    response = RedirectResponse("/auth/me", status_code=303, headers=PRIVATE_HEADERS)
    response.set_cookie(
        SESSION_COOKIE, handle, max_age=SESSION_TTL, secure=settings.secure_cookies,
        httponly=True, samesite="lax",
    )
    return response
