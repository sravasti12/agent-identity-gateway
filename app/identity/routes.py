import base64
import hashlib
from secrets import compare_digest, token_urlsafe
from urllib.parse import urlencode, urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from app.identity.delegation import TOOL_SCOPE, DelegationDenied, delegation_scope
from app.identity.sessions import (
    HANDOFF_TTL,
    LOGIN_COOKIE,
    LOGIN_TTL,
    SESSION_COOKIE,
    SESSION_TTL,
    BrowserSession,
    LoginAttempt,
)
from app.identity.tokens import InvalidToken, KeycloakUnavailable

router = APIRouter(prefix="/auth")
CALLBACK_PATH = "/auth/callback"
PRIVATE_HEADERS = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


@router.get("/login")
def login(request: Request, delegate: bool = False) -> Response:
    app = request.app.state
    settings = app.settings
    scopes = "openid profile"
    if delegate:
        if not settings.delegation_enabled:
            return JSONResponse({"detail": "Delegation unavailable"}, 404)
        scopes += f" {TOOL_SCOPE} {delegation_scope(settings.keycloak_hr_agent_client_id)}"
    attempt = LoginAttempt(verifier=token_urlsafe(48), nonce=token_urlsafe(32), delegate=delegate)
    state = app.login_attempts.add(attempt)
    digest = hashlib.sha256(attempt.verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.keycloak_client_id,
            "redirect_uri": settings.keycloak_redirect_uri,
            "scope": scopes,
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
    response: Response
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


@router.post("/delegation")
def delegation_handoff(request: Request) -> Response:
    app = request.app.state
    if not app.settings.delegation_enabled:
        return JSONResponse({"detail": "Delegation unavailable"}, 404)
    redirect = urlsplit(app.settings.keycloak_redirect_uri)
    if request.headers.get("Origin") != f"{redirect.scheme}://{redirect.netloc}":
        return JSONResponse({"detail": "Origin not permitted"}, 403)
    handle = request.cookies.get(SESSION_COOKIE, "")
    session = app.sessions.get(handle)
    if session is None:
        return JSONResponse({"detail": "Browser session required"}, 401)
    if session.handoff is None or app.handoffs.get(session.handoff) != handle:
        return JSONResponse({"detail": "No active delegation handoff"}, 403)
    try:
        app.delegation.verify_subject(session.token)
    except InvalidToken:
        return JSONResponse({"detail": "Browser session expired"}, 401)
    except DelegationDenied:
        return JSONResponse({"detail": "Delegation denied"}, 403)
    except KeycloakUnavailable:
        return JSONResponse({"detail": "Identity provider unavailable"}, 503)
    return JSONResponse({"handoff": session.handoff, "expires_within_seconds": HANDOFF_TTL})


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
        if attempt.delegate:
            app.delegation.verify_subject(access_token)
    except DelegationDenied:
        return JSONResponse({"detail": "Delegation denied"}, 403, headers=PRIVATE_HEADERS)
    except (httpx.HTTPError, KeycloakUnavailable):
        return JSONResponse(
            {"detail": "Identity provider unavailable"}, 503, headers=PRIVATE_HEADERS,
        )
    except ValueError:
        return JSONResponse({"detail": "Login failed"}, 401, headers=PRIVATE_HEADERS)

    previous = request.cookies.get(SESSION_COOKIE)
    if previous:
        app.sessions.get(previous, consume=True)
    session = BrowserSession(access_token)
    handle = app.sessions.add(session)
    if attempt.delegate:
        session.handoff = app.handoffs.add(handle)
    response = RedirectResponse("/auth/me", status_code=303, headers=PRIVATE_HEADERS)
    response.set_cookie(
        SESSION_COOKIE, handle, max_age=SESSION_TTL, secure=settings.secure_cookies,
        httponly=True, samesite="lax",
    )
    return response
