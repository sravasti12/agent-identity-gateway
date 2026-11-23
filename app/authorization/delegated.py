from time import time

from app.identity.delegation import TOOL_SCOPE, DelegatedIdentity, DelegationDenied


def authorize_team_read(identity: DelegatedIdentity, audience: str) -> None:
    if (
        identity.audience != audience
        or time() >= identity.expires_at
        or TOOL_SCOPE not in identity.granted_scopes
        or "hr_manager" not in identity.subject.realm_roles
        or "hr_agent" not in identity.actor.realm_roles
    ):
        raise DelegationDenied
