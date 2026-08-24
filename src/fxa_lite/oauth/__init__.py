"""The OAuth server: clients, scopes, grants, and the keys that sign tokens.

Upstream this was a separate service (`fxa-oauth-server`) that was merged into
the auth server but kept its own routes, its own error numbering and its own
notion of identity — a signed assertion about a session token, rather than the
session token itself.  The merge is finished here: `grant.SessionClaims` is that
assertion, passed as an object rather than round-tripped through a JWT.
"""
