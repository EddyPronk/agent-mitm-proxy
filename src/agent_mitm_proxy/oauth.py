"""Claude Code's OAuth endpoints and the credential fields of their bodies, as observed (October
2026). Shared by `redact` (which keeps them out of the traffic log) and `credential_vault` (which
keeps them out of the sandbox); each decides what to do with them.
"""

TOKEN_HOST = "platform.claude.com"
# Sign-in (authorization code) and refresh: request credentials, and the tokens handed out.
TOKEN_PATH = "/v1/oauth/token"
# Signing out: the token being revoked, in the request's "token" field.
REVOKE_PATH = "/v1/oauth/token/revoke"

# The token endpoint's request fields that are credentials: the authorization code and its PKCE
# verifier, or the refresh token being spent; state ties a sign-in to its browser session.
TOKEN_REQUEST_FIELDS = ("code", "code_verifier", "refresh_token", "state")
# Its response fields that are credentials.
TOKEN_FIELDS = ("access_token", "refresh_token", "id_token")
