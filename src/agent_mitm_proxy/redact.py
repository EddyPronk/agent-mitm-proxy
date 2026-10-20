"""Redaction for the traffic log: credentials and the user's identity in known endpoints' JSON bodies.

    body, redacted = redact_body(text, host="platform.claude.com", path="/v1/oauth/token",
                                 direction="response")

Headers are never logged (`plugins.TrafficLogPlugin`), but credentials travel in bodies too: an
OAuth token exchange sends a refresh token and gets new tokens back, with the account's email
address and ids. `FIELD_RULES` nominates each such place: the endpoint (host, path, request or
response) and where the field sits in its JSON body. A JSON body is logged as JSON (so that jq
reads `.body.account` directly), with its keys in their original order and the nominated fields'
values overwritten with `[REDACTED]`; other bodies are logged as text, as they were.

A nominated endpoint's body that isn't valid JSON (an unfinished response, a body that couldn't be
decompressed) can't be redacted field by field, so it's withheld whole.
"""

import json
from dataclasses import dataclass
from typing import Any

REDACTED = "[REDACTED]"
WITHHELD = "[WITHHELD: not valid JSON, so its credentials couldn't be redacted]"


@dataclass(frozen=True)
class FieldRule:
    """The credentials in one endpoint's bodies.

    `path` is the request path without its query, split at "/"; a "*" segment stands for any one
    segment (an id). `fields` are key paths from the top of the JSON body; a "*" stands for any list
    item, or any key of an object (such as a map of feature flags by name). `host` is compared
    exactly; None matches any host.
    """

    path: str
    direction: str  # "request" or "response"
    fields: tuple[tuple[str, ...], ...]
    host: str | None = None

    def applies(self, host: str, path: str, direction: str) -> bool:
        if direction != self.direction or (self.host is not None and host != self.host):
            return False
        want, have = self.path.split("/"), path.partition("?")[0].split("/")
        return len(want) == len(have) and all(w in ("*", h) for w, h in zip(want, have))


# Nominated from Claude Code's traffic through the proxy (October 2026): what each holds.
# Credentials first, then the user's identity: account and organisation ids, email address, name.
# Ids that don't point to a person stay: messages', MCP servers', the Claude Code application's.
FIELD_RULES = (
    # OAuth sign-in and refresh: the authorization code and its PKCE verifier, or the refresh
    # token being spent; state ties a sign-in to its browser session.
    FieldRule("/v1/oauth/token", "request",
              (("code",), ("code_verifier",), ("refresh_token",), ("state",)),
              host="platform.claude.com"),
    # ... and the tokens it hands out, with whose they are. The organisation's default name holds
    # the email address ("...'s Organization").
    FieldRule("/v1/oauth/token", "response",
              (("access_token",), ("refresh_token",), ("id_token",), ("token_uuid",),
               ("organization", "uuid"), ("organization", "name"),
               ("account", "uuid"), ("account", "email_address")),
              host="platform.claude.com"),
    # Signing out: the token being revoked.
    FieldRule("/v1/oauth/token/revoke", "request", (("token",),),
              host="platform.claude.com"),
    # Remote Control: the session worker's JWT.
    FieldRule("/v1/code/sessions/*/bridge", "response", (("worker_jwt",),),
              host="api.anthropic.com"),
    # Messages: an opaque token that lets a request fall back to other credits; and the user id
    # in the metadata, which holds the account id.
    FieldRule("/v1/messages", "request", (("fallback_credit_token",), ("metadata", "user_id")),
              host="api.anthropic.com"),
    # The signed-in user's profile; the invoice URL opens an invoice without signing in.
    FieldRule("/api/oauth/profile", "response",
              (("account", "uuid"), ("account", "email"), ("account", "full_name"),
               ("account", "display_name"), ("organization", "uuid"), ("organization", "name"),
               ("organization", "payment_auth_hosted_invoice_url")),
              host="api.anthropic.com"),
    # Claude Code's start-up settings, with the account they're for.
    FieldRule("/api/claude_cli/bootstrap", "response",
              (("oauth_account", "account_uuid"), ("oauth_account", "account_email"),
               ("oauth_account", "organization_uuid"), ("oauth_account", "organization_name")),
              host="api.anthropic.com"),
    # The user's role in their organisation and workspace.
    FieldRule("/api/oauth/claude_cli/roles", "response",
              (("organization_uuid",), ("organization_name",), ("workspace_uuid",),
               ("workspace_name",)),
              host="api.anthropic.com"),
    # Feature flags: evaluated for the account and organisation, and each experiment's result
    # carries the value it was bucketed by, the account id.
    FieldRule("/api/eval/*", "request",
              (("attributes", "accountUUID"), ("attributes", "organizationUUID")),
              host="api.anthropic.com"),
    FieldRule("/api/eval/*", "response",
              (("features", "*", "experimentResult", "hashValue"),),
              host="api.anthropic.com"),
    # Telemetry: each event names the account and organisation it comes from.
    FieldRule("/api/event_logging/v2/batch", "request",
              (("events", "*", "event_data", "auth", "account_uuid"),
               ("events", "*", "event_data", "auth", "organization_uuid")),
              host="api.anthropic.com"),
)


def nominated(host: str, path: str, direction: str,
              rules: tuple[FieldRule, ...] = FIELD_RULES) -> tuple[tuple[str, ...], ...]:
    """The key paths to redact in this endpoint's body; empty if it has none."""
    return tuple(f for rule in rules if rule.applies(host, path, direction) for f in rule.fields)


Body = str | dict[str, Any] | list[Any]


def parse_body(text: str) -> Body:
    """TEXT as a JSON object or array if it is one (keys in their original order), else TEXT."""
    if not text or text.lstrip()[:1] not in ("{", "["):
        return text
    try:
        return json.loads(text)
    except ValueError:
        return text


def redact_body(text: str, *, host: str, path: str, direction: str,
                rules: tuple[FieldRule, ...] = FIELD_RULES) -> tuple[Body, list[str]]:
    """The body to log: a JSON object or array as such (`parse_body`), with the nominated fields'
    values replaced, or the text; and the key paths it replaced ("a.*.b"), each once, however
    many list items had it."""
    body = parse_body(text)
    fields = nominated(host, path, direction, rules)
    if not fields or not text:
        return body, []
    if isinstance(body, str):
        return WITHHELD, ["body"]
    replaced: list[str] = []
    for keys in fields:
        _overwrite(body, keys, (), replaced)
    return body, list(dict.fromkeys(replaced))


def _overwrite(value: object, keys: tuple[str, ...], done: tuple[str, ...],
               replaced: list[str]) -> None:
    """Overwrite, in place, the value at KEYS below VALUE (DONE: the keys above it)."""
    head, rest = keys[0], keys[1:]
    if head == "*":
        children = (list(range(len(value))) if isinstance(value, list)
                    else list(value) if isinstance(value, dict) else [])
    elif isinstance(value, dict) and head in value:
        children = [head]
    else:
        return
    for child in children:
        here = done + ("*" if head == "*" else child,)
        if rest:
            _overwrite(value[child], rest, here, replaced)
        elif value[child] not in (None, ""):
            value[child] = REDACTED
            replaced.append(".".join(here))
