import json

import pytest

from agent_mitm_proxy.redact import (
    FIELD_RULES,
    REDACTED,
    WITHHELD,
    FieldRule,
    nominated,
    parse_body,
    redact_body,
)

TOKEN_RESPONSE = json.dumps({
    "token_type": "Bearer", "access_token": "sk-ant-oat01-secret", "expires_in": 28800,
    "refresh_token": "sk-ant-ort01-secret", "scope": "user:inference", "token_uuid": "t-secret",
    "refresh_token_expires_in": 2522760,
    "organization": {"uuid": "o-secret", "name": "me@example.com's Organization"},
    "account": {"uuid": "a-secret", "email_address": "me@example.com"},
})


def oauth(text, direction="response"):
    return redact_body(text, host="platform.claude.com", path="/v1/oauth/token", direction=direction)


def test_the_token_response_keeps_everything_but_the_tokens_and_identity_in_their_order():
    body, replaced = oauth(TOKEN_RESPONSE)
    assert replaced == ["access_token", "refresh_token", "token_uuid", "organization.uuid",
                        "organization.name", "account.uuid", "account.email_address"]
    assert list(body) == list(json.loads(TOKEN_RESPONSE))   # the original key order
    assert list(body["account"]) == ["uuid", "email_address"]
    assert (body["access_token"], body["refresh_token"]) == (REDACTED, REDACTED)
    assert body["expires_in"] == 28800 and body["scope"] == "user:inference"
    assert "secret" not in json.dumps(body) and "example.com" not in json.dumps(body)


def test_telemetry_names_each_redacted_path_once_however_many_events():
    events = [{"event_data": {"event_name": f"e{i}", "auth": {"account_uuid": "a-secret",
                                                               "organization_uuid": "o-secret"}}}
              for i in range(3)] + [{"event_data": {"event_name": "no auth"}}]
    body, replaced = redact_body(json.dumps({"events": events}), host="api.anthropic.com",
                                 path="/api/event_logging/v2/batch", direction="request")
    assert replaced == ["events.*.event_data.auth.account_uuid",
                        "events.*.event_data.auth.organization_uuid"]
    assert [e["event_data"]["event_name"] for e in body["events"]] == ["e0", "e1", "e2", "no auth"]
    assert "secret" not in json.dumps(body)


@pytest.mark.parametrize("request_body", [
    {"grant_type": "authorization_code", "code": "c-secret", "redirect_uri": "https://x/cb",
     "client_id": "id", "code_verifier": "v-secret", "state": "s-secret"},
    {"grant_type": "refresh_token", "refresh_token": "r-secret", "client_id": "id", "scope": "s"},
])
def test_both_kinds_of_token_request_lose_their_credentials(request_body):
    body, replaced = oauth(json.dumps(request_body), "request")
    assert list(body) == list(request_body)
    assert "secret" not in json.dumps(body)
    assert body["client_id"] == "id" and replaced


def test_signing_out_loses_the_token_it_revokes():
    body, replaced = redact_body(
        '{"token":"sk-ant-oat01-secret","token_type_hint":"access_token","client_id":"c"}',
        host="platform.claude.com", path="/v1/oauth/token/revoke", direction="request")
    assert replaced == ["token"]
    assert body == {"token": REDACTED, "token_type_hint": "access_token", "client_id": "c"}


def test_a_wildcard_field_stands_for_every_key_of_an_object_such_as_feature_flags():
    features = {"flag_a": {"value": True, "experimentResult": {"hashValue": "a-secret", "key": "1"}},
                "flag_b": {"value": 3},
                "flag_c": {"experimentResult": {"hashValue": "a-secret"}}}
    body, replaced = redact_body(json.dumps({"features": features}), host="api.anthropic.com",
                                 path="/api/eval/sdk-abc", direction="response")
    assert replaced == ["features.*.experimentResult.hashValue"]
    assert list(body["features"]) == ["flag_a", "flag_b", "flag_c"]
    assert body["features"]["flag_a"] == {"value": True, "experimentResult": {"hashValue": REDACTED, "key": "1"}}
    assert body["features"]["flag_b"] == {"value": 3}
    assert "secret" not in json.dumps(body)


def test_feature_flag_requests_and_messages_lose_the_account_ids():
    body, replaced = redact_body(
        json.dumps({"attributes": {"id": "d", "accountUUID": "a-secret", "organizationUUID": "o-secret",
                                   "appVersion": "2"}, "url": "u"}),
        host="api.anthropic.com", path="/api/eval/sdk-abc", direction="request")
    assert replaced == ["attributes.accountUUID", "attributes.organizationUUID"]
    assert list(body["attributes"]) == ["id", "accountUUID", "organizationUUID", "appVersion"]
    body, replaced = redact_body(
        json.dumps({"model": "m", "messages": [], "metadata": {"user_id": '{"account_uuid":"a-secret"}'}}),
        host="api.anthropic.com", path="/v1/messages", direction="request")
    assert replaced == ["metadata.user_id"] and "secret" not in json.dumps(body)


def test_a_wildcard_path_segment_stands_for_a_session_id():
    body, replaced = redact_body(json.dumps({"worker_jwt": "eyJ.secret", "expires_in": 3600}),
                                 host="api.anthropic.com", path="/v1/code/sessions/cse_01Ab/bridge",
                                 direction="response")
    assert replaced == ["worker_jwt"] and body == {"worker_jwt": REDACTED, "expires_in": 3600}


def test_the_rule_has_to_match_host_path_direction_and_segment_count():
    assert nominated("platform.claude.com", "/v1/oauth/token?x=1", "response")
    assert not nominated("example.com", "/v1/oauth/token", "response")
    assert not nominated("platform.claude.com", "/v1/oauth/token", "sideways")
    assert not nominated("api.anthropic.com", "/v1/code/sessions/a/b/bridge", "response")
    assert not nominated("api.anthropic.com", "/v1/messages/count_tokens", "request")


@pytest.mark.parametrize(("text", "body"), [
    ('{"b": 1,  "a": [1, 2]}', {"b": 1, "a": [1, 2]}),   # an object, keys in their order
    ("  [1, {\"x\": null}]", [1, {"x": None}]),           # an array
    ("not json", "not json"),
    ("{broken", "{broken"),
    ('"a JSON string"', '"a JSON string"'),               # scalars stay text: no doubt what came
    ("true", "true"),
    ("data: {\"type\": \"ping\"}\n\n", "data: {\"type\": \"ping\"}\n\n"),   # an event stream
    ("", ""),
])
def test_a_json_object_or_array_is_logged_as_json_anything_else_as_text(text, body):
    assert parse_body(text) == body
    assert redact_body(text, host="api.example", path="/x", direction="request") == (body, [])


def test_other_endpoints_keep_their_fields_whatever_they_are_called():
    text = '{"b": 1, "access_token": "kept: not a nominated endpoint"}'
    assert redact_body(text, host="api.example", path="/v1/oauth/token", direction="response") == \
        ({"b": 1, "access_token": "kept: not a nominated endpoint"}, [])


def test_a_nominated_body_without_the_fields_is_logged_as_it_came():
    assert oauth('{"error":  "invalid_grant"}') == ({"error": "invalid_grant"}, [])


def test_a_nominated_body_that_isnt_json_is_withheld_whole():
    assert oauth('{"access_token": "sk-ant-oat01-secr') == (WITHHELD, ["body"])


def test_empty_and_null_values_are_left_alone():
    assert oauth('{"access_token": "", "refresh_token": null}') == \
        ({"access_token": "", "refresh_token": None}, [])


def test_nested_and_list_paths():
    rules = (FieldRule("/x", "request", (("auth", "token"), ("keys", "*", "secret"))),)
    text = json.dumps({"auth": {"token": "t", "user": "u"},
                       "keys": [{"id": 1, "secret": "s1"}, {"id": 2}, "not an object"]})
    body, replaced = redact_body(text, host="h", path="/x", direction="request", rules=rules)
    assert replaced == ["auth.token", "keys.*.secret"]
    assert body == {"auth": {"token": REDACTED, "user": "u"},
                    "keys": [{"id": 1, "secret": REDACTED}, {"id": 2}, "not an object"]}


def test_a_field_of_another_shape_than_expected_is_replaced_whole():
    assert oauth('{"access_token": {"value": "secret", "kind": "x"}}')[0] == {"access_token": REDACTED}


def test_every_rule_names_a_direction_and_fields():
    for rule in FIELD_RULES:
        assert rule.direction in ("request", "response") and rule.fields
        assert rule.path.startswith("/") and all(rule.fields)
