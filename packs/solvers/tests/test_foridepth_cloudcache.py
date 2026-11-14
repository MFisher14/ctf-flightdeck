"""Cloud-cache tests use MSAL's real producer and documented AWS/ADAL wire examples.

No engine encoder exists. All credentials here are deterministic synthetic evidence.
"""
import base64
import hashlib
import json

import msal
import pytest

from foridepth_cloudcache import ForidepthCloudCacheError, main, parse_cache


def parse(doc, kind, **kwargs):
    return parse_cache(json.dumps(doc), kind=kind, **kwargs)["records"]


def test_msal_real_producer_and_offline_readback():
    # The MSAL TokenCache producer builds schema and canonical cache keys itself.
    cache = msal.SerializableTokenCache()
    info = base64.urlsafe_b64encode(b'{"uid":"user-1","utid":"tenant-2"}').decode().rstrip("=")
    cache.add({
        "client_id": "client-3", "scope": ["scope-b", "scope-a"],
        "token_endpoint": "https://login.microsoftonline.com/tenant-2/oauth2/v2.0/token",
        "response": {"access_token": "CSCTF{synthetic_access}", "refresh_token": "synthetic-refresh",
                     "token_type": "Bearer", "expires_in": 3600, "client_info": info,
                     "id_token_claims": {"sub": "user-1", "oid": "user-1", "tid": "tenant-2",
                                         "preferred_username": "synthetic@example.invalid"}},
        "data": {}}, now=1_700_000_000)
    produced = cache.serialize()
    rows = parse_cache(produced, kind="azure-msal", source="msal_token_cache.json", show_secrets=True)["records"]
    by_kind = {r["kind"]: r for r in rows}
    token = by_kind["AccessToken"]
    assert token["identity"]["home_account_id"] == "user-1.tenant-2"
    assert token["identity"]["realm"] == "tenant-2"
    assert token["properties"]["target"] == "scope-a scope-b"
    assert token["timestamps"]["cached_at"]["utc"] == "2023-11-14T22:13:20Z"
    assert token["timestamps"]["expires_on"]["utc"] == "2023-11-14T23:13:20Z"
    assert by_kind["Account"]["identity"]["username"] == "synthetic@example.invalid"
    restored = msal.SerializableTokenCache()
    restored.deserialize(produced)
    oracle = list(restored.search(msal.TokenCache.CredentialType.ACCESS_TOKEN, now=1_700_000_001))[0]
    assert token["secrets"]["secret"]["value"] == oracle["secret"]
    assert by_kind["RefreshToken"]["secrets"]["secret"]["value"] == "synthetic-refresh"
    assert all(r["source"] == "msal_token_cache.json" for r in rows)
    assert parse_cache("{}", kind="azure-msal")["records"] == []


def test_msal_client_credentials_nullable_account():
    cache = msal.SerializableTokenCache()
    cache.add({"client_id": "service", "scope": ["api/.default"],
               "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
               "response": {"access_token": "service-token", "expires_in": 60}, "data": {}}, now=0)
    records = parse_cache(cache.serialize(), kind="azure-msal")["records"]
    assert "home_account_id" not in records[0]["identity"]
    assert records[0]["timestamps"]["expires_on"]["utc"] == "1970-01-01T00:01:00Z"


def test_sts_documented_cache_shape_and_redaction():
    doc = {"Credentials": {"AccessKeyId": "ASIASYNTHETIC", "SecretAccessKey": "synthetic-secret",
                            "SessionToken": "synthetic-session", "Expiration": "2026-11-05T08:00:00-05:00"},
           "AssumedRoleUser": {"Arn": "arn:aws:sts::123456789012:assumed-role/ReadOnly/demo", "AssumedRoleId": "AROAX:demo"},
           "ResponseMetadata": {"HTTPStatusCode": 200}}
    row = parse(doc, "aws-sts")[0]
    assert row["timestamps"]["Expiration"]["utc"] == "2026-11-05T13:00:00Z"
    assert row["identity"]["AssumedRoleId"] == "AROAX:demo"
    secret = row["secrets"]["SecretAccessKey"]
    assert secret["value"] == "[REDACTED]"
    assert secret["sha256"] == hashlib.sha256(b"synthetic-secret").hexdigest()
    assert secret["length"] == 16
    assert "synthetic-secret" not in json.dumps(row)
    assert parse(doc, "aws-sts", show_secrets=True)[0]["secrets"]["SessionToken"]["value"] == "synthetic-session"


def test_sso_access_and_registration_cache():
    doc = {"accessToken": "token", "refreshToken": "refresh", "expiresAt": "2026-11-05T13:00:00UTC",
           "startUrl": "https://synthetic.awsapps.com/start", "region": "eu-west-1", "clientId": "client",
           "clientSecret": "secret", "registrationExpiresAt": "2026-11-06T13:00:00Z"}
    row = parse(doc, "aws-sso", show_secrets=True)[0]
    assert row["timestamps"]["expiresAt"]["utc"] == "2026-11-05T13:00:00Z"
    assert row["identity"]["region"] == "eu-west-1"
    assert row["secrets"]["clientSecret"]["value"] == "secret"
    registration = parse({"clientId": "demo", "clientSecret": "private", "clientSecretExpiresAt": 1_700_000_000,
                          "scopes": ["sso:account:access"]}, "aws-sso")[0]
    assert registration["timestamps"]["clientSecretExpiresAt"]["utc"] == "2023-11-14T22:13:20Z"
    assert registration["properties"]["scopes"] == ["sso:account:access"]


def test_ini_profiles_escapes_and_inert_command():
    text = """[profile operations]
role_arn = arn:aws:iam::123456789012:role/ReadOnly
source_profile = default
region = eu-west-1
credential_process = sh -c 'this-is-inert %value%'
[default]
aws_access_key_id = AKIASYNTHETIC
aws_secret_access_key = secret%not_interpolated
[sso-session transport]
sso_start_url = https://synthetic.awsapps.com/start
sso_region = eu-west-1
sso_registration_scopes = sso:account:access
"""
    rows = parse_cache(text, kind="aws-ini", show_secrets=True)["records"]
    assert rows[0]["identity"]["profile"] == "operations"
    assert rows[0]["identity"]["source_profile"] == "default"
    assert rows[0]["secrets"]["credential_process"]["value"] == "sh -c 'this-is-inert %value%'"
    assert rows[1]["secrets"]["aws_secret_access_key"]["value"] == "secret%not_interpolated"
    assert rows[2]["kind"] == "sso_session"
    assert rows[2]["identity"]["profile"] == "transport"


def test_azure_legacy_does_not_invent_timezone():
    rows = parse([{"accessToken": "old-token", "refreshToken": "refresh", "userId": "person@example.invalid",
                   "_clientId": "client", "tenantId": "tenant", "resource": "https://management.azure.com/",
                   "expiresOn": "2026-11-05 08:00:00.000000"}], "azure-legacy")
    assert rows[0]["timestamps"]["expiresOn"] == {
        "raw": "2026-11-05 08:00:00.000000", "utc": None, "timezone_known": False}
    assert rows[0]["identity"]["tenantId"] == "tenant"


def test_azure_profile_bom_subscription():
    doc = {"subscriptions": [{"id": "subscription-1", "name": "synthetic", "tenantId": "tenant-1",
                              "isDefault": True, "user": {"name": "demo@example.invalid", "type": "user"}}]}
    row = parse_cache(b"\xef\xbb\xbf" + json.dumps(doc).encode(), kind="azure-profile")["records"][0]
    assert row["identity"]["id"] == "subscription-1"
    assert row["identity"]["user"]["type"] == "user"
    assert row["properties"]["isDefault"] is True


@pytest.mark.parametrize("data,kind", [
    ('{"AccessToken":{},"AccessToken":{}}', "azure-msal"),
    ('{"AccessToken":{"x":{"secret":"a","secret":"b"}}}', "azure-msal"),
    ('{"AccessToken":[]}', "azure-msal"),
    ('{"AccessToken":{"x":1}}', "azure-msal"),
    ('{"AccessToken":{"x":{"secret":123}}}', "azure-msal"),
    ('{"AccessToken":{"x":{"secret":"a","credential_type":"RefreshToken"}}}', "azure-msal"),
    ('{"AccessToken":{"x":{"secret":"a","expires_on":"999999999999"}}}', "azure-msal"),
    ('{"Unknown":{}}', "azure-msal"),
    ('{"Account":{"x":{}}}', "azure-msal"),
    ('{"AppMetadata":{"x":{}}}', "azure-msal"),
    ('{"accessToken":"x"}', "aws-sso"),
    ('{"accessToken":"x","expiresAt":"2026-11-05"}', "aws-sso"),
    ('{"clientSecret":"x","clientSecretExpiresAt":true}', "aws-sso"),
    ('{"clientSecret":"x","scopes":"scope"}', "aws-sso"),
    ('{"Credentials":null}', "aws-sts"),
    ('{"Credentials":{"AccessKeyId":"x"}}', "aws-sts"),
    ('[{}]', "azure-legacy"),
    ('{"subscriptions":[{"id":"x","isDefault":1}]}', "azure-profile"),
    ('[default]\nregion=x\nregion=y', "aws-ini"),
    ('[default]\nregion=x\n[profile default]\nregion=y', "aws-ini"),
    ('[DEFAULT]\nregion=x\n[default]\noutput=json', "aws-ini"),
    ('[default]\naws_access_key_id=x', "aws-ini"),
    ('', "aws-ini"),
    ('{"x":NaN}', "azure-msal"),
    ('{"x":1e999}', "azure-msal"),
    ('{"Account":{"x":{"home_account_id":"\\ud800"}}}', "azure-msal"),
    ('[', "aws-sso"),
    (b'\xff\x00', "azure-msal"),
    (None, "azure-msal"),
])
def test_malformed_only_declared_error(data, kind):
    with pytest.raises(ForidepthCloudCacheError):
        parse_cache(data, kind=kind)


def test_limits_and_bad_options(monkeypatch):
    import foridepth_cloudcache as engine
    with pytest.raises(ForidepthCloudCacheError):
        parse_cache("{}", kind=[])
    with pytest.raises(ForidepthCloudCacheError):
        parse_cache("{}", kind="azure-msal", show_secrets=1)
    with pytest.raises(ForidepthCloudCacheError):
        parse_cache("[" * 1100, kind="azure-msal")
    monkeypatch.setattr(engine, "MAX_INPUT", 3)
    with pytest.raises(ForidepthCloudCacheError):
        parse_cache("{}  ", kind="azure-msal")


def test_cli_help_errors_and_redaction(tmp_path, capsys):
    assert main(["--help"]) == 0
    capsys.readouterr()
    assert main([]) == 2
    capsys.readouterr()
    path = tmp_path / "token.json"
    path.write_text('{"clientId":"demo","clientSecret":"cli-private"}')
    assert main(["aws-sso", str(path)]) == 0
    output = capsys.readouterr().out
    assert "cli-private" not in output
    assert "[REDACTED]" in output
    assert main(["aws-sso", str(path), "--show-secrets"]) == 0
    assert "cli-private" in capsys.readouterr().out
    assert main(["aws-sso", str(tmp_path / "missing")]) == 2
    assert "Traceback" not in capsys.readouterr().err
