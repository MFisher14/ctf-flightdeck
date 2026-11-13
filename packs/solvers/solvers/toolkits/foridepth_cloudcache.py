#!/usr/bin/env python3
"""Bounded, offline readers for supplied AWS/Azure CLI credential cache artifacts.

Only caller-supplied bytes/files are read. No home-directory discovery, SDK credential
resolution, process execution, token refresh, JWT trust decisions, or network requests.
Secrets are redacted by default, with SHA-256 and source field preserved for correlation.
Unknown formats, duplicate JSON/INI keys and malformed records fail closed.

Sources: botocore tokens.py/credentials.py; MSAL Python token_cache.py; AWS shared
configuration documentation. Azure legacy naive expiresOn times are retained without
inventing a timezone. Windows-protected MSAL binary caches are not JSON and are rejected.
"""
from __future__ import annotations

import argparse
import configparser
import datetime as dt
import hashlib
import json
import math
import re
import sys
from pathlib import Path

MAX_INPUT = 16 << 20
MAX_RECORDS = 100_000
MAX_NODES = 500_000
MAX_TEXT = 1 << 20
KINDS = ("aws-ini", "aws-sts", "aws-sso", "azure-msal", "azure-legacy", "azure-profile")
_MSAL_KINDS = {"AccessToken", "RefreshToken", "IdToken", "Account", "AppMetadata"}


class ForidepthCloudCacheError(ValueError):
    """Unsupported, malformed or resource-exhausting supplied cache artifact."""


def _text(data):
    if isinstance(data, bytes):
        if len(data) > MAX_INPUT:
            raise ForidepthCloudCacheError("cache exceeds input limit")
        data = data.decode("utf-8-sig")
    if not isinstance(data, str) or len(data) > MAX_INPUT or len(data.encode("utf-8")) > MAX_INPUT:
        raise ForidepthCloudCacheError("cache must be bounded UTF-8 text")
    return data.removeprefix("\ufeff")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ForidepthCloudCacheError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(_value):
    raise ForidepthCloudCacheError("non-finite JSON number")


def _json(text):
    doc = json.loads(text, object_pairs_hook=_pairs, parse_constant=_bad_constant)
    stack, nodes = [(doc, 0)], 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > 32:
            raise ForidepthCloudCacheError("JSON structure exceeds limit")
        if isinstance(value, dict):
            if len(value) > MAX_RECORDS:
                raise ForidepthCloudCacheError("too many JSON fields")
            stack.extend((v, depth + 1) for v in value.values())
            stack.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
        elif isinstance(value, str):
            if len(value) > MAX_TEXT:
                raise ForidepthCloudCacheError("JSON string exceeds limit")
            value.encode("utf-8")  # Reject escaped unpaired surrogates as invalid UTF-8.
        elif isinstance(value, float) and not math.isfinite(value):
            raise ForidepthCloudCacheError("non-finite JSON number")
    return doc


def _mapping(value):
    if not isinstance(value, dict):
        raise ForidepthCloudCacheError("expected JSON object")
    return value


def _string(row, key, *, required=False):
    value = row.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or len(value) > MAX_TEXT or (required and not value):
        raise ForidepthCloudCacheError("invalid string field")
    return value


def _stamp(value, *, epoch=False, naive=False):
    if epoch:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ForidepthCloudCacheError("invalid epoch timestamp")
        if not re.fullmatch(r"[0-9]{1,12}", str(value)):
            raise ForidepthCloudCacheError("invalid epoch timestamp")
        instant = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=int(value))
    else:
        if not isinstance(value, str) or len(value) > 128:
            raise ForidepthCloudCacheError("invalid ISO timestamp")
        instant = dt.datetime.fromisoformat(value.removesuffix("UTC").removesuffix("Z") +
                                           ("+00:00" if value.endswith(("UTC", "Z")) else ""))
        if instant.tzinfo is None:
            if not naive:
                raise ForidepthCloudCacheError("timestamp lacks timezone")
            return {"raw": value, "utc": None, "timezone_known": False}
    return {"raw": value, "utc": instant.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "timezone_known": True}


def _row(provider, kind, pointer):
    return {"provider": provider, "kind": kind, "record": pointer, "identity": {},
            "properties": {}, "timestamps": {}, "secrets": {}}


def _fields(out, doc, fields, target="properties"):
    for key in fields:
        value = _string(doc, key)
        if value is not None:
            out[target][key] = value


def _secret(out, doc, key, show, *, required=False):
    value = _string(doc, key, required=required)
    if value is not None:
        out["secrets"][key] = {"value": value if show else "[REDACTED]",
                               "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                               "length": len(value), "field": key}


def _times(out, doc, keys, *, epoch=False, naive=False):
    for key in keys:
        if key in doc:
            out["timestamps"][key] = _stamp(doc[key], epoch=epoch, naive=naive)


def _msal(doc, show):
    doc = _mapping(doc)
    if set(doc) - _MSAL_KINDS:
        raise ForidepthCloudCacheError("unsupported MSAL cache category")
    result = []
    for kind, entries in doc.items():
        for cache_key, item in _mapping(entries).items():
            item = _mapping(item)
            pointer_key = cache_key.replace("~", "~0").replace("/", "~1")
            out = _row("azure", kind, f"/{kind}/{pointer_key}")
            if "credential_type" in item and item["credential_type"] != kind:
                raise ForidepthCloudCacheError("MSAL category and credential type disagree")
            _fields(out, item, ("home_account_id", "environment", "client_id", "realm", "username",
                                "local_account_id", "authority_type"), "identity")
            _fields(out, item, ("target", "token_type", "family_id", "key_id"))
            _times(out, item, ("cached_at", "expires_on", "extended_expires_on", "last_modification_time"), epoch=True)
            if kind in {"AccessToken", "RefreshToken", "IdToken"}:
                _secret(out, item, "secret", show, required=True)
            elif kind == "Account":
                _string(item, "home_account_id", required=True)
            elif kind == "AppMetadata":
                _string(item, "client_id", required=True)
                _string(item, "environment", required=True)
            result.append(out)
            if len(result) > MAX_RECORDS:
                raise ForidepthCloudCacheError("too many cache records")
    return result


def _sts(doc, show):
    doc = _mapping(doc)
    credentials = _mapping(doc.get("Credentials"))
    out = _row("aws", "sts_credentials", "/Credentials")
    for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        _secret(out, credentials, key, show, required=True)
    if "Expiration" not in credentials:
        raise ForidepthCloudCacheError("STS credentials lack expiration")
    _times(out, credentials, ("Expiration",))
    _fields(out, credentials, ("AccountId",), "identity")
    if "AssumedRoleUser" in doc:
        _fields(out, _mapping(doc["AssumedRoleUser"]), ("Arn", "AssumedRoleId"), "identity")
    _fields(out, doc, ("ProviderType",))
    return [out]


def _sso(doc, show):
    doc = _mapping(doc)
    if not ("accessToken" in doc or "clientSecret" in doc):
        raise ForidepthCloudCacheError("not an SSO token or registration cache")
    out = _row("aws", "sso_oidc", "/")
    _fields(out, doc, ("startUrl", "region", "clientId", "registrationClientUri"), "identity")
    for key in ("accessToken", "refreshToken", "clientSecret"):
        _secret(out, doc, key, show, required=key in doc)
    if "accessToken" in doc and "expiresAt" not in doc:
        raise ForidepthCloudCacheError("SSO token lacks expiration")
    _times(out, doc, ("expiresAt", "registrationExpiresAt"))
    _times(out, doc, ("clientSecretExpiresAt",), epoch=True)
    for key in ("scopes", "registrationScopes"):
        if key in doc:
            value = doc[key]
            if not isinstance(value, list) or not all(isinstance(s, str) for s in value):
                raise ForidepthCloudCacheError("invalid SSO scopes")
            out["properties"][key] = value
    return [out]


def _legacy(doc, show):
    if not isinstance(doc, list) or len(doc) > MAX_RECORDS:
        raise ForidepthCloudCacheError("legacy cache must be an array")
    result = []
    for i, item in enumerate(doc):
        item = _mapping(item)
        if not any(k in item for k in ("accessToken", "refreshToken")):
            raise ForidepthCloudCacheError("legacy record lacks token")
        out = _row("azure", "adal_token", f"/{i}")
        _fields(out, item, ("userId", "_clientId", "clientId", "tenantId", "_authority"), "identity")
        _fields(out, item, ("resource", "tokenType"))
        for key in ("accessToken", "refreshToken", "idToken"):
            _secret(out, item, key, show, required=key in item)
        _times(out, item, ("expiresOn",), naive=True)
        result.append(out)
    return result


def _profile(doc, _show):
    doc = _mapping(doc)
    subscriptions = doc.get("subscriptions")
    if not isinstance(subscriptions, list) or len(subscriptions) > MAX_RECORDS:
        raise ForidepthCloudCacheError("invalid Azure profile subscriptions")
    result = []
    for i, item in enumerate(subscriptions):
        item = _mapping(item)
        out = _row("azure", "subscription", f"/subscriptions/{i}")
        out["identity"]["id"] = _string(item, "id", required=True)
        _fields(out, item, ("name", "tenantId", "homeTenantId"), "identity")
        _fields(out, item, ("state", "environmentName"))
        if "isDefault" in item:
            if not isinstance(item["isDefault"], bool):
                raise ForidepthCloudCacheError("invalid default subscription flag")
            out["properties"]["isDefault"] = item["isDefault"]
        if "user" in item:
            user = _mapping(item["user"])
            out["identity"]["user"] = {k: _string(user, k) for k in ("name", "type") if k in user}
        result.append(out)
    return result


def _ini(text, show):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(text)
    if parser.defaults():
        raise ForidepthCloudCacheError("AWS does not use INI DEFAULT inheritance")
    if len(parser.sections()) > MAX_RECORDS:
        raise ForidepthCloudCacheError("too many INI profiles")
    result, names = [], set()
    for section in parser.sections():
        item = dict(parser.items(section, raw=True))
        kind = "sso_session" if section.startswith("sso-session ") else "profile"
        name = section.removeprefix("sso-session ") if kind == "sso_session" else section.removeprefix("profile ")
        if not name or (kind, name) in names:
            raise ForidepthCloudCacheError("ambiguous profile name")
        names.add((kind, name))
        out = _row("aws", kind, f"[{section}]")
        out["identity"]["profile"] = name
        _fields(out, item, ("role_arn", "source_profile", "sso_account_id", "sso_role_name", "sso_session",
                            "sso_start_url", "sso_region"), "identity")
        _fields(out, item, ("region", "output", "credential_source", "mfa_serial", "web_identity_token_file",
                            "sso_registration_scopes", "role_session_name", "duration_seconds"))
        for key in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token", "aws_security_token", "credential_process"):
            _secret(out, item, key, show)
        if "aws_access_key_id" in item and "aws_secret_access_key" not in item or \
                "aws_secret_access_key" in item and "aws_access_key_id" not in item:
            raise ForidepthCloudCacheError("incomplete AWS static credentials")
        known = set(out["identity"]) | set(out["properties"]) | set(out["secrets"])
        out["uninterpreted_keys"] = sorted(set(item) - known)
        result.append(out)
    if not result:
        raise ForidepthCloudCacheError("INI contains no profiles")
    return result


def parse_cache(data, *, kind, source="artifact", show_secrets=False):
    """Return JSON-ready records; malformed input raises only ForidepthCloudCacheError.

    ``kind`` selects a schema explicitly. No network validation is implied; timestamps
    are observations in the cache, and an expired token is still retained as evidence.
    Secrets are available only with ``show_secrets=True``. Original secret-field names,
    record pointer and supplied source label locate each recovered value.
    """
    try:
        if not isinstance(kind, str) or kind not in KINDS or not isinstance(source, str) or len(source) > 4096:
            raise ForidepthCloudCacheError("invalid format or source label")
        if not isinstance(show_secrets, bool):
            raise ForidepthCloudCacheError("show_secrets must be bool")
        text = _text(data)
        if kind == "aws-ini":
            records = _ini(text, show_secrets)
        else:
            parse = {"aws-sts": _sts, "aws-sso": _sso, "azure-msal": _msal,
                     "azure-legacy": _legacy, "azure-profile": _profile}[kind]
            records = parse(_json(text), show_secrets)
        for record in records:
            record["source"] = source
        return {"format": kind, "source": source, "records": records}
    except ForidepthCloudCacheError:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError, configparser.Error) as exc:
        raise ForidepthCloudCacheError("malformed credential cache") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=KINDS)
    parser.add_argument("path", help="supplied artifact file only")
    parser.add_argument("--show-secrets", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.path).open("rb") as stream:
            data = stream.read(MAX_INPUT + 1)
        result = parse_cache(data, kind=args.kind, source=args.path, show_secrets=args.show_secrets)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (ForidepthCloudCacheError, OSError, ValueError) as exc:
        print(f"cloud cache: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
