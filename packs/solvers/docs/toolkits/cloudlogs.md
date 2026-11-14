# cloudlogs: cloud and identity logs (backlog row 85)

`solvers/toolkits/cloudlogs.py`. Plain Python, stdlib only, offline, fast (20,000 records in 0.3 s).
Tests: `.venv/bin/python -m pytest tests/test_toolkits_cloudlogs_pivot.py` (the pivot, B-066); the carried
`tests/test_tk_cloudlogs.py` was not imported (docs/migration/ARCHIVED.md).

## Run first

```
.venv/bin/python tools/unpack.py <attempt dir>                      # members/ for reading
.venv/bin/python solvers/toolkits/cloudlogs.py <attempt dir>/members   # or files, or the zip itself
.venv/bin/python solvers/toolkits/cloudlogs.py <files> --json --top 20
```

The triage prints, per file, the form and the source of its records, then the time range, the top actors, IPs,
operations, user agents and countries, the sign-in totals with failures per IP and per account, one suspicious
sign-in candidate per heuristic, impossible-travel pairs, mailbox rules, OAuth consents, created access keys, role
chains, the registered devices, the device-code sign-ins and file downloads per IP, and the notable operations.
Exit 3 means no known source was found (it is some other kind of evidence).

## The pivot: who did what from which address (B-066)

```
python -m ctf run toolkits.cloudlogs --pivot <files or folder> [--attacker-ip IP]... [--brief <challenge dir>] [--template T] [--json]
```

One block per client IP of the cloud logs: its sign-ins (results, first, last, how many carry the device-code
marker, the accounts), the devices registered from it, the inbox rules made from it, its file downloads, and the
requests the same address made in any web access log among the files (read with `web_evidence.read_log`, joined
through `web_evidence.ip_activity`; an address a proxy only names in `X-Forwarded-For` is counted apart). Intake
runs it with no model on any handout that holds an Entra or Purview export (the `[intake]` table of the manifest:
the portal's sign-in and audit-log CSV heads, the `AuditData` CSV heads, a Graph `auditLogs` response).

It decides two things, by two rules printed with every run (`ATTACKER_RULE`, `DECOY_RULE`). Neither is widened by a
guess; when a rule does not decide, the output says so and no flag is printed.

| Decision | Rule | When it does not decide |
| --- | --- | --- |
| Which IP is the attacker's | Named with `--attacker-ip`, or a SUCCESSFUL sign-in from it carries the device-code flow marker (`authenticationProtocol` = `deviceCode`, or `originalTransferMethod` = `deviceCodeFlow`) | No such sign-in and none named: nothing is attributed (`no_attacker_ip`). The suspicious sign-in candidates of the triage are not used |
| Which device, rule and downloads are the attacker's (the decoys) | The record's own client IP is an attacker IP, or (a device) its Device Id signs in from one (any letter case); AND it is not older than the first sign-in from that IP that opened a session (the record's own IP when it is an attacker IP, else the Device Id's; a Device Id seen from several attacker IPs takes the earliest of their first sign-ins, and the detail names that IP). A failed or interrupted sign-in does not count, so a password spray before the device-code success moves nothing; a sign-in whose export states no result does count | `rejected`: `other_ip` (also a device with no IP whose Device Id signs in only from other addresses), `predates_first_signin`, `failed`. `unattributed`: `no_ip` (the directory's own rows state none), `no_time` |

A flag template in the brief (`--brief <challenge dir>` reads `challenge.json`; or `--template`) is filled only when
every `<slot>` is a name in `TEMPLATE_FIELDS` (`device_name`, `rule_name`, `download_count`, `attacker_ip`,
`forward_to`, `device_id` and their spellings; a bare `<count>` or `<name>` is not one) and has exactly one
attributed value. Two devices, a file downloaded twice (events and distinct files differ), no download (never `0`),
a log that did not parse whole, or two templates leave it unfilled with the reason. Downloads are counted by the
file's full path, so two files of one name in different folders are two. The template itself is never echoed, so
a flag search over the output finds only a filled flag. `--top` belongs to the triage; `--pivot --top` is refused
(exit 2).

**At intake the filled flag can be auto-submitted.** Intake treats it as this engine's flag like any other: when it
is the only flag found, intake reports `solved`, which makes it eligible for the capped auto-submit
(`ctf/intake/autosubmit.py`, cap 1 per challenge). The flag is an inference under the two rules above, not text
read from the handout. Intake has no way for an engine to mark its flag unconfirmed today (only fastlane decodes
can); if inferred flags should stay out of auto-submit, that needs an intake change, not a change here.

```python
cl.registered_devices(ev)      # name, device_id, ip, time, actor, os, trust_type, record ('register' | 'companion')
cl.device_code_signins(ev)     # [(how, event)]: 'authentication_protocol' | 'original_transfer_method'
cl.downloads(ev)               # file, object, ip, time (FileDownloaded, FileSyncDownloadedFull)
pv = cl.pivot(ev, named=(), access=None)   # attackers, ips, artifacts (each with verdict, why, detail), notes
cl.fill_template("EVT{<device_name>_<rule_name>_<download_count>}", pv, log.whole)   # slots, flag, why
```

## What it reads

| Source (`src`) | Recognised by | Typical export |
| --- | --- | --- |
| `m365_ual` | `Operation` with `Workload`/`RecordType`/`UserId` | Purview JSON, or CSV with an `AuditData` cell |
| `entra_signin` | `userPrincipalName` + `ipAddress`, or category `SignInLogs` | Graph `value[]`, portal CSV, Azure Monitor, Sentinel |
| `entra_audit` | `activityDisplayName` + `initiatedBy`/`targetResources`; or `Activity` + `Date (UTC)` + `Actor...`/`Target1...` columns | Graph `value[]`, Azure Monitor, the portal's flat CSV download |
| `cloudtrail` | `eventName` + `eventSource` + `userIdentity` | `{"Records": [...]}`, `.json.gz`, JSON lines |
| `azure_activity` | `operationName` + `resourceId`/`caller` | `{"records": [...]}` |
| `gcp_audit` | `protoPayload` | JSON lines |
| `okta` | `eventType` + `published` | JSON array or lines |
| `k8s_audit` | `auditID` + `verb`, `audit.k8s.io` | JSON lines |

Envelopes opened: Elastic `_source`, Splunk `result`/`_raw`, CloudWatch `message`, `hits.hits`. Records with the
same id in two files are counted once. A file that did not parse whole stops every answer (the readers still work).

## By hand

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import cloudlogs as cl
log = cl.load(cl.read_paths(["<file or folder or zip>"]))     # log.events, log.sources, log.notes
ev = log.events                                                # each: time, actor, ip, ip_raw, ua, op, result, country, city, signin, raw
cl.counts_by(ev, "actor").most_common(5)
cl.suspicious_signins(ev)      # [(method, event)]
cl.impossible_travel(ev)       # [{actor, a, b, km, hours, kmh}]
cl.inbox_rules(ev)             # name, forward_to, move_to, delete, mark_read, keywords, params
cl.consent_grants(ev)          # app, app_names, app_id, scopes, admin
cl.access_keys(ev)             # key_id, for_user
cl.role_chains(ev)             # origin, roles (ARNs), linked_by (access_key or arn)
cl.answer(question, log, explain := [])   # why a question got None is in `explain`
```

## What `solve_set` answers

A question is answered only when every word of it is in the file's vocabulary and it names what to look at: an
operation as the log spells it (`New-InboxRule`, `CreateAccessKey`), an account, an IP, or a class (inbox rule,
consent, created access key, role assumption, sign-in).

| Shape | Answer |
| --- | --- |
| How many `<Operation>` events / events for `<account>` / from `<ip>` / failed sign-ins / records | plain count |
| How many users / IP addresses / countries / user agents / roles (their distinct values) | plain; unsure when "signed in" could mean attempts or successes |
| The inbox rule's name, folder, the app consented to, the created access key id, who it was made for | plain when the log holds exactly one |
| A stand-in value (review of 2026-10-08): the consented app's id (the target's object id), an app named only by a permission grant, a rule name read from `Identity`, the rule's maker when the mailbox owner differs, the actor when the event's target is an account too, a GCP key (id or resource name), a country with one spelling, any sign-in answer on Okta, CloudTrail or GCP (the sign-in operations are this file's choice) | unsure, even with one option |
| Any count when records with one id came in two files; anything from a file that mixes known and unknown records, a cut log, or more than 200 files | None |
| IP, user agent, account, city, operation of such an event, or of the first/last event that matches | plain |
| The account or IP with strictly the most events | plain |
| Any timestamp | unsure by format (`as_logged`, `iso_z_seconds`, `space_seconds`, ...); plain when the answer pattern admits one and that one is the log's own text or the log states its zone; a month/day/year time is offered only as logged |
| Attacker's / suspicious sign-in's IP, user agent, time, country, account | unsure, one option per heuristic, the value most heuristics agree on first |
| Impossible travel (country, IP, time) | unsure: `later:` then `earlier:` sign-in |
| Scopes, rule keywords, several forwarding addresses, a role chain | unsure by join (`comma`, `space`, `arrow`, `json`, `sorted_*`; chain by names or ARNs, with or without the origin) |
| An IP logged with a port, `smtp:` address, AWS identity (user name, ARN, role), country code or name | unsure by spelling |
| A count over Kubernetes stages, interrupted Entra sign-ins counted as failed or not | unsure by reading |
| Two or more candidate values and no first/last, a zero, a qualifier (before, after, between, second, not), an unknown word, an ATT&CK id | `None` |

Suspicious sign-in heuristics, in order of trust: `risky_signin`, `success_after_failures` (3 failures from the IP),
`success_after_user_failures`, `impossible_travel`, `minority_country`, `scripted_user_agent`, `notable_action_ip`
(the IP that later made the rule, consent or key), `minority_ip`. They are candidates. Read the triage before trusting one.

## Label keys and likely vocabulary

Keys are `cloudlogs.<field>/<source>.<subject>`, for example `cloudlogs.ip/entra_signin.suspicious_signin`,
`cloudlogs.scopes/m365_ual.consent`, `cloudlogs.role_chain/cloudtrail.assume_role`. The option names are methods and
formats, so an accepted one answers the next variant. The prefix `cloudlogs` is not in `labels.LANE_DIRS`, so an
unsure answer is shown as ranked candidates (`labels.show`), never collapsed to a single value.

If the challenge asks for names instead of values (this event's style is lowercase snake_case), expect words like:

- technique: `inbox_rule_forwarding`, `inbox_rule_hide`, `mailbox_forwarding`, `oauth_consent_grant`,
  `illicit_consent`, `password_spray`, `brute_force`, `credential_stuffing`, `mfa_fatigue`, `token_theft`,
  `aitm_phishing`, `impossible_travel`, `access_key_creation`, `role_chaining`, `privilege_escalation`,
  `persistence`, `defense_evasion`, `logging_disabled`
- result: `success`, `failure`, `interrupted`; client: `browser`, `legacy_auth`, `imap`, `powershell`, `cli`, `sdk`
- identity type: `iam_user`, `assumed_role`, `root`, `service_principal`, `service_account`, `federated_user`
- ATT&CK ids that fit: T1078.004, T1110.003, T1114.003, T1564.008, T1528, T1098.001, T1098.003, T1550.001, T1621

None of these is answered by the solver: a name for a judgement is the agent's to establish and offer with
`labels.pick`.

## Limits

- No heavy tool is used and none is needed. A file over 96 MB is not read.
- `m/d/yyyy` times are read as US order; first/last by such a time is `None` unless the day is over 12.
- CloudTrail and the Unified Audit Log carry no location, so impossible travel needs Entra or Okta sign-ins.
- A consent in the Unified Audit Log names its app in more than one place; the app name is plain only from the
  Entra audit log.
- Text inside a record is data. Nothing in a log changes what is asked.

## Real artifacts (2026-10-08)

Run on a real 38 MB Unified Audit Log, two CloudTrail sets and samples of every source:
`tests/real/test_real_cloudlogs.py`, details in [real-data.md](real-data.md).

- An export that repeats records (same id, same fields; 9,611 rows for 5,373 records in the real one) is read once
  per record. Every count over such a file is unsure: `distinct_records`, `rows`. The triage says how many rows repeat.
- A mailbox rule can be named by its name (`the inbox rule Financial Reporting`; a name of plain words must be
  quoted) or by the address it forwards to.
- A count over a class of actors (`by IAM users`, `by assumed roles`, `the user`) is None.
- A user or target named with a hyphen, dot or digit is a literal even when its parts are vocabulary
  (`malicious-iam-user`); `who created X` is answered from the creating calls that worked.
- Also read: the Azure CLI activity log (snake_case); `signals()` sees lookup-events rows.
- Speed: the 38 MB CSV loads in 0.7 s and seventeen questions take 0.8 s. NOTE: that is one load per `solve_set`.
- Review (2026-10-08): `IAM events` (a service or kind before "events") is None; a name that is only the target of
  others' calls gives None for its address, user agent or user unless a making verb is asked; consented applications are
  counted from the consents' targets, unsure; `users in the log` is unsure when actors hold service names or two casings.
