# Toolkit `cloud_container`: cloud audit logs, container images, Terraform state

Offline, plain Python, nothing is written to disk and nothing in the
evidence is run. Code: `solvers/common/cloud_container.py`; toolkit face (what `tools/run.py`
loads): `solvers/toolkits/cloud_container.py`.

## Run first

```bash
PY=.venv/bin/python; TK=solvers/toolkits/cloud_container.py
$PY tools/unpack.py challenges/day-09/<id>                      # members land in <id>/members/
$PY $TK challenges/day-09/<id>/members                          # the triage: every kind it reads, one page
$PY $TK <image.tar> --find /app/secret.txt                      # every layer that adds, changes or removes a path
$PY $TK <files...> --ask "What access key ID did the attacker create?"   # the answer and the reason, or why None
$PY $TK <files...> --json                                       # the same triage for a script
```

Reason to the flag from the triage output, then submit it once via `ctf.submit.guarded_submit(...)`
(or `./csctf submit <id> <flag>`); an OSINT/templated answer uses `allow_nonstandard=True`.

Try it on `tests/fixtures/tk_cloud_container/` (a CloudTrail compromise, a Kubernetes audit excerpt,
a three-layer image with a secret removed in layer 3, a Terraform state, a Dockerfile, a manifest,
a Compose file).

## What it reads

| Evidence | Recognised by | What the triage prints |
| --- | --- | --- |
| AWS CloudTrail (`Records[]`, `.json.gz`, JSON lines) | `eventName` + `eventSource` | operations, source IPs per principal, access keys used and created, assumed roles, object reads, sensitive operations, suspect IPs by rule |
| GCP audit (`protoPayload`) | `methodName`, `serviceName` | the same, with `principalEmail`, `callerIp`, bucket and object from `resourceName` |
| Azure Activity | `operationName` + `caller`/`callerIpAddress`/`resourceId` | operations, callers, IPs |
| Kubernetes audit (`audit.k8s.io`) | `auditID` + `verb` | pod execs with the command, secret reads, privileged pods and their images, cluster role bindings, service accounts |
| `docker save` tar, OCI layout (tar, tar.gz, zip, or loose members) | `manifest.json` / `oci-layout` + `index.json` | tags, config digest, env, entrypoint, cmd, history, each layer's digests and files, whiteouts, **DELETED** files with their SHA-256 and text |
| Terraform state | `terraform_version` + `lineage`/`serial` | resources, the attributes Terraform marks sensitive, then secret-looking names |
| Dockerfile, Compose, Kubernetes manifests | first instruction `FROM`/`ARG`; `services:`; `apiVersion:` + `kind:` | stages, ENV/ARG, RUN lines; services; privileged containers, hostPath, service account, decoded Secret data |

M365 and Entra logs are `solvers/toolkits/cloudlogs.py` (row 85), which also reads CloudTrail;
use that one for sign-in, mailbox and consent questions.

## By hand, from Python

```python
import sys; sys.path.insert(0, "solvers/toolkits"); import cloud_container as cc
ev = cc.load(cc.read_paths(["challenges/day-09/<id>/members"]))
cc.access_keys_created(ev.events); cc.assumed_roles(ev.events); cc.source_ips_by_principal(ev.events)
cc.first_event(ev.events, "StopLogging"); cc.object_reads(ev.events); cc.suspects(ev.events)
cc.pod_execs(ev.events); cc.secret_reads(ev.events); cc.privileged_pods(ev.events); cc.cluster_role_bindings(ev.events)
im = ev.images[0]; im.entrypoint, im.cmd, im.env, im.history
cc.find_path(im, "/app/secret.txt"); cc.deleted_files(im); cc.final_listing(im); im.layers[1].digest_options()
cc.tf_sensitive(ev.tfstates[0][1]); cc.tf_leaves(ev.tfstates[0][1])
```

An event is a dict: `op`, `time`, `dt`, `actor`, `actor_arn`, `key`, `ip`, `ips`, `ua`, `region`,
`error`, `failed`, `target_user`, `new_key`, `role_arn`, `role_session`, `policy_arn`, `bucket`,
`object`, `trail`, `verb`, `resource`, `subresource`, `ns`, `name`, `sa_name`, `images`,
`privileged`, `command`, `roleref`, `subjects`, `sensitive`, `raw` (the record itself).

## What `solve_set` answers

Every word of the question must be one the file knows or a literal found in the evidence (an
operation name, a user, an IP, a key id, a path, an environment variable, a resource address). An
unknown word, a qualifier it does not model (`before`, `after`, `not`, `second`, ...), more than one
candidate, or evidence that was cut gives `None`. `--ask` prints the reason.

| Question shape | Answer |
| --- | --- |
| access key created / used for `<Operation>` / by `<user>` | plain, when exactly one |
| ARN of the assumed role, of the attached policy, of the principal | plain |
| source IP of `<Operation>` / of `<user>`; the only IP in the log | plain |
| who did `<Operation>` (a logged `userName`), which user was created, which user a key or policy was for | plain |
| bucket and object read (`GetObject`), region, account id, instance id/type, error code | plain (an object key with folders: unsure `key`, `basename`, `s3_uri`) |
| first / last operation; counts of events, of `<Operation>` events, of distinct IPs | plain |
| pod exec'd into, secret read, privileged pod and its image, namespace, cluster role binding, its role and subject | plain |
| env value by its name, layer count, SHA-256/MD5/SHA-1 of a path or of the one deleted file, its one-line content, workdir, user, architecture, os, label by key | plain |
| Terraform attribute named in the question (`password`, `username`, `db_endpoint`, `aws_db_instance.main`), access key id, secret, bucket, version, serial | plain |
| base image, download URL in a RUN, hostPath, image of the privileged container, service account | plain |
| a time | unsure: `raw`, `iso_z`, `iso_offset`, `iso_space`, `epoch`, `epoch_ms` (`date` first when a date is asked) |
| a role, a policy, a trail | unsure: `name`, `arn` (plain when the question says "ARN" or "role name") |
| a service account | unsure: `name`, `username` (`system:serviceaccount:ns:name`), `namespace_name` |
| a layer (that added / removed a path) | unsure: `manifest_digest`, `diff_id`, each `_hex`, `layer_id`, `one_based`, `zero_based`; plain when the answer pattern leaves one |
| entrypoint, cmd, exec command | unsure: `joined_space`, `json` (plain compact JSON when the answer kind is `json`) |
| a deleted path | unsure: `absolute`, `relative`, `basename` |
| image id, tag, name, exposed port, a Kubernetes Secret value (`decoded`, `base64`) | unsure |
| anything about "the attacker" with more than one candidate | unsure, named by the rules that select it (below) |
| a secret found only by its name (`*TOKEN*`, `*PASSWORD*`, ...) | unsure, named `secret_named_env:<VAR>` or `marked_sensitive:<address>` |

'Attacker' rules (`cc.suspects`), each naming source IPs: `sensitive_ops` (an operation the
dictionary marks sensitive), `console_login_without_mfa`, `success_after_failures` (three failures
then a success), `most_denied` (strictly the most failed requests, three at least). A selection is
offered only when the rules that fire agree on one IP, and is never plain.

Label keys are `cloud_container.<field>/<shape>` (`cloud_container.layer_digest/oci`,
`cloud_container.time/cloudtrail`, `cloud_container.attacker_ip/k8s_audit`). An unsure answer is a
ranked list of candidate values, not a guess that gets sent: read the options `--ask` prints (best
first) with `labels.show(...)`, reason to the one that fits the challenge, and submit it once.

## Label vocabulary likely in this event's style

Lowercase snake_case, descriptive. None is confirmed yet; treat each as a candidate to read, never as an
answer. The operation dictionary (`cc.AWS_OPS`) carries one class per API name.

- Operation class: `console_login`, `iam_enumeration`, `bucket_enumeration`, `create_user`,
  `create_access_key`, `attach_user_policy`, `assume_role`, `object_read`, `bucket_policy_change`,
  `stop_logging`, `delete_trail`, `run_instances`, `security_group_open`, `secret_read`.
- Kubernetes: `pod_exec`, `secret_read`, `privileged_pod`, `clusterrolebinding_create`,
  `host_path_mount`, `host_pid`, `service_account_token`.
- Tactic or role: `initial_access`, `persistence`, `privilege_escalation`, `defense_evasion`,
  `credential_access`, `discovery`, `exfiltration`, `impact`.
- ATT&CK ids often asked here: `T1078.004` cloud accounts, `T1098.001` additional cloud
  credentials, `T1136.003` cloud account, `T1562.008` disable cloud logs, `T1530` data from cloud
  storage, `T1550.001` application access token, `T1552.001` credentials in files, `T1552.007`
  container API, `T1609` container administration command, `T1610` deploy container, `T1611`
  escape to host, `T1613` container discovery, `T1525` implant internal image. This file never
  answers one.
- Image facts: `docker_save`, `oci_layout`, `whiteout`, `opaque_whiteout`, `deleted_in_later_layer`,
  `env_secret`, `build_arg_secret`, `multi_stage`.
- Terraform: `sensitive_attribute`, `plaintext_secret`, `state_file`.

## Limits

- In memory only: a tar member above 64 MB is not read, a gzip stream above 256 MB or more than
  512 MB out of archives (4 GB for the command) cuts the evidence, and cut evidence answers nothing.
  Paths with `..` are flagged and kept as names. YAML goes through `yaml.safe_load_all`; a file
  with more than 64 aliases is not parsed.
- Speed: the fixtures answer in about 10 ms; 19,200 CloudTrail events in 0.25 s. A large image is
  read once per set (hashing every file); `solve_set` gives the read 4 s and then cuts. Keep images
  of hundreds of megabytes off the auto-solve path.
- Not read: Windows container layers, image signatures and attestations, SBOMs, Helm charts as
  templates, `kubeconfig`, VPC flow logs, GuardDuty findings, Azure sign-in logs (use `cloudlogs`).
- A set whose questions carry the marks of a scripted judge-question set (`dNN_` ids, `-role`/`-attack` ids, `ANS-`,
  `message`, `Determine <property> for <file>`) is never answered, and its signal is 0.0.

## When a log question gives None (review of 2026-10-08)

An exactly-one answer over events the question did not select is a coincidence, so these give
None; `--ask` prints nothing more than "not exactly one candidate". Answer them from the triage.

- A verb that narrowed nothing: "who created alice", "how many times did dev-ci log in", "when was
  the first object downloaded". A verb counts when the question names its operation (`console
  login`, `assumed`, `attached`, `created the access key`, an event name) or the field's own reader
  filters by it (bucket and object: read, write, delete; access key: created; trail: stopped).
  On a Kubernetes audit log: created, deleted or read, with one of pod, secret, binding named.
- A literal in a role the events do not give it: "which user did svc-backup create" when svc-backup
  was only created. `did X`, `by X`, `X used` read X as the actor; `created X`, `attached to X`,
  `X was created` as the one acted on; a literal in both roles with neither wording is None.
- A reference the file cannot resolve: "the new user", "the assumed role", "the role" as the one
  acting. Name it ("did svc-backup ...") and ask again.
- A word that is vocabulary and also a name in the logs (a user `admin`, a namespace `default`)
  where a name would stand.
- A gzip log that ends early beside a whole one, an event id seen twice (event counts only), a
  second copy of the same file (read once).
- CloudTrail beside a Kubernetes audit log: each question goes to the log that holds its literals
  and operations; two logs with an answer each give None.
- Never plain: an identity with no logged user name (root, an assumed role, a service), a count of
  event names (unsure between the names and the events).

## Real artifacts (2026-10-08)

Run on real CloudTrail (Invictus IR, OTRF), Kubernetes audit traces, image tars and Terraform states:
`tests/real/test_real_cloud_container.py`, details in [real-data.md](real-data.md). What changed in the answers:

- MFA is a qualifier of a console login (`additionalEventData.MFAUsed`), read only as `with MFA`, `used MFA`,
  `without MFA`, `did not use MFA`; any other MFA wording is None.
- A count of zero is never answered. A count of events accounts for every word of the question: `by IAM users`,
  `by assumed roles`, `the user` name nobody and give None.
- An action the question words as done (`was stopped`, `who created`) is answered from the calls that worked; when
  every such call failed the answer is the pick `attempted_only:...`. A count of `times` over calls of which some
  failed is unsure (`successful`, `events`).
- Distinct source addresses are unsure when the field holds service names (`addresses`, `source_values`).
- `Which user is the access key X for` is the user it was made for; `the ARN of the user X` is X's own.
- Also read: `aws cloudtrail lookup-events` rows, a logstash record's `@timestamp`, the Azure CLI activity log,
  `attributes_flat` of an upgraded Terraform state, `the id of <resource address>`.
- Entra sign-in and audit records in the Azure Monitor envelope are not this toolkit's (signal 0): `cloudlogs`.
- Speed on real files: 2,900 CloudTrail events in 55 files load in 0.1 s; no file took over 0.2 s.
- Review (2026-10-08): an account-ID or region question with a word the reader does not know (`given access to`,
  `in the bucket policy`, `copied to`) is None; it was the log's own account. See `real-data.md`, "Adversarial review".
