#!/usr/bin/env python3
"""Review checks of the `cloud_container` toolkit: the never-guess defects the adversarial review
of 2026-10-08 found, each one a question or a delivery that was answered plain and wrong before.

  .venv/bin/python tests/test_tk_cloud_container_review.py

Offline: no network, no token, nothing written. Reads the synthetic fixtures under
tests/fixtures/tk_cloud_container/. Prints one line per check and `ok` at the end; exits 1 when a
check fails.

The rule every check below guards: an exactly-one answer over events the question did not select
is a coincidence, not a fact. A verb that narrowed nothing, a literal in the wrong role, a noun
phrase the file cannot resolve, a word that is both vocabulary and a name, evidence that is
missing or doubled: each gives None (or an unsure answer), never a plain one.
"""
import copy
import gzip
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "tk_cloud_container"
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"       # nothing here makes a request; this makes sure
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import cloud_container as cc    # noqa: E402

FAILED = []


def check(name, cond, detail=""):
    print(("ok   " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def ask(files, text, member=None, fmt=None):
    q = {"qid": "q", "question": text}
    if member:
        q["member"] = member
    if fmt:
        q["answer_format"] = fmt
    return cc.solve_set([q], files, {})["q"]


def plain(a):
    return a is not None and not str(a).startswith("??")


def unsure_values(a):
    return [v for _, v in json.loads(a[2:])["o"]] if isinstance(a, str) and a.startswith("??") else []


RECS = json.loads(gzip.decompress((FIX / "cloudtrail.json.gz").read_bytes()))["Records"]
K8S = [json.loads(line) for line in (FIX / "k8s-audit.log").read_text().splitlines() if line.strip()]


def ct(records) -> bytes:
    return json.dumps({"Records": records}).encode()


def k8(records) -> bytes:
    return "\n".join(json.dumps(r) for r in records).encode()


def test_verbs_must_narrow():
    """A verb of the question that selected no events: the answer over all events is not its answer."""
    files = {"cloudtrail.json": ct(RECS)}
    for text in (
        "Who created alice?",                               # was: alice (nobody created alice)
        "Who created dev-ci?",                              # was: dev-ci
        "Which user created dev-ci?",
        "Which IP address created alice?",                  # was: alice's own address
        "How many times did dev-ci log in?",                # was: 9, every event of dev-ci
        "Which user performed the first failed login?",
        "When was the first object downloaded?",            # was: unsure, the time of ListBuckets
        "When was the last object downloaded?",             # was: unsure, the time of RunInstances
        "When did the attacker first log in?",
        "When was svc-backup created?",
        "Which bucket was made public?",
        "How many users did alice create?",                 # was: 1
    ):
        check(f"None, a verb that narrowed nothing: {text}", ask(files, text) is None, repr(ask(files, text)))
    files = {"audit.log": k8(K8S)}
    for text in (
        "Which secret was deleted?",                        # was: db-credentials (it was read)
        "Which secret was created?",                        # was: db-credentials
        "Which pod was deleted?",
        "Which pod was launched?",
        "Which pod was started?",
    ):
        check(f"None, a Kubernetes verb no event carries: {text}", ask(files, text) is None, repr(ask(files, text)))
    a = ask(files, "What time was the first secret read?")
    check("the first secret read is the first read of a secret, not the first event",
          a is None or "2026-10-01T09:14:02Z" in unsure_values(a), repr(a))
    check("a Kubernetes verb and its resource still select: Which pod was created?", ask(files, "Which pod was created?") == "debug-shell")
    check("... Which secret was read?", ask(files, "Which secret was read?") == "db-credentials")
    check("... Which namespace was the secret read from?", ask(files, "Which namespace was the secret read from?") == "prod")
    check("... Which pod was exec'd into?", ask(files, "Which pod was exec'd into?") == "payments-api-7d9f")


def test_literal_roles():
    """A named literal acts or is acted on; the sentence says which."""
    files = {"cloudtrail.json": ct(RECS)}
    for text in (
        "Which user did svc-backup create?",                # was: svc-backup (dev-ci created it; it created nobody)
        "Which access key did svc-backup create?",          # was: the key created FOR svc-backup
        "Which policy was attached to dev-ci?",             # was: unsure, the policy dev-ci attached to someone else
        "Which policy did svc-backup attach?",
        "Which access key was used with the role OrgDataExport?",
        "Which access key belongs to alice?",
    ):
        check(f"None, a literal in a role the events do not give it: {text}", ask(files, text) is None, repr(ask(files, text)))
    for text, want in (
        ("Which user did dev-ci create?", "svc-backup"),
        ("What access key ID was created for svc-backup?", "AKIAEXAMPLEBACKDOOR1"),  # secret-scan: allow
        ("Which access key was used by svc-backup?", "AKIAEXAMPLEBACKDOOR1"),  # secret-scan: allow
        ("Which access key did OrgDataExport use?", "ASIAEXAMPLESESSION01"),
        ("Who assumed the role OrgDataExport?", "svc-backup"),
        ("Which user used AKIAEXAMPLEBACKDOOR1?", "svc-backup"),  # secret-scan: allow
        ("Which user has the access key AKIAEXAMPLEBACKDOOR1?", "svc-backup"),  # secret-scan: allow
        ("What is the name of the role assumed by svc-backup?", "OrgDataExport"),
        ("How many access keys did svc-backup use?", "1"),
        ("How many events did svc-backup perform?", "3"),
        ("What was the last API call made by svc-backup?", "RunInstances"),
        ("Which user was the policy attached to?", "svc-backup"),
    ):
        check(f"plain, the literal in its role: {text}", ask(files, text) == want, repr(ask(files, text)))


def test_noun_phrases():
    """'the new user', 'the assumed role', 'the role': a reference this file cannot resolve."""
    files = {"cloudtrail.json": ct(RECS)}
    for text in (
        "Which access key did the assumed role use?",       # was: the key that assumed the role, not the role's
        "Which access key was created by the new user?",    # was: the key created FOR the new user
        "What IP address did the created user use?",
        "Which user agent did the created user use?",
        "Which access key did the new user use?",
        "How many buckets did the role read?",              # was: 2
        "What is the ARN of the created user?",             # was: the creator's ARN
        "What is the ARN of the new user?",
    ):
        check(f"None, a reference that is not resolved: {text}", ask(files, text) is None, repr(ask(files, text)))


def test_counts():
    files = {"cloudtrail.json": ct(RECS)}
    a = ask(files, "How many event names are in the log?")      # was: 16 plain (12 names in 16 events)
    check("a count of event names is unsure between the names and the events", sorted(unsure_values(a)) == ["12", "16"], repr(a))
    more = copy.deepcopy(RECS)
    user = copy.deepcopy(next(r for r in RECS if r["eventName"] == "CreateUser"))
    user["requestParameters"]["userName"] = user["responseElements"]["user"]["userName"] = "svc-two"
    user["eventTime"], user["eventID"] = "2026-09-30T14:13:06Z", "review-user-2"
    key = copy.deepcopy(next(r for r in RECS if r["eventName"] == "CreateAccessKey"))
    key["responseElements"]["accessKey"]["accessKeyId"] = "AKIAEXAMPLESECOND002"  # secret-scan: allow
    key["eventTime"], key["eventID"] = "2026-09-30T14:13:21Z", "review-key-2"
    files2 = {"cloudtrail.json": ct(more + [user, key])}
    # was 1 and 1: the one user who made the calls, the one key that signed them
    check("users created are the users created, not their creators", ask(files2, "How many users were created?") == "2")
    check("access keys created are the keys returned, not the keys that signed", ask(files2, "How many access keys were created?") == "2")
    check("'how many users created access keys' is not decided here", ask(files2, "How many users created access keys?") is None)
    check("two users created: 'which user was created' is None", ask(files2, "Which user was created?") is None)
    check("the fixture's counts hold: users created", ask(files, "How many users were created?") == "1")
    check("... buckets accessed are the buckets read", ask(files, "How many buckets were accessed?") == "2")
    check("... events of one actor", ask(files, "How many events did dev-ci make?") == "9")
    audit = {"audit.log": k8(K8S)}
    check("a service account among the actors: 'how many users' is None", ask(audit, "How many users appear in the log?") is None)
    image = {"image.tar": (FIX / "image.tar").read_bytes()}
    check("the image's layer count", ask(image, "How many layers does the image have?") == "3")
    for text in ("How many layers deleted a file?", "How many layers were added?", "How many layers added secret.txt?"):   # was: 3
        check(f"None, layers that did something are not the layer count: {text}", ask(image, text) is None, repr(ask(image, text)))


def test_vocabulary_names():
    """A user named with a word of the vocabulary: the word selected nothing."""
    recs = copy.deepcopy(RECS)
    for r in recs:
        ui = r["userIdentity"]
        if ui.get("userName") == "alice":
            ui["userName"], ui["arn"] = "admin", ui["arn"].replace("alice", "admin")
    files = {"cloudtrail.json": ct(recs)}
    for text in ("How many events did admin make?",             # was: 16, every event of the log
                 "What was the last API call made by admin?",   # was: RunInstances, the log's last event
                 "What IP address did admin use?"):
        check(f"None, a name that is also vocabulary: {text}", ask(files, text) is None, repr(ask(files, text)))
    check("the same word used as a word does not veto", ask(files, "How many events are in the log?") == "16")


def test_evidence_whole():
    whole = ct(RECS)
    twice = {"a/cloudtrail.json": whole, "b/cloudtrail.json": bytes(bytearray(whole))}
    check("the same log under two names is counted once", ask(twice, "How many events are in the log?") == "16",       # was: 32
          repr(ask(twice, "How many events are in the log?")))
    dup = {"a.json": ct(RECS), "b.json": ct(RECS[:4] + [dict(RECS[0], awsRegion="us-east-1 ")])}
    check("an event id seen twice: no event count", ask(dup, "How many events are in the log?") is None)
    gz = (FIX / "cloudtrail.json.gz").read_bytes()
    cutgz = {"part1.json": ct(RECS[:5]), "part2.json.gz": gz[:len(gz) // 2]}
    for text in ("How many events are in the log?", "What IP address did alice use?"):     # was: 5, and alice's address
        check(f"None, a gzip log that ends early beside a whole one: {text}", ask(cutgz, text) is None, repr(ask(cutgz, text)))
    junk = {"part1.json": ct(RECS), "notes.gz": b"\x1f\x8b\x08\x00garbage-that-is-no-deflate-stream"}
    check("a gzip that holds nothing readable is a note, not a cut", ask(junk, "How many events are in the log?") == "16")


def test_sources_apart():
    """CloudTrail beside a Kubernetes audit log: each question goes to the log that can answer it."""
    files = {"cloudtrail.json": ct(RECS), "audit.log": k8(K8S)}
    check("a Kubernetes question is read from the Kubernetes log, the smaller one", ask(files, "Which secret was read?") == "db-credentials",
          repr(ask(files, "Which secret was read?")))      # was: None or a manifest's answer, by the larger log's rules
    check("... Which pod was exec'd into?", ask(files, "Which pod was exec'd into?") == "payments-api-7d9f")
    check("a CloudTrail question is read from CloudTrail", ask(files, "Which user created the access key?") == "dev-ci")
    check("... What IP address did alice use?", ask(files, "What IP address did alice use?") == "198.51.100.10")
    check("a question both logs answer differently is None", ask(files, "What was the first event?") is None)
    check("an event count over two logs is None", ask(files, "How many events are in the log?") is None)
    every = {p.name: p.read_bytes() for p in FIX.iterdir() if p.is_file()}
    a = ask(every, "Which pod is privileged?")              # was: node-agent, a Deployment's name out of a manifest
    check("a Deployment is not a pod", a is None, repr(a))
    manifests = {n: every[n] for n in ("Dockerfile", "deployment.yaml", "docker-compose.yml")}
    check("... in manifests alone", ask(manifests, "Which pod is privileged?") is None)
    a = ask(manifests, "What user does the container run as?")     # was: 65532, the Dockerfile's USER
    check("a container's user beside manifests is not the Dockerfile's USER", a is None, repr(a))
    check("... the Dockerfile alone answers", ask({"Dockerfile": every["Dockerfile"]}, "What user does the container run as?") == "65532")


def test_identity_without_name():
    recs = copy.deepcopy(RECS[:2])
    for r in recs:
        r["userIdentity"] = {"type": "Root", "arn": "arn:aws:iam::123456789012:root", "accountId": "123456789012"}
    a = ask({"cloudtrail.json": ct(recs)}, "Which user made the first call?")      # was: the root ARN, plain
    check("an identity with no logged user name is never plain", not plain(a), repr(a))


def test_kept():
    """What the guards must not take away."""
    files = {"cloudtrail.json": ct(RECS)}
    for text, want in (
        ("Which user logged in to the console?", "dev-ci"),
        ("Which user failed to log in to the console?", "dev-ci"),
        ("How many console logins failed?", "3"),
        ("Which region were the events logged in?", "us-east-1"),
        ("Which access key was used to assume the role?", "AKIAEXAMPLEBACKDOOR1"),  # secret-scan: allow
        ("Which user created the access key?", "dev-ci"),
        ("Which user was created?", "svc-backup"),
        ("What is the name of the new IAM user?", "svc-backup"),
        ("Which bucket did alice read?", "corp-public-assets"),
        ("Which object did alice download?", "logo.png"),
        ("What instance type was launched?", "c5.4xlarge"),
        ("Who stopped logging?", "svc-backup"),
        ("What IP address is associated with svc-backup?", "203.0.113.66"),
        ("What is the ARN of the policy attached to svc-backup?", "arn:aws:iam::aws:policy/AdministratorAccess"),
    ):
        check(f"kept: {text}", ask(files, text) == want, repr(ask(files, text)))
    a = ask(files, "Which trail was stopped?")
    check("kept, unsure: Which trail was stopped?", "org-trail" in unsure_values(a), repr(a))
    audit = {"audit.log": k8(K8S)}
    for text, want in (("What is the source IP of the ci-runner service account?", "10.0.3.7"),
                       ("Which namespace does the service account belong to?", "dev"),
                       ("Which clusterrole was granted?", "cluster-admin"),
                       ("Which pod did ci-runner exec into?", "payments-api-7d9f")):
        check(f"kept: {text}", ask(audit, text) == want, repr(ask(audit, text)))


def main() -> int:
    test_verbs_must_narrow()
    test_literal_roles()
    test_noun_phrases()
    test_counts()
    test_vocabulary_names()
    test_evidence_whole()
    test_sources_apart()
    test_identity_without_name()
    test_kept()
    if FAILED:
        print(f"\n{len(FAILED)} FAILED: " + "; ".join(FAILED))
        return 1
    print("\nok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
