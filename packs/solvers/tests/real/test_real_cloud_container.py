#!/usr/bin/env python3
"""`cloud_container` on real artifacts (the cache of tests/real/fetch_b.py; SKIPs without it).

  .venv/bin/python tests/real/test_real_cloud_container.py

Offline, nothing written, no request. Every expected value below was read from the records with
plain `json` (never with the toolkit), or is stated by the source: see docs/toolkits/real-data.md.

- Invictus IR's CloudTrail data set (55 files, 2,900 events of a Stratus Red Team run): the review's
  wrong plain answers, each asserted the right way round (MFA, zero counts, actor classes, a key's
  owner, a named user's ARN, a role "assumed" by calls that failed).
- OTRF's ec2_proxy_s3_exfiltration (a logstash export: the time is @timestamp).
- plaso's `aws cloudtrail lookup-events` rows and Azure CLI activity log; beats' Azure Monitor
  sign-in logs (not this toolkit's: signal 0).
- falco's Kubernetes audit traces; go-containerregistry's `docker save` tars; Terraform's own states.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_b as rd      # noqa: E402

R = rd.Run("cloud_container")

# AWS key ids of the public datasets: the commit guard keeps key-shaped literals out of the repo,
# so each is pinned by its SHA-256 and read back from the corpus files at run time.
_AWS_KEY_1 = rd.pinned_token("12992551cbf4550d6879dcb2d2f5c5e8f6dd1338c3766faadfabc3bbb88bb645", "cloudlogs/aws_dataset")
_AWS_KEY_2 = rd.pinned_token("71e92523898ff6e1b46168da6d6d5e632c0a96d75f50b2c6a35ccac65c6492ec", "cloudlogs/otrf/ec2_proxy_s3_exfiltration.zip.d")
_AWS_KEY_3 = rd.pinned_token("8d904a23f44c6860d89bd3016270a9f03e3488f1fce3c9765ff511f4c4937262", "cloudlogs/aws_dataset")
A = "cloudlogs/aws_dataset"

AWS_PLAIN = [   # (question, the value read from the records with plain json)
    ("How many console logins used MFA?", "1"),                        # was 2: MFAUsed was not read
    ("How many console logins did not use MFA?", "1"),
    ("How many ConsoleLogin events were made without MFA?", "1"),
    ("Which user logged in to the console without MFA?", "stratus-red-team-nmfalu-gfjyeaypjt"),
    ("Which user logged in to the console with MFA?", "bert-jan"),
    ("What is the source IP address of the console login without MFA?", "192.168.10.20"),
    ("How many ConsoleLogin events are in the logs?", "2"),
    (f"Which user is the access key {_AWS_KEY_1} for?", "malicious-iam-user"),     # was bert-jan, who made it
    ("What is the access key ID created for malicious-iam-user?", _AWS_KEY_1),
    (f"Who created the access key {_AWS_KEY_1}?", "bert-jan"),
    ("What policy ARN was attached to malicious-iam-user?", "arn:aws:iam::aws:policy/AdministratorAccess"),
    ("Which IAM user was attached the AdministratorAccess policy?", "malicious-iam-user"),
    ("What is the ARN of the user malicious-iam-user?", "arn:aws:iam::123837392027:user/malicious-iam-user"),   # was bert-jan's
    ("How many CreateUser events are there?", "4"),
    ("How many users were created?", "4"),
    ("How many access keys were created?", "2"),
    ("How many AssumeRole events are there?", "49"),
    ("How many AssumeRole events failed?", "13"),
    ("How many AssumeRole events were made by bert-jan?", "23"),
    ("How many events were made by bert-jan?", "2642"),
    ("How many events came from 192.168.10.20?", "2154"),
    ("How many events did bert-jan make from 10.8.8.10?", "281"),
    ("How many events are in the logs?", "2900"),
    ("How many events failed?", "300"),
    ("How many events have an error?", "300"),                         # was 2900
    ("How many access keys did benjamin use?", "17"),
    ("What is the AWS account ID?", "123837392027"),
    ("Which AWS region was used?", "us-east-1"),
    ("What was the first event in the logs?", "GetRegionOptStatus"),
    ("What was the last operation?", "DescribeEventAggregates"),
    ("What error code did the LeaveOrganization call return?", "AccessDenied"),
    ("What error code was returned for GetPasswordData?", "Client.UnauthorizedOperation"),
    ("What session name was used when assuming stratus-red-team-leave-org-role?", "aws-go-sdk-1688990515440126480"),
    ("How many GetSecretValue calls did bert-jan make?", "60"),
    ("How many RunInstances events failed?", "6"),
    ("Which user made the first console login?", "stratus-red-team-nmfalu-gfjyeaypjt"),
    ("Which user did bert-jan attach a policy to?", "malicious-iam-user"),
]
AWS_NEVER_PLAIN = [     # each was a plain wrong answer, or is a question the records do not settle
    "How many failed console logins are there?",                        # zero events: no plain 0
    "How many DeleteUser events did benjamin make?",
    "How many CreateUser events came from 10.8.8.10?",
    "How many events were made by IAM users?",                          # was 2900 (2748 by IAM users)
    "How many events were made by assumed roles?",                      # was 49, the AssumeRole calls (76 by assumed roles)
    "How many different users made requests?",                          # was 2900
    "How many distinct source IP addresses are in the logs?",           # 7 addresses, 16 values with service names
    "How many buckets are there?",
    "How many times was a role assumed?",                               # 49 calls, 36 that worked
    "How many times did bert-jan assume a role?",
    "Who stopped logging?",                                             # every StopLogging failed (TrailNotFoundException)
    "Which trail was stopped?",
    "How many logins used MFA?",
    "How many API calls used MFA?",
    "How many users have MFA?",
    "How many console logins by root?",
    "How many events were not made by bert-jan?",
    "What is the attacker's IP address?",
    "What is the MITRE ATT&CK technique for StopLogging?",
]
AWS_UNSURE = [          # (question, a value the options must hold)
    ("How many distinct source IP addresses are in the logs?", "7"),
    ("How many distinct source IP addresses are in the logs?", "16"),
    ("How many times was a role assumed?", "36"),
    ("Who stopped logging?", "bert-jan"),
    ("When was the first event?", "2023-07-10T11:42:18Z"),
    ("What is the attacker's IP address?", "192.168.10.20"),
]
OTRF_PLAIN = [
    ("Which object was downloaded from the S3 bucket?", "ring.txt"),
    ("What file did the attacker exfiltrate?", "ring.txt"),
    ("Which bucket was the object downloaded from?", "mordors3stack-s3bucket-llp2yingx64a"),
    ("How many GetObject events are there?", "2"),
    ("What access key ID was used for the GetObject requests?", _AWS_KEY_2),
    ("What is the source IP of the ListBuckets calls?", "1.2.3.4"),
    ("Which user made the DescribeInstances calls?", "pedro"),
    ("How many events did pedro make?", "87"),
    ("How many AssumeRole events are there?", "5"),
    ("What is the account ID?", "123456789123"),
    ("How many events are there?", "103"),
    ("What is the ARN of pedro?", "arn:aws:iam::123456789123:user/pedro"),
]
K8S_PLAIN = [
    ("Which pod was exec'd into?", "nginx-deployment-7998647bdf-phvq7"),
    ("Which user exec'd into the pod?", "minikube-user"),
    ("What source IP address exec'd into the pod?", "192.168.99.1"),
    ("What is the name of the cluster role binding that was created?", "some-reader-binding"),
    ("Which cluster role was bound by the new cluster role binding?", "cluster-admin"),
    ("Which subject was granted cluster-admin?", "minikube"),
    ("What image does the privileged pod use?", "nginx"),
    ("Which secret was created in the kube-system namespace?", "bootstrap-token-ne7bxu"),
    ("Which secret did minikube-user create?", "example-secret"),
    ("Which user created the secret bootstrap-token-ne7bxu?", "admin"),
    ("How many events are in the audit log?", "13"),
    ("How many events did minikube-user make?", "7"),
]
IMG_PLAIN = [
    ("What is the SHA-256 of the deleted file?", "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
    ("What is the content of the deleted file?", "foo"),
    ("How many layers does the image have?", "3"),
    ("What is the architecture of the image?", "amd64"),
    ("What is the operating system of the image?", "linux"),
    ("What is the SHA-256 of bar.txt?", "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
]
TF_PLAIN = [
    ("What version of Terraform wrote the state?", "0.12.0"),
    ("What is the lineage of the state?", "f2968801-fa14-41ab-a044-224f3a4adf04"),
    ("What is the value of the output numbers?", "0,1"),
    ("What is the id of null_resource.bar?", "5388490630832483079"),       # attributes_flat was not read
]


def battery(cc, fs, name, plains=(), never=(), unsure=()):
    qs = [{"qid": f"p{i}", "question": t} for i, (t, _) in enumerate(plains)]
    qs += [{"qid": f"n{i}", "question": t} for i, t in enumerate(never)]
    qs += [{"qid": f"u{i}", "question": t} for i, (t, _) in enumerate(unsure)]
    ans = R.timed(f"{name}: solve_set of {len(qs)} questions", lambda: cc.solve_set(qs, fs, {}))
    for i, (t, want) in enumerate(plains):
        R.check(f"{name}: plain {want!r}: {t}", ans[f"p{i}"] == want, repr(ans[f"p{i}"])[:120])
    for i, t in enumerate(never):
        R.check(f"{name}: never plain: {t}", not rd.plain(ans[f"n{i}"]), repr(ans[f"n{i}"])[:120])
    for i, (t, want) in enumerate(unsure):
        R.check(f"{name}: offers {want!r}: {t}", want in [str(v) for v in rd.options(ans[f"u{i}"])], repr(ans[f"u{i}"])[:160])


def main() -> int:
    cc = rd.toolkit("cloud_container")
    if R.need("Invictus CloudTrail", A):
        fs = rd.files(A)
        sig = R.timed("aws_dataset: signals", lambda: cc.signals([], fs))
        R.check("aws_dataset: signal reaches the registry threshold (0.7)", sig >= 0.7, sig)
        ev = R.timed("aws_dataset: load of 55 files", lambda: cc.load(fs))
        R.check("aws_dataset: 2,900 events, one source, nothing cut", len(ev.events) == 2900 and dict(ev.sources) == {"cloudtrail": 2900} and not ev.cut,
                f"{len(ev.events)} {dict(ev.sources)} {ev.cut}")
        made = cc.access_keys_created(ev.events)
        R.check("aws_dataset: the two created access keys and whom they are for",
                sorted((k["key"], k["for_user"]) for k in made) == [(_AWS_KEY_3, "stratus-red-team-backdoor-u-user"),
                                                                    (_AWS_KEY_1, "malicious-iam-user")], made)
        battery(cc, fs, "aws_dataset", AWS_PLAIN, AWS_NEVER_PLAIN, AWS_UNSURE)
    o = "cloudlogs/otrf/ec2_proxy_s3_exfiltration.zip.d"
    if R.need("OTRF CloudTrail", o):
        fs = rd.files(o)
        ev = cc.load(fs)
        R.check("otrf: the time of a logstash record is read from @timestamp", all(e["dt"] is not None for e in ev.events) and len(ev.events) == 103)
        battery(cc, fs, "otrf", OTRF_PLAIN, ["How many events failed?", "Which user downloaded ring.txt?", "What is the attacker's IP address?"])
    if R.need("plaso lookup-events rows", "cloudlogs/plaso/aws_cloudtrail.jsonl"):
        fs = rd.files("cloudlogs/plaso/aws_cloudtrail.jsonl")
        ev = cc.load(fs)
        R.check("lookup-events: the six CloudTrailEvent strings are read as records",
                sorted(e["op"] for e in ev.events) == ["CreateSecurityGroup", "DescribeInstances", "RunInstances", "SharedSnapshotVolumeCreated",
                                                      "StopInstances", "TerminateInstances"], [e["op"] for e in ev.events])
        R.check("lookup-events: signal", cc.signals([], fs) >= 0.7)
    if R.need("plaso Azure CLI activity log", "cloudlogs/plaso/azure_activity_log.jsonl"):
        fs = rd.files("cloudlogs/plaso/azure_activity_log.jsonl")
        ev = cc.load(fs)
        R.check("az activity log: four events with operation, address and time",
                len(ev.events) == 4 and {e["ip"] for e in ev.events} == {"1.2.3.4"} and all(e["dt"] for e in ev.events)
                and "Microsoft.Compute/disks/delete" in {e["op"] for e in ev.events}, [(e["op"], e["ip"]) for e in ev.events])
    if R.need("beats Azure Monitor sign-in logs", "cloudlogs/beats/azure/signinlogs.log"):
        for n in ("signinlogs.log", "test-non-interactive-user-signin.log", "auditlogs.log", "activitylogs_identity.log"):
            if rd.have("cloudlogs/beats/azure/" + n):
                fs = rd.files("cloudlogs/beats/azure/" + n)
                R.check(f"Entra records in the Azure Monitor envelope are left to cloudlogs: {n}", cc.signals([], fs) == 0.0 and not cc.load(fs).events)
        R.check("a real Azure activity record is still read", len(cc.load(rd.files("cloudlogs/beats/azure/activitylogs.log")).events) == 1)
    for n in ("cloudlogs/beats/o365/01-exchange-admin.log", "cloudlogs/beats/okta/okta-system-test.json.log", "cloudlogs/plaso/microsoft_audit_log.jsonl"):
        if rd.have(n):
            R.check(f"not this toolkit's log, signal 0: {n.rsplit('/', 1)[-1]}", cc.signals([], rd.files(n)) == 0.0)
    k = "cloudlogs/falco_k8s_audit"
    if R.need("falco Kubernetes audit traces", k):
        battery(cc, rd.files(k), "k8s", K8S_PLAIN, ["How many pods were created?", "Which secret was created?", "Which secret was read?",
                                                   "What is the attacker's IP address?"],
                [("What command was executed in the pod?", "bash"), ("Which service account created the privileged pod?", "replicaset-controller")])
    w = "cloud_container/gcr/whiteout_image.tar"
    if R.need("go-containerregistry whiteout image", w):
        fs = rd.files(w)
        im = R.timed("whiteout_image: load", lambda: cc.load(fs)).images[0]
        gone = cc.deleted_files(im)
        R.check("whiteout_image: foo.txt added in layer 1, removed in layer 2", len(gone) == 1 and "foo.txt" in str(gone[0]), gone)
        battery(cc, fs, "whiteout_image", IMG_PLAIN, ["What is the entrypoint of the image?", "What base image was used?", "How many files are in the image?"],
                [("Which file was deleted from the image?", "foo.txt"), ("What is the image tag?", "bazel/pkg/v1/mutate:whiteout_image"),
                 ("Which layer removed foo.txt?", "sha256:88d2a7b2ae6dddeb3490c9370cfc070aaa1aab9c22a6fb03523787d8b21c17db"),
                 ("What is the image ID?", "sha256:decb630649c3e1256345d416b228d6c3ceb387a55120ad44dc3ec992976d28b9")])
    h = "cloud_container/gcr/hello-world-v25.tar"
    if R.need("docker 25 save of hello-world", h):
        im = cc.load(rd.files(h)).images[0]
        R.check("hello-world (docker 25, OCI blobs): arm64, cmd /hello, one layer holding hello",
                im.cmd == ["/hello"] and len(im.layers) == 1 and "hello" in im.layers[0].entries and im.config.get("architecture") == "arm64", (im.cmd, len(im.layers)))
    b = "cloud_container/gcr/test_bundle.tar"
    if R.need("two images in one tar", b):
        fs = rd.files(b)
        R.check("test_bundle: two images are read", len(cc.load(fs).images) == 2)
        R.check("test_bundle: a question two images answer differently is None", rd.ask(cc, fs, "What is the image tag?") is None
                or rd.unsure(rd.ask(cc, fs, "What is the image tag?")))
    t = "cloud_container/terraform/roundtrip__v4-simple.in.tfstate"
    if R.need("Terraform v4 state", t):
        fs = rd.files(t)
        battery(cc, fs, "tfstate v4", TF_PLAIN, ["What password is stored in the state?",       # was '0': an attribute is named "what"
                                                 "What is the id of null_resource.foo?"])
    t3 = "cloud_container/terraform/roundtrip__v3-simple.in.tfstate"
    if R.need("Terraform v3 state", t3):
        ev = cc.load(rd.files(t3))
        R.check("tfstate v3: the four resources of the root module", {r["address"] for r in ev.tf_rows if r["mode"] == "managed"}
                == {"null_resource.bar", "null_resource.foo.0", "null_resource.foo.1", "null_resource.foobar"}, sorted({r["address"] for r in ev.tf_rows}))
    return R.done()


if __name__ == "__main__":
    sys.exit(main())
