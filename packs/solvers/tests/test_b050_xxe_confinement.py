"""B-050: inert XXE confinement catalog and the offline traversal/confinement mapper.

The catalog rows are string-only probe documents; the mapper classifies saved
read observations as data (substring tests only). Neither performs I/O.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import xml_ssrf_catalog as catalog  # noqa: E402
import xxe_read  # noqa: E402


# --- catalog -----------------------------------------------------------------

def test_confinement_catalog_covers_container_chroot_and_mount_probes():
    rows = catalog.xxe_confinement_catalog()
    names = [row.name for row in rows]
    assert names == [
        "passwd_reachable",
        "hostname",
        "self_cgroup",
        "init_cgroup",
        "self_mountinfo",
        "init_root_hostname",
        "self_environ",
    ]
    assert {row.family for row in rows} == {"xxe-confinement"}
    docs = {row.name: row.document for row in rows}
    assert 'SYSTEM "file:///proc/self/cgroup"' in docs["self_cgroup"]
    assert 'SYSTEM "file:///proc/1/root/etc/hostname"' in docs["init_root_hostname"]
    # /proc/self/root is the reader's own root: it can never reveal a chroot,
    # so no probe may rely on it.
    assert not any("/proc/self/root" in row.document for row in rows)
    assert all("<!DOCTYPE" in row.document and "<!ENTITY probe SYSTEM" in row.document
               for row in rows)
    assert all(row.to_dict()["inert"] and row.to_dict()["offline"]
               and row.to_dict()["network_requests"] == 0 for row in rows)


def test_confinement_catalog_appends_one_validated_operator_resource():
    rows = catalog.xxe_confinement_catalog("/srv/flag.txt")
    assert rows[-1].name == "operator_resource"
    assert 'SYSTEM "file:///srv/flag.txt"' in rows[-1].document
    # the built-in set is unchanged ahead of the appended row
    assert rows[-1].name not in [r.name for r in catalog.xxe_confinement_catalog()]


def test_confinement_catalog_rejects_unsafe_or_duplicate_extra_resource():
    with pytest.raises(catalog.CatalogInputError, match="local file resources only"):
        catalog.xxe_confinement_catalog("https://outside.invalid/x")
    with pytest.raises(catalog.CatalogInputError, match="XML/control delimiter"):
        catalog.xxe_confinement_catalog('/etc/pa"sswd')
    with pytest.raises(catalog.CatalogInputError, match="duplicates a built-in"):
        catalog.xxe_confinement_catalog("/etc/passwd")


# --- mapper ------------------------------------------------------------------

_CID = "3f4e5d6c7b8a" * 5 + "9a8b"  # a 64-hex container id


def test_mapper_identifies_docker_and_chroot_and_unreachable_paths():
    observations = {
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
        "/etc/hostname": "abc123\n",
        "/proc/self/cgroup": f"12:cpuset:/docker/{_CID}\n",
        "/proc/1/root/etc/hostname": "the-real-host\n",
        "/etc/shadow": None,
    }
    result = xxe_read.map_traversal_confinement(observations)
    assert result["confinement"] == "container"
    assert result["container"] == {
        "detected": True,
        "runtime": "docker",
        "evidence": f"/proc/self/cgroup: cgroup path /docker/{_CID}",
    }
    assert result["chroot_or_jail"] == {
        "suspected": True,
        "evidence": "/proc/1/root/etc/hostname differs from a direct /etc/hostname read",
    }
    assert result["unreachable"] == ["/etc/shadow"]
    assert result["roots_reachable"] == ["/etc", "/proc"]
    # deepest read: proc/1/root/etc/hostname has five components
    assert result["max_path_depth"] == 5
    assert result["network_requests"] == 0 and result["offline"] is True


def test_max_path_depth_counts_components_of_the_deepest_reachable_read():
    result = xxe_read.map_traversal_confinement({
        "/etc/passwd": "root:x:0:0::/root:/bin/sh",
        "/proc/self/cgroup": "0::/\n",
        "/a/b/c/d/e/f": None,  # unreachable paths never count toward depth
    })
    assert result["max_path_depth"] == 3
    assert xxe_read.map_traversal_confinement({"/flag": "x"})["max_path_depth"] == 1
    assert xxe_read.map_traversal_confinement({"/flag": None})["max_path_depth"] == 0


def test_proc_self_root_read_is_never_chroot_evidence():
    # /proc/self/root IS the reader's root; even a "differing" value (which a
    # real kernel cannot produce for the reader) must not be taken as a chroot.
    result = xxe_read.map_traversal_confinement({
        "/etc/hostname": "jail\n",
        "/proc/self/root/etc/hostname": "something-else\n",
    })
    assert result["chroot_or_jail"]["suspected"] is False
    assert result["confinement"] == "filesystem-read"


# mountinfo rows: id parent maj:min root mount-point options [opt...] - fstype source superopts
_HOST_MOUNTINFO = (
    "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n"
    "23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw\n"
)
_CHROOT_MOUNTINFO = (
    "22 1 8:2 /srv/jail / rw,relatime shared:1 - ext4 /dev/sda2 rw\n"
    "23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw\n"
)


def test_mountinfo_root_field_exposes_a_chroot():
    result = xxe_read.map_traversal_confinement({
        "/etc/passwd": "root:x:0:0::/root:/bin/sh",
        "/proc/self/mountinfo": _CHROOT_MOUNTINFO,
    })
    assert result["chroot_or_jail"]["suspected"] is True
    assert "'/srv/jail'" in result["chroot_or_jail"]["evidence"]
    assert "ext4" in result["chroot_or_jail"]["evidence"]
    assert result["confinement"] == "chroot_or_jail"


def test_mountinfo_host_root_and_btrfs_subvolume_are_not_a_chroot():
    host = xxe_read.map_traversal_confinement({"/proc/self/mountinfo": _HOST_MOUNTINFO})
    assert host["chroot_or_jail"]["suspected"] is False
    btrfs = xxe_read.map_traversal_confinement({
        "/proc/self/mountinfo": "30 1 0:27 /@ / rw,relatime shared:1 - btrfs /dev/nvme0n1p2 rw\n",
    })
    assert btrfs["chroot_or_jail"]["suspected"] is False
    assert any("btrfs subvolume '/@'" in note for note in btrfs["notes"])
    # but a deeper btrfs path is a chroot
    deep = xxe_read.map_traversal_confinement({
        "/proc/self/mountinfo": "30 1 0:27 /@/srv/jail / rw - btrfs /dev/nvme0n1p2 rw\n",
    })
    assert deep["chroot_or_jail"]["suspected"] is True


def test_mountinfo_last_root_row_wins_and_escapes_decode():
    # a later mount stacked on "/" hides the earlier one; octal \040 is a space
    stacked = (
        "22 1 8:2 /old / rw - ext4 /dev/sda2 rw\n"
        "40 22 8:3 /my\\040jail / rw master:3 - xfs /dev/sdb1 rw\n"
    )
    result = xxe_read.map_traversal_confinement({"/proc/self/mountinfo": stacked})
    assert result["chroot_or_jail"]["suspected"] is True
    assert "'/my jail'" in result["chroot_or_jail"]["evidence"]
    assert "xfs" in result["chroot_or_jail"]["evidence"]
    clean_last = (
        "22 1 8:2 /old / rw - ext4 /dev/sda2 rw\n"
        "40 22 0:50 / / rw - overlay overlay rw\n"
    )
    assert xxe_read.map_traversal_confinement(
        {"/proc/self/mountinfo": clean_last})["chroot_or_jail"]["suspected"] is False


def test_mapper_detects_kubernetes_from_environ_markers():
    observations = [
        {"resource": "/proc/self/environ", "content": "KUBERNETES_SERVICE_HOST=10.0.0.1\x00PATH=/usr/bin"},
        {"resource": "/etc/passwd", "content": "root:x:0:0::/root:/bin/sh"},
    ]
    result = xxe_read.map_traversal_confinement(observations)
    assert result["container"]["runtime"] == "kubernetes"
    assert result["confinement"] == "container"


def test_mapper_reports_filesystem_read_without_confinement_markers():
    # Reads succeed but nothing proves a container/chroot: stay inconclusive,
    # never silently claim "unconfined".
    result = xxe_read.map_traversal_confinement({"/etc/passwd": "root:x:0:0::/root:/bin/sh"})
    assert result["confinement"] == "filesystem-read"
    assert result["container"]["detected"] is False
    assert result["chroot_or_jail"]["suspected"] is False
    assert any("inconclusive" in note for note in result["notes"])


def test_mapper_handles_no_reads_and_pair_form_and_bytes():
    assert xxe_read.map_traversal_confinement({"/etc/passwd": None})["confinement"] == "no-read"
    assert xxe_read.map_traversal_confinement({})["confinement"] == "no-read"
    # (resource, content) pairs and bytes content both normalize
    pairs = [("/proc/self/cgroup",
              f"0::/system.slice/cri-containerd-{_CID}.scope\n".encode()),
             ("/etc/passwd", b"root:x:0:0::/root:/bin/sh")]
    result = xxe_read.map_traversal_confinement(pairs)
    assert result["container"]["runtime"] == "containerd"
    assert result["container"]["evidence"] == (
        f"/proc/self/cgroup: cgroup segment 'cri-containerd-{_CID}.scope'")


def test_mapper_chroot_only_when_proc_root_read_differs():
    # Identical proc-root and direct reads must NOT be called a chroot.
    same = {
        "/etc/hostname": "host\n",
        "/proc/1/root/etc/hostname": "host\n",
        "/etc/passwd": "root:x:0:0::/root:/bin/sh",
    }
    result = xxe_read.map_traversal_confinement(same)
    assert result["chroot_or_jail"]["suspected"] is False
    assert result["confinement"] == "filesystem-read"


# --- container detection reads structure, not substrings ----------------------

# An unconfined host that merely RUNS Docker: ext4 root, the daemon's overlay
# mounts under /var/lib/docker, the daemon's own cgroup, a docker group.
_DOCKER_HOST_MOUNTINFO = (
    "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n"
    "23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw\n"
    f"90 22 0:60 / /var/lib/docker/overlay2/{_CID}/merged rw,relatime - overlay overlay "
    f"rw,lowerdir=/var/lib/docker/overlay2/l/ABC,upperdir=/var/lib/docker/overlay2/{_CID}/diff\n"
    f"91 22 0:61 / /run/docker/netns/{_CID[:12]} rw shared:80 - nsfs nsfs rw\n"
    # an operator bind of a container's file to a host path is not /etc/hostname
    f"92 22 8:2 /var/lib/docker/containers/{_CID}/hostname /mnt/inspect rw - ext4 /dev/sda2 rw\n"
)


def test_host_that_runs_docker_is_not_called_a_container():
    result = xxe_read.map_traversal_confinement({
        "/etc/passwd": "root:x:0:0::/root:/bin/sh\n",
        "/proc/self/mountinfo": _DOCKER_HOST_MOUNTINFO,
        "/proc/self/cgroup": "0::/system.slice/docker.service\n",
        "/proc/1/cgroup": "0::/init.scope\n",
        "/proc/self/environ": "PATH=/usr/bin\x00DOCKER_HOST=unix:///run/docker.sock\x00",
    })
    assert result["container"] == {"detected": False, "runtime": None, "evidence": None}
    assert result["chroot_or_jail"]["suspected"] is False
    assert result["confinement"] == "filesystem-read"
    # the host-side containerd and lxc monitor units are not containers either
    for cgroup in ("0::/system.slice/containerd.service\n", "0::/lxc.monitor.web\n",
                   "0::/docker\n", "0::/user.slice/user-1000.slice/session-2.scope\n"):
        assert xxe_read.map_traversal_confinement(
            {"/proc/self/cgroup": cgroup})["container"]["detected"] is False, cgroup


def test_container_markers_in_files_other_than_cgroup_mountinfo_environ_are_ignored():
    # Ordinary files that happen to mention docker -- a docker user/group, an
    # /etc/environment that sets container=docker, a saved copy of a cgroup
    # line -- say nothing about the reader's own confinement.
    result = xxe_read.map_traversal_confinement({
        "/etc/passwd": f"root:x:0:0::/root:/bin/sh\ndocker:x:999:999::/docker/{_CID}:/bin/sh\n",
        "/etc/group": "docker:x:999:ctf\nkubepods:x:998:\n",
        "/etc/environment": "container=docker\nKUBERNETES_SERVICE_HOST=10.0.0.1\n",
        "/srv/app/notes.txt": f"0::/docker/{_CID}\n0::/kubepods/besteffort/pod1\n",
        "/srv/app/mounts.bak": "500 400 0:90 / / rw - overlay overlay rw,lowerdir=/l\n",
    })
    assert result["container"]["detected"] is False
    assert result["confinement"] == "filesystem-read"


@pytest.mark.parametrize(("resource", "content", "runtime", "evidence"), [
    ("/proc/self/cgroup", f"0::/system.slice/docker-{_CID}.scope\n", "docker",
     f"cgroup segment 'docker-{_CID}.scope'"),
    ("/proc/1/cgroup", f"0::/machine.slice/libpod-{_CID}.scope/container\n", "podman",
     f"cgroup segment 'libpod-{_CID}.scope'"),
    ("/proc/self/cgroup", "0::/lxc.payload.web/system.slice\n", "lxc",
     "cgroup segment 'lxc.payload.web'"),
    ("/proc/self/cgroup", "4:memory:/lxc/web\n", "lxc", "cgroup path /lxc/web"),
    ("/proc/self/cgroup", f"0::/docker/buildkit/{_CID[:25]}\n", "docker",
     "cgroup path /docker/buildkit"),
    ("/proc/self/cgroup", "0::/kubepods.slice/kubepods-besteffort.slice/x\n", "kubernetes",
     "cgroup segment 'kubepods.slice'"),
    ("/proc/self/mountinfo",
     "500 400 0:90 / / rw,relatime - overlay overlay "
     "rw,lowerdir=/var/lib/docker/overlay2/l/A,upperdir=/var/lib/docker/overlay2/x/diff\n",
     "docker", "'/' is an overlay filesystem (container image root)"),
    ("/proc/self/mountinfo",
     "500 400 0:90 / / rw - overlay overlay rw,lowerdir=/l,upperdir=/u\n",
     "unknown", "'/' is an overlay filesystem (container image root)"),
    ("/proc/self/mountinfo",
     "22 1 8:2 / / rw - ext4 /dev/sda2 rw\n"
     f"30 22 8:2 /var/lib/docker/containers/{_CID}/hostname /etc/hostname rw - ext4 /dev/sda2 rw\n",
     "docker", f"/etc/hostname is bind-mounted from '/var/lib/docker/containers/{_CID}/hostname'"),
    ("/proc/self/environ", "PATH=/bin\x00container=podman\x00", "podman",
     "container='podman' is set"),
])
def test_container_runtime_shapes(resource, content, runtime, evidence):
    result = xxe_read.map_traversal_confinement({resource: content})
    assert result["container"] == {
        "detected": True, "runtime": runtime, "evidence": f"{resource}: {evidence}"}
    assert result["confinement"] == "container"


def test_kubernetes_outranks_the_engine_it_runs_on():
    result = xxe_read.map_traversal_confinement({
        "/proc/self/cgroup": f"0::/system.slice/docker-{_CID}.scope\n",
        "/proc/self/environ": "KUBERNETES_SERVICE_HOST=10.0.0.1\x00",
    })
    assert result["container"]["runtime"] == "kubernetes"
    assert result["container"]["evidence"] == (
        "/proc/self/environ: KUBERNETES_SERVICE_HOST is set")


# --- chroot into a plain directory: no row mounted at "/" ----------------------

def test_mountinfo_without_a_root_row_exposes_a_classic_chroot():
    # The kernel hides mounts whose mount point lies outside the reader's root,
    # so a chroot into a directory that is not a mount point lists only the
    # mounts made inside the jail -- and none at "/".
    jail = (
        "23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw\n"
        "24 22 0:5 / /dev rw,nosuid - devtmpfs udev rw\n"
    )
    result = xxe_read.map_traversal_confinement({
        "/etc/passwd": "root:x:0:0::/root:/bin/sh",
        "/proc/self/mountinfo": jail,
    })
    assert result["chroot_or_jail"] == {
        "suspected": True,
        "evidence": ("/proc/self/mountinfo: 2 mount(s) listed but none at '/': "
                     "the root is not a mount point (classic chroot)"),
    }
    assert result["confinement"] == "chroot_or_jail"
    # garbage that parses as no mountinfo rows at all is not evidence
    noise = xxe_read.map_traversal_confinement({"/proc/self/mountinfo": "not a mount table\n"})
    assert noise["chroot_or_jail"]["suspected"] is False


def test_truncated_mountinfo_without_a_root_row_is_not_a_chroot():
    row = "24 22 0:5 / /dev rw,nosuid - devtmpfs udev rw\n"
    big = row * (xxe_read.MAP_MAX_SCAN // len(row) + 2)
    result = xxe_read.map_traversal_confinement({"/proc/self/mountinfo": big})
    assert result["chroot_or_jail"]["suspected"] is False
    assert any("truncated" in note and "not counted as a chroot" in note
               for note in result["notes"])


def test_mountinfo_catalog_signal_names_the_missing_root_row():
    (row,) = [r for r in catalog.xxe_confinement_catalog() if r.name == "self_mountinfo"]
    signal = row.to_dict()["expected_signal"]
    assert "no row is mounted at '/'" in signal
    assert "overlay" in signal
