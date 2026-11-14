"""The host governor (governor.py): the probe, the decision, the deck's start gate and a run's tick
(doctor's host line is in test_setup.py).

The probe is given a fake machine (tests/fake_host.py) and its own load, CPU and disk readers,
so nothing here depends on the load, RAM or disk of the machine the tests run on. The deck
tests use the recording driver of test_deck.py; the run test plays two lanes against the fake
model server with a reading the test changes."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from ctf_flightdeck import governor
from ctf_flightdeck.config import GovernorConfig
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.model import Challenge, DeckConfig, EventKind
from ctf_flightdeck.governor import Decision, Governor, Reading, decide, probe, summary
from ctf_flightdeck.hardware import GIB, MIB, Fact, ProbeError
from ctf_flightdeck.run import RunError, RunOptions, prepare_run

from fake_host import FakeHost
from fake_model import FakeModelServer, tool_call_reply
from test_deck import FLAG_FORMAT, MODELS, Clock, RecordingDriver, RecordingVerifier, events, queued_ids

VM_STAT = """Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               10000.
Pages active:                            400000.
Pages inactive:                          200000.
Pages speculative:                         5000.
Pages throttled:                              0.
Pages wired down:                        150000.
Pages purgeable:                           3000.
"File-backed pages":                     100000.
"""
MEMINFO = "MemTotal:       16000000 kB\nMemFree:          500000 kB\nMemAvailable:    3000000 kB\nBuffers:  1000 kB\n"
POLICY = GovernorConfig()  # load 3.0 per CPU, 2048 MiB of RAM, 10240 MiB of disk


@pytest.fixture(autouse=True)
def calm_host():
    """Replaces conftest's fixture of this name: here governor.probe is the real one."""
    yield


def mac(**kw) -> FakeHost:
    kw.setdefault("programs", {"vm_stat": "/usr/bin/vm_stat"})
    kw.setdefault("commands", {("/usr/bin/vm_stat",): VM_STAT})
    return FakeHost("Darwin", "arm64", **kw)


def linux(meminfo: str | None = MEMINFO) -> FakeHost:
    return FakeHost("Linux", "x86_64", files={} if meminfo is None else {"/proc/meminfo": meminfo})


def read(host, path: Path, *, load=(4.0, 3.0, 2.0), cpus=8, free=50 * GIB) -> Reading:
    return probe(path, host, loadavg=lambda: load, cpu_count=lambda: cpus, disk_usage=lambda p: (100 * GIB, 50 * GIB, free))


def reading(*, load: float | None = 4.0, cpus: int | None = 8, ram: int | None = 8 * GIB, disk: int | None = 50 * GIB,
            why: str = "not read here") -> Reading:
    fact = lambda value: Fact(value) if value is not None else Fact(None, why)  # noqa: E731
    return Reading(load=fact(load), cpus=fact(cpus), free_ram=fact(ram), free_disk=fact(disk), disk_path="/runs")


# ---------------------------------------------------------------------- the probe


def test_the_probe_reads_load_per_cpu_available_ram_and_free_disk_on_macos(tmp_path):
    host = mac()
    got = read(host, tmp_path)
    assert got.load == Fact(4.0) and got.cpus == Fact(8) and got.load_per_cpu == Fact(0.5)
    assert got.free_ram == Fact((10000 + 200000 + 5000) * 16384)  # free, inactive and speculative pages; not purgeable or active
    assert got.free_disk == Fact(50 * GIB) and got.disk_path == str(tmp_path)
    assert host.ran == [["/usr/bin/vm_stat"]] and got.unknown() == []


def test_the_probe_reads_memavailable_on_linux_and_runs_no_program(tmp_path):
    host = linux()
    got = read(host, tmp_path, load=(12.0, 1.0, 1.0), cpus=4)
    assert got.free_ram == Fact(3000000 * 1024) and got.load_per_cpu == Fact(3.0)
    assert host.ran == []


def test_the_disk_is_read_at_the_nearest_folder_that_exists(tmp_path):
    asked = []

    def usage(path):
        asked.append(path)
        return (10, 5, 7 * GIB)

    got = probe(tmp_path / "runs" / "not" / "yet", linux(), loadavg=lambda: (0.0, 0.0, 0.0), cpu_count=lambda: 2, disk_usage=usage)
    assert asked == [tmp_path] and got.disk_path == str(tmp_path) and got.free_disk == Fact(7 * GIB)


def raising(exc):
    def reader(*args):
        raise exc

    return reader


@pytest.mark.parametrize(("host", "kw", "fact", "reason"), [
    (mac(programs={}), {}, "free_ram", "vm_stat is not on PATH"),
    (mac(commands={("/usr/bin/vm_stat",): ProbeError("vm_stat gave no answer within 2 s")}), {}, "free_ram",
     "vm_stat gave no answer within 2 s"),
    (mac(commands={("/usr/bin/vm_stat",): "Pages free: 12.\n"}), {}, "free_ram",
     "vm_stat printed something flightdeck cannot read the page size and the free, inactive and speculative pages from"),
    (mac(commands={("/usr/bin/vm_stat",): VM_STAT.replace("Pages speculative:", "Pages guessed:")}), {}, "free_ram",
     "vm_stat printed something flightdeck cannot read the page size and the free, inactive and speculative pages from"),
    (linux(None), {}, "free_ram", "/proc/meminfo cannot be read (No such file or directory)"),
    (linux("MemTotal: 16000000 kB\nMemFree: 1 kB\n"), {}, "free_ram",
     "/proc/meminfo has no MemAvailable line in kB that flightdeck can read"),
    (FakeHost("Windows", "AMD64"), {}, "free_ram", "available RAM is read on macOS and Linux (WSL counts as Linux), not on Windows"),
    (linux(), {"loadavg": raising(OSError(5, "Input/output error"))}, "load", "the load average cannot be read (Input/output error)"),
    (linux(), {"loadavg": lambda: (float("nan"), 0.0, 0.0)}, "load", "the load average read is not a load"),
    (linux(), {"loadavg": lambda: (-1.0, 0.0, 0.0)}, "load", "the load average read is not a load"),
    (linux(), {"cpu_count": lambda: None}, "cpus", "the number of CPUs cannot be read"),
    (linux(), {"cpu_count": lambda: 0}, "cpus", "the number of CPUs cannot be read"),
    (linux(), {"disk_usage": raising(PermissionError(13, "Permission denied"))}, "free_disk", "cannot be read (Permission denied)"),
    (linux(), {"disk_usage": lambda p: (1, 1, -5)}, "free_disk", "is not a number of bytes"),
])
def test_a_reading_that_cannot_be_taken_is_unknown_with_the_reason_and_never_a_guess(tmp_path, host, kw, fact, reason):
    readers = {"loadavg": lambda: (1.0, 1.0, 1.0), "cpu_count": lambda: 4, "disk_usage": lambda p: (9, 4, 5 * GIB), **kw}
    got = probe(tmp_path, host, **readers)
    found = getattr(got, fact)
    assert found.value is None and reason in found.unknown
    others = {"load", "cpus", "free_ram", "free_disk"} - {fact}
    assert all(getattr(got, name).value is not None for name in others)  # one unread reading costs no other
    if fact in ("load", "cpus"):
        assert got.load_per_cpu == Fact(None, found.unknown)
    assert len(got.unknown()) == 1 and reason in got.unknown()[0]


def test_the_real_probe_of_this_machine_never_raises_and_gives_a_value_or_a_reason_for_each(tmp_path):
    got = probe(tmp_path)  # this machine, whatever it is: only the shape is asserted, never its load
    for fact in (got.load_per_cpu, got.free_ram, got.free_disk):
        assert (fact.value is None) == bool(fact.unknown)
    assert got.disk_path == str(tmp_path)


def test_vm_stat_is_found_where_macos_keeps_it_when_path_leaves_its_folder_out(monkeypatch, tmp_path):
    import platform

    from ctf_flightdeck import hardware

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(hardware.shutil, "which", lambda program, path=None: f"{path}/{program}" if path == "/usr/bin" else None)
    host = hardware.RealHost({"PATH": str(tmp_path)})  # a PATH without /usr/bin: a cron job's, say
    assert host.which("vm_stat") == "/usr/bin/vm_stat"
    host.run = lambda argv, timeout: VM_STAT if list(argv) == ["/usr/bin/vm_stat"] else pytest.fail(f"ran {argv}")
    assert read(host, tmp_path).free_ram == Fact(215000 * 16384)


# ---------------------------------------------------------------------- decide


def test_within_every_limit_a_lane_starts_and_nothing_binds():
    assert decide(reading(), POLICY, 3) == Decision(True, ()) and decide(reading(), POLICY, 3).reason == ""


@pytest.mark.parametrize(("got", "reason"), [
    (reading(load=33.6), "load 4.2 per CPU (33.6 on 8 CPUs) is over max_load_per_cpu 3"),
    (reading(load=140.0, cpus=1), "load 140.0 per CPU (140.0 on 1 CPU) is over max_load_per_cpu 3"),
    (reading(ram=806 * MIB), "806 MiB of RAM available is under min_free_ram_mb 2048"),
    (reading(disk=3 * GIB + GIB // 2), "3.5 GiB free on the disk at /runs is under min_free_disk_mb 10240"),
])
def test_a_reading_past_its_limit_holds_new_lanes_and_the_reason_names_the_limit_and_the_reading(got, reason):
    decision = decide(got, POLICY, 2)
    assert decision.start is False and decision.binding == (reason,) and decision.reason == reason
    assert "\n" not in decision.reason


def test_every_limit_that_binds_is_named_in_one_line():
    decision = decide(reading(load=80.0, ram=100 * MIB, disk=GIB), POLICY, 1)
    assert decision.reason == ("load 10.0 per CPU (80.0 on 8 CPUs) is over max_load_per_cpu 3; 100 MiB of RAM available is under "
                               "min_free_ram_mb 2048; 1.0 GiB free on the disk at /runs is under min_free_disk_mb 10240")


def test_a_reading_exactly_at_its_limit_does_not_bind():
    at = reading(load=24.0, ram=2048 * MIB, disk=10240 * MIB)  # 3.0 per CPU
    assert decide(at, POLICY, 4).start is True
    just_past = reading(load=24.1, ram=2048 * MIB - 1, disk=10240 * MIB - 1)
    assert len(decide(just_past, POLICY, 4).binding) == 3


def test_with_no_lane_at_work_one_always_starts_and_the_limit_is_still_named():
    busy = reading(load=80.0)
    decision = decide(busy, POLICY, 0)
    assert decision.start is True and decision.reason == ""
    assert decision.limits == "load 10.0 per CPU (80.0 on 8 CPUs) is over max_load_per_cpu 3"
    assert decide(busy, POLICY, 1).start is False


def test_an_unknown_reading_never_holds_a_start():
    nothing = reading(load=None, cpus=None, ram=None, disk=None)
    assert decide(nothing, POLICY, 5) == Decision(True, ())
    assert decide(reading(load=80.0, cpus=None), POLICY, 5).start is True  # no CPU count: no load per CPU
    assert decide(reading(ram=None, disk=GIB), POLICY, 5).binding == ("1.0 GiB free on the disk at /runs is under min_free_disk_mb 10240",)


def test_a_limit_of_zero_is_off_and_a_governor_turned_off_holds_nothing():
    awful = reading(load=800.0, ram=0, disk=0)
    assert decide(awful, GovernorConfig(max_load_per_cpu=0, min_free_ram_mb=0, min_free_disk_mb=0), 3).start is True
    assert decide(awful, GovernorConfig(max_load_per_cpu=0), 3).binding == (
        "0 MiB of RAM available is under min_free_ram_mb 2048", "0 MiB free on the disk at /runs is under min_free_disk_mb 10240")
    assert decide(awful, GovernorConfig(enabled=False), 3) == Decision(True, ())


@pytest.mark.parametrize("running", [-1, 1.5, True, None])
def test_decide_refuses_a_number_of_lanes_that_is_not_one(running):
    with pytest.raises(ValueError, match="running_lanes must be a whole number, 0 or more"):
        decide(reading(), POLICY, running)


def test_the_summary_says_each_reading_and_why_one_is_unknown():
    assert summary(reading()) == "load 0.5 per CPU (8 CPUs), 8.0 GiB of RAM available, 50.0 GiB free on the disk at /runs"
    assert summary(reading(load=None, ram=None, disk=None, why="no such thing")) == (
        "load not read (no such thing), available RAM not read (no such thing), free disk at /runs not read (no such thing)")


def test_a_runs_governor_goes_by_its_last_reading_and_by_none_until_it_has_one(tmp_path):
    now = [reading(load=80.0)]
    gov = Governor(POLICY, tmp_path, read=lambda path: now[0])
    assert gov.limit() == ""  # nothing read yet: nothing binds
    assert gov.refresh() is now[0]
    assert gov.limit() == "load 10.0 per CPU (80.0 on 8 CPUs) is over max_load_per_cpu 3"  # whatever runs: the deck owns "one always starts"
    now[0] = reading()
    assert gov.limit() != ""  # take() alone changes nothing
    gov.use(gov.take())
    assert gov.limit() == ""
    gov.use(None)
    assert gov.limit() == ""
    off = Governor(GovernorConfig(enabled=False), tmp_path, read=lambda path: reading(load=80.0))
    off.refresh()
    assert off.limit() == ""


# ---------------------------------------------------------------------- the deck's start gate

BUSY = "load 10.0 per CPU (80.0 on 8 CPUs) is over max_load_per_cpu 3"


def gated_deck(n=4, max_lanes=3, gate=BUSY):
    """A deck whose start gate answers `answer[0]`, with c0..c{n-1} released."""
    answer = [gate]
    driver = RecordingDriver()
    deck = Deck(DeckConfig(event="test", max_lanes=max_lanes, flag_format=FLAG_FORMAT, models=MODELS), driver, Clock(),
                verify=RecordingVerifier())
    deck.start_gate = lambda: answer[0]
    challenges = [Challenge(f"c{i}", f"Chall {i}", "misc", 100, solves=10) for i in range(n)]
    deck.release(challenges, [QueueEntry(c.id, MODELS[0]) for c in challenges])
    return deck, driver, answer


def gate_warnings(deck) -> list[tuple[bool, str]]:
    return [(e.data["gated"], e.text) for e in events(deck, EventKind.WARNING) if "gated" in e.data]


def test_while_the_gate_names_a_limit_one_lane_starts_and_the_rest_stay_queued_with_one_warning():
    deck, driver, _ = gated_deck()
    assert driver.started() == ["c0"] and queued_ids(deck) == ["c1", "c2", "c3"]  # three free slots, one used
    assert deck.gated == BUSY
    assert gate_warnings(deck) == [(True, f"no new lane starts for now: {BUSY}; the lanes at work carry on, and queued lanes "
                                          "start by themselves once this machine is back within the limit ([governor] in your config)")]
    for _ in range(5):  # asked again and again: nothing starts, nothing more is said
        deck.recheck_starts()
    assert driver.started() == ["c0"] and len(gate_warnings(deck)) == 1


def test_the_gate_is_no_hold_and_stops_or_pauses_no_lane():
    deck, driver, _ = gated_deck()
    assert deck.held == ""  # not hold_queue: nothing for the player to lift, nothing that disengages autopilot
    assert not [e for e in events(deck, EventKind.WARNING) if "held" in e.data]
    assert driver.named("stop") == [] and driver.named("pause") == []
    assert not deck.release_hold().ok  # there is no hold to lift


def test_lanes_start_by_themselves_when_the_gate_clears_and_one_warning_says_so():
    deck, driver, answer = gated_deck()
    answer[0] = ""
    assert driver.started() == ["c0"]  # nothing asks the gate until the run does, or a lane ends
    deck.recheck_starts()
    assert driver.started() == ["c0", "c1", "c2"] and queued_ids(deck) == ["c3"] and deck.gated == ""
    assert gate_warnings(deck)[1:] == [(False, f"queued lanes start again: this machine is back within its limits (it was: {BUSY})")]
    deck.recheck_starts()
    assert len(gate_warnings(deck)) == 2


def test_a_gate_that_binds_again_later_warns_again_once():
    deck, driver, answer = gated_deck(n=6, max_lanes=2)
    answer[0] = ""
    deck.recheck_starts()
    answer[0] = "the disk is nearly full"
    lane = deck.lanes_on("c0")[0]
    assert deck.apply(iv.Kill(lane.id, requeue=False)).ok  # a slot frees while the gate binds: nothing fills it
    assert driver.started() == ["c0", "c1"] and len(deck.active_lanes()) == 1
    assert [gated for gated, _ in gate_warnings(deck)] == [True, False, True]
    assert "the disk is nearly full" in gate_warnings(deck)[-1][1]


def test_when_the_last_lane_ends_while_gated_the_next_one_starts_and_nothing_more_is_said():
    deck, driver, _ = gated_deck()
    for expected in (["c0", "c1"], ["c0", "c1", "c2"], ["c0", "c1", "c2", "c3"]):
        (lane,) = deck.active_lanes()
        assert deck.apply(iv.Kill(lane.id, requeue=False)).ok
        assert driver.started() == expected and len(deck.active_lanes()) == 1  # never none while something is queued
    assert deck.queue == [] and len(gate_warnings(deck)) == 1 and deck.gated == BUSY


def test_a_reason_that_changes_while_starts_are_held_is_kept_but_not_said_again():
    deck, _, answer = gated_deck()
    answer[0] = "the disk is nearly full"
    deck.recheck_starts()
    assert deck.gated == "the disk is nearly full" and len(gate_warnings(deck)) == 1


def test_the_gate_clearing_is_said_with_nothing_left_in_the_queue_too():
    deck, driver, answer = gated_deck(n=2, max_lanes=2)
    assert deck.apply(iv.Kill(deck.lanes_on("c0")[0].id, requeue=False)).ok  # c1 starts: no lane was at work
    assert deck.queue == [] and deck.gated == BUSY
    answer[0] = ""
    deck.recheck_starts()
    assert deck.gated == "" and [gated for gated, _ in gate_warnings(deck)] == [True, False]


def test_a_gate_that_never_binds_is_never_mentioned_and_all_slots_fill():
    deck, driver, _ = gated_deck(gate="")
    assert driver.started() == ["c0", "c1", "c2"] and gate_warnings(deck) == [] and deck.gated == ""


def test_a_fork_queued_behind_the_gate_says_why_it_did_not_start():
    deck, driver, _ = gated_deck()
    (lane,) = deck.active_lanes()
    out = deck.apply(iv.Fork(lane.id))
    assert out.ok and out.message == f"Fork of {lane.id} (mid) is first in the queue; no new lane starts for now: {BUSY}"
    assert queued_ids(deck)[0] == "c0" and driver.started() == ["c0"]


def test_a_closing_deck_asks_the_gate_nothing_and_a_gate_must_answer_with_text():
    deck, _, answer = gated_deck()
    asked = []
    deck.start_gate = lambda: asked.append(1) or ""
    deck.close()
    deck.recheck_starts()
    assert asked == [] and deck.gated == BUSY
    other, _, _ = gated_deck()
    other.start_gate = lambda: None
    with pytest.raises(TypeError, match="the start gate must answer with a string"):
        other.recheck_starts()


# ---------------------------------------------------------------------- a run

FLAGS = {"one": "t{one}", "two": "t{two}"}


def board(tmp_path: Path) -> Path:
    root = tmp_path / "board"
    for points, (name, flag) in enumerate(FLAGS.items(), 1):
        folder = root / name
        folder.mkdir(parents=True)
        (folder / "note.txt").write_text("a note\n")
        (folder / "challenge.json").write_text(json.dumps({"name": name, "category": "misc", "points": points * 10, "solves": 1}))
    (root / "board.json").write_text(json.dumps({"event": "Test Event", "flag_format": r"t\{[a-z0-9_]+\}"}))
    (root / "answers.sha256.json").write_text(json.dumps({n: hashlib.sha256(f.encode()).hexdigest() for n, f in FLAGS.items()}))
    return root


def config(tmp_path: Path, base_url: str, extra: str = "") -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        f'[api]\nbase_url = "{base_url}"\nkey_env = ""\n[models]\nladder = ["fake/small"]\n'
        f'[lanes]\nmax_lanes = 2\nruntime = "host"\n[run]\ndir = "{tmp_path / "runs"}"\n{extra}'
    )
    return path


async def wait_for(cond, what: str, seconds: float = 20.0) -> None:
    for _ in range(int(seconds / 0.01)):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def test_a_run_holds_its_second_lane_while_the_machine_is_busy_and_starts_it_when_the_reading_recovers(tmp_path):
    now = [reading(load=80.0)]
    asked: list[Path] = []

    def host_reading(path: Path) -> Reading:
        asked.append(path)
        return now[0]

    # each lane proposes a flag and waits for the player (submit confirm): both stay open
    server = FakeModelServer([tool_call_reply("submit_flag", {"flag": "t{not_it}"}) for _ in range(4)])

    async def main():
        with server:
            run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url),
                                         governor_seconds=0.02, host_reading=host_reading))
            deck = run.deck
            run.release()
            try:
                assert len(deck.lanes) == 1 and len(deck.queue) == 1  # one always starts; the other is held back
                assert deck.gated == BUSY and deck.held == ""
                await wait_for(lambda: len(asked) >= 4, "the governor's tick to read the machine again")
                assert len(deck.lanes) == 1 and len(deck.queue) == 1  # still busy: still held, and said once
                first = next(iter(deck.lanes.values()))
                now[0] = reading()
                await wait_for(lambda: len(deck.lanes) == 2, "the held lane to start by itself")
                assert deck.queue == [] and deck.gated == "" and not first.finished
            finally:
                await run.shutdown()
            run.close()
            said = [(e.data["gated"], e.data["reason"]) for e in deck.events if e.kind is EventKind.WARNING and "gated" in e.data]
            assert said == [(True, BUSY), (False, BUSY)]
            assert asked[0] == run.dir and run.errors == []
            logged = [json.loads(line) for line in run.log.path.read_text().splitlines()]
            assert [line["data"]["gated"] for line in logged if line["kind"] == "warning" and "gated" in line["data"]] == [True, False]

    asyncio.run(main())


def test_a_run_whose_governor_is_off_reads_nothing_and_sets_no_gate(tmp_path):
    def host_reading(path: Path) -> Reading:
        raise AssertionError("the governor is off: the machine must not be read")

    with FakeModelServer([]) as server:
        cfg = config(tmp_path, server.base_url, "[governor]\nenabled = false\n")
        run = prepare_run(RunOptions(board=board(tmp_path), config=cfg, host_reading=host_reading))
    try:
        assert run.governor is None and run.deck.start_gate is None
    finally:
        run.close()


def test_a_run_says_before_it_starts_which_reading_it_has_not_got(tmp_path):
    unread = reading(ram=None, why="vm_stat is not on PATH")
    with FakeModelServer([]) as server:
        run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url), host_reading=lambda path: unread))
    try:
        assert "the host governor cannot read the available RAM (vm_stat is not on PATH): no lane is held back for it" in run.notes()
        assert run.governor.limit() == ""
    finally:
        run.close()


def test_a_reading_that_fails_outright_during_a_run_is_a_warning_once_and_holds_nothing(tmp_path):
    state = {"calls": 0, "fail": False}

    def host_reading(path: Path) -> Reading:
        state["calls"] += 1
        if state["fail"]:
            raise OSError("the reader broke")
        return reading(load=80.0)

    server = FakeModelServer([tool_call_reply("submit_flag", {"flag": "t{not_it}"}) for _ in range(4)])

    async def main():
        with server:
            run = prepare_run(RunOptions(board=board(tmp_path), config=config(tmp_path, server.base_url),
                                         governor_seconds=0.02, host_reading=host_reading))
            deck = run.deck
            run.release()
            try:
                assert len(deck.lanes) == 1 and deck.gated
                state["fail"] = True
                before = state["calls"]
                await wait_for(lambda: state["calls"] >= before + 4, "the failing reader to be asked a few times")
                await wait_for(lambda: len(deck.lanes) == 2, "the held lane to start: there is no reading to hold it by")
            finally:
                await run.shutdown()
            run.close()
            failed = [e.text for e in deck.events if e.kind is EventKind.WARNING and e.data.get("source") == "governor"]
            assert failed == ["the host governor could not read this machine (the reader broke): it holds no lane back until it can"]

    asyncio.run(main())


def test_a_first_reading_that_fails_outright_stops_the_run_before_it_starts_and_a_bad_tick_is_refused(tmp_path):
    with FakeModelServer([]) as server:
        cfg, folder = config(tmp_path, server.base_url), board(tmp_path)
        with pytest.raises(RunError, match="the host governor could not read this machine: it broke"):
            prepare_run(RunOptions(board=folder, config=cfg, host_reading=raising(OSError("it broke"))))
        with pytest.raises(RunError, match="governor_seconds must be a positive number of seconds, not 0"):
            prepare_run(RunOptions(board=folder, config=cfg, governor_seconds=0))
