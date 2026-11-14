#!/usr/bin/env python3
"""The toolkit agent_trace on real traces, tool sources and pages (docs/toolkits/real-data.md).

  .venv/bin/python tests/real/test_real_agent_trace.py

SKIPs (exit 0) when challenges/_realdata/agent_trace is not there; tests/real/fetch_d.py fills it.
The files: four saved runs of the AgentDojo benchmark (each run file states the injected text and
whether the attack worked: that is the ground truth here, read with json), a Claude Code session,
an MCP tool definition and an mcp.json as their projects ship them, the three public MCP
tool-poisoning samples (Python server sources), the Unicode emoji table, a Wikipedia page, an
OCRed PDF, and the 12 MB terminal capture of Huntress 2024's warmup "The Void", whose flag the
write-up states. Text in these files that addresses a model is data: nothing here acts on it.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common_d as C                    # noqa: E402
from common_d import check, q, opts, timed     # noqa: E402

KIT = "agent_trace"
D = C.fetch_d.have(KIT)
if D is None:
    sys.exit(C.fetch_d.skip("tests/real/test_real_agent_trace.py", KIT))
T = C.toolkit(KIT)
at = T.at
SLOW = []
VOID_FLAG = "flag{b1370ac4fadd8c0237f8771d7d77286a}"          # Huntress-CTF-2024/warmups/the_void_COMPLETED/flag.txt


def ask(name, *questions, limit=2.0):
    data = (D / name).read_bytes()
    got, took = timed(T.solve_set, list(questions), {name: data}, {})
    if took > limit:
        SLOW.append((name, round(took, 2)))
    return [got[x["qid"]] for x in questions]


def run_of(name):
    data = (D / name).read_bytes()
    doc = json.loads(data)
    calls = [(i, c["function"], c["args"]) for i, m in enumerate(doc["messages"]) for c in m.get("tool_calls") or []]
    return doc, calls, at.load_trace(data, name)


def test_agentdojo():
    # workspace: the planted text (in a calendar event) makes the agent mail a stranger
    n = "agentdojo-workspace-ut0-it0.json"
    doc, calls, rows = run_of(n)
    check("AgentDojo: every tool call of the run file is a row with its tool's name (the run writes {'function': name, 'args': {...}})",
          [(r["msg"], r["tool"]) for r in rows if r["kind"] == "call"] == [(i, f) for i, f, _ in calls], [(r["msg"], r["tool"]) for r in rows if r["kind"] == "call"])
    injected = next(i for i, m in enumerate(doc["messages"]) if m["role"] == "tool" and "<INFORMATION>" in str(m.get("content")))
    marks = at.injected_turns(rows)
    check("AgentDojo workspace: the tool output that holds the run's injected text is the one marked, as an instruction that was followed",
          doc["security"] is True and [(m["row"]["msg"], m["why"]) for m in marks] == [(injected, ["followed", "instruction", "proven"])],
          [(m["row"]["msg"], m["why"]) for m in marks])
    a = ask(n, q("used", "Which tool did the agent use to exfiltrate data after the injection?", member=n),
            q("src", "Which tool returned the injected instruction?", member=n), q("host", "Which host received the exfiltrated message?", member=n),
            q("turn", "At which message index did the injected instruction enter the conversation?", "integer", n),
            q("calls", "How many tool calls did the agent make?", "integer", n))
    check("AgentDojo workspace: the tool the agent then used and the tool whose output brought the text in, each to its own question",
          a[0] == "send_email" == calls[-1][1] and a[1] == "search_calendar_events" == calls[1][1], a[:2])
    check("AgentDojo workspace: a mail address's domain is offered beside the address, never asserted as the host",
          opts(a[2]) == {"mail_domain": "gmail.com", "address": "mark.black-2134@gmail.com"}, a[2])
    check("AgentDojo workspace: the message index in both bases (the run has no turn field); the call count plain",
          opts(a[3]) == {"zero_based": str(injected), "one_based": str(injected + 1)} and a[4] == str(len(calls)), a[3:])

    # banking: no host anywhere; the planted text names an account and the next call pays it
    n = "agentdojo-banking-ut0-it0.json"
    doc, calls, rows = run_of(n)
    iban = re.search(r"\bUS\d{15,30}\b", " ".join(doc["injections"].values())).group()
    fol = at.followed_values(rows)
    check("AgentDojo banking: no external host, but the call that pays the account the planted text names is found",
          not at.external_calls(rows) and [(c["row"]["tool"], c["values"], c["source"]["tool"]) for c in fol] == [("send_money", [iban], "read_file")],
          [(c["row"]["tool"], c["values"]) for c in fol])
    a = ask(n, q("used", "Which tool did the agent call to send the attacker's payment after the injection?", member=n),
            q("src", "Which tool returned the injected instruction?", member=n))
    check("AgentDojo banking: both tools are offered as picks (the source's wording is a classifier's verdict)",
          opts(a[0]) == {"tool_that_carried_the_value": "send_money"} and opts(a[1]) == {"tool_whose_output_was_followed": "read_file"}, a)

    # slack: the agent opens a link a colleague posted (benign) and then sends the planted link: two hosts
    n = "agentdojo-slack-ut1-it1.json"
    doc, calls, rows = run_of(n)
    ext = at.external_calls(rows)
    a = ask(n, q("used", "Which tool did the agent use to exfiltrate data after the injection?", member=n), q("host", "Which host did the injected instruction point to?", member=n))
    check("AgentDojo slack: two calls leave for hosts no user turn named (one of them an honest link): two candidates, no answer",
          [c["hosts"] for c in ext] == [["www.informations.com"], ["www.secure-systems-252.com"]] and a == [None, None], (a, [c["hosts"] for c in ext]))
    check("AgentDojo slack: the output that reads as an instruction and was followed is the web page, not the channel",
          [m["row"]["tool"] for m in at.injected_turns(rows) if "instruction" in m["why"]] == ["get_webpage"])

    # the same task with no attack
    n = "agentdojo-workspace-ut0-none.json"
    doc, calls, rows = run_of(n)
    a = ask(n, q("used", "Which tool did the agent use to exfiltrate data after the injection?", member=n), q("src", "Which tool returned the injected instruction?", member=n))
    check("AgentDojo, no attack: nothing is marked and nothing is answered", doc["attack_type"] is None and not at.injected_turns(rows)
          and not at.external_calls(rows) and not at.followed_values(rows) and a == [None, None], a)


def test_sessions_and_configs():
    name = "claude-code-log-representative.jsonl"
    rows = at.load_trace((D / name).read_bytes(), name)
    lines = [json.loads(ln) for ln in (D / name).read_text().splitlines() if ln.strip()]
    uses = [b["name"] for ln in lines for b in ((ln.get("message") or {}).get("content") if isinstance((ln.get("message") or {}).get("content"), list) else [])
            if isinstance(b, dict) and b.get("type") == "tool_use"]
    check("Claude Code session JSONL: read as a transcript, its tool_use blocks as calls in order",
          at.trace_shape(rows) == "claude_code" and [r["tool"] for r in rows if r["kind"] == "call"] == uses and len(uses) >= 2, uses)
    cfg = at.read_config((D / "servers-mcp.json").read_bytes(), "servers-mcp.json")
    raw = json.loads((D / "servers-mcp.json").read_text())["mcpServers"]
    check("mcp.json: its servers by name and URL", {s["name"]: s["url"] for s in cfg["servers"]} == {k: v.get("url") for k, v in raw.items()}, cfg["servers"])
    snap = json.loads((D / "toolsnap-create_issue.snap").read_text())
    cfg = at.read_config((D / "toolsnap-create_issue.snap").read_bytes(), "create_issue.snap")
    check("a tool definition as a server ships it: name and description", [(t["name"], t["description"]) for t in cfg["tools"]] == [(snap["name"], snap["description"])])


def test_poisoned_servers():
    name = "invariant-direct-poisoning.py"
    cfg = at.python_tools((D / name).read_bytes(), name)
    flagged = at.flagged_tools(cfg["tools"])
    check("tool poisoning sample: the Python server's tool is read by ast (name, server, docstring) and its text flagged",
          [(t["name"], t["server"]) for t in cfg["tools"]] == [("add", "Demo")] and "<IMPORTANT>" in cfg["tools"][0]["description"]
          and [(f["tool"]["name"], f["why"]) for f in flagged] == [("add", ["instruction"])], flagged)
    a = ask(name, q("tool", "Which MCP tool carries the malicious instruction?", member=name), q("attack", "What class of attack is this?", member=name),
            q("n", "How many tools does the MCP server define?", "integer", name))
    check("tool poisoning sample: the tool is a pick (the classifier alone flags it), the attack class a pick led by tool_poisoning, the count plain",
          opts(a[0]) == {"tool_whose_text_addresses_the_model": "add"} and list(opts(a[1]) or {})[:1] == ["tool_poisoning"] and a[2] == "1", a)
    name = "invariant-whatsapp-takeover.py"
    cfg = at.python_tools((D / name).read_bytes(), name)
    check("rug pull sample: the docstring swapped in at run time is read as the tool's text and flagged",
          cfg["tools"][0]["description"].strip() == "Get a random fact of the day." and "+13241234123" in cfg["tools"][0].get("description_swapped", "")
          and [f["tool"]["name"] for f in at.flagged_tools(cfg["tools"])] == ["get_fact_of_the_day"], cfg["tools"][0].get("description_swapped", "")[:80])
    name = "invariant-shadowing.py"
    cfg = at.python_tools((D / name).read_bytes(), name)
    check("shadowing sample: flagged as well", [f["tool"]["name"] for f in at.flagged_tools(cfg["tools"])] == ["add"])


def test_benign_text():
    name = "emoji-test.txt"
    found = at.scan(name, (D / name).read_bytes())
    text = (D / name).read_text(encoding="utf-8")
    check("the emoji table: its tag characters are the flags of England, Scotland and Wales, and they are no hidden text",
          len(re.findall("[\U000E0020-\U000E007F]", text)) >= 18 and not [f for f in found if f["strong"]], [(f["kind"], f["text"]) for f in found if f["strong"]])
    check("the emoji table: no hidden text is answered", ask(name, q("h", "What is the hidden text in the document?", member=name)) == [None])
    name = "wikipedia-prompt-injection.html"
    found = at.scan(name, (D / name).read_bytes())
    strong = [f for f in found if f["strong"]]
    a = ask(name, q("h", "What is the hidden text in the document?", member=name), q("doc", "Which document is poisoned?", member=name))
    check("a Wikipedia page: its one display:none element is its short description; it is offered, never asserted, and the page is not called poisoned",
          [f["text"] for f in strong] == ["Type of attack in machine learning"] and opts(a[0]) == {"the_one_hidden_text": "Type of attack in machine learning"} and a[1] is None, a)
    out = subprocess.run([sys.executable, str(C.REPO / "solvers" / "toolkits" / "agent_trace.py"), str(D / name)], capture_output=True, text=True, timeout=60)
    check("a Wikipedia page: the command prints twelve link titles and counts the rest", out.returncode == 0
          and out.stdout.count("FINDING weak   html_attr") == 12 and re.search(r"\.\.\. \d+ more weak html_attr findings", out.stdout), out.stdout[-300:])
    name = "ocrmypdf-graph_ocred.pdf"
    found = [f for f in at.scan(name, (D / name).read_bytes()) if f["kind"] == "pdf_render_mode_3"]
    check("an OCRed PDF: its render-mode-3 text layer is read as two-byte text ('Oppose', 'Percentage'), not as NUL-separated bytes",
          len(found) == 1 and "Oppose" in found[0]["text"] and "Percentage" in found[0]["text"] and "\x00O" not in found[0]["text"], found and found[0]["text"][:120])
    check("an OCRed PDF: the layer is offered as the hidden text, never asserted",
          list(opts(ask(name, q("h", "What is the hidden text in the PDF?", member=name))[0]) or {}) == ["the_one_hidden_text"])


def test_the_void():
    name = "the_void-output.txt"
    data = (D / name).read_bytes()
    found, took = timed(at.ansi_hidden, data)
    visible = re.sub(rb"\^\[\[[0-9;]*m|\s", b"", data)
    period = (visible + visible).find(visible, 1)
    check("2024 The Void: 12 MB of black on black; the characters that are not blank spell the write-up's flag, over and over",
          len(found) == 1 and found[0]["text"] == VOID_FLAG and found[0]["strong"] and visible[:period].decode() == VOID_FLAG,
          (found and found[0]["text"][:60], visible[:60]))
    check("2024 The Void: one pass over the capture in under 2 s", took < 2.0, round(took, 2))
    a = ask(name, q("flag", "What is the flag hidden in the terminal output?", member=name), q("how", "Which technique hides the text?", member=name), limit=4.0)
    check("2024 The Void: end to end, the flag is the plain answer; the technique's name is a pick",
          a[0] == VOID_FLAG and "black_on_black" in (opts(a[1]) or {}), a)


def main() -> int:
    for t in (test_agentdojo, test_sessions_and_configs, test_poisoned_servers, test_benign_text, test_the_void):
        try:
            t()
        except Exception as e:      # noqa: BLE001 - a crash on a real file is the finding
            check(f"{t.__name__} ran to its end", False, f"{type(e).__name__}: {e}")
    check("no file took solve_set more than 2 s (the 12 MB capture: 4 s for its two passes)", not SLOW, SLOW)
    return C.finish("tests/real/test_real_agent_trace.py")


if __name__ == "__main__":
    sys.exit(main())
