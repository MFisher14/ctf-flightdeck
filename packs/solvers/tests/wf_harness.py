"""Shared node harness for exercising workflow scripts in tests (B-194; lifted from hm-05).

A workflow script (`export const meta = {...}` then an async body using agent()/pipeline()/parallel()/
phase()/log()/args) is run under node with those globals stubbed, so a test sees exactly which prompts
the script would send, which StructuredOutput schemas it would force, and which argument/cap errors it
raises BEFORE any agent runs. Each agent() call is recorded; its reply is built from the schema's
required fields so the pipeline keeps flowing.

Mark any test that calls run_wf with @pytest.mark.needs_tool("node") so it is reported as NOT RUN (never
silently green) when node is absent, instead of skipping inside the body.

    from wf_harness import run_wf, HARNESS            # conftest puts tests/ on sys.path

    @pytest.mark.needs_tool("node")
    def test_it(tmp_path):
        r = run_wf(path_to_script, {...}, tmp_path)
        assert r["ok"]; assert [c["label"] for c in r["calls"]] == [...]
"""
import json
import shutil
import subprocess

# Runs a workflow script body with stubbed workflow globals. Each agent() call is recorded; its reply is
# built from the schema's required fields so the pipeline continues. `discover` returns a fixed listing
# (the legacy writeups.js discovery stage).
HARNESS = r"""
const fs = require('fs')
const [file, argsJson] = process.argv.slice(2)
let src = fs.readFileSync(file, 'utf8').replace(/^export const meta/m, 'const meta')
const calls = []
const fake = (schema, label) => {
  if (label === 'discover') return { solved: [{ dir: '/r/workspace/1-a', idslug: '1-a' }, { dir: '/r/workspace/2-b', idslug: '2-b' }] }
  if (!schema) return 'ok'
  const o = {}
  for (const k of schema.required || []) {
    const t = (schema.properties[k] || {}).type
    o[k] = t === 'array' ? [] : t === 'number' ? 0 : t === 'boolean' ? true : `${label}:${k}`
  }
  return o
}
const agent = async (prompt, opts = {}) => { calls.push({ label: opts.label, prompt, schema: opts.schema || null }); return fake(opts.schema, opts.label) }
const pipeline = async (items, ...stages) => Promise.all(items.map(async (it) => {
  let v = it
  for (let i = 0; i < stages.length; i++) v = await stages[i](i === 0 ? it : v, it)
  return v
}))
const parallel = async (thunks) => Promise.all(thunks.map(async (t) => { try { return await t() } catch (e) { return null } }))
const phase = () => {}
const logs = []
const log = (m) => logs.push(m)
const fn = new Function('args', 'agent', 'pipeline', 'parallel', 'phase', 'log', `return (async () => { ${src}\n })()`)
fn(JSON.parse(argsJson), agent, pipeline, parallel, phase, log)
  .then(r => console.log(JSON.stringify({ ok: true, result: r, calls, logs })))
  .catch(e => console.log(JSON.stringify({ ok: false, error: String(e && e.message || e), calls, logs })))
"""

NODE = shutil.which("node")


def run_wf(path, args, tmp_path):
    """Run one workflow script under the stub harness and return the parsed result. The caller must mark
    its test @pytest.mark.needs_tool("node"); node is assumed present here (not skipped in the body)."""
    assert NODE is not None, "run_wf called without node: mark the test @pytest.mark.needs_tool('node')"
    h = tmp_path / "harness.cjs"
    h.write_text(HARNESS)
    p = subprocess.run([NODE, str(h), str(path), json.dumps(args)], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])
