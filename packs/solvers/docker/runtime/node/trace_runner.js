// ctf-runtime-node runner (B-242): one JavaScript file or V8 cached-data blob (.jsc) on Node, time-bounded.
//
// Runs INSIDE a ctf-runtime-node container (no network, no host mount, read-only root). `vm` is not a
// security boundary and this script does not pretend it is: the container is. Never run on the host
// against a delivered file.
//
//   node trace_runner.js --artifact FILE --fuel N --seconds S [--max-events N] [--probe-hex HEX]...
//
// What it does:
//   - runs the script in a fresh vm context whose console, process, timers, stdin, readline and
//     require are recording stand-ins (require gives the pure built-ins only; anything else is
//     recorded and refused), once per probe while the script reads input (the probe is argv[2],
//     stdin and every readline answer);
//   - V8 cached data (a bytenode .jsc) is loaded the way bytenode does (a dummy source of the recorded
//     length, the flags hash patched); when this Node's V8 rejects it the trace says so and gives
//     both version hashes, so the caller can pick another Node image;
//   - reports what the script printed, every base64 string it decoded with atob, and the globals and
//     module.exports members it left behind (a string it built at run time shows up here);
//   - calls each function it left behind that takes at most one argument (once, or once per probe).
// V8 has no instruction fuel: every run and call gets a share of --seconds through vm's timeout, and
// one that does not finish is reported. --fuel is accepted and ignored. ES module syntax is not run.
//
// Output: one line on stdout, "@@CTF-RUNTIME-TRACE@@ " + JSON (schema 1, every value a bounded string).
'use strict';
const fs = require('fs');
const vm = require('vm');
const v8 = require('v8');

const MARKER = '@@CTF-RUNTIME-TRACE@@ ';
const MAX_TEXT = 2048;
const MAX_STRINGS = 256;
const MAX_ENTRIES = 256;
const MAX_CALLS = 64;
const MAX_TIMERS = 64;
const PURE_MODULES = ['crypto', 'buffer', 'util', 'zlib', 'assert', 'string_decoder', 'events', 'path', 'url',
  'querystring', 'punycode'];

const doc = {schema: 1, runtime: 'node', runtime_version: process.version + ' (v8 ' + process.versions.v8 + ')',
  status: 'ok', fuel: {kind: 'time', limit: 0, used: 0, exhausted: false}, entries: [], events: [],
  strings: [], notes: [], truncated: false};
let maxEvents = 512;
let emitted = false;
const started = Date.now();
const seen = new Set();

function clip(value) {
  let text;
  try {
    text = typeof value === 'string' ? value : String(value);
  } catch (e) {
    text = '<unprintable>';
  }
  return text.length <= MAX_TEXT ? text : text.slice(0, MAX_TEXT) + '...[cut]';
}

function event(kind, fields) {
  if (doc.events.length >= maxEvents) {
    doc.truncated = true;
    return;
  }
  const row = {kind};
  for (const k of Object.keys(fields)) row[k] = clip(fields[k]);
  doc.events.push(row);
}

function string(value) {
  if (typeof value !== 'string' || value.length === 0) return;
  const text = clip(value);
  if (seen.has(text)) return;
  if (doc.strings.length >= MAX_STRINGS) {
    doc.truncated = true;
    return;
  }
  seen.add(text);
  doc.strings.push(text);
}

function partial() {
  if (doc.status === 'ok') doc.status = 'partial';
}

function emit() {
  if (emitted) return;
  emitted = true;
  doc.fuel.used = Date.now() - started;
  fs.writeSync(1, MARKER + JSON.stringify(doc).replace(/[\u007f-￿]/g,
    (c) => '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4)) + '\n');
}

function render(value) {
  if (typeof value === 'string') {
    string(value);
    return value;
  }
  if (value === null || value === undefined || typeof value === 'number' || typeof value === 'boolean'
      || typeof value === 'bigint') return String(value);
  if (typeof value === 'function') return '<function ' + (value.name || 'anonymous') + '/' + value.length + '>';
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const text = Buffer.from(value).toString('latin1');
    if (/^[\x20-\x7e\r\n\t]+$/.test(text)) {
      string(text);
      return text;
    }
    return 'hex:' + Buffer.from(value).toString('hex').slice(0, MAX_TEXT);
  }
  try {
    const text = JSON.stringify(value, (k, v) => {
      if (typeof v === 'string') string(v);
      return typeof v === 'bigint' ? String(v) : v;
    });
    return text === undefined ? '<' + typeof value + '>' : text;
  } catch (e) {
    return '<' + typeof value + '>';
  }
}

function parseArgs(argv) {
  const out = {artifact: null, seconds: 20, probes: []};
  for (let i = 0; i + 1 < argv.length; i += 2) {
    const k = argv[i];
    const v = argv[i + 1];
    if (k === '--artifact') out.artifact = v;
    else if (k === '--seconds') out.seconds = Number(v);
    else if (k === '--max-events') maxEvents = Number(v);
    else if (k === '--probe-hex') out.probes.push(Buffer.from(v, 'hex').toString('utf8'));
    else if (k !== '--fuel' && k !== '--deps') {
      process.stderr.write('trace_runner: unknown option ' + k + '\n');
      process.exit(2);
    }
  }
  if (!out.artifact || !(out.seconds > 0)) {
    process.stderr.write('trace_runner: --artifact and a positive --seconds are required\n');
    process.exit(2);
  }
  if (out.probes.length === 0) out.probes.push('');
  return out;
}

class ExitSignal extends Error {}

// One context for one run of the script with one probe.
function makeContext(probe, state) {
  const timers = [];
  const cap = (stream) => (...parts) => {
    const text = parts.map((p) => (typeof p === 'string' ? p : render(p))).join(' ');
    event('output', {stream, text});
    for (const line of text.split(/\r?\n/)) if (line.trim()) string(line.trim());
  };
  const later = (fn, ms, ...args) => {
    if (typeof fn === 'function' && timers.length < MAX_TIMERS) timers.push([fn, args]);
    return timers.length;
  };
  const stdin = {
    setEncoding() {}, resume() {}, pause() {},
    on(name, cb) {
      state.inputUsed = true;
      if (name === 'data') later(cb, 0, probe + '\n');
      if (name === 'end' || name === 'close') later(cb, 0);
      return stdin;
    },
    read() { state.inputUsed = true; return probe + '\n'; },
  };
  const readline = {
    createInterface() {
      state.inputUsed = true;
      const rl = {
        question(q, cb) { event('output', {stream: 'stdout', text: String(q)}); later(cb, 0, probe); },
        on(name, cb) {
          if (name === 'line') later(cb, 0, probe);
          if (name === 'close') later(cb, 0);
          return rl;
        },
        close() {}, setPrompt() {}, prompt() {},
      };
      return rl;
    },
  };
  const proc = {
    argv: ['node', 'artifact.js', probe], env: {}, platform: 'linux', version: process.version,
    versions: Object.assign({}, process.versions), pid: 4242, exitCode: undefined,
    stdout: {write: (t) => { cap('stdout')(String(t)); return true; }},
    stderr: {write: (t) => { cap('stderr')(String(t)); return true; }},
    stdin,
    exit(code) { event('exit', {text: String(code === undefined ? 0 : code)}); throw new ExitSignal('exit'); },
    nextTick: (fn, ...args) => later(fn, 0, ...args),
    on() { return proc; }, cwd: () => '/work', hrtime: process.hrtime, uptime: () => 1,
  };
  Object.defineProperty(proc, 'argv', {get() { state.inputUsed = true; return ['node', 'artifact.js', probe]; }});
  const req = (name) => {
    const bare = String(name).replace(/^node:/, '');
    event('require', {name: String(name)});
    if (bare === 'readline') return readline;
    if (PURE_MODULES.includes(bare)) return require(bare);
    throw new Error("module '" + name + "' is not available in the trace sandbox");
  };
  const moduleObj = {exports: {}, id: '.', filename: '/work/artifact.js', loaded: false, children: [], paths: []};
  const sandbox = {
    console: {log: cap('stdout'), info: cap('stdout'), debug: cap('stdout'), warn: cap('stderr'),
      error: cap('stderr'), trace: cap('stderr')},
    process: proc, require: req, module: moduleObj, exports: moduleObj.exports,
    __filename: '/work/artifact.js', __dirname: '/work',
    Buffer, TextEncoder, TextDecoder, URL, URLSearchParams,
    atob: (s) => { const r = atob(s); string(r); return r; },
    btoa: (s) => btoa(s),
    setTimeout: later, setInterval: later, setImmediate: (fn, ...a) => later(fn, 0, ...a),
    clearTimeout() {}, clearInterval() {}, clearImmediate() {},
    queueMicrotask: (fn) => later(fn, 0),
  };
  sandbox.global = sandbox;
  const context = vm.createContext(sandbox, {name: 'artifact', microtaskMode: 'afterEvaluate'});
  return {context, sandbox, timers, moduleObj};
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  doc.fuel.limit = Math.round(args.seconds * 1000);
  const deadline = started + doc.fuel.limit;
  const share = Math.max(100, Math.floor(doc.fuel.limit / 4));
  process.on('exit', () => {
    if (!emitted) {
      doc.notes.push('the process ended before the trace was complete');
      partial();
    }
    emit();
  });

  // Runs `fn` (which must execute inside vm with the given timeout); false when the budget is gone.
  function bounded(name, argsText, fn, report) {
    const left = deadline - Date.now();
    if (left <= 0) {
      doc.fuel.exhausted = true;
      partial();
      return false;
    }
    const timeout = Math.max(1, Math.min(share, left));
    try {
      const result = fn(timeout);
      if (report) event('call', {name, args: argsText, result: render(result)});
    } catch (e) {
      if (e instanceof ExitSignal) return true;
      const timedOut = e && e.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT';
      const text = timedOut ? 'did not finish in ' + timeout + ' ms' : clip(e && e.stack ? String(e.stack).split('\n')[0] : e);
      event(report ? 'call' : 'error', report ? {name, args: argsText, error: text} : {name, text});
      partial();
    }
    return true;
  }

  const data = fs.readFileSync(args.artifact);
  const cached = data.length >= 24 && data.readUInt32LE(0) >>> 16 === 0xC0DE;
  let script = null;
  if (cached) {
    v8.setFlagsFromString('--no-lazy');
    v8.setFlagsFromString('--no-flush-bytecode');
    const fresh = new vm.Script('"x"').createCachedData();
    const blob = Buffer.from(data);
    const length = blob.readUInt32LE(8) & 0x7fffffff;
    fresh.subarray(12, 16).copy(blob, 12);
    const dummy = length > 1 ? '"' + '​'.repeat(length - 2) + '"' : '';
    script = new vm.Script(dummy, {cachedData: blob, filename: 'artifact.jsc'});
    event('cache', {name: 'v8 cached data', text: 'version hash ' + data.readUInt32LE(4).toString(16)
      + ', this runtime ' + fresh.readUInt32LE(4).toString(16) + ', source length ' + length});
    if (script.cachedDataRejected) {
      doc.status = 'error';
      event('error', {name: 'load', text: 'V8 rejected the cached data: it was made by another V8 (version hash '
        + data.readUInt32LE(4).toString(16) + ', this runtime ' + fresh.readUInt32LE(4).toString(16) + ')'});
      emit();
      return;
    }
  } else {
    try {
      script = new vm.Script(data.toString('utf8'), {filename: 'artifact.js'});
    } catch (e) {
      doc.status = 'error';
      const text = clip(e);
      event('error', {name: 'load', text: /import|export/.test(text) && /module/i.test(text)
        ? text + ' (ES module syntax is not run by this runner)' : text});
      emit();
      return;
    }
  }

  let calls = 0;
  for (let p = 0; p < args.probes.length; p++) {
    const probe = args.probes[p];
    const state = {inputUsed: false};
    const {context, sandbox, timers, moduleObj} = makeContext(probe, state);
    const baseline = new Set(Object.getOwnPropertyNames(sandbox));
    const alive = bounded('script', 'probe ' + p, (timeout) => {
      const value = script.runInContext(context, {timeout});
      if (typeof value === 'function' && cached) {     // bytenode compiles the CommonJS wrapper function
        sandbox.__ctfWrapped = value;
        return new vm.Script('__ctfWrapped.call(module.exports, exports, require, module, __filename, __dirname)')
          .runInContext(context, {timeout});
      }
      return value;
    }, false);
    if (!alive) break;
    sandbox.__ctfDrain = () => {
      let n = 0;
      while (timers.length && n++ < MAX_TIMERS) {
        const [fn, a] = timers.shift();
        fn(...a);
      }
    };
    bounded('timers', 'probe ' + p, (timeout) => new vm.Script('__ctfDrain()').runInContext(context, {timeout}), false);

    const found = [];
    for (const name of Object.getOwnPropertyNames(sandbox)) {
      if (baseline.has(name) || name.startsWith('__ctf')) continue;
      found.push([name, sandbox[name]]);
    }
    const exported = moduleObj.exports;
    if (typeof exported === 'function') found.push(['module.exports', exported]);
    else if (exported && typeof exported === 'object') {
      for (const name of Object.keys(exported)) found.push(['exports.' + name, exported[name]]);
    }
    for (const [name, value] of found) {
      if (typeof value === 'function') {
        if (p === 0) {
          if (doc.entries.length < MAX_ENTRIES) doc.entries.push({name: clip(name), signature: 'function/' + value.length});
          else doc.truncated = true;
        }
        if (value.length > 1 || (value.length === 0 && p > 0)) continue;
        if (calls >= MAX_CALLS) {
          if (!doc.notes.includes('call limit reached')) doc.notes.push('call limit reached');
          partial();
          continue;
        }
        calls++;
        sandbox.__ctfFn = value;
        sandbox.__ctfArg = probe;
        const src = value.length === 0 ? '__ctfFn()' : '__ctfFn(__ctfArg)';
        if (!bounded(name, value.length === 0 ? '' : 'probe ' + p,
          (timeout) => new vm.Script(src).runInContext(context, {timeout}), true)) break;
      } else if (p === 0 || state.inputUsed) {
        event('global', {name, value: render(value)});
      }
    }
    if (!state.inputUsed && !found.some(([, v]) => typeof v === 'function' && v.length === 1)) break;
  }
  emit();
}

main();
