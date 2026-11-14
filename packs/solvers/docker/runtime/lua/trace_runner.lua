-- ctf-runtime-lua runner (B-242): one Lua chunk (source or bytecode) on a Lua VM, instruction-bounded.
--
-- Runs INSIDE the ctf-runtime-lua container (no network, no host mount, read-only root). The sandbox
-- table below is a recording stand-in, not a security boundary: the container is. Never run on the
-- host against a delivered file.
--
--   luaX trace_runner.lua --artifact FILE --fuel N [--seconds S] [--max-events N] [--probe-hex HEX]...
--
-- What it does (written for Lua 5.1, 5.2, 5.3, 5.4 and LuaJIT; bytecode loads only on the VM that
-- made it, and a mismatch is reported as the load error it is):
--   - runs the chunk in an environment whose print, io, os, require and load are recording stand-ins
--     (no file, no process, no module loading), once per probe while the chunk reads input (the probe
--     is arg[1] and every io.read answer);
--   - fuel is VM instructions, counted by a debug hook in steps of 1000 (coroutines the chunk
--     creates are hooked too; LuaJIT's compiler is turned off so the hook fires); one run or call
--     may use an eighth of it, so a function that never returns does not leave the rest untraced;
--     the chunk's pcall, xpcall and coroutine.resume pass the runner's stops (fuel, share, os.exit)
--     on instead of catching them, and an xpcall handler never sees one; a __gc finalizer (which
--     would run with hooks off) is never armed, and the runner exits without closing the state;
--     NOT bounded by fuel: one long C call (string.rep, a pathological string.find pattern, a huge
--     table.concat) runs no VM instruction, so only the container's time and memory limits end it;
--   - every chunk the code builds and loads at run time (load / loadstring) is reported as text;
--   - reports what the chunk printed and returned, the globals it left behind (one level into
--     tables), and calls each function it left behind that takes at most one argument.
--
-- Output: one line on stdout, "@@CTF-RUNTIME-TRACE@@ " + JSON (schema 1, every value a bounded string;
-- a byte outside printable ASCII is written as \u00XX).
local MARKER = "@@CTF-RUNTIME-TRACE@@ "
local MAX_TEXT, MAX_STRINGS, MAX_ENTRIES, MAX_CALLS, MAX_FIELDS = 2048, 256, 256, 64, 64
local STEP = 1000

local real_load = loadstring or load
local unpack_ = table.unpack or unpack
if jit and jit.off then jit.off() end

local doc = { status = "ok", entries = {}, events = {}, strings = {}, notes = {}, truncated = false }
local fuel = { limit = 0, used = 0, exhausted = false }
local max_events = 512
local seen = {}

local function clip(v)
  local s = type(v) == "string" and v or tostring(v)
  if #s > MAX_TEXT then s = s:sub(1, MAX_TEXT) .. "...[cut]" end
  return s
end

local function quote(s)
  return '"' .. s:gsub('[%c"\\\127-\255]', function(c)
    if c == '"' or c == "\\" then return "\\" .. c end
    return string.format("\\u%04x", c:byte())
  end) .. '"'
end

local function object(pairs_)
  local parts = {}
  for i = 1, #pairs_, 2 do
    parts[#parts + 1] = quote(pairs_[i]) .. ":" .. quote(clip(pairs_[i + 1]))
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function event(...)
  if #doc.events >= max_events then doc.truncated = true return end
  doc.events[#doc.events + 1] = object({ ... })
end

local function observed(s)
  if type(s) ~= "string" or s == "" then return end
  s = clip(s)
  if seen[s] then return end
  if #doc.strings >= MAX_STRINGS then doc.truncated = true return end
  seen[s] = true
  doc.strings[#doc.strings + 1] = quote(s)
end

local function partial()
  if doc.status == "ok" then doc.status = "partial" end
end

local function emit()
  local notes = {}
  for i, n in ipairs(doc.notes) do notes[i] = quote(clip(n)) end
  io.stdout:write(MARKER, '{"schema":1,"runtime":"lua","runtime_version":', quote(jit and jit.version or _VERSION),
    ',"status":', quote(doc.status),
    ',"fuel":{"kind":"instructions","limit":', string.format("%d", fuel.limit), ',"used":',
    string.format("%d", fuel.used), ',"exhausted":', tostring(fuel.exhausted), "}",
    ',"entries":[', table.concat(doc.entries, ","), "]",
    ',"events":[', table.concat(doc.events, ","), "]",
    ',"strings":[', table.concat(doc.strings, ","), "]",
    ',"notes":[', table.concat(notes, ","), "]",
    ',"truncated":', tostring(doc.truncated), "}\n")
  io.stdout:flush()
end

-- ------------------------------------------------------------------------------------ arguments
local artifact, probes = nil, {}
do
  local i = 1
  while i + 1 <= #arg do
    local k, v = arg[i], arg[i + 1]
    if k == "--artifact" then artifact = v
    elseif k == "--fuel" then fuel.limit = tonumber(v) or 0
    elseif k == "--max-events" then max_events = tonumber(v) or max_events
    elseif k == "--probe-hex" then
      probes[#probes + 1] = (v:gsub("%x%x", function(h) return string.char(tonumber(h, 16)) end))
    elseif k ~= "--seconds" and k ~= "--deps" then
      io.stderr:write("trace_runner: unknown option " .. tostring(k) .. "\n")
      os.exit(2)
    end
    i = i + 2
  end
end
if not artifact or fuel.limit <= 0 then
  io.stderr:write("trace_runner: --artifact and a positive --fuel are required\n")
  os.exit(2)
end
if #probes == 0 then probes[1] = "" end

-- ------------------------------------------------------------------------------------------ fuel
local FUEL = {}   -- the error value of an exhausted budget (a table: no script error equals it)
local SHARE = {}  -- the error value of one run or call that used its share (an eighth of the budget)
local EXIT = {}   -- the error value of os.exit
local call_cap = 0

local function hook()
  fuel.used = fuel.used + STEP
  if fuel.used >= fuel.limit then
    fuel.exhausted = true
    error(FUEL, 0)
  end
  if fuel.used >= call_cap then error(SHARE, 0) end
end

-- One run or call under the hook. It may use an eighth of the budget, so a function that never
-- returns does not leave the rest untraced.
local function guarded(fn, ...)
  call_cap = fuel.used + math.max(STEP, math.floor(fuel.limit / 8))
  debug.sethook(hook, "", STEP)
  local res = { pcall(fn, ...) }
  debug.sethook()
  return res
end

-- ----------------------------------------------------------------------------------- sandbox env
local function copy(t)
  local out = {}
  if t then for k, v in pairs(t) do out[k] = v end end
  return out
end

-- The runner's own stops (out of fuel, its share used, os.exit) must reach `guarded`: a protected
-- call the chunk makes (pcall, xpcall, coroutine.resume) passes them on instead of returning them.
local function stop(e)
  return e == FUEL or e == SHARE or e == EXIT
end

local function passed_on(ok, ...)
  if not ok and stop((...)) then error((...), 0) end
  return ok, ...
end

local function make_env(probe, state)
  local env = {}
  for _, name in ipairs({ "assert", "error", "ipairs", "next", "pairs", "select", "tonumber",
    "tostring", "type", "unpack", "rawequal", "rawget", "rawset", "rawlen", "setmetatable", "getmetatable",
    "_VERSION" }) do
    env[name] = _G[name]
  end
  -- A finalizer (__gc) runs with debug hooks off, so its instructions would escape the fuel. An object
  -- is marked for finalization only if its metatable has __gc (a raw field) when setmetatable is
  -- called: the field is hidden for that call and put back, so the chunk still sees its own metatable
  -- but the object is never finalized. (Lua 5.1 and LuaJIT run no __gc on tables; newproxy is absent.)
  env.setmetatable = function(t, mt)
    if type(mt) == "table" and rawget(mt, "__gc") ~= nil then
      event("kind", "refused", "name", "__gc", "text", "finalizers do not run in the trace sandbox")
      local gc = rawget(mt, "__gc")
      rawset(mt, "__gc", nil)
      local ok, res = pcall(setmetatable, t, mt)
      rawset(mt, "__gc", gc)
      if not ok then error(res, 2) end
      return res
    end
    return setmetatable(t, mt)
  end
  env.pcall = function(f, ...) return passed_on(pcall(f, ...)) end
  env.xpcall = function(f, handler, ...)
    local n, args = select("#", ...), { ... }
    -- the handler never sees a stop (it could swallow it); Lua 5.1's xpcall passes no arguments
    return passed_on(xpcall(function() return f(unpack_(args, 1, n)) end,
      function(e) if stop(e) then return e end return handler(e) end))
  end
  env.string, env.table, env.math = copy(string), copy(table), copy(math)
  env.bit32, env.bit, env.utf8 = bit32 and copy(bit32), bit and copy(bit), utf8 and copy(utf8)
  env.coroutine = copy(coroutine)
  env.coroutine.create = function(f)
    local co = coroutine.create(f)
    debug.sethook(co, hook, "", STEP)
    return co
  end
  env.coroutine.resume = function(co, ...) return passed_on(coroutine.resume(co, ...)) end
  env.coroutine.wrap = function(f)
    local co = env.coroutine.create(f)
    return function(...)
      local res = { coroutine.resume(co, ...) }
      if not res[1] then error(res[2], 0) end
      return unpack_(res, 2)
    end
  end
  local function out(stream)
    return function(...)
      local parts = {}
      for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
      local text = table.concat(parts)
      event("kind", "output", "stream", stream, "text", text)
      for line in text:gmatch("[^\r\n]+") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" then observed(trimmed) end
      end
    end
  end
  env.print = function(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
    out("stdout")(table.concat(parts, "\t"))
  end
  local function read()
    state.input_used = true
    if state.read_done then return nil end
    state.read_done = true
    return probe
  end
  local stdin = { read = function(_, ...) return read() end, lines = function() return read end, close = function() end }
  local stdout = { write = function(self, ...) out("stdout")(...) return self end, flush = function() end,
    close = function() end, setvbuf = function() end }
  local stderr = { write = function(self, ...) out("stderr")(...) return self end, flush = function() end,
    close = function() end, setvbuf = function() end }
  env.io = { write = function(...) out("stdout")(...) return stdout end, read = function(...) return read() end,
    lines = function() return read end, stdin = stdin, stdout = stdout, stderr = stderr,
    open = function(name)
      event("kind", "refused", "name", "io.open", "text", tostring(name))
      return nil, tostring(name) .. ": not available in the trace sandbox"
    end }
  env.os = { time = function() return 1700000000 end, clock = os.clock, date = function() return "2026-01-01" end,
    getenv = function() return nil end, difftime = os.difftime,
    exit = function(code)
      event("kind", "exit", "text", tostring(code == nil and 0 or code))
      error(EXIT, 0)
    end }
  env.require = function(name)
    event("kind", "require", "name", tostring(name))
    error("module '" .. tostring(name) .. "' is not available in the trace sandbox", 2)
  end
  local function loader(chunk, name, mode, e)
    if type(chunk) == "function" then
      local pieces = {}
      while #pieces < 4096 do
        local piece = chunk()
        if not piece or piece == "" then break end
        pieces[#pieces + 1] = piece
      end
      chunk = table.concat(pieces)
    end
    if type(chunk) ~= "string" then return nil, "bad chunk" end
    event("kind", "chunk", "name", tostring(name or "=(load)"), "text", chunk)
    if chunk:byte(1) ~= 27 then observed(chunk) end
    local target = e or env
    if setfenv then
      local f, err = real_load(chunk, name)
      if f then setfenv(f, target) end
      return f, err
    end
    return load(chunk, name, mode or "bt", target)
  end
  env.load, env.loadstring = loader, loader
  env.dofile = function(name) error("dofile is not available in the trace sandbox", 2) end
  env.loadfile = function(name) return nil, "loadfile is not available in the trace sandbox" end
  env.arg = { [0] = "artifact.lua", probe }
  env._G = env
  return env
end

local function render(v)
  local t = type(v)
  if t == "string" then observed(v) return v end
  if t == "number" or t == "boolean" or t == "nil" then return tostring(v) end
  return "<" .. t .. ">"
end

local function nparams(f)
  local ok, info = pcall(debug.getinfo, f, "u")
  if ok and info and info.nparams then return info.nparams, info.isvararg end
  return nil, nil
end

-- ------------------------------------------------------------------------------------------- run
local handle, open_err = io.open(artifact, "rb")
if not handle then
  doc.status = "error"
  event("kind", "error", "name", "load", "text", tostring(open_err))
  emit()
  os.exit(0)
end
local source = handle:read("*a")
handle:close()

local function compile(env)
  if setfenv then
    local f, err = real_load(source, "=artifact")
    if f then setfenv(f, env) end
    return f, err
  end
  return load(source, "=artifact", "bt", env)
end

local calls = 0
local function failure(name, args, err, as_call)
  if err == FUEL then
    event("kind", as_call and "call" or "error", "name", name, "args", args, as_call and "error" or "text", "out of fuel")
  elseif err == SHARE then
    event("kind", as_call and "call" or "error", "name", name, "args", args, as_call and "error" or "text",
      "stopped: it used its share of the fuel")
  elseif err == EXIT then
    return
  else
    event("kind", as_call and "call" or "error", "name", name, "args", args, as_call and "error" or "text", tostring(err))
  end
  partial()
end

for p, probe in ipairs(probes) do
  local state = { input_used = false }
  local env = make_env(probe, state)
  local baseline = {}
  for k in pairs(env) do baseline[k] = true end
  local chunk, err = compile(env)
  if not chunk then
    doc.status = "error"
    event("kind", "error", "name", "load", "text", tostring(err))
    break
  end
  local res = guarded(chunk, probe)
  if res[1] then
    for i = 2, #res do event("kind", "return", "name", "chunk", "value", render(res[i])) end
  else
    failure("chunk", "probe " .. (p - 1), res[2], false)
  end
  if fuel.exhausted then break end

  local found = {}
  local names = {}
  for k in pairs(env) do
    if not baseline[k] and type(k) == "string" then names[#names + 1] = k end
  end
  table.sort(names)
  for _, name in ipairs(names) do
    local v = env[name]
    if type(v) == "table" then
      local keys = {}
      for k in pairs(v) do
        if type(k) == "string" and #keys < MAX_FIELDS then keys[#keys + 1] = k end
      end
      table.sort(keys)
      for _, k in ipairs(keys) do found[#found + 1] = { name .. "." .. k, v[k] } end
    else
      found[#found + 1] = { name, v }
    end
  end
  local unary = false
  for _, item in ipairs(found) do
    local name, v = item[1], item[2]
    if type(v) == "function" then
      local n, vararg = nparams(v)
      if p == 1 then
        if #doc.entries < MAX_ENTRIES then
          doc.entries[#doc.entries + 1] = object({ "name", name, "signature",
            "function/" .. (n and tostring(n) or "?") .. (vararg and "+" or "") })
        else
          doc.truncated = true
        end
      end
      local takes_one = n == nil or n == 1
      if takes_one then unary = true end
      if (n == 0 and p == 1) or takes_one then
        if calls >= MAX_CALLS then
          partial()
        else
          calls = calls + 1
          local r = guarded(v, probe)
          local args = takes_one and ("probe " .. (p - 1)) or ""
          if r[1] then
            event("kind", "call", "name", name, "args", args, "result", render(r[2]))
          else
            failure(name, args, r[2], true)
          end
          if fuel.exhausted then break end
        end
      end
    elseif p == 1 or state.input_used then
      event("kind", "global", "name", name, "value", render(v))
    end
  end
  if fuel.exhausted then break end
  if not state.input_used and not unary then break end
end
if fuel.exhausted then partial() end
emit()
-- Exit without lua_close: closing the state would run any finalizer left, with no hook and no fuel.
os.exit(0)
