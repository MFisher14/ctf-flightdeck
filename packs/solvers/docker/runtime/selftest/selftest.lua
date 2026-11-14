-- The build-time self-test of ctf-runtime-lua (B-242): our own chunk, never a delivered one. The
-- token is built when the chunk runs, so finding it in the trace proves the runner ran it. Lua 5.1
-- syntax, so every interpreter in the image runs it.
TOKEN = (("dug.tfmguftu.pl"):gsub(".", function(c) return string.char(c:byte() - 1) end))

function check(s)
  return s == TOKEN
end
