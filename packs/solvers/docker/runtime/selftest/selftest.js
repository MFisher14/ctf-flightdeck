// The build-time self-test of ctf-runtime-node (B-242): our own script, never a delivered one. The
// token is built when the script runs, so finding it in the trace proves the runner ran it.
var TOKEN = 'dug.tfmguftu.pl'.split('').map(function (c) {
  return String.fromCharCode(c.charCodeAt(0) - 1);
}).join('');

function check(s) {
  return s === TOKEN;
}
