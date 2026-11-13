# The build-time self-test of ctf-runtime-python (B-242): our own module, never a delivered one. The
# token is built when the module runs, so finding it in the trace proves the runner ran it.
TOKEN = "".join(chr(ord(c) - 1) for c in "dug.tfmguftu.pl")


def check(s):
    return s == TOKEN
