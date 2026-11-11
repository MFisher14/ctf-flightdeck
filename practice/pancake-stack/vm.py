"""Pancake Stack: a tiny stack machine that takes breakfast orders.

Run: python3 vm.py program.bin
Every value is a byte (0 to 255). Jump addresses are two bytes, high byte first.
"""

import sys

OPCODES = {
    "PUSH": 0x10,  # PUSH n: push the byte n
    "DUP": 0x11,  # copy the top of the stack
    "SWAP": 0x12,  # swap the top two
    "DROP": 0x13,  # pop and forget
    "ADD": 0x20,  # a b -> (a + b) % 256
    "SUB": 0x21,  # a b -> (a - b) % 256
    "XOR": 0x22,  # a b -> a ^ b
    "ROL": 0x23,  # ROL n: rotate the top byte left by n bits
    "NOT": 0x24,  # a -> 255 - a
    "IN": 0x30,  # push the next byte of your order (0 once it runs out)
    "OUT": 0x31,  # pop a byte and print it as a character
    "EQ": 0x40,  # a b -> 1 if a == b else 0
    "JZ": 0x41,  # JZ hi lo: pop; jump if it was 0
    "JMP": 0x42,  # JMP hi lo
    "HALT": 0xFF,
}
NAMES = {code: name for name, code in OPCODES.items()}
WIDTH = {"PUSH": 1, "ROL": 1, "JZ": 2, "JMP": 2}  # operand bytes after the opcode
MAX_STEPS = 1_000_000


def run(program: bytes, order: bytes) -> str:
    stack: list[int] = []
    out: list[str] = []
    feed = iter(order)
    pc = 0
    for _ in range(MAX_STEPS):
        name = NAMES[program[pc]]
        arg = program[pc + 1 : pc + 1 + WIDTH.get(name, 0)]
        pc += 1 + len(arg)
        if name == "PUSH":
            stack.append(arg[0])
        elif name == "DUP":
            stack.append(stack[-1])
        elif name == "SWAP":
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif name == "DROP":
            stack.pop()
        elif name in ("ADD", "SUB", "XOR", "EQ"):
            b, a = stack.pop(), stack.pop()
            if name == "ADD":
                stack.append((a + b) % 256)
            elif name == "SUB":
                stack.append((a - b) % 256)
            elif name == "XOR":
                stack.append(a ^ b)
            else:
                stack.append(int(a == b))
        elif name == "ROL":
            a, n = stack.pop(), arg[0] % 8
            stack.append(((a << n) | (a >> (8 - n))) & 0xFF)
        elif name == "NOT":
            stack.append(255 - stack.pop())
        elif name == "IN":
            stack.append(next(feed, 0))
        elif name == "OUT":
            out.append(chr(stack.pop()))
        elif name == "JZ":
            if stack.pop() == 0:
                pc = int.from_bytes(arg, "big")
        elif name == "JMP":
            pc = int.from_bytes(arg, "big")
        elif name == "HALT":
            return "".join(out)
    raise RuntimeError("the griddle overheated: too many steps")


def main() -> None:
    with open(sys.argv[1], "rb") as f:
        program = f.read()
    order = input("order: ").strip().encode()
    print(run(program, order), end="")


if __name__ == "__main__":
    main()
