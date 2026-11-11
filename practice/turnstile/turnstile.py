"""The ferry turnstile: it turns only for a valid ticket.

Run: python3 turnstile.py
"""

KEY = b"ferry"
TICKET = [
    0xb0, 0xf0, 0x09, 0x31, 0x49, 0x91, 0x81, 0x42, 0x0a, 0x62, 0xaa, 0x9a,
    0x6b, 0x93, 0x7b, 0xf3, 0x55, 0xbb, 0x2c, 0xe4, 0x2e, 0xd4, 0x6d, 0x95,
    0xd5, 0x06, 0xd5, 0xed, 0xd6, 0xae, 0x58, 0x07, 0xa7, 0x3f, 0xe7, 0x08,
    0xa0,
]


def punch(ticket: bytes) -> list[int]:
    """Every byte of the ticket goes through the punch, one hole at a time."""
    holes = []
    for i, byte in enumerate(ticket):
        x = byte ^ KEY[i % len(KEY)]
        x = (x + 7 * i) % 256
        x = ((x << 3) | (x >> 5)) & 0xFF
        holes.append(x)
    return holes


def main() -> None:
    ticket = input("ticket: ").strip().encode()
    if punch(ticket) == TICKET:
        print("click. welcome aboard.")
    else:
        print("the turnstile does not move.")


if __name__ == "__main__":
    main()
