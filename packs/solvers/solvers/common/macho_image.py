#!/usr/bin/env python3
"""Mach-O 64-bit images (x86-64, arm64) mapped for the whole-image emulator (B-241).

``native_image.py`` loads an ELF the way the dynamic loader does and runs one function of it under its
never-wrong contract (two layouts, byte-granular definedness, modelled libc, everything else declines).
This module reads a Mach-O the way dyld does and hands ``native_image`` an image with the same shape, so a
macOS or iOS-simulator crackme's function runs in the same engine:

  * every segment with a protection is a mapped range (``__PAGEZERO`` has none and is not mapped), file
    backed for its file size, zero-filled and defined for the rest; addresses are kept relative to the
    Mach header, so the engine slides the image as dyld does;
  * the fixups dyld applies become the engine's relocation plan: rebases (a pointer into the image), and
    binds against this image's own symbols, against a modelled libSystem function (the name without its
    leading underscore: ``_strlen`` is ``strlen``, ``___memcpy_chk`` is ``__memcpy_chk``), against
    ``___stack_chk_guard`` (a pointer to the engine's canary cell) or against anything else (a trap that
    declines when called).  Both encodings are read: the ``LC_DYLD_INFO`` rebase/bind/lazy-bind opcode
    streams, and ``LC_DYLD_CHAINED_FIXUPS`` with 64-bit pointer formats;
  * a ``SG_READ_ONLY`` segment (``__DATA_CONST``) is read-only after the fixups, as dyld leaves it;
  * the initializers dyld runs before any call (``__mod_init_func`` pointers, ``__init_offsets``) are the
    image's constructors.

What dyld would do and this does not model sets ``problem``, and every emulation of the image then
declines: arm64e (pointer authentication), an encrypted image, a non-PIE executable, a text rebase, a
threaded bind, a 32-bit or unknown chained pointer format, a fixup outside a writable segment, two
read-only data segments that are not adjacent.  A weak (coalesced) bind, a flat-namespace or
main-executable lookup and a tagged pointer make their slot undefined: which definition wins is the
process's.  A universal file needs the slice named (``arch``) when it holds more than one this engine runs.

Never-wrong note: the libc model, the allocator rules and the two layouts were argued for Android.  They
hold for the functions shared with libSystem (the modelled subset is ISO C plus the ``__*_chk`` forms) and
decline wherever an allocator's choice or an address could matter, but no Darwin device was replayed
against them.  Treat a Mach-O result as a reader, never as a label on its own.

Nothing from the file is run on the host.
"""
import struct

import native_emulate as _ne

EmulationError = _ne.EmulationError
ARCH_X86_64 = _ne.ARCH_X86_64
ARCH_ARM64 = _ne.ARCH_ARM64

M64 = (1 << 64) - 1
PAGE = 0x1000
ET_DYN = 3
MAX_FILE = 32 << 20
MAX_SPAN = 64 << 20
MAX_COMMANDS = 4096
MAX_SYMS = 200_000
MAX_FIXUPS = 200_000

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
CPU_X86_64, CPU_ARM64 = 0x01000007, 0x0100000C
MH_EXECUTE, MH_DYLIB, MH_BUNDLE = 2, 6, 8
MH_PIE = 0x200000
SG_READ_ONLY = 0x10
LC_SEGMENT, LC_SYMTAB, LC_UNIXTHREAD, LC_LOAD_DYLIB, LC_SEGMENT_64 = 0x1, 0x2, 0x5, 0xC, 0x19
LC_DYLD_INFO, LC_ENCRYPTION_INFO_64 = 0x22, 0x2C
LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB = 0x80000018, 0x8000001F, 0x80000023
LC_DYLD_CHAINED_FIXUPS = 0x80000034
_DYLIB_COMMANDS = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB)
S_MOD_INIT_FUNC_POINTERS, S_INIT_FUNC_OFFSETS = 0x9, 0x16
DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET = 2, 6
# The libraries whose C functions the engine's libc model stands for (libSystem re-exports libsystem_c).
_SYSTEM_LIBS = ("/usr/lib/libSystem.B.dylib", "/usr/lib/libSystem.dylib", "/usr/lib/system/libsystem_c.dylib",
                "/usr/lib/system/libsystem_malloc.dylib", "/usr/lib/system/libsystem_platform.dylib")
_ARCH_OF = {CPU_X86_64: ARCH_X86_64, CPU_ARM64: ARCH_ARM64}


def is_macho(data):
    """True when `data` starts like a 64-bit Mach-O or a universal (fat) file."""
    head = bytes(data[:4])
    return head == struct.pack("<I", MH_MAGIC_64) or head in (struct.pack(">I", FAT_MAGIC),
                                                               struct.pack(">I", FAT_MAGIC_64))


def slices(data):
    """[(arch name or None, offset, size)] of a universal file's members, or one row for a thin file."""
    data = bytes(data)
    if len(data) < 8:
        raise EmulationError("not a Mach-O image")
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return [(None, 0, len(data))]
    count = struct.unpack_from(">I", data, 4)[0]
    if not 0 < count <= 32:
        raise EmulationError("bad universal header")
    out, at = [], 8
    for _ in range(count):
        if magic == FAT_MAGIC:
            cputype, cpusub, offset, size, _align = struct.unpack_from(">IIIII", data, at)
            at += 20
        else:
            cputype, cpusub, offset, size, _align, _res = struct.unpack_from(">IIQQII", data, at)
            at += 32
        if offset + size > len(data):
            raise EmulationError("a universal member lies outside the file")
        name = _ARCH_OF.get(cputype)
        if cputype == CPU_ARM64 and cpusub & 0xFFFFFF == 2:
            name = None                                   # arm64e: not an architecture this engine runs
        out.append((name, offset, size))
    return out


def _uleb(raw, pos):
    value = shift = 0
    while True:
        if pos >= len(raw) or shift > 63:
            raise EmulationError("truncated or over-long LEB128 in the dyld info")
        byte = raw[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def _sleb(raw, pos):
    value, pos2 = _uleb(raw, pos)
    width = 7 * (pos2 - pos)
    if raw[pos2 - 1] & 0x40:
        value -= 1 << width
    return value, pos2


class _Sym:
    __slots__ = ("name", "value", "external")

    def __init__(self, name, value, external):
        self.name, self.value, self.external = name, value, external


class MachOImage:
    """One 64-bit Mach-O slice with the shape native_image's engine runs (see the module docstring).
    `libc_ids` is native_image's {function name: trap id}."""

    def __init__(self, data, arch=None, libc_ids=None):
        data = bytes(data)
        if len(data) > MAX_FILE:
            raise EmulationError("image exceeds the size cap")
        rows = slices(data)
        runnable = [row for row in rows if row[0] is not None]
        if len(rows) > 1 or rows[0][1]:
            wanted = [row for row in runnable if arch in (None, row[0])]
            if not wanted:
                raise EmulationError("the universal file holds no %s slice this engine runs" % (arch or "64-bit"))
            if len(wanted) > 1:
                raise EmulationError("a universal file with %d slices this engine runs: name the arch (%s)"
                                     % (len(wanted), ", ".join(sorted(row[0] for row in wanted))))
            data = data[wanted[0][1]:wanted[0][1] + wanted[0][2]]
        self.data = data
        self.problem = None
        self.libc_ids = dict(libc_ids or {})
        if len(data) < 32 or struct.unpack_from("<I", data, 0)[0] != MH_MAGIC_64:
            raise EmulationError("only 64-bit little-endian Mach-O images are emulated")
        _magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, _res = struct.unpack_from("<IIIIIIII", data, 0)
        if cputype not in _ARCH_OF:
            raise EmulationError("Mach-O cputype %#x is not emulated" % cputype)
        self.arch = _ARCH_OF[cputype]
        self.machine = cputype
        if arch is not None and arch != self.arch:
            raise EmulationError("image is %s, not %s" % (self.arch, arch))
        if cputype == CPU_ARM64 and cpusub & 0xFFFFFF == 2:
            self.problem = "arm64e (pointer authentication) is not modelled"
        if filetype not in (MH_EXECUTE, MH_DYLIB, MH_BUNDLE):
            raise EmulationError("Mach-O file type %d is not loadable" % filetype)
        if filetype == MH_EXECUTE and not flags & MH_PIE:
            self.problem = self.problem or "a non-PIE Mach-O executable is not modelled"
        if not 0 < ncmds <= MAX_COMMANDS or 32 + sizeofcmds > len(data):
            raise EmulationError("bad Mach-O load commands")
        self.etype = ET_DYN
        self.dynamic, self.dyn, self.dynsyms, self.has_tls = None, {}, [], False
        self._segments, self._sections, self._dylibs = [], [], []
        symtab = dyld_info = chained = None
        at = 32
        for _ in range(ncmds):
            if at + 8 > 32 + sizeofcmds:
                raise EmulationError("bad Mach-O load commands")
            cmd, size = struct.unpack_from("<II", data, at)
            if size < 8 or size % 8 or at + size > 32 + sizeofcmds:
                raise EmulationError("bad Mach-O load command size")
            if cmd == LC_SEGMENT_64:
                self._segment(at, size)
            elif cmd in (LC_SEGMENT, LC_UNIXTHREAD):
                raise EmulationError("a 32-bit or statically started Mach-O is not emulated")
            elif cmd == LC_SYMTAB:
                symtab = struct.unpack_from("<IIII", data, at + 8)
            elif cmd & 0x7FFFFFFF == LC_DYLD_INFO:
                dyld_info = struct.unpack_from("<IIIIIIIIII", data, at + 8)
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                chained = struct.unpack_from("<II", data, at + 8)
            elif cmd in _DYLIB_COMMANDS:
                name_at = at + struct.unpack_from("<I", data, at + 8)[0]
                end = data.find(b"\0", name_at, at + size)
                self._dylibs.append(data[name_at:end if end >= 0 else at + size].decode("latin1"))
            elif cmd == LC_ENCRYPTION_INFO_64 and struct.unpack_from("<I", data, at + 16)[0]:
                self.problem = self.problem or "the image is encrypted (cryptid is set)"
            at += size
        self._layout()
        self._symbols(symtab)
        self.plan = []
        self._fixups = 0
        if dyld_info is not None:
            self._dyld_info(dyld_info)
        if chained is not None:
            self._chained(*chained)
        self.constructors()

    # --------------------------------------------------------------- segments
    def _segment(self, at, size):
        data = self.data
        name = data[at + 8:at + 24].split(b"\0", 1)[0].decode("latin1")
        vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, nsects, flags = struct.unpack_from(
            "<QQQQiiII", data, at + 24)
        if 72 + 80 * nsects > size:
            raise EmulationError("bad Mach-O segment command")
        self._segments.append((name, vmaddr, vmsize, fileoff, filesize, initprot, flags))
        for k in range(nsects):
            s = at + 72 + 80 * k
            addr, ssize, _off, _align, _reloff, _nreloc, sflags = struct.unpack_from("<QQIIIII", data, s + 32)
            self._sections.append((addr, ssize, sflags & 0xFF))

    def _layout(self):
        mapped = [seg for seg in self._segments if seg[2] and seg[5] & 7]
        text = [seg for seg in mapped if seg[3] == 0 and seg[4]]
        if len(text) != 1:
            raise EmulationError("no single segment maps the Mach header")
        self.bias = text[0][1]                       # every address below is relative to the Mach header
        self.loads, relro = [], []
        for (name, vmaddr, vmsize, fileoff, filesize, prot, flags) in mapped:
            va = vmaddr - self.bias
            if va < 0 or filesize > vmsize or fileoff + filesize > len(self.data) or vmsize > MAX_SPAN:
                raise EmulationError("bad Mach-O segment %s" % name)
            if fileoff % PAGE != va % PAGE:
                raise EmulationError("a segment whose file offset and address are not congruent modulo the page")
            pf = (4 if prot & 1 else 0) | (2 if prot & 2 else 0) | (1 if prot & 4 else 0)
            if pf & 3 == 3:
                raise EmulationError("a segment both writable and executable")
            self.loads.append((va, vmsize, filesize, fileoff, pf))
            if flags & SG_READ_ONLY and pf & 2:
                relro.append((va, vmsize))
        self.loads.sort()
        for (a, m, _f, _o, _fl), (b, _m2, _f2, _o2, _fl2) in zip(self.loads, self.loads[1:]):
            if a + m > b:
                raise EmulationError("overlapping Mach-O segments")
        self.lo = self.loads[0][0] & ~(PAGE - 1)
        self.hi = (self.loads[-1][0] + self.loads[-1][1] + PAGE - 1) & ~(PAGE - 1)
        if self.lo != 0 or self.hi > MAX_SPAN:
            raise EmulationError("image span outside the modelled range")
        self.relro = None
        if relro:
            relro.sort()
            if any(a + m != b for (a, m), (b, _m) in zip(relro, relro[1:])):
                self.problem = self.problem or "read-only data segments that are not adjacent"
            self.relro = (relro[0][0], relro[-1][0] + relro[-1][1] - relro[0][0])

    # --------------------------------------------------------------- address helpers (ElfImage's)
    def seg_of(self, vaddr):
        for seg in self.loads:
            if seg[0] <= vaddr < seg[0] + seg[1]:
                return seg
        return None

    def file_bytes(self, vaddr, n):
        for (va, _m, fs, off, _fl) in self.loads:
            if va <= vaddr and vaddr + n <= va + fs:
                return self.data[off + vaddr - va: off + vaddr - va + n]
        raise EmulationError("table at %#x is not file-backed" % vaddr)

    def _in_exec(self, vaddr):
        seg = self.seg_of(vaddr)
        return seg is not None and bool(seg[4] & 1)

    def _linkedit(self, offset, size, what):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise EmulationError("the %s lies outside the file" % what)
        return self.data[offset:offset + size]

    # --------------------------------------------------------------- symbols
    def _symbols(self, symtab):
        self.symtab = []
        if symtab is None:
            return
        symoff, nsyms, stroff, strsize = symtab
        if nsyms > MAX_SYMS:
            raise EmulationError("too many symbols")
        table = self._linkedit(symoff, 16 * nsyms, "symbol table")
        strings = self._linkedit(stroff, strsize, "string table")
        for k in range(nsyms):
            strx, n_type, _sect, _desc, value = struct.unpack_from("<IBBHQ", table, 16 * k)
            if n_type & 0xE0 or n_type & 0x0E != 0x0E or strx >= len(strings):
                continue                                 # a debug entry, or not defined in a section
            end = strings.find(b"\0", strx)
            name = strings[strx:end if end >= 0 else len(strings)].decode("latin1")
            if name:
                self.symtab.append(_Sym(name, value - self.bias, bool(n_type & 1)))

    @staticmethod
    def _c_name(name):
        """A C symbol's source name: the linker's leading underscore removed."""
        return name[1:] if name.startswith("_") else name

    def exports(self):
        """{C name: address} of the external functions defined in executable segments (the leading
        underscore of each symbol removed, so `_check` is `check`)."""
        out = getattr(self, "_exports", None)
        if out is None:
            out, amb = {}, set()
            for s in self.symtab:
                if s.external and self._in_exec(s.value):
                    if out.setdefault(self._c_name(s.name), s.value) != s.value:
                        amb.add(self._c_name(s.name))
            self._exports, self._amb_exports = out, frozenset(amb)
        return dict(out)

    def ambiguous_exports(self):
        self.exports()
        return self._amb_exports

    def symbol(self, name, allow_local=True):
        ex = self.exports()
        if name in ex:
            return ex[name]
        if allow_local:
            for s in self.symtab:
                if name in (s.name, self._c_name(s.name)) and self._in_exec(s.value):
                    return s.value
        return None

    # --------------------------------------------------------------- load-time code
    def constructors(self):
        """[(kind, address)] of the initializers dyld runs before any call, in section order: each
        __mod_init_func slot (its fixed-up value is read at run time) and each __init_offsets entry."""
        cached = getattr(self, "_ctors", None)
        if cached is not None:
            return list(cached)
        out = []
        for (addr, size, kind) in self._sections:
            va = addr - self.bias
            if kind == S_MOD_INIT_FUNC_POINTERS:
                if size % 8 or size > 8 * 4096:
                    self.problem = self.problem or "an initializer table of an unexpected size"
                    continue
                out += [("array", va + 8 * k) for k in range(size // 8)]
            elif kind == S_INIT_FUNC_OFFSETS:
                if size % 4 or size > 4 * 4096:
                    self.problem = self.problem or "an initializer table of an unexpected size"
                    continue
                try:
                    raw = self.file_bytes(va, size)
                except EmulationError:
                    self.problem = self.problem or "an initializer table that is not file-backed"
                    continue
                out += [("func", off) for (off,) in struct.iter_unpack("<I", raw)]
        self._ctors = tuple(out)
        return list(out)

    def section_constructors(self):
        return False

    def has_load_code(self, jni=False):
        return bool(self.constructors()) or bool(jni and "JNI_OnLoad" in self.exports())

    # --------------------------------------------------------------- fixups -> relocation plan
    def _slot(self, off):
        """True when a pointer fixup at `off` is one the engine applies; else it sets `problem`. Every fixup
        step of every stream passes here and is charged to MAX_FIXUPS: a stream's repeat counts come from the
        file (a ULEB up to 2**64)."""
        self._fixups += 1
        if self._fixups > MAX_FIXUPS:
            raise EmulationError("too many fixups")
        seg = self.seg_of(off)
        if seg is None or not seg[4] & 2 or seg[4] & 1 or off + 8 > seg[0] + seg[1]:
            self.problem = self.problem or "fixup at %#x outside a writable, non-executable segment" % off
            return False
        return True

    def _rebase(self, off, target):
        """A pointer into the image: `target` is relative to the Mach header."""
        if self._slot(off):
            self.plan.append((off, "rel", target & M64))

    def _bind(self, off, ordinal, name, addend):
        if not self._slot(off):
            return
        if ordinal == 0:                                 # BIND_SPECIAL_DYLIB_SELF
            own = self._own_symbols().get(name, ())
            if len(own) == 1:
                self.plan.append((off, "sym", (next(iter(own)) + addend) & M64))
            else:
                self.plan.append((off, "poison", 8))
            return
        if ordinal < 0 or ordinal > len(self._dylibs):   # flat, main-executable or weak lookup: the process's
            self.plan.append((off, "poison", 8))
            return
        c_name = self._c_name(name)
        if self._dylibs[ordinal - 1] in _SYSTEM_LIBS and addend == 0:
            if c_name == "__stack_chk_guard":
                self.plan.append((off, "canary", 0))
                return
            if c_name in self.libc_ids:
                self.plan.append((off, "trap", self.libc_ids[c_name]))
                return
        if name == "dyld_stub_binder" or not name:
            self.plan.append((off, "poison", 8))
        else:
            self.plan.append((off, "import", c_name))    # a call lands on a trap that declines by name

    def _own_symbols(self):
        """{name: {address}} of the image's external symbols, indexed once (a bind stream may name thousands)."""
        index = getattr(self, "_own_index", None)
        if index is None:
            index = {}
            for s in self.symtab:
                if s.external:
                    index.setdefault(s.name, set()).add(s.value)
            self._own_index = index
        return index

    def _seg_base(self, index):
        if not 0 <= index < len(self._segments):
            raise EmulationError("a fixup names a segment the image does not have")
        return self._segments[index][1] - self.bias

    def _dyld_info(self, info):
        rebase_off, rebase_size, bind_off, bind_size, weak_off, weak_size, lazy_off, lazy_size, _eo, _es = info
        self._rebases(self._linkedit(rebase_off, rebase_size, "rebase info"))
        self._binds(self._linkedit(bind_off, bind_size, "bind info"), lazy=False)
        self._binds(self._linkedit(lazy_off, lazy_size, "lazy bind info"), lazy=True)
        # a weak (coalesced) bind: the first definition any image of the process holds wins
        before = len(self.plan)
        self._binds(self._linkedit(weak_off, weak_size, "weak bind info"), lazy=False)
        self.plan[before:] = [(off, "poison", 8) for (off, _kind, _payload) in self.plan[before:]]

    def _rebases(self, raw):
        pos, addr, kind = 0, None, 1
        while pos < len(raw):
            op, imm = raw[pos] & 0xF0, raw[pos] & 0x0F
            pos += 1
            count, skip = 0, 0
            if op == 0x00:
                break
            elif op == 0x10:
                kind = imm
            elif op == 0x20:
                value, pos = _uleb(raw, pos)
                addr = self._seg_base(imm) + value
            elif op == 0x30:
                value, pos = _uleb(raw, pos)
                addr += value
            elif op == 0x40:
                addr += imm * 8
            elif op == 0x50:
                count = imm
            elif op == 0x60:
                count, pos = _uleb(raw, pos)
            elif op == 0x70:
                skip, pos = _uleb(raw, pos)
                count = 1
            elif op == 0x80:
                count, pos = _uleb(raw, pos)
                skip, pos = _uleb(raw, pos)
            else:
                raise EmulationError("unknown rebase opcode %#x" % op)
            if count and kind != 1:
                # the image declines on it: no need to walk (a hostile count is up to 2**64)
                self.problem = self.problem or "a text rebase is not modelled"
                return
            for _ in range(count):
                if addr is None:
                    raise EmulationError("a rebase before any segment was named")
                try:                                     # each step reaches _slot, which charges MAX_FIXUPS
                    target = struct.unpack("<Q", self.file_bytes(addr, 8))[0]
                except EmulationError:
                    target = None
                if target is None:
                    if self._slot(addr):
                        self.plan.append((addr, "poison", 8))
                else:
                    self._rebase(addr, target - self.bias)
                addr += 8 + skip

    def _binds(self, raw, lazy):
        pos, addr, name, ordinal, addend, kind = 0, None, "", 0, 0, 1
        while pos < len(raw):
            op, imm = raw[pos] & 0xF0, raw[pos] & 0x0F
            pos += 1
            count, skip = 0, 0
            if op == 0x00:
                if lazy:
                    continue                             # each lazy entry ends with DONE; the stream goes on
                break
            elif op == 0x10:
                ordinal = imm
            elif op == 0x20:
                ordinal, pos = _uleb(raw, pos)
            elif op == 0x30:
                ordinal = (imm | ~0x0F) if imm else 0    # sign-extended: -1 main executable, -2 flat, -3 weak
            elif op == 0x40:
                end = raw.find(b"\0", pos)
                if end < 0:
                    raise EmulationError("an unterminated symbol name in the bind info")
                name, pos = raw[pos:end].decode("latin1"), end + 1
            elif op == 0x50:
                kind = imm
            elif op == 0x60:
                addend, pos = _sleb(raw, pos)
            elif op == 0x70:
                value, pos = _uleb(raw, pos)
                addr = self._seg_base(imm) + value
            elif op == 0x80:
                value, pos = _uleb(raw, pos)
                addr += value
            elif op == 0x90:
                count = 1
            elif op == 0xA0:
                skip, pos = _uleb(raw, pos)
                count = 1
            elif op == 0xB0:
                skip, count = imm * 8, 1
            elif op == 0xC0:
                count, pos = _uleb(raw, pos)
                skip, pos = _uleb(raw, pos)
            else:
                self.problem = self.problem or "a bind opcode %#x that is not modelled" % op
                return
            if count and kind != 1:
                self.problem = self.problem or "a text bind is not modelled"
                return
            for _ in range(count):
                if addr is None:
                    raise EmulationError("a bind before any segment was named")
                self._bind(addr, ordinal, name, addend)        # _bind charges MAX_FIXUPS through _slot
                addr += 8 + skip

    def _chained(self, dataoff, datasize):
        raw = self._linkedit(dataoff, datasize, "chained fixups")
        if len(raw) < 28:
            raise EmulationError("truncated chained fixups")
        _version, starts_off, imports_off, symbols_off, imports_count, imports_format, symbols_format = \
            struct.unpack_from("<IIIIIII", raw, 0)
        if symbols_format != 0 or imports_format not in (1, 2, 3) or imports_count > MAX_FIXUPS:
            self.problem = self.problem or "a chained-fixup import table format that is not modelled"
            return
        imports = []
        entry = {1: 4, 2: 8, 3: 16}[imports_format]
        for k in range(imports_count):
            at = imports_off + entry * k
            if at + entry > len(raw):
                raise EmulationError("truncated chained-fixup imports")
            if imports_format == 3:
                word, addend = struct.unpack_from("<QQ", raw, at)
                ordinal, name_off = word & 0xFFFF, word >> 32
                ordinal -= (1 << 16) if ordinal > 0xFFF0 else 0
                addend -= (1 << 64) if addend >> 63 else 0
            else:
                word = struct.unpack_from("<I", raw, at)[0]
                ordinal, name_off = word & 0xFF, word >> 9
                ordinal -= (1 << 8) if ordinal > 0xF0 else 0
                addend = struct.unpack_from("<i", raw, at + 4)[0] if imports_format == 2 else 0
            end = raw.find(b"\0", symbols_off + name_off)
            if end < 0:
                raise EmulationError("an unterminated chained-fixup symbol name")
            imports.append((ordinal, raw[symbols_off + name_off:end].decode("latin1"), addend))
        if starts_off + 4 > len(raw):
            raise EmulationError("truncated chained-fixup starts")
        seg_count = struct.unpack_from("<I", raw, starts_off)[0]
        if seg_count > 256 or starts_off + 4 + 4 * seg_count > len(raw):
            raise EmulationError("bad chained-fixup starts")
        for k in range(seg_count):
            info = struct.unpack_from("<I", raw, starts_off + 4 + 4 * k)[0]
            if not info:
                continue
            at = starts_off + info
            if at + 22 > len(raw):
                raise EmulationError("truncated chained-fixup segment starts")
            _size, page_size, pointer_format, segment_offset, _max, page_count = \
                struct.unpack_from("<IHHQIH", raw, at)
            if pointer_format not in (DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET):
                self.problem = self.problem or "chained pointer format %d is not modelled" % pointer_format
                return
            if at + 22 + 2 * page_count > len(raw) or page_size not in (0x1000, 0x4000):
                raise EmulationError("bad chained-fixup page starts")
            for page in range(page_count):
                start = struct.unpack_from("<H", raw, at + 22 + 2 * page)[0]
                if start == 0xFFFF:
                    continue
                if start & 0x8000:
                    self.problem = self.problem or "multi-start chained pages are not modelled"
                    return
                self._chain(segment_offset + page * page_size + start, pointer_format, imports)

    def _chain(self, off, pointer_format, imports):
        while True:
            try:
                value = struct.unpack("<Q", self.file_bytes(off, 8))[0]
            except EmulationError:
                self.problem = self.problem or "a chained fixup at %#x that is not file-backed" % off
                return
            if value >> 63:                              # a bind: ordinal 24, addend 8
                index = value & 0xFFFFFF
                if index >= len(imports):
                    raise EmulationError("a chained bind names an import the table does not have")
                ordinal, name, addend = imports[index]
                self._bind(off, ordinal, name, addend + ((value >> 24) & 0xFF))
            else:                                        # a rebase: target 36, high8 8
                target = value & ((1 << 36) - 1)
                if (value >> 36) & 0xFF:
                    if self._slot(off):
                        self.plan.append((off, "poison", 8))      # a tagged pointer
                else:
                    self._rebase(off, target - self.bias if pointer_format == DYLD_CHAINED_PTR_64 else target)
            step = (value >> 51) & 0xFFF
            if not step:
                return
            off += 4 * step
