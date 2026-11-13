"""Day 12 dotnet.mvid_guid for the Metadata speed solver: the Module table's Mvid (ECMA-335 II.22.30), read
through the PE's CLR header -> metadata root -> #~ and #GUID streams, as lowercase 8-4-4-4-12 text.
Fails closed (None) on anything ambiguous (no CLR header, two #GUID or #~ streams, a Module table that is
not one row; a truncated or malformed image).

B-222: this file no longer carries a reader of its own. It asks the Metadata lane's armed CLR reader,
solvers/metadata-forensics/readers_dotnet.py (read_mvid), so the speed solver and the lane read one
structure one way: the #~ HeapSizes "extra data" bit is 0x40 (0x20 is DeltaOnly and adds no dword), a
#GUID index past the heap is no answer, and a .NET single-file bundle is read through its application
assembly. The lane (properties_strict and its packs) is loaded once by path, the module its tests share.
"""
from __future__ import annotations


def _reader():
    """readers_dotnet as the loaded lane registered it (PackMissing / PackLoadError when the lane cannot load)."""
    from ctf.formats.matrix import lane_module
    return lane_module().MORE_MODULES["readers_dotnet.py"]


def dotnet_mvid(name, d):
    return _reader().read_mvid(bytes(d))


PROPS = {"dotnet-mvid-guid": dotnet_mvid}
