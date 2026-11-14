"""The shared recursive codec graph (B-163), used by every lane.

    from ctf.codec import Graph, FlagOracle, CribOracle, SlugOracle, Recognizer, AnyOf
    Graph().search(blob, FlagOracle(profile)).unique

Modules: `codecs` (the codec registry: strict, symbol, loose, keyed), `oracle` (goal oracles that
validate the final object), `graph` (the bounded search), `records` (numbered-record blobs: readings
at the true cut and the N-record consensus), `pack` (breadth packs loaded by path through ctf.packs).
See docs/CONTRACTS.md section 41.
"""
from .codecs import Codec, CodecError, apply_chain, by_name, core
from .graph import Graph, Hit, SearchResult, search
from .oracle import AnyOf, CribOracle, FlagOracle, Oracle, Recognizer, SlugOracle

__all__ = ["Codec", "CodecError", "apply_chain", "by_name", "core", "Graph", "Hit", "SearchResult", "search",
           "AnyOf", "CribOracle", "FlagOracle", "Oracle", "Recognizer", "SlugOracle"]
