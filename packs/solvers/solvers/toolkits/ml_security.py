#!/usr/bin/env python3
"""Static ML/AI-security risk triage layered over the safe model-file readers.

The existing ``common/ai_model_files.py`` parser walks pickle opcodes, Keras configs, GGUF and
ONNX structures without loading a model.  This module adds security-facing interpretation:

* a malicious-pickle/``__reduce__`` gadget catalogue and ranked call report;
* Keras Lambda, ONNX custom-op/external-data, and GGUF chat-template/metadata risks;
* shape/dtype/parameter-count summaries derived only from declared tensor metadata;
* prompt-injection detection for model cards, RAG documents, and agent transcript text.

It never calls pickle.load, yaml.load, a framework loader, eval/exec, or a network API.  Findings
are ranked leads for a human; text in an artifact is always data and is never followed as an order.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import ntpath
import re
import sys
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
MAX_INPUT = 128 << 20
MAX_TEXT = 4 << 20
MAX_JSON_DEPTH = 32
MAX_TEXT_NODES = 10000
MAX_FINDINGS = 512
MAX_TENSORS = 200000
MAX_DIMS = 16
MAX_DIM = 1 << 50
MAX_ELEMENTS = 1 << 80


def _load_reader():
    name = "csctf_ai_model_static_reader"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, COMMON / "ai_model_files.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("AI model reader is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


reader = _load_reader()


GADGET_CATALOG = {
    "os.system": (100, "execute a shell command"),
    "posix.system": (100, "execute a shell command"),
    "nt.system": (100, "execute a shell command"),
    "subprocess.Popen": (100, "spawn a process"),
    "subprocess.call": (100, "spawn a process"),
    "subprocess.run": (100, "spawn a process"),
    "builtins.exec": (100, "execute Python source"),
    "builtins.eval": (100, "evaluate a Python expression"),
    "__builtin__.exec": (100, "execute Python source"),
    "__builtin__.eval": (100, "evaluate a Python expression"),
    "os.popen": (98, "spawn a shell and open a pipe"),
    "commands.getoutput": (98, "execute a shell command and capture output"),
    "runpy._run_code": (96, "execute a Python code object"),
    "runpy._run_module_code": (96, "execute a Python module"),
    "marshal.loads": (92, "materialize a Python code object for a later gadget"),
    "types.FunctionType": (92, "construct a callable from supplied code"),
    "builtins.compile": (90, "compile supplied Python source"),
    "pip._internal.main": (88, "invoke the package installer"),
    "urllib.request.urlopen": (86, "open a URL while loading"),
    "socket.create_connection": (86, "open a network connection while loading"),
    "pathlib.Path.write_text": (82, "write a file while loading"),
    "pathlib.Path.write_bytes": (82, "write a file while loading"),
    "shutil.rmtree": (100, "delete a directory tree"),
}


PROMPT_INJECTION_CORPUS = (
    ("instruction-override", r"\b(?:ignore|disregard|forget|override)\b.{0,80}\b(?:previous|prior|system|developer|instructions?|rules?)\b"),
    ("role-spoof", r"(?im)^\s*(?:system|developer|assistant|tool)\s*(?:message|prompt)?\s*[:>]"),
    ("secret-exfiltration", r"\b(?:reveal|print|send|exfiltrat\w*|leak|return)\b.{0,100}\b(?:secret|token|password|api key|system prompt|credential)\b"),
    ("tool-coercion", r"\b(?:call|invoke|use|run|execute)\b.{0,80}\b(?:tool|function|shell|terminal|browser|http|curl|wget)\b"),
    ("authority-claim", r"\b(?:this is|act as|you are now|highest priority|authorized by)\b.{0,80}\b(?:system|developer|administrator|root|policy)\b"),
    ("rag-indirect", r"\b(?:when (?:the )?(?:agent|assistant|model) reads|instructions? for (?:the )?(?:agent|assistant|model)|do not summarize)\b"),
    ("filter-evasion", r"\b(?:base64|rot13|unicode|homoglyph|zero.width|invisible text|html comment)\b.{0,80}\b(?:decode|instruction|prompt|bypass|filter)\b"),
    ("persistence", r"\b(?:remember|persist|store|write)\b.{0,80}\b(?:instruction|prompt|memory|profile|future sessions?)\b"),
)
_PROMPT_PATTERNS = [(name, re.compile(pattern, re.I | re.S)) for name, pattern in PROMPT_INJECTION_CORPUS]


def _finding(kind: str, score: int, reason: str, **fields) -> dict:
    result = {"kind": kind, "score": int(score), "reason": reason}
    result.update(fields)
    return result


def pickle_gadgets(report: dict) -> list[dict]:
    """Rank calls represented by the symbolic pickle VM; nothing is imported or invoked."""
    findings = []
    calls = report.get("calls") if isinstance(report, dict) else None
    if not isinstance(calls, list):
        return findings
    for call in calls[:MAX_FINDINGS * 4]:
        if not isinstance(call, dict):
            continue
        target = call.get("callable")
        if not isinstance(target, str):
            findings.append(_finding("computed-pickle-call", 90,
                                     "pickle invokes a callable whose target is not statically resolved",
                                     opcode=call.get("kind"), position=call.get("pos")))
            continue
        score, behavior = GADGET_CATALOG.get(target, (0, ""))
        if not score:
            module = target.rsplit(".", 1)[0] if "." in target else target
            if module in {"os", "posix", "nt", "subprocess", "socket", "urllib", "http.client",
                          "ctypes", "multiprocessing", "asyncio.subprocess"}:
                score, behavior = 80, "invoke a side-effect-capable module while loading"
            elif call.get("kind") in ("reduce", "inst", "obj", "newobj", "newobj_ex"):
                score, behavior = 35, "construct or invoke an object during deserialization"
        if score:
            findings.append(_finding("pickle-gadget", score, behavior, callable=target,
                                     opcode=call.get("kind"), position=call.get("pos"),
                                     arguments=call.get("args")))
    return sorted(findings[:MAX_FINDINGS], key=lambda item: (-item["score"], str(item.get("callable", ""))))


def detect_prompt_injection(text: str, *, source: str = "text") -> list[dict]:
    """Return ranked lexical injection leads with bounded excerpts and exact spans."""
    if not isinstance(text, str):
        raise ValueError("prompt input must be text")
    if len(text) > MAX_TEXT:
        raise ValueError("prompt input exceeds 4 MiB cap")
    findings = []
    for category, pattern in _PROMPT_PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            excerpt = text[max(0, start - 60):min(len(text), end + 100)].replace("\x00", "\\0")
            score = 95 if category in ("secret-exfiltration", "instruction-override") else 82
            findings.append(_finding("prompt-injection", score, category.replace("-", " "),
                                     category=category, source=source, span=[start, end], excerpt=excerpt))
            if len(findings) >= MAX_FINDINGS:
                return sorted(findings, key=lambda item: (-item["score"], item["span"][0]))
    # Delimiter-shaped role tokens are useful even when surrounded by binary/model-card noise.
    for pattern, label in ((r"<\|(?:system|assistant|tool|im_start)\|>", "model role delimiter"),
                           (r"\[/?INST\]|<<SYS>>", "instruction delimiter")):
        for match in re.finditer(pattern, text, re.I):
            findings.append(_finding("prompt-injection", 75, label, category="role-delimiter",
                                     source=source, span=list(match.span()), excerpt=match.group(0)))
            if len(findings) >= MAX_FINDINGS:
                break
    return sorted(findings[:MAX_FINDINGS], key=lambda item: (-item["score"], item["span"][0]))


def _text_nodes(value, *, source: str = "$", depth: int = 0, state=None):
    if state is None:
        state = {"count": 0}
    if depth > MAX_JSON_DEPTH or state["count"] >= MAX_TEXT_NODES:
        return
    if isinstance(value, str):
        state["count"] += 1
        yield source, value
    elif isinstance(value, list):
        for index, item in enumerate(value[:MAX_TEXT_NODES]):
            yield from _text_nodes(item, source=f"{source}[{index}]", depth=depth + 1, state=state)
            if state["count"] >= MAX_TEXT_NODES:
                break
    elif isinstance(value, dict):
        for key, item in list(value.items())[:MAX_TEXT_NODES]:
            if not isinstance(key, (str, int, float, bool, type(None))):
                continue
            yield from _text_nodes(item, source=f"{source}.{str(key)[:128]}", depth=depth + 1, state=state)
            if state["count"] >= MAX_TEXT_NODES:
                break


def scan_transcript(value) -> list[dict]:
    findings = []
    for source, text in _text_nodes(value):
        remaining = MAX_FINDINGS - len(findings)
        if remaining <= 0:
            break
        findings.extend(detect_prompt_injection(text, source=source)[:remaining])
    return sorted(findings, key=lambda item: (-item["score"], item["source"], item["span"][0]))


def tensor_summary(report: dict) -> dict:
    tensors = report.get("tensors") if isinstance(report, dict) else None
    if not isinstance(tensors, list):
        tensors = []
    if len(tensors) > MAX_TENSORS:
        return {"tensor_count": len(tensors), "capped": True, "valid_shapes": False}
    dtypes, total, valid, largest = Counter(), 0, True, []
    for tensor in tensors:
        if not isinstance(tensor, dict):
            valid = False
            continue
        dtype = str(tensor.get("dtype"))
        dtypes[dtype] += 1
        shape = tensor.get("shape")
        if not isinstance(shape, (list, tuple)) or len(shape) > MAX_DIMS:
            valid = False
            continue
        elements = 1
        for dimension in shape:
            if not isinstance(dimension, int) or isinstance(dimension, bool) or dimension < 0 or dimension > MAX_DIM:
                valid = False
                elements = None
                break
            elements *= dimension
            if elements > MAX_ELEMENTS:
                valid = False
                elements = None
                break
        if elements is not None:
            total += elements
            if total > MAX_ELEMENTS:
                valid = False
                total = None
                break
            largest.append((elements, tensor.get("name")))
    largest.sort(reverse=True, key=lambda item: item[0])
    return {"tensor_count": len(tensors), "dtype_counts": dict(dtypes),
            "declared_elements": total if valid else None, "valid_shapes": valid,
            "largest": [{"name": name, "elements": count} for count, name in largest[:10]],
            "capped": False}


def model_risks(report: dict) -> list[dict]:
    if not isinstance(report, dict):
        return []
    findings = pickle_gadgets(report)
    kind = report.get("kind")
    if kind in ("keras_zip", "hdf5"):
        layers = report.get("lambda_layers")
        for layer in (layers if isinstance(layers, list) else [])[:MAX_FINDINGS]:
            if isinstance(layer, dict):
                code_strings = layer.get("code_strings", [])
                findings.append(_finding("keras-lambda", 95,
                                         "Lambda layer may deserialize or execute supplied Python code",
                                         layer=layer.get("name"), function_type=layer.get("function_type"),
                                         code_strings=(code_strings if isinstance(code_strings, list) else [])[:20]))
    if kind == "onnx":
        standard = {"", "ai.onnx", "ai.onnx.ml", "ai.onnx.preview.training"}
        nodes = report.get("nodes")
        for node in (nodes if isinstance(nodes, list) else [])[:MAX_FINDINGS * 2]:
            if not isinstance(node, dict):
                continue
            domain, op = node.get("domain") or "", node.get("op_type")
            if domain not in standard or op in {"PythonOp", "PyFunc", "ATen", "Plugin", "Custom"}:
                findings.append(_finding("onnx-custom-op", 90,
                                         "runtime-specific custom operator requires code outside the ONNX graph",
                                         node=node.get("name"), op_type=op, domain=domain))
        external_list = report.get("external")
        for external in (external_list if isinstance(external_list, list) else [])[:MAX_FINDINGS]:
            if not isinstance(external, dict):
                continue
            location = external.get("location")
            if isinstance(location, str) and (location.startswith(("/", "\\")) or ntpath.isabs(location)
                                              or ".." in Path(location).parts):
                findings.append(_finding("onnx-external-path", 92,
                                         "external tensor path escapes or is absolute", tensor=external.get("tensor"),
                                         location=location))
    if kind == "gguf":
        template = report.get("chat_template")
        if isinstance(template, str):
            findings.extend(detect_prompt_injection(template, source="gguf.chat_template")[:64])
        duplicates = report.get("duplicate_keys") or []
        if duplicates:
            findings.append(_finding("gguf-duplicate-metadata", 70,
                                     "duplicate metadata keys can be interpreted differently by loaders",
                                     keys=list(duplicates)[:64]))
    return sorted(findings[:MAX_FINDINGS], key=lambda item: (-item["score"], item["kind"]))


def analyze_model(data: bytes, name: str = "model") -> dict | None:
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ValueError("model bytes exceed 128 MiB cap")
    report = reader.analyze(data, name)
    if report is None:
        return None
    public = reader.public(report)
    return {"report": public, "risks": model_risks(public), "tensor_summary": tensor_summary(public)}


def _read(path: str, limit: int = MAX_INPUT) -> bytes:
    with Path(path).open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input exceeds size cap")
    return raw


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="ml_security.py")
    parser.add_argument("operation", choices=("model", "transcript", "model-card"))
    parser.add_argument("input")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        raw = _read(args.input, MAX_INPUT if args.operation == "model" else MAX_TEXT)
        if args.operation == "model":
            result = analyze_model(raw, Path(args.input).name)
            if result is None:
                raise ValueError("unrecognized model format")
        elif args.operation == "transcript":
            value = json.loads(raw.decode("utf-8"))
            result = {"findings": scan_transcript(value)}
        else:
            result = {"findings": detect_prompt_injection(raw.decode("utf-8", "replace"),
                                                            source=Path(args.input).name)}
        if args.json:
            print(json.dumps(result, sort_keys=True, default=str))
        else:
            findings = result.get("risks", result.get("findings", []))
            for rank, finding in enumerate(findings, 1):
                print(f"{rank}. [{finding['score']}] {finding['kind']}: {finding['reason']}")
            if "tensor_summary" in result:
                print("tensor-summary " + json.dumps(result["tensor_summary"], sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError) as exc:
        print(f"ml_security: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
