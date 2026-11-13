#!/usr/bin/env python3
"""The ways an AutoIt script can hold the tagged descriptor: rewrites of one `.au3` specimen.

Used by tests/test_script_au3_forms.py (the AutoIt forms fuzz, written after Day 12, 2026-10-12). A Day 12
specimen holds a version-3 plan twice, as the same payload:

    ; HUNTRESS_ANALYSIS_V1:<TAG>-<payload>
    Global Const $descriptor_<id> = "<payload>"
    Func build_plan_<id>()
      Return $descriptor_<id>
    EndFunc

forms(text) -> [(name, bytes, whole)]: the same payload written back in the other ways AutoIt can write a
string and a comment. `whole` says the rewrite still holds the plan whole in a form a reader is expected to
read (then every answer should be the key's); False marks a form where a careful reader may decline (a
decoy, pieces joined through variables, a call around the value). Nothing here is run.
"""
import re

TAG_RE = re.compile(r"HUNTRESS_ANALYSIS_V1:([A-Za-z0-9_]+)-([A-Za-z0-9+/=._:-]+)")
LIT_RE = re.compile(r'^(\s*)(Global Const|Global|Local Const|Local|Dim|Static|Const)\s+(\$descriptor_\w+)\s*=\s*"([^"\n]*)"\s*$',
                    re.M)


def split(s: str, n: int) -> list:
    k = max(1, -(-len(s) // n))
    return [s[i:i + k] for i in range(0, len(s), k)]


def forms(text: str) -> list:
    tm = TAG_RE.search(text)
    lm = LIT_RE.search(text)
    if not tm or not lm or lm.group(4) != tm.group(2):
        return []
    tag, payload, var = tm.group(1), tm.group(2), lm.group(3)
    cmt = f"HUNTRESS_ANALYSIS_V1:{tag}-{payload}"
    cline = next(l for l in text.split("\n") if cmt in l)
    lit = lm.group(0)
    no_comment = text.replace(cline + "\n", "", 1)
    no_literal = text.replace(lit, f"Global Const {var} = \"\"", 1)
    out = []

    def add(name, t, whole=True, raw=None):
        out.append((name, raw if raw is not None else t.encode("utf-8"), whole))

    def with_lit(new, base=text):
        return base.replace(lit, new, 1)

    add("as_shipped", text)
    add("crlf", text.replace("\n", "\r\n"))
    add("utf8_bom", text, raw=b"\xef\xbb\xbf" + text.encode("utf-8"))
    add("utf16le_bom", text, raw=b"\xff\xfe" + text.encode("utf-16-le"))
    add("comment_only", text.replace(lit + "\n", "", 1))
    add("literal_only", no_comment)
    # ---- declarations
    for word in ("Local", "Dim", "Static", "Global", "Local Const", "Const", "Global Static", "Local Static"):
        add("decl_" + word.lower().replace(" ", "_"), with_lit(f'{word} {var} = "{payload}"'))
    add("decl_bare_assign", with_lit(f'{var} = "{payload}"'))
    add("decl_single_quotes", with_lit(f"Global Const {var} = '{payload}'"))
    add("decl_no_spaces", with_lit(f'Global Const {var}="{payload}"'))
    add("decl_tabs", with_lit(f'Global\tConst\t{var}\t=\t"{payload}"'))
    add("decl_two_in_one", with_lit(f'Global Const $build_tag = "au3", {var} = "{payload}"'))
    add("decl_indented", with_lit(f'    Global Const {var} = "{payload}"'))
    # ---- ; comments after the payload
    add("trail_comment", with_lit(f'Global Const {var} = "{payload}" ; analysis descriptor'))
    add("trail_comment_tight", with_lit(f'Global Const {var} = "{payload}";descriptor'))
    add("trail_comment_literal_only", with_lit(f'Global Const {var} = "{payload}" ; analysis descriptor', no_comment))
    add("comment_line_trail", text.replace(cline, cline + " ; inert", 1), whole=False)
    add("comment_no_space", text.replace(cline, ";" + cmt, 1))
    add("comment_indented", text.replace(cline, "    ; " + cmt, 1))
    add("comment_double_semicolon", text.replace(cline, ";; " + cmt, 1))
    add("comment_after_code", text.replace(cline + "\n", "", 1).replace(lit, lit + " ; " + cmt, 1))
    # ---- #cs .. #ce block comments
    add("block_cs", text.replace(cline, "#cs\n" + cmt + "\n#ce", 1))
    add("block_cs_semicolon", text.replace(cline, "#cs\n; " + cmt + "\n#ce", 1))
    add("block_comments_start", text.replace(cline, "#comments-start\n" + cmt + "\n#comments-end", 1))
    add("block_cs_notes", text.replace(cline, "#cs analysis notes\n  " + cmt + "\n  inert fixture\n#ce", 1))
    add("block_cs_comment_only", text.replace(cline, "#cs\n" + cmt + "\n#ce", 1).replace(lit + "\n", "", 1))
    add("block_cs_literal_inside", text.replace(lit, "#cs\n" + lit + "\n#ce", 1), whole=False)
    add("region", text.replace(cline, "#Region analysis\n" + cline + "\n#EndRegion", 1))
    # ---- & joins
    for n in (2, 4):
        joined = " & ".join(f'"{p}"' for p in split(payload, n))
        add(f"amp{n}", with_lit(f"Global Const {var} = {joined}"))
        add(f"amp{n}_literal_only", with_lit(f"Global Const {var} = {joined}", no_comment))
        add(f"amp{n}_tight", with_lit("Global Const " + var + " = " + "&".join(f'"{p}"' for p in split(payload, n))))
    # ---- a ` _` line continuation
    for n in (2, 4):
        cont = " & _\n    ".join(f'"{p}"' for p in split(payload, n))
        add(f"cont{n}", with_lit(f"Global Const {var} = {cont}"))
        add(f"cont{n}_literal_only", with_lit(f"Global Const {var} = {cont}", no_comment))
        add(f"cont{n}_crlf", with_lit(f"Global Const {var} = {cont}").replace("\n", "\r\n"))
        lead = " _\n    & ".join(f'"{p}"' for p in split(payload, n))
        add(f"cont{n}_lead_amp", with_lit(f"Global Const {var} = {lead}"))
        noted = " & _ ; piece\n    ".join(f'"{p}"' for p in split(payload, n))
        add(f"cont{n}_commented", with_lit(f"Global Const {var} = {noted}"))
    add("cont_before_value", with_lit(f'Global Const {var} = _\n    "{payload}"'))
    # ---- &= accumulation
    a, b = split(payload, 2)[0], "".join(split(payload, 2)[1:])
    add("append", with_lit(f'Global {var} = "{a}"\n{var} &= "{b}"'))
    add("append_literal_only", with_lit(f'Global {var} = "{a}"\n{var} &= "{b}"', no_comment))
    add("append_self", with_lit(f'Global {var} = "{a}"\n{var} = {var} & "{b}"'))
    add("append_three", with_lit('Global ' + var + ' = ""\n' + "\n".join(f'{var} &= "{p}"' for p in split(payload, 3))))
    # ---- a $descriptor built inside a Func
    func = re.search(r"Func (\w+)\(\)\n\s*Return \$descriptor_\w+\nEndFunc", text)
    if func:
        fname = func.group(1)
        inside = f'Func {fname}()\n  Local {var} = "{payload}"\n  Return {var}\nEndFunc'
        add("func_local", text.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        add("func_local_literal_only", no_comment.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        inside = f'Func {fname}()\n  Local Const {var} = "{payload}"\n  Return {var}\nEndFunc'
        add("func_local_const", text.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        inside = f'Func {fname}()\n  Static {var} = "{payload}"\n  Return {var}\nEndFunc'
        add("func_static", text.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        inside = f'Func {fname}()\n  Return "{payload}"\nEndFunc'
        add("func_return_literal", text.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        inside = f'Func {fname}()\n  Local {var} = "{a}"\n  {var} &= "{b}"\n  Return {var}\nEndFunc'
        add("func_append", text.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        add("func_append_literal_only", no_comment.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        inside = f'Func {fname}()\n  Local {var} = "{a}" & _\n      "{b}"\n  Return {var}\nEndFunc'
        add("func_cont", text.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        add("func_cont_literal_only", no_comment.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1))
        inside = (f'Func {fname}()\n  Local $part_a = "{a}"\n  Local $part_b = "{b}"\n'
                  f'  Local {var} = $part_a & $part_b\n  Return {var}\nEndFunc')
        add("func_parts", text.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1), whole=False)
        add("func_parts_literal_only", no_comment.replace(lit + "\n", "", 1).replace(func.group(0), inside, 1), whole=False)
        add("func_first", text.replace(func.group(0) + "\n", "", 1).replace(lit, func.group(0) + "\n" + lit, 1))
    # ---- pieces through variables, arrays, calls: a careful reader may decline
    add("parts_global", with_lit(f'Global Const $part_a = "{a}"\nGlobal Const $part_b = "{b}"\nGlobal Const {var} = $part_a & $part_b'),
        whole=False)
    add("parts_global_literal_only", with_lit(f'Global Const $part_a = "{a}"\nGlobal Const $part_b = "{b}"\n'
                                              f'Global Const {var} = $part_a & $part_b', no_comment), whole=False)
    arr = ", ".join(f'"{p}"' for p in split(payload, 3))
    add("array", with_lit(f"Global {var}[3] = [{arr}]"), whole=False)
    add("array_literal_only", with_lit(f"Global {var}[3] = [{arr}]", no_comment), whole=False)
    add("call_wrapped", with_lit(f'Global Const {var} = String("{payload}")'), whole=False)
    add("call_wrapped_literal_only", with_lit(f'Global Const {var} = String("{payload}")', no_comment), whole=False)
    add("stringreverse_literal_only", with_lit(f'Global Const {var} = StringReverse("{payload[::-1]}")', no_comment), whole=False)
    add("tag_in_literal", with_lit(f'Global Const {var} = "{tag}-{payload}"'), whole=False)
    add("renamed_var", with_lit(f'Global Const $cfg_{var[len("$descriptor_"):]} = "{payload}"'))
    add("renamed_var_literal_only", with_lit(f'Global Const $cfg_{var[len("$descriptor_"):]} = "{payload}"', no_comment), whole=False)
    # ---- decoys: a second, different copy that must never win
    cut = payload[:len(payload) * 2 // 3]
    add("decoy_cut_in_block", text.replace(cline, cline + f'\n#cs\nGlobal Const {var} = "{cut}"\n#ce', 1), whole=False)
    add("decoy_cut_comment_line", text.replace(cline, cline + f'\n; Global Const {var} = "{cut}"', 1), whole=False)
    add("cut_literal", with_lit(f'Global Const {var} = "{cut}"'), whole=False)
    add("cut_literal_only", with_lit(f'Global Const {var} = "{cut}"', no_comment), whole=False)
    add("cut_comment_only", text.replace(lit + "\n", "", 1).replace(cmt, f"HUNTRESS_ANALYSIS_V1:{tag}-{cut}", 1), whole=False)
    add("cut_amp_tail_variable", with_lit(f'Global Const {var} = "{a}" & $tail', no_comment), whole=False)
    add("cut_cont_dangling", with_lit(f'Global Const {var} = "{a}" & _\n    $tail', no_comment), whole=False)
    add("cut_append_variable", with_lit(f'Global {var} = "{a}"\n{var} &= $tail', no_comment), whole=False)
    add("cut_lead_amp_variable", with_lit(f'Global Const {var} = "{a}" _\n    & $tail', no_comment), whole=False)
    add("cut_lead_amp_commented", with_lit(f'Global Const {var} = "{a}" _ ; first piece\n    & $tail', no_comment), whole=False)
    a1, a2 = split(a, 2)[0], "".join(split(a, 2)[1:])
    add("cut_lead_amp_join_variable", with_lit(f'Global Const {var} = "{a1}" _\n    & "{a2}" _\n    & $tail', no_comment),
        whole=False)
    add("cut_cont_join_variable", with_lit(f'Global Const {var} = "{a1}" & _\n    "{a2}" & _\n    $tail', no_comment),
        whole=False)
    add("cut_commented_join_variable", with_lit(f'Global Const {var} = "{a1}" & _ ; one\n    "{a2}" & _ ; two\n    $tail',
                                                no_comment), whole=False)
    add("cut_func_append_variable", with_lit(f'Global {var} = "{a}"', no_comment).replace(
        f"  Return {var}", f"  {var} &= $tail\n  Return {var}", 1), whole=False)
    add("cut_comment_beside_whole_literal", text.replace(cmt, f"HUNTRESS_ANALYSIS_V1:{tag}-{cut}", 1), whole=False)
    # ---- the dangerous cut: every field is there and only the LAST value lacks its end (the piece in the
    # file decodes to a plan of fifteen fields), the rest comes from a variable the file does not show
    long = payload[:-8]
    l1, l2 = split(long, 2)[0], "".join(split(long, 2)[1:])
    for name, new in (
            ("tail_amp_variable", f'Global Const {var} = "{long}" & $tail'),
            ("tail_cont_variable", f'Global Const {var} = "{long}" & _\n    $tail'),
            ("tail_cont_commented_variable", f'Global Const {var} = "{long}" & _ ; rest\n    $tail'),
            ("tail_lead_amp_variable", f'Global Const {var} = "{long}" _\n    & $tail'),
            ("tail_lead_amp_commented_variable", f'Global Const {var} = "{long}" _ ; rest\n    & $tail'),
            ("tail_join_lead_amp_variable", f'Global Const {var} = "{l1}" _\n    & "{l2}" _\n    & $tail'),
            ("tail_join_cont_variable", f'Global Const {var} = "{l1}" & _\n    "{l2}" & _\n    $tail'),
            ("tail_join_commented_variable", f'Global Const {var} = "{l1}" & _ ; one\n    "{l2}" & _ ; two\n    $tail'),
            ("tail_append_variable", f'Global {var} = "{long}"\n{var} &= $tail'),
            ("tail_append_self_variable", f'Global {var} = "{long}"\n{var} = {var} & $tail'),
            ("tail_call_variable", f'Global Const {var} = StringFormat("%s%s", "{long}", $tail)')):
        add(name, with_lit(new, no_comment), whole=False)
    add("tail_func_append_variable", with_lit(f'Global {var} = "{long}"', no_comment).replace(
        f"  Return {var}", f"  {var} &= $tail\n  Return {var}", 1), whole=False)
    add("tail_func_return_joined", with_lit(f'Global {var} = "{long}"', no_comment).replace(
        f"  Return {var}", f"  Return {var} & $tail", 1), whole=False)
    add("tail_cut_literal_beside_comment", with_lit(f'Global Const {var} = "{long}"'), whole=False)
    add("empty_literal", no_literal, whole=False)
    return out
