"""The Sage side of algebra_service (B-157): `sage -python worker.py job.json`.

Run by algebra_service only: copied next to the job file and started inside the pinned ctf-sage image
(no network) or under a local `sage`. It reads one wire job (integers and exponent lists; the variable
names are x0..xN made here, so nothing from a challenge is ever parsed or evaluated as code) and prints
one line, SENTINEL + JSON: {"status": "ok", "sage_version", "engine", "data"} or
{"status": "error" | "timeout", "error"}. The caller checks every value it returns.

It imports the standard library and Sage only, so it runs without the repo.
"""
import json
import sys

SENTINEL = "CTF-ALGEBRA-RESULT "
OPS = ("lll", "bkz", "groebner", "variety", "eliminate", "resultant", "roots", "small_roots")


def _base(ring):
    from sage.all import GF, QQ, Zmod
    kind = ring["kind"]
    if kind == "QQ":
        return QQ
    if kind == "GF":
        return GF(int(ring["modulus"]))
    if kind == "Zmod":
        return Zmod(int(ring["modulus"]))
    raise ValueError("unknown ring kind %r" % (kind,))


def _coef_in(c, base):
    if isinstance(c, list):
        return base(int(c[0])) / base(int(c[1]))
    return base(int(c))


def _coef_out(c, kind):
    if kind == "QQ":
        num, den = int(c.numerator()), int(c.denominator())
        return num if den == 1 else [num, den]
    return int(c)


def _ring(job):
    from sage.all import PolynomialRing
    n = int(job["nvars"])
    return PolynomialRing(_base(job["ring"]), n, ["x%d" % i for i in range(n)], order=str(job["order"]))


def _poly_in(R, terms):
    base, gens = R.base_ring(), R.gens()
    f = R.zero()
    for c, exps in terms:
        mono = R.one()
        for g, e in zip(gens, exps):
            if int(e):
                mono = mono * g ** int(e)
        f = f + _coef_in(c, base) * mono
    return f


def _poly_out(f, kind):
    terms = [[_coef_out(c, kind), [int(e) for e in exps]] for exps, c in f.dict().items()]
    terms.sort(key=lambda t: t[1], reverse=True)
    return terms


def _ideal(job):
    R = _ring(job)
    return R, R.ideal([_poly_in(R, terms) for terms in job["polys"]])


def _rows(M):
    from sage.all import ZZ
    return [[int(ZZ(x)) for x in row] for row in M.rows()]


def op_reduce(job):
    """LLL or BKZ, with the transforms U (U*B = R) and V (V*R = B) the caller multiplies out."""
    from sage.all import ZZ, matrix
    B = matrix(ZZ, [[int(x) for x in row] for row in job["basis"]])
    if B.rank() != B.nrows():
        raise ValueError("the basis rows are linearly dependent")
    if job["op"] == "lll":
        R = B.LLL()
    else:
        kw = {"block_size": int(job["block_size"])}
        if job.get("tours") is not None:
            kw["max_loops"] = int(job["tours"])
        R = B.BKZ(**kw)
    return {"basis": _rows(R), "u": _rows(B.solve_left(R)), "v": _rows(R.solve_left(B))}


def op_groebner(job):
    R, I = _ideal(job)
    kind = job["ring"]["kind"]
    return {"basis": [_poly_out(g, kind) for g in I.groebner_basis()]}


def op_variety(job):
    R, I = _ideal(job)
    kind = job["ring"]["kind"]
    dim = I.dimension()                          # checked here, not left to variety(): -1 is the unit ideal
    if dim == -1:
        return {"points": []}
    if dim != 0:
        raise ValueError("the ideal is not zero-dimensional (dimension %s)" % (dim,))
    names = [str(g) for g in R.gens()]
    points = []
    for pt in I.variety():
        by_name = dict((str(k), v) for k, v in pt.items())
        points.append([_coef_out(by_name[n], kind) for n in names])
    return {"points": points}


def op_eliminate(job):
    R, I = _ideal(job)
    kind = job["ring"]["kind"]
    J = I.elimination_ideal([R.gen(int(i)) for i in job["eliminate"]])
    return {"basis": [_poly_out(g, kind) for g in J.gens()]}     # a zero generator is dropped by the caller


def op_resultant(job):
    R, I = _ideal(job)
    f, g = I.gens()[0], I.gens()[1]
    res = R(f.resultant(g, R.gen(int(job["var"]))))
    return {"poly": _poly_out(res, job["ring"]["kind"])}


def op_roots(job):
    from sage.all import PolynomialRing
    base = _base(job["ring"])
    kind = job["ring"]["kind"]
    degree = max(int(exps[0]) for _, exps in job["polys"][0])
    dense = [base(0)] * (degree + 1)
    for c, exps in job["polys"][0]:
        dense[int(exps[0])] = _coef_in(c, base)
    f = PolynomialRing(base, "x")(dense)
    return {"roots": [_coef_out(r, kind) for r in f.roots(multiplicities=False)]}


def op_small_roots(job):
    from sage.all import PolynomialRing, Zmod
    f = PolynomialRing(Zmod(int(job["modulus"])), "x")([int(c) for c in job["poly"]]).monic()
    kw = {"X": int(job["bound"]), "beta": float(job["beta"])}
    if job.get("epsilon") is not None:
        kw["epsilon"] = float(job["epsilon"])
    return {"roots": [int(r) for r in f.small_roots(**kw)]}


HANDLERS = {"lll": op_reduce, "bkz": op_reduce, "groebner": op_groebner, "variety": op_variety,
            "eliminate": op_eliminate, "resultant": op_resultant, "roots": op_roots,
            "small_roots": op_small_roots}


def _emit(obj):
    sys.stdout.write("\n" + SENTINEL + json.dumps(obj, sort_keys=True) + "\n")
    sys.stdout.flush()


def _arm(seconds):
    """Ask cysignals for an AlarmInterrupt at the time limit, so a timeout is reported as one. The hard
    stop is the caller's (`timeout` around this process); where cysignals has no alarm, only that one
    applies, and the result says so."""
    try:
        from cysignals.alarm import alarm
    except ImportError:
        return False
    alarm(int(seconds))
    return True


def _disarm():
    from cysignals.alarm import cancel_alarm
    cancel_alarm()


def main(argv):
    if len(argv) != 2:
        _emit({"status": "error", "error": "usage: worker.py job.json"})
        return 2
    put = getattr(sys, "set_int_max_str_digits", None)
    if put is not None:
        put(0)
    try:
        with open(argv[1], "r", encoding="utf-8") as fh:
            job = json.load(fh)
        from sage.version import version
        handler = HANDLERS.get(job.get("op"))
        if handler is None:
            raise ValueError("unknown op %r" % (job.get("op"),))
        armed = _arm(job["timeout"]) if job.get("timeout") else False
        try:
            data = handler(job)
        finally:
            if armed:
                _disarm()
    except KeyboardInterrupt:                    # cysignals' AlarmInterrupt is one
        _emit({"status": "timeout", "error": "Sage was interrupted at the job's time limit"})
        return 0
    except Exception as ex:
        _emit({"status": "error", "error": ("%s: %s" % (type(ex).__name__, ex))[:2000]})
        return 0
    _emit({"status": "ok", "sage_version": str(version), "engine": "SageMath %s" % (version,),
           "soft_timeout": bool(armed), "data": data})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
