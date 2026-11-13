#!/usr/bin/env python3
"""Adversarial offline tests for web_evidence's bounded static source review.

The fixtures are source *text*.  The reader must never import, compile, or execute any of it.
Run with:
  .venv/bin/python tests/test_web_static_taint.py
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("web_evidence_static_taint", ROOT / "solvers" / "toolkits" / "web_evidence.py")
WE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(WE)


def scan(name: str, source: str):
    return WE.read_source({name: source.encode()})


def paths(result):
    return {(r["method"], r["path"], r["handler"]) for r in result["routes"]}


class StaticTaintTests(unittest.TestCase):
    def test_express_mount_multiline_destructure_and_provenance(self):
        result = scan("server.js", r'''
            const express = require("express");
            const api = express.Router();
            // app.get('/comment-decoy', (req, res) => eval(req.query.nope));
            const example = "app.get('/string-decoy', (req,res) => db.query(req.query.nope))";
            app.use('/api', api);
            api.get(
              '/search/:id',
              (req, res) => {
                const {term: query} = req.query;
                const sql = String(query).trim();
                db.query(sql);
              }
            );
        ''')
        self.assertEqual(paths(result), {("GET", "/api/search/:id", "get /api/search/:id")})
        self.assertEqual(len(result["taint"]), 1)
        flow = result["taint"][0]
        self.assertEqual((flow["family"], flow["reads"]), ("sqli", ["term"]))
        self.assertEqual(flow["aliases"], ["query", "sql"])
        self.assertEqual([p["kind"] for p in flow["provenance"] if "kind" in p], ["query", "sink"])
        self.assertIn("String", flow["transforms"])
        self.assertIn("trim", flow["transforms"])
        self.assertFalse(any("decoy" in r["path"] for r in result["routes"]))
        self.assertFalse(any(s["line"] in (4, 5) for s in result["sinks"]))

    def test_minified_and_interpolated_source_is_code_but_plain_string_is_not(self):
        good = scan("good.js", "app.get('/x',(req,res)=>{const q=`SELECT ${req.query.q}`;db.query(q);});")
        bad = scan("bad.js", "app.get('/x',(req,res)=>{const q='req.query.q';db.query(q);});")
        self.assertEqual([(x["family"], x["reads"]) for x in good["taint"]], [("sqli", ["q"])])
        self.assertEqual(bad["taint"], [])

    def test_cross_handler_reassignment_branch_two_sources_unknown_wrapper_and_dead_code_decline(self):
        cases = {
            "cross.js": r'''
                app.get('/a', (req,res) => { const q=req.query.q; res.send('ok'); });
                app.get('/b', (req,res) => { db.query(q); });
            ''',
            "reassign.js": r'''
                app.get('/x', (req,res) => { let q=req.query.q; q='fixed'; db.query(q); });
            ''',
            "branch.js": r'''
                app.get('/x', (req,res) => {
                  let q;
                  if (req.query.useIt) { q=req.query.q; }
                  db.query(q);
                });
            ''',
            "two.js": r'''
                app.get('/x', (req,res) => {
                  const a=req.query.a; const b=req.query.b; const q=a+b; db.query(q);
                });
            ''',
            "wrapper.js": r'''
                app.get('/x', (req,res) => { const q=req.query.q; const x=maybeSafe(q); db.query(x); });
            ''',
            "dead.js": r'''
                app.get('/x', (req,res) => { const q=req.query.q; return res.send('done'); db.query(q); });
            ''',
        }
        for name, source in cases.items():
            with self.subTest(name=name):
                self.assertEqual(scan(name, source)["taint"], [])

    def test_short_acyclic_chain_cap(self):
        accepted = scan("four.py", '''
def f():
    a = request.args.get("q")
    b = a.strip()
    c = str(b)
    d = c.lower()
    e = d.upper()
    return os.system(e)
''')
        declined = scan("five.py", '''
def f():
    a = request.args.get("q")
    b = a.strip()
    c = str(b)
    d = c.lower()
    e = d.upper()
    f = e.strip()
    return os.system(f)
''')
        self.assertEqual(accepted["taint"][0]["aliases"], ["a", "b", "c", "d", "e"])
        self.assertEqual(declined["taint"], [])

    def test_context_specific_sanitizers_only_suppress_matching_sink(self):
        html_safe = scan("html_safe.py", '''
def f():
    q = request.args.get("q")
    x = html.escape(q)
    return Markup(x)
''')
        shell_not_html = scan("shell_not_html.py", '''
def f():
    q = request.args.get("q")
    x = shlex.quote(q)
    return Markup(x)
''')
        shell_safe = scan("shell_safe.py", '''
def f():
    q = request.args.get("q")
    x = shlex.quote(q)
    return os.system(x)
''')
        html_not_shell = scan("html_not_shell.py", '''
def f():
    q = request.args.get("q")
    x = html.escape(q)
    return os.system(x)
''')
        self.assertEqual(html_safe["taint"], [])
        self.assertEqual(shell_safe["taint"], [])
        self.assertEqual([(x["family"], x["sanitizers"]) for x in shell_not_html["taint"]], [("xss", ["shell"])])
        self.assertEqual([(x["family"], x["sanitizers"]) for x in html_not_shell["taint"]], [("cmdi", ["html"])])

    def test_flask_blueprint_and_fastapi_router_prefixes(self):
        result = scan("routes.py", '''
bp = Blueprint("bp", __name__, url_prefix="/v1")
app.register_blueprint(bp, url_prefix="/api")

@bp.post(
    "/render"
)
def render_view():
    q = request.form.get("q")
    return Markup(q)

router = APIRouter(prefix="/v2")
app.include_router(router, prefix="/root")

@router.get("/find/{item}")
def find(term: str = Query(..., alias="q"), item: str = Path(...)):
    value = term.strip()
    return Markup(value)
''')
        ps = {(m, p) for m, p, _ in paths(result)}
        self.assertEqual(ps, {("POST", "/api/v1/render"), ("GET", "/root/v2/find/{item}")})
        got = {(x["routes"][0]["path"], tuple(x["reads"])) for x in result["taint"]}
        self.assertEqual(got, {("/api/v1/render", ("q",)), ("/root/v2/find/{item}", ("q",))})

    def test_spring_jaxrs_and_webservlet_routes_and_parameters(self):
        spring = scan("Search.java", '''
@RestController
@RequestMapping("/api")
class Search {
  @GetMapping(
      "/find/{id}"
  )
  public String find(@RequestParam("q") String term) {
    String value = term.trim();
    return writer.write(value);
  }
}
''')
        self.assertIn(("GET", "/api/find/{id}", "find"), paths(spring))
        self.assertEqual((spring["taint"][0]["reads"], spring["taint"][0]["family"]), (["q"], "xss"))

        jax = scan("Resource.java", '''
@Path("/v1")
class Resource {
  @GET @Path("/run")
  public String run(@QueryParam("cmd") String command) {
    String value = command.trim();
    return Runtime.getRuntime().exec(value);
  }
}
''')
        self.assertIn(("GET", "/v1/run", "run"), paths(jax))
        self.assertEqual(jax["taint"][0]["reads"], ["cmd"])

        servlet = scan("GoServlet.java", '''
@WebServlet(urlPatterns = {"/go"})
class GoServlet extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res) {
    String next = req.getParameter("next");
    res.sendRedirect(next);
  }
}
''')
        self.assertIn(("GET", "/go", "doGet"), paths(servlet))
        self.assertEqual((servlet["taint"][0]["family"], servlet["taint"][0]["reads"]), ("open_redirect", ["next"]))

    def test_rails_controller_route_link_and_sinatra(self):
        result = WE.read_source({
            "config/routes.rb": b"get '/users/:id', to: 'users#show'\n",
            "app/controllers/users_controller.rb": b'''class UsersController
  def show
    cmd = params[:cmd]
    value = cmd.strip
    system(value)
  end
end
''',
            "sinatra.rb": b'''post '/lookup' do
  q = params[:q]
  DB.execute(q)
end
''',
        })
        found = {(x["handler"], tuple((r["method"], r["path"]) for r in x["routes"]), tuple(x["reads"]))
                 for x in result["taint"]}
        self.assertIn(("show", (("GET", "/users/:id"),), ("cmd",)), found)
        self.assertIn(("post /lookup", (("POST", "/lookup"),), ("q",)), found)

    def test_go_net_http_gin_echo_chi_and_fiber(self):
        result = scan("handlers.go", '''
func netH(w http.ResponseWriter, r *http.Request) {
  p := r.FormValue("path")
  os.ReadFile(p)
}
func ginH(c *gin.Context) {
  q := c.Query("q")
  exec.Command("sh", "-c", q)
}
func echoH(c echo.Context) {
  u := c.QueryParam("url")
  http.Get(u)
}
func chiH(w http.ResponseWriter, r *http.Request) {
  id := chi.URLParam(r, "id")
  db.Query(id)
}
func fiberH(c *fiber.Ctx) {
  q := c.Query("name")
  template.HTML(q)
}
func main() {
  http.HandleFunc("/file", netH)
  api := r.Group("/api")
  api.GET("/run", ginH)
  e.GET("/fetch", echoH)
  r.Get("/item/{id}", chiH)
  app.Get("/hello", fiberH)
}
''')
        got = {(x["routes"][0]["path"], x["family"], tuple(x["reads"])) for x in result["taint"]}
        self.assertEqual(got, {
            ("/file", "traversal", ("path",)),
            ("/api/run", "cmdi", ("q",)),
            ("/fetch", "ssrf", ("url",)),
            ("/item/{id}", "sqli", ("id",)),
            ("/hello", "xss", ("name",)),
        })

    def test_php_framework_helpers_routes_and_attributes(self):
        laravel = scan("routes.php", '''<?php
Route::post(
  '/render',
  function (Request $request) {
    $q = $request->input('q');
    $value = trim($q);
    echo $value;
  }
);
''')
        self.assertIn(("POST", "/render", "post /render"), paths(laravel))
        self.assertEqual((laravel["taint"][0]["family"], laravel["taint"][0]["reads"]), ("xss", ["q"]))

        symfony = scan("Controller.php", '''<?php
class Controller {
  #[Route('/read', methods: ['GET'])]
  public function read(Request $request) {
    $name = request()->input('name');
    $path = trim($name);
    return file_get_contents($path);
  }
}
''')
        self.assertIn(("GET", "/read", "read"), paths(symfony))
        self.assertEqual((symfony["taint"][0]["family"], symfony["taint"][0]["reads"]), ("traversal", ["name"]))

    def test_answer_path_uses_only_one_proved_flow_and_remains_unsure(self):
        source = b'''@app.get("/run")
def run():
    q = request.args.get("cmd")
    value = q.strip()
    return db.execute(value)
'''
        ev = WE.Evidence({"app.py": source})
        q = {"id": "web-route", "question": "Which vulnerable route executes the command?",
             "answer_format": {"kind": "exact_text"}}
        answer = WE.answer(q, ev, ev.files)
        self.assertIsInstance(answer, str)
        self.assertTrue(answer.startswith("??") and "web.route/source.static_taint" in answer, answer)

    def test_hard_caps_fail_closed(self):
        # More than the per-handler statement cap cannot leave a partial proved flow behind.
        body = "\n".join(f"    x{i} = {i}" for i in range(WE.STATIC_MAX_STATEMENTS + 5))
        result = scan("large.py", "def f():\n    q=request.args.get('q')\n" + body + "\n    return os.system(q)\n")
        self.assertTrue(result["taint_cut"])
        self.assertEqual(result["taint"], [])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(StaticTaintTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
