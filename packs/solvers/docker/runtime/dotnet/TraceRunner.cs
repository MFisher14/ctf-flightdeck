// ctf-runtime-dotnet runner (B-242): one .NET assembly (CIL) on the .NET runtime, time-bounded.
//
// Runs INSIDE the ctf-runtime-dotnet container (no network, no host mount, read-only root). Never run
// on the host against a delivered file: the container is the boundary, this program is not one.
//
//   dotnet TraceRunner.dll --artifact FILE [--deps DIR] --fuel N --seconds S
//          [--max-events N] [--probe-hex HEX]...
//
// What it does:
//   - loads the assembly from memory into its own AssemblyLoadContext (--deps holds the assemblies it
//     may reference, resolved by simple name, also from memory);
//   - lists every declared method of its types (the entry points);
//   - runs each type's static constructor and reports its static fields: a string a static
//     constructor decoded shows up here;
//   - calls the entry point (Main) once per probe (the probe as args[0] and as Console.In), every
//     static method that takes nothing and returns a value, and every static method that takes one
//     string, byte[] or char[] (once per probe), capturing Console.Out / Console.Error;
//   - the CLR has no instruction fuel: each call gets a share of --seconds, a call that does not
//     return is reported and left behind, and a watchdog ends the run at --seconds. --fuel is
//     accepted and ignored.
// Environment.Exit from the artifact is caught by a ProcessExit handler that still emits the trace.
//
// Output: one line on stdout, "@@CTF-RUNTIME-TRACE@@ " + JSON (schema 1, every value a bounded string).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Loader;
using System.Text;
using System.Threading;

public static class TraceRunner
{
    const string Marker = "@@CTF-RUNTIME-TRACE@@ ";
    const int MaxText = 2048;
    const int MaxStrings = 256;
    const int MaxEntries = 256;
    const int MaxTypes = 64;
    const int MaxCalls = 96;
    const int MaxStuck = 3;
    const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static
        | BindingFlags.Instance | BindingFlags.DeclaredOnly;

    static readonly object Gate = new object();
    static readonly Stream RealOut = Console.OpenStandardOutput();
    static readonly List<string> Entries = new List<string>();
    static readonly List<string> Events = new List<string>();
    static readonly List<string> Strings = new List<string>();
    static readonly HashSet<string> Seen = new HashSet<string>();
    static readonly List<string> Notes = new List<string>();
    static string status = "ok";
    static bool truncated, exhausted, emitted, finished;
    static int maxEvents = 512;
    static int stuck;
    static long limitMs;
    static DateTime started;

    // ------------------------------------------------------------------------------------ trace
    static string Clip(string s)
    {
        if (s == null) return "null";
        return s.Length <= MaxText ? s : s.Substring(0, MaxText) + "...[cut]";
    }

    static string Quote(string s)
    {
        var b = new StringBuilder("\"");
        foreach (char c in s)
        {
            if (c == '"' || c == '\\') b.Append('\\').Append(c);
            else if (c < 0x20 || c > 0x7e) b.Append("\\u").Append(((int)c).ToString("x4"));
            else b.Append(c);
        }
        return b.Append('"').ToString();
    }

    static string Obj(params string[] pairs)
    {
        var parts = new List<string>();
        for (int i = 0; i + 1 < pairs.Length; i += 2) parts.Add(Quote(pairs[i]) + ":" + Quote(Clip(pairs[i + 1])));
        return "{" + string.Join(",", parts) + "}";
    }

    static void Event(params string[] pairs)
    {
        lock (Gate)
        {
            if (Events.Count >= maxEvents) { truncated = true; return; }
            Events.Add(Obj(pairs));
        }
    }

    static void Observed(string s)
    {
        if (string.IsNullOrEmpty(s)) return;
        s = Clip(s);
        lock (Gate)
        {
            if (Seen.Contains(s)) return;
            if (Strings.Count >= MaxStrings) { truncated = true; return; }
            Seen.Add(s);
            Strings.Add(Quote(s));
        }
    }

    static void Note(string s) { lock (Gate) Notes.Add(Quote(Clip(s))); }

    static void Partial() { lock (Gate) { if (status == "ok") status = "partial"; } }

    static void Emit()
    {
        lock (Gate)
        {
            if (emitted) return;
            emitted = true;
            long used = (long)(DateTime.UtcNow - started).TotalMilliseconds;
            string doc = "{\"schema\":1,\"runtime\":\"dotnet\",\"runtime_version\":" + Quote(Clip(Environment.Version.ToString()))
                + ",\"status\":" + Quote(status)
                + ",\"fuel\":{\"kind\":\"time\",\"limit\":" + limitMs + ",\"used\":" + used
                + ",\"exhausted\":" + (exhausted ? "true" : "false") + "}"
                + ",\"entries\":[" + string.Join(",", Entries) + "]"
                + ",\"events\":[" + string.Join(",", Events) + "]"
                + ",\"strings\":[" + string.Join(",", Strings) + "]"
                + ",\"notes\":[" + string.Join(",", Notes) + "]"
                + ",\"truncated\":" + (truncated ? "true" : "false") + "}";
            byte[] line = Encoding.ASCII.GetBytes(Marker + doc + "\n");
            RealOut.Write(line, 0, line.Length);
            RealOut.Flush();
        }
    }

    // ----------------------------------------------------------------------------------- values
    static bool Printable(string s)
    {
        if (s.Length == 0) return false;
        foreach (char c in s) if (c < 0x20 && c != '\n' && c != '\t' && c != '\r') return false;
        return true;
    }

    /// A value as text; strings (and printable byte[] / char[]) are also recorded as observed strings.
    static string Render(object v)
    {
        if (v == null) return "null";
        if (v is string s) { Observed(s); return s; }
        if (v is char[] chars)
        {
            string t = new string(chars);
            if (Printable(t)) Observed(t);
            return t;
        }
        if (v is byte[] bytes)
        {
            if (bytes.Length > 0 && bytes.All(x => x < 0x7f && (x >= 0x20 || x == 10 || x == 9 || x == 13)))
            {
                string t = Encoding.ASCII.GetString(bytes);
                Observed(t);
                return t;
            }
            return "hex:" + Convert.ToHexString(bytes, 0, Math.Min(bytes.Length, MaxText / 2)).ToLowerInvariant();
        }
        if (v is Array arr && arr.Rank == 1 && arr.Length <= 64)
        {
            var parts = new List<string>();
            foreach (object o in arr) parts.Add(Render(o));
            return "[" + string.Join(", ", parts) + "]";
        }
        if (v is IFormattable || v is bool || v is char) return Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture);
        return "<" + v.GetType().FullName + ">";
    }

    static string Signature(MethodBase m)
    {
        string ret = m is MethodInfo mi ? mi.ReturnType.Name : "void";
        return (m.IsStatic ? "static " : "") + ret + " (" + string.Join(", ", m.GetParameters().Select(p => p.ParameterType.Name)) + ")";
    }

    // ------------------------------------------------------------------------------------ calls
    /// Runs one step on its own background thread for at most `ms`; false when it threw or did not return.
    static bool Bounded(string name, string args, long ms, Func<object> step, bool report)
    {
        object result = null;
        Exception failure = null;
        var t = new Thread(() =>
        {
            try { result = step(); }
            catch (TargetInvocationException e) { failure = e.InnerException ?? e; }
            catch (Exception e) { failure = e; }
        }, 16 * 1024 * 1024);
        t.IsBackground = true;
        t.Start();
        if (!t.Join(TimeSpan.FromMilliseconds(ms)))
        {
            stuck++;
            Event("kind", "call", "name", name, "args", args, "error", "did not return in " + ms + " ms");
            Partial();
            return false;
        }
        if (failure != null)
        {
            Exception root = failure is TypeInitializationException && failure.InnerException != null ? failure.InnerException : failure;
            Event("kind", report ? "call" : "error", "name", name, "args", args, report ? "error" : "text",
                root.GetType().FullName + ": " + root.Message);
            Partial();
            return false;
        }
        if (report)
        {
            Event("kind", "call", "name", name, "args", args, "result", Render(result));
        }
        return true;
    }

    static void Flush(StringWriter w, string stream)
    {
        string text;
        lock (w) { text = w.ToString(); w.GetStringBuilder().Clear(); }
        if (text.Length == 0) return;
        Event("kind", "output", "stream", stream, "text", text);
        foreach (string line in text.Split('\n'))
            if (line.Trim().Length > 0) Observed(line.Trim());
    }

    public static int Main(string[] argv)
    {
        string artifact = null, deps = null;
        double seconds = 20.0;
        var probes = new List<byte[]>();
        for (int i = 0; i + 1 < argv.Length; i += 2)
        {
            string k = argv[i], v = argv[i + 1];
            if (k == "--artifact") artifact = v;
            else if (k == "--deps") deps = v;
            else if (k == "--seconds") seconds = double.Parse(v, System.Globalization.CultureInfo.InvariantCulture);
            else if (k == "--max-events") maxEvents = int.Parse(v);
            else if (k == "--probe-hex") probes.Add(Convert.FromHexString(v));
            else if (k != "--fuel") { Console.Error.WriteLine("TraceRunner: unknown option " + k); return 2; }
        }
        if (artifact == null) { Console.Error.WriteLine("TraceRunner: --artifact is required"); return 2; }
        if (probes.Count == 0) probes.Add(new byte[0]);
        started = DateTime.UtcNow;
        limitMs = (long)(seconds * 1000);
        long perCall = Math.Max(250L, limitMs / 8);

        var outw = new StringWriter();
        var errw = new StringWriter();
        Console.SetOut(TextWriter.Synchronized(outw));
        Console.SetError(TextWriter.Synchronized(errw));
        AppDomain.CurrentDomain.ProcessExit += (s, e) =>
        {
            if (!finished)
            {
                Note("the artifact ended the process (Environment.Exit) before the trace was complete");
                Partial();
                Flush(outw, "stdout");
                Flush(errw, "stderr");
            }
            Emit();
        };
        var watchdog = new Thread(() =>
        {
            Thread.Sleep(TimeSpan.FromMilliseconds(limitMs));
            exhausted = true;
            Note("the run reached its time limit of " + limitMs + " ms");
            Partial();
            finished = true;
            Emit();
            Environment.Exit(0);
        });
        watchdog.IsBackground = true;
        watchdog.Start();

        var context = new AssemblyLoadContext("artifact");
        var byName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (deps != null && Directory.Exists(deps))
        {
            foreach (string f in Directory.GetFiles(deps).OrderBy(x => x, StringComparer.Ordinal))
            {
                try { byName[AssemblyName.GetAssemblyName(f).Name] = f; }
                catch (Exception) { /* not an assembly: not a dependency */ }
            }
        }
        context.Resolving += (ctx, name) =>
            byName.TryGetValue(name.Name ?? "", out string path) ? ctx.LoadFromStream(new MemoryStream(File.ReadAllBytes(path))) : null;

        Assembly asm;
        try
        {
            asm = context.LoadFromStream(new MemoryStream(File.ReadAllBytes(artifact)));
        }
        catch (Exception e)
        {
            status = "error";
            Event("kind", "error", "name", "load", "text", e.GetType().FullName + ": " + e.Message);
            finished = true;
            Emit();
            return 0;
        }
        Type[] types;
        try { types = asm.GetTypes(); }
        catch (ReflectionTypeLoadException e)
        {
            types = e.Types.Where(x => x != null).ToArray();
            foreach (Exception le in e.LoaderExceptions.Where(x => x != null).Take(8))
                Event("kind", "error", "name", "link", "text", le.GetType().FullName + ": " + le.Message);
            Partial();
        }
        MethodInfo entry = null;
        try { entry = asm.EntryPoint; } catch (Exception) { }
        var targets = types.Where(t => !t.Name.StartsWith("<") && !t.IsGenericTypeDefinition)
            .OrderBy(t => entry != null && t == entry.DeclaringType ? 0 : 1).ThenBy(t => t.FullName, StringComparer.Ordinal).ToList();
        if (targets.Count == 0) { status = "error"; Note("no type was loaded from the artifact"); }
        if (targets.Count > MaxTypes)
        {
            Note(targets.Count + " types: only the first " + MaxTypes + " were traced");
            Partial();
            targets = targets.Take(MaxTypes).ToList();
        }

        int calls = 0;
        foreach (Type type in targets)
        {
            if (stuck >= MaxStuck) { Note("stopped after " + MaxStuck + " calls that did not return"); break; }
            MethodInfo[] methods;
            FieldInfo[] fields;
            try
            {
                methods = type.GetMethods(Declared).OrderBy(m => m.Name + Signature(m), StringComparer.Ordinal).ToArray();
                fields = type.GetFields(Declared);
            }
            catch (Exception e)
            {
                Event("kind", "error", "name", "link " + type.FullName, "text", e.GetType().FullName + ": " + e.Message);
                Partial();
                continue;
            }
            foreach (MethodInfo m in methods)
            {
                if (Entries.Count >= MaxEntries) { truncated = true; break; }
                Entries.Add(Obj("name", type.FullName + "." + m.Name, "signature", Signature(m)));
            }
            bool inited = Bounded(type.FullName + "..cctor", "", perCall, () =>
            {
                RuntimeHelpers.RunClassConstructor(type.TypeHandle);
                return null;
            }, false);
            Flush(outw, "stdout");
            Flush(errw, "stderr");
            if (!inited) continue;
            foreach (FieldInfo f in fields.Where(x => x.IsStatic))
            {
                try { Event("kind", "static", "name", type.FullName + "." + f.Name, "value", Render(f.GetValue(null))); }
                catch (Exception e) { Event("kind", "error", "name", type.FullName + "." + f.Name, "text", e.GetType().FullName + ": " + e.Message); }
            }
            foreach (MethodInfo m in methods)
            {
                if (!m.IsStatic || m.ContainsGenericParameters) continue;
                ParameterInfo[] ps = m.GetParameters();
                bool isEntry = entry != null && m == entry;
                bool nullary = !isEntry && ps.Length == 0 && m.ReturnType != typeof(void);
                bool unary = !isEntry && ps.Length == 1 && (ps[0].ParameterType == typeof(string)
                    || ps[0].ParameterType == typeof(byte[]) || ps[0].ParameterType == typeof(char[]));
                if (!isEntry && !nullary && !unary) continue;
                int rounds = nullary ? 1 : probes.Count;
                for (int p = 0; p < rounds; p++)
                {
                    if (calls >= MaxCalls || stuck >= MaxStuck) break;
                    calls++;
                    byte[] probe = probes[p];
                    string text = Encoding.UTF8.GetString(probe);
                    object[] callArgs;
                    if (isEntry)
                    {
                        Console.SetIn(new StringReader(text + "\n"));
                        callArgs = ps.Length == 0 ? new object[0] : new object[] { new[] { text } };
                    }
                    else if (nullary) callArgs = new object[0];
                    else if (ps[0].ParameterType == typeof(string)) callArgs = new object[] { text };
                    else if (ps[0].ParameterType == typeof(byte[])) callArgs = new object[] { (byte[])probe.Clone() };
                    else callArgs = new object[] { text.ToCharArray() };
                    Bounded(type.FullName + "." + m.Name, nullary ? "" : "probe " + p, perCall, () => m.Invoke(null, callArgs), true);
                    Flush(outw, "stdout");
                    Flush(errw, "stderr");
                }
            }
            if (calls >= MaxCalls)
            {
                Note("the call limit of " + MaxCalls + " was reached: later methods were not called");
                Partial();
                break;
            }
        }
        finished = true;
        Emit();
        return 0;
    }
}
