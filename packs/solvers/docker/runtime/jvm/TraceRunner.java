// ctf-runtime-jvm runner (B-242): one Java class or jar on a JVM, time-bounded.
//
// Runs INSIDE the ctf-runtime-jvm container (no network, no host mount, read-only root). Never run on
// the host against a delivered file: the container is the boundary, this program is not one.
//
//   java -cp /opt/runner TraceRunner --artifact FILE [--deps DIR] --fuel N --seconds S
//        [--max-events N] [--probe-hex HEX]...
//
// What it does (Java source level 8, so any later JDK compiles it):
//   - loads the classes from memory (a lone .class, or the .class entries of a jar; --deps adds more),
//     never from a URL;
//   - lists every declared method of the artifact's classes (the entry points);
//   - initialises each class (its static initialiser runs) and reports its static fields: a string a
//     static initialiser decoded shows up here;
//   - calls `main(String[])` once per probe (the probe as argv[0] and as stdin), every static method
//     that takes nothing and returns a value, and every static method that takes one String, byte[]
//     or char[] (once per probe), capturing System.out/System.err;
//   - a JVM has no instruction fuel: each call gets a share of --seconds, a call that does not
//     return is reported and left behind, and a watchdog ends the run at --seconds. --fuel is
//     accepted and ignored.
// System.exit from the artifact is caught by a shutdown hook that still emits the trace.
//
// Output: one line on stdout, "@@CTF-RUNTIME-TRACE@@ " + JSON (schema 1, every value a bounded string).
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public final class TraceRunner {
    static final String MARKER = "@@CTF-RUNTIME-TRACE@@ ";
    static final int MAX_TEXT = 2048;
    static final int MAX_STRINGS = 256;
    static final int MAX_ENTRIES = 256;
    static final int MAX_CLASSES = 64;
    static final int MAX_CALLS = 96;
    static final int MAX_STUCK = 3;
    static final int MAX_JAR_ENTRIES = 20000;
    static final long MAX_ENTRY_BYTES = 16L << 20;

    static final PrintStream REAL_OUT = System.out;
    static final List<String> entries = new ArrayList<String>();
    static final List<String> events = new ArrayList<String>();
    static final Set<String> strings = new LinkedHashSet<String>();
    static final List<String> notes = new ArrayList<String>();
    static String status = "ok";
    static boolean truncated;
    static boolean exhausted;
    static boolean emitted;
    static boolean finished;
    static int maxEvents = 512;
    static long startMs;
    static long limitMs;

    // ---------------------------------------------------------------------------------- trace
    static String clip(String s) {
        if (s == null) {
            return "null";
        }
        return s.length() <= MAX_TEXT ? s : s.substring(0, MAX_TEXT) + "...[cut]";
    }

    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c < 0x20 || c > 0x7e) {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.append('"').toString();
    }

    static String object(String... pairs) {
        StringBuilder b = new StringBuilder("{");
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            if (i > 0) {
                b.append(',');
            }
            b.append(quote(pairs[i])).append(':').append(quote(clip(pairs[i + 1])));
        }
        return b.append('}').toString();
    }

    static synchronized void event(String... pairs) {
        if (events.size() >= maxEvents) {
            truncated = true;
            return;
        }
        events.add(object(pairs));
    }

    static synchronized void string(String s) {
        if (s == null || s.isEmpty()) {
            return;
        }
        s = clip(s);
        if (strings.contains(s)) {
            return;
        }
        if (strings.size() >= MAX_STRINGS) {
            truncated = true;
            return;
        }
        strings.add(s);
    }

    static synchronized void note(String s) {
        notes.add(clip(s));
    }

    static synchronized void partial() {
        if (status.equals("ok")) {
            status = "partial";
        }
    }

    static String list(Iterable<String> rendered) {
        StringBuilder b = new StringBuilder("[");
        boolean first = true;
        for (String r : rendered) {
            if (!first) {
                b.append(',');
            }
            first = false;
            b.append(r);
        }
        return b.append(']').toString();
    }

    static synchronized void emit() {
        if (emitted) {
            return;
        }
        emitted = true;
        List<String> quoted = new ArrayList<String>();
        for (String s : strings) {
            quoted.add(quote(s));
        }
        List<String> quotedNotes = new ArrayList<String>();
        for (String s : notes) {
            quotedNotes.add(quote(s));
        }
        long used = System.currentTimeMillis() - startMs;
        String doc = "{\"schema\":1,\"runtime\":\"jvm\",\"runtime_version\":"
                + quote(clip(System.getProperty("java.version", "?")))
                + ",\"status\":" + quote(status)
                + ",\"fuel\":{\"kind\":\"time\",\"limit\":" + limitMs + ",\"used\":" + used
                + ",\"exhausted\":" + exhausted + "}"
                + ",\"entries\":" + list(entries)
                + ",\"events\":" + list(events)
                + ",\"strings\":" + list(quoted)
                + ",\"notes\":" + list(quotedNotes)
                + ",\"truncated\":" + truncated + "}";
        REAL_OUT.println(MARKER + doc);
        REAL_OUT.flush();
    }

    // ---------------------------------------------------------------------------------- loading
    static final class MemLoader extends ClassLoader {
        final Map<String, byte[]> classes = new LinkedHashMap<String, byte[]>();
        final Map<String, byte[]> resources = new LinkedHashMap<String, byte[]>();

        MemLoader() {
            super(TraceRunner.class.getClassLoader());
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] b = classes.get(name);
            if (b == null) {
                throw new ClassNotFoundException(name);
            }
            return defineClass(name, b, 0, b.length);
        }

        @Override
        public InputStream getResourceAsStream(String name) {
            byte[] b = resources.get(name.startsWith("/") ? name.substring(1) : name);
            return b != null ? new ByteArrayInputStream(b) : super.getResourceAsStream(name);
        }
    }

    /** The binary name in a class file's this_class entry, or null when the bytes are not a class. */
    static String className(byte[] b) {
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(b));
            if (in.readInt() != 0xCAFEBABE) {
                return null;
            }
            in.readUnsignedShort();
            in.readUnsignedShort();
            int count = in.readUnsignedShort();
            String[] utf = new String[count];
            int[] classIndex = new int[count];
            for (int i = 1; i < count; i++) {
                int tag = in.readUnsignedByte();
                switch (tag) {
                    case 1: utf[i] = in.readUTF(); break;
                    case 3: case 4: in.readInt(); break;
                    case 5: case 6: in.readLong(); i++; break;
                    case 7: classIndex[i] = in.readUnsignedShort(); break;
                    case 8: case 16: case 19: case 20: in.readUnsignedShort(); break;
                    case 9: case 10: case 11: case 12: case 17: case 18: in.readInt(); break;
                    case 15: in.readUnsignedByte(); in.readUnsignedShort(); break;
                    default: return null;
                }
            }
            in.readUnsignedShort();
            int self = in.readUnsignedShort();
            if (self <= 0 || self >= count || classIndex[self] <= 0 || classIndex[self] >= count) {
                return null;
            }
            String name = utf[classIndex[self]];
            return name == null ? null : name.replace('/', '.');
        } catch (IOException e) {
            return null;
        }
    }

    static byte[] readAll(InputStream in, long cap) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        long total = 0;
        int n;
        while ((n = in.read(buf)) > 0) {
            total += n;
            if (total > cap) {
                throw new IOException("entry over " + cap + " bytes");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** Adds one file to the loader; returns the class names it contributed and the jar's Main-Class (first). */
    static List<String> add(MemLoader loader, byte[] data, String label, String[] mainClass) {
        List<String> names = new ArrayList<String>();
        if (data.length >= 4 && data[0] == 'P' && data[1] == 'K') {
            int seen = 0;
            try {
                ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(data));
                ZipEntry e;
                while ((e = zip.getNextEntry()) != null) {
                    if (++seen > MAX_JAR_ENTRIES) {
                        note(label + ": more than " + MAX_JAR_ENTRIES + " entries, the rest were not read");
                        partial();
                        break;
                    }
                    if (e.isDirectory()) {
                        continue;
                    }
                    byte[] body;
                    try {
                        body = readAll(zip, MAX_ENTRY_BYTES);
                    } catch (IOException ex) {
                        note(label + ": " + e.getName() + " not read (" + ex.getMessage() + ")");
                        partial();
                        continue;
                    }
                    String name = e.getName();
                    if (name.endsWith(".class")) {
                        String cn = className(body);
                        if (cn != null && !loader.classes.containsKey(cn)) {
                            loader.classes.put(cn, body);
                            names.add(cn);
                        }
                    } else {
                        loader.resources.put(name, body);
                        if (name.equals("META-INF/MANIFEST.MF") && mainClass != null) {
                            for (String line : new String(body, StandardCharsets.UTF_8).split("\r?\n")) {
                                if (line.startsWith("Main-Class:")) {
                                    mainClass[0] = line.substring("Main-Class:".length()).trim();
                                }
                            }
                        }
                    }
                }
            } catch (IOException ex) {
                event("kind", "error", "name", "load", "text", label + ": " + ex);
                partial();
            }
            return names;
        }
        String cn = className(data);
        if (cn == null) {
            event("kind", "error", "name", "load", "text", label + ": neither a Java class nor a jar");
            return names;
        }
        if (!loader.classes.containsKey(cn)) {
            loader.classes.put(cn, data);
            names.add(cn);
        }
        return names;
    }

    // ---------------------------------------------------------------------------------- values
    static boolean printable(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 && c != '\n' && c != '\t' && c != '\r') {
                return false;
            }
        }
        return true;
    }

    /** A value as text; strings (and printable byte[] / char[]) are also recorded as observed strings. */
    static String render(Object v) {
        if (v == null) {
            return "null";
        }
        if (v instanceof String) {
            string((String) v);
            return (String) v;
        }
        if (v instanceof char[]) {
            String s = new String((char[]) v);
            if (printable(s)) {
                string(s);
            }
            return s;
        }
        if (v instanceof byte[]) {
            byte[] b = (byte[]) v;
            String s = new String(b, StandardCharsets.ISO_8859_1);
            boolean ascii = printable(s);
            for (int i = 0; ascii && i < b.length; i++) {
                ascii = b[i] >= 0;
            }
            if (ascii) {
                string(s);
                return s;
            }
            StringBuilder hex = new StringBuilder("hex:");
            for (int i = 0; i < b.length && i < MAX_TEXT / 2; i++) {
                hex.append(String.format("%02x", b[i] & 0xff));
            }
            return hex.toString();
        }
        if (v instanceof Object[]) {
            List<String> parts = new ArrayList<String>();
            for (Object o : (Object[]) v) {
                if (parts.size() >= 64) {
                    break;
                }
                parts.add(render(o));
            }
            return parts.toString();
        }
        if (v instanceof int[]) {
            return Arrays.toString((int[]) v);
        }
        if (v instanceof long[]) {
            return Arrays.toString((long[]) v);
        }
        if (v instanceof Number || v instanceof Boolean || v instanceof Character) {
            return String.valueOf(v);
        }
        return "<" + v.getClass().getName() + ">";
    }

    // ---------------------------------------------------------------------------------- calls
    interface Step {
        Object run() throws Throwable;
    }

    static int stuck;

    /** Runs one step on its own daemon thread for at most `ms`; false when it threw or did not return. */
    static boolean bounded(final String name, final String args, long ms, final Step step, final boolean report) {
        final Object[] box = new Object[2];
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    box[0] = step.run();
                } catch (InvocationTargetException e) {
                    box[1] = e.getCause() != null ? e.getCause() : e;
                } catch (Throwable e) {
                    box[1] = e;
                }
            }
        }, "trace-call");
        t.setDaemon(true);
        t.start();
        try {
            t.join(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (t.isAlive()) {
            stuck++;
            event("kind", "call", "name", name, "args", args, "error", "did not return in " + ms + " ms");
            partial();
            return false;
        }
        if (box[1] != null) {
            Throwable e = (Throwable) box[1];
            if (e instanceof ExceptionInInitializerError && e.getCause() != null) {
                e = e.getCause();
            }
            event("kind", report ? "call" : "error", "name", name, "args", args, report ? "error" : "text",
                    String.valueOf(e));
            partial();
            return false;
        }
        if (report) {
            event("kind", "call", "name", name, "args", args, "result", render(box[0]));
        }
        return true;
    }

    static String signature(Method m) {
        StringBuilder b = new StringBuilder();
        b.append(Modifier.isStatic(m.getModifiers()) ? "static " : "");
        b.append(m.getReturnType().getSimpleName()).append(" (");
        Class<?>[] ps = m.getParameterTypes();
        for (int i = 0; i < ps.length; i++) {
            b.append(i > 0 ? ", " : "").append(ps[i].getSimpleName());
        }
        return b.append(")").toString();
    }

    static void flush(ByteArrayOutputStream buf, String stream) {
        String text = new String(buf.toByteArray(), StandardCharsets.UTF_8);
        buf.reset();
        if (text.isEmpty()) {
            return;
        }
        event("kind", "output", "stream", stream, "text", text);
        for (String line : text.split("\r?\n")) {
            if (!line.trim().isEmpty()) {
                string(line.trim());
            }
        }
    }

    public static void main(String[] argv) throws Exception {
        String artifact = null;
        String deps = null;
        double seconds = 20.0;
        final List<byte[]> probes = new ArrayList<byte[]>();
        for (int i = 0; i + 1 < argv.length; i += 2) {
            String k = argv[i];
            String v = argv[i + 1];
            if (k.equals("--artifact")) {
                artifact = v;
            } else if (k.equals("--deps")) {
                deps = v;
            } else if (k.equals("--seconds")) {
                seconds = Double.parseDouble(v);
            } else if (k.equals("--max-events")) {
                maxEvents = Integer.parseInt(v);
            } else if (k.equals("--probe-hex")) {
                byte[] b = new byte[v.length() / 2];
                for (int j = 0; j < b.length; j++) {
                    b[j] = (byte) Integer.parseInt(v.substring(2 * j, 2 * j + 2), 16);
                }
                probes.add(b);
            } else if (!k.equals("--fuel")) {
                System.err.println("TraceRunner: unknown option " + k);
                System.exit(2);
            }
        }
        if (artifact == null) {
            System.err.println("TraceRunner: --artifact is required");
            System.exit(2);
        }
        if (probes.isEmpty()) {
            probes.add(new byte[0]);
        }
        startMs = System.currentTimeMillis();
        limitMs = (long) (seconds * 1000);
        final long perCall = Math.max(250L, limitMs / 8);

        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ByteArrayOutputStream err = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, "UTF-8"));
        System.setErr(new PrintStream(err, true, "UTF-8"));
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            public void run() {
                if (!finished) {
                    note("the artifact ended the JVM (System.exit) before the trace was complete");
                    partial();
                    flush(out, "stdout");
                    flush(err, "stderr");
                }
                emit();
            }
        }));
        Thread watchdog = new Thread(new Runnable() {
            public void run() {
                try {
                    Thread.sleep(limitMs);
                } catch (InterruptedException e) {
                    return;
                }
                exhausted = true;
                note("the run reached its time limit of " + limitMs + " ms");
                partial();
                finished = true;
                emit();
                Runtime.getRuntime().halt(0);
            }
        }, "trace-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();

        final MemLoader loader = new MemLoader();
        String[] mainClass = new String[1];
        List<String> targets = add(loader, Files.readAllBytes(new File(artifact).toPath()), "artifact", mainClass);
        if (deps != null) {
            File[] extra = new File(deps).listFiles();
            if (extra != null) {
                Arrays.sort(extra);
                for (File f : extra) {
                    if (f.isFile()) {
                        add(loader, Files.readAllBytes(f.toPath()), "dep " + f.getName(), null);
                    }
                }
            }
        }
        if (targets.isEmpty()) {
            status = "error";
            note("no class was loaded from the artifact");
        }
        if (mainClass[0] != null && targets.remove(mainClass[0])) {
            targets.add(0, mainClass[0]);
        }
        if (targets.size() > MAX_CLASSES) {
            note(targets.size() + " classes: only the first " + MAX_CLASSES + " were traced");
            partial();
            targets = targets.subList(0, MAX_CLASSES);
        }

        int calls = 0;
        boolean anyLoaded = false;
        for (final String name : targets) {
            if (stuck >= MAX_STUCK) {
                note("stopped after " + MAX_STUCK + " calls that did not return");
                break;
            }
            final Class<?> c;
            try {
                c = loader.loadClass(name);
            } catch (Throwable e) {
                event("kind", "error", "name", "load " + name, "text", String.valueOf(e));
                partial();
                continue;
            }
            anyLoaded = true;
            Method[] methods;
            Field[] fields;
            try {
                methods = c.getDeclaredMethods();
                fields = c.getDeclaredFields();
            } catch (Throwable e) {
                event("kind", "error", "name", "link " + name, "text", String.valueOf(e));
                partial();
                continue;
            }
            Arrays.sort(methods, new java.util.Comparator<Method>() {
                public int compare(Method a, Method b) {
                    return (a.getName() + signature(a)).compareTo(b.getName() + signature(b));
                }
            });
            for (Method m : methods) {
                if (entries.size() >= MAX_ENTRIES) {
                    truncated = true;
                    break;
                }
                entries.add(object("name", name + "." + m.getName(), "signature", signature(m)));
            }
            boolean inited = bounded(name + ".<clinit>", "", perCall, new Step() {
                public Object run() throws Throwable {
                    return Class.forName(name, true, loader);
                }
            }, false);
            flush(out, "stdout");
            flush(err, "stderr");
            if (!inited) {
                continue;
            }
            for (final Field f : fields) {
                if (!Modifier.isStatic(f.getModifiers())) {
                    continue;
                }
                try {
                    f.setAccessible(true);
                    event("kind", "static", "name", name + "." + f.getName(), "value", render(f.get(null)));
                } catch (Throwable e) {
                    event("kind", "error", "name", name + "." + f.getName(), "text", String.valueOf(e));
                }
            }
            for (final Method m : methods) {
                if (!Modifier.isStatic(m.getModifiers()) || m.isSynthetic()) {
                    continue;
                }
                final Class<?>[] ps = m.getParameterTypes();
                final boolean isMain = m.getName().equals("main") && ps.length == 1 && ps[0] == String[].class;
                final boolean nullary = ps.length == 0 && m.getReturnType() != void.class;
                final boolean unary = ps.length == 1
                        && (ps[0] == String.class || ps[0] == byte[].class || ps[0] == char[].class);
                if (!isMain && !nullary && !unary) {
                    continue;
                }
                try {
                    m.setAccessible(true);
                } catch (Throwable e) {
                    continue;
                }
                int rounds = nullary ? 1 : probes.size();
                for (int p = 0; p < rounds; p++) {
                    if (calls >= MAX_CALLS || stuck >= MAX_STUCK) {
                        break;
                    }
                    calls++;
                    final byte[] probe = probes.get(p);
                    final String text = new String(probe, StandardCharsets.UTF_8);
                    final Object arg;
                    if (isMain) {
                        arg = new String[] {text};
                        System.setIn(new ByteArrayInputStream((text + "\n").getBytes(StandardCharsets.UTF_8)));
                    } else if (nullary) {
                        arg = null;
                    } else if (ps[0] == String.class) {
                        arg = text;
                    } else if (ps[0] == byte[].class) {
                        arg = probe.clone();
                    } else {
                        arg = text.toCharArray();
                    }
                    bounded(name + "." + m.getName(), nullary ? "" : "probe " + p, perCall, new Step() {
                        public Object run() throws Throwable {
                            return nullary ? m.invoke(null) : m.invoke(null, arg);
                        }
                    }, true);
                    flush(out, "stdout");
                    flush(err, "stderr");
                }
            }
            if (calls >= MAX_CALLS) {
                note("the call limit of " + MAX_CALLS + " was reached: later methods were not called");
                partial();
                break;
            }
        }
        if (!targets.isEmpty() && !anyLoaded) {
            status = "error";
        }
        finished = true;
        emit();
        Runtime.getRuntime().halt(0);
    }
}
