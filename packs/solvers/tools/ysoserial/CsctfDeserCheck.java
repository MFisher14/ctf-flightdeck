// The proof that a payload of solvers/toolkits/java_deser.py WORKS: it reads one serialized stream from stdin,
// deserializes it with ysoserial-all.jar's libraries on the class path (commons-collections 3.1 and 4.0,
// commons-beanutils 1.9.2, ...) and prints how long readObject took and whether a marker file exists afterwards.
//
// Run ONLY inside the pinned temurin 8 container (--network none, read-only root, a tmpfs /tmp) by the Java
// deserialization test, on this repository's own template payloads (`touch /tmp/<marker>`, Thread.sleep).
// Never on anything from a challenge delivery or a target.
//
// usage: java -cp ysoserial-all.jar:classes CsctfDeserCheck <marker file>   < payload
// prints: elapsed_ms=<n> marker=<yes|no> error=<exception class or ->

import java.io.File;
import java.io.ObjectInputStream;

public class CsctfDeserCheck {
    public static void main(String[] args) throws Exception {
        File marker = new File(args[0]);
        long t0 = System.nanoTime();
        String error = "-";
        try {
            new ObjectInputStream(System.in).readObject();
        } catch (Throwable e) {
            error = e.getClass().getName();   // many chains end in a ClassCastException after they ran
        }
        long ms = (System.nanoTime() - t0) / 1000000L;
        for (int i = 0; i < 40 && !marker.exists(); i++) {
            Thread.sleep(50);                  // Runtime.exec returns at once: give `touch` its moment
        }
        System.out.println("elapsed_ms=" + ms + " marker=" + (marker.exists() ? "yes" : "no") + " error=" + error);
    }
}
