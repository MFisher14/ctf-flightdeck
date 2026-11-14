// The build-time self-test of ctf-runtime-jvm (B-242): our own class, never a delivered one. The
// token is built in the static initialiser, so finding it in the trace proves the runner ran it.
public class Selftest {
    static final String TOKEN;

    static {
        StringBuilder b = new StringBuilder();
        for (char c : "dug.tfmguftu.pl".toCharArray()) {
            b.append((char) (c - 1));
        }
        TOKEN = b.toString();
    }

    public static boolean check(String s) {
        return TOKEN.equals(s);
    }
}
