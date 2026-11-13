package com.huntress.fixture;

public final class Puzzle {
    public static String assemble() {
        StringBuilder sb = new StringBuilder();
        sb.append("ANS-");
        sb.append("DEAD");
        sb.append("BEEF");
        sb.append("0011");
        sb.append("2233");
        return sb.toString();
    }
    public static String other() { return "hello" + System.currentTimeMillis(); }
}
