package com.huntress.fixture;

public final class Puzzle {
    static final byte[] BLOB = {(byte)0x5a, (byte)0x1b, (byte)0x14, (byte)0x09, (byte)0x77, (byte)0x6a, (byte)0x6b, (byte)0x68, (byte)0x69, (byte)0x6e, (byte)0x6f, (byte)0x6c, (byte)0x6d, (byte)0x62, (byte)0x63, (byte)0x1b, (byte)0x18, (byte)0x19, (byte)0x1e, (byte)0x1f, (byte)0x1c, (byte)0x5a};
    public static String reveal() {
        byte[] out = new byte[BLOB.length];
        for (int i = 0; i < BLOB.length; i++) out[i] = (byte) (BLOB[i] ^ 0x5a);
        return new String(out);
    }
}
