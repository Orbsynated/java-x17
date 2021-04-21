package utils;

import crypto.Digest;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.fail;
import static utils.ByteArrayUtils.encodeLatin1;
import static utils.ByteArrayUtils.strtobin;

public abstract class HelperFunctions {
    public static void reportSuccess(String name)
    {
        System.out.println("===== test " + name + " passed");
    }

    public static void testKatHex(Digest dig, String data, String ref)
    {
        testKat(dig, strtobin(data), strtobin(ref));
    }

    public static void testX17(byte[] output, byte[] expected ){
        assertEquals(output, expected);
    }

    public static byte[] strToBytesArrayUTF8(String str){
        return str.getBytes(StandardCharsets.UTF_8);
    }
    public static void testCollision(Digest dig, String s1, String s2)
    {
        byte[] msg1 = strtobin(s1);
        byte[] msg2 = strtobin(s2);
        assertNotEquals(msg1, msg2);
        assertEquals(dig.digest(msg1), dig.digest(msg2));
    }

    public static void testKatMillionA(Digest dig, String ref)
    {
        byte[] buf = new byte[1000];
        for (int i = 0; i < 1000; i ++)
            buf[i] = 'a';
        for (int i = 0; i < 1000; i ++)
            dig.update(buf);
        assertEquals(dig.digest(), strtobin(ref));
    }


    public static void assertNotEquals(byte[] b1, byte[] b2)
    {
        if (equals(b1, b2))
            fail("byte streams are equal");
    }

    public static void testKat(Digest dig, String data, String ref)
    {
        testKat(dig, encodeLatin1(data), strtobin(ref));
    }


    public static void testKat(Digest dig, byte[] buf, byte[] exp)
    {
        /*
         * First test the hashing itself.
         */
        byte[] out = dig.digest(buf);
        assertEquals(out, exp);

        /*
         * Now the update() API; this also exercises auto-reset.
         */
        for (byte b : buf) dig.update(b);
        assertEquals(dig.digest(), exp);

        /*
         * The cloning API.
         */
        int blen = buf.length;
        dig.update(buf, 0, blen / 2);
        Digest dig2 = dig.copy();
        dig.update(buf, blen / 2, blen - (blen / 2));
        assertEquals(dig.digest(), exp);
        dig2.update(buf, blen / 2, blen - (blen / 2));
        assertEquals(dig2.digest(), exp);
    }

    private static void assertEquals(byte[] b1, byte[] b2) {
        if (!equals(b1, b2))
            fail("byte streams are not equal");
    }

    private static boolean equals(byte[] b1, byte[] b2)
    {
        if (b1 == b2)
            return true;
        if (b1 == null || b2 == null)
            return false;
        if (b1.length != b2.length)
            return false;
        for (int i = 0; i < b1.length; i ++)
            if (b1[i] != b2[i])
                return false;
        return true;
    }
}
