package utils;


import org.spongycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

public class ByteArrayUtils {

    /**
     * Get the first 32 bytes of a given byte array
     * @param bytes Input byte array
     */
    public static byte[] trim256(byte [] bytes)
    {
        byte [] result = new byte[32];
        if(bytes.length < 32) return null;
        System.arraycopy(bytes, 0, result, 0, 32);
        return result;
    }

    /**
     * Get the bytes representation of a hex encoded string
     * @param str Hex encoded string
     */
    public static byte[] hexEncodedStringToBytes(String str)
    {
        return Hex.decode(str);
    }

    /**
     * Get the bytes representation of a given string encoded in UTF-8
     * @param str Input string
     */
    public static byte[] stringToBytes(String str)
    {
        return str.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Returns the given byte array hex encoded.
     */
    public static String bytesToHexString(byte[] bytes) {
        return Hex.toHexString(bytes);
    }

}
