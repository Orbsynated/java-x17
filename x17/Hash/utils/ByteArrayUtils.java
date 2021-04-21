/*
 * Copyright 2014 Hash Engineering Solutions.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package utils;

/**
 * Created by HashEngineering on 7/2/14.
 */
public class ByteArrayUtils {

    public static byte[] trim256(byte [] bytes)
    {
        byte [] result = new byte[32];
        System.arraycopy(bytes, 0, result, 0, 32);
        return result;
    }

    public static byte[] strtobin(String str)
    {
        int blen = str.length() / 2;
        byte[] buf = new byte[blen];
        for (int i = 0; i < blen; i ++) {
            String bs = str.substring(i * 2, i * 2 + 2);
            buf[i] = (byte)Integer.parseInt(bs, 16);
        }
        return buf;
    }

    public static byte[] encodeLatin1(String str)
    {
        int blen = str.length();
        byte[] buf = new byte[blen];
        for (int i = 0; i < blen; i ++)
            buf[i] = (byte)str.charAt(i);
        return buf;
    }

    /**
     * Returns the given byte array hex encoded.
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            String s = Integer.toString(0xFF & b, 16);
            if (s.length() < 2)
                buf.append('0');
            buf.append(s);
        }
        return buf.toString();
    }

}
