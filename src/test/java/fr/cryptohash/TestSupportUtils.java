// $Id: TestDigest.java 257 2011-07-15 20:57:08Z tp $

package fr.cryptohash;

import fr.cryptohash.test.*;
import org.testng.Assert;

import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;

/**
 * This class is a program entry point; it includes tests for the
 * implementation of the hash functions.
 * <p/>
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @author Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 * @version $Revision: 257 $
 */

public class TestSupportUtils {
     public static byte[] strtobin(String str) {
        int blen = str.length() / 2;
        byte[] buf = new byte[blen];
        for (int i = 0; i < blen; i++) {
            String bs = str.substring(i * 2, i * 2 + 2);
            buf[i] = (byte) Integer.parseInt(bs, 16);
        }
        return buf;
    }

     public static byte[] encodeLatin1(String str) {
        int blen = str.length();
        byte[] buf = new byte[blen];
        for (int i = 0; i < blen; i++)
            buf[i] = (byte) str.charAt(i);
        return buf;
    }

     static boolean equals(byte[] b1, byte[] b2) {
         if (b1 != b2) {
             if (b1 == null || b2 == null || b1.length != b2.length) return false;
             for (int i = 0; i < b1.length; i++)
                 if (b1[i] != b2[i])
                     return false;
         }
         return true;
     }


     public static void reportSuccess(String name) {

    }

     static void testKat(Digest dig, byte[] buf, byte[] exp) {
        /*
         * First test the hashing itself.
		 */
        byte[] out = dig.digest(buf);
        assertEquals(out, exp);

		/*
		 * Now the update() API; this also exercises auto-reset.
		 */
        for (int i = 0; i < buf.length; i++)
            dig.update(buf[i]);
        assertEquals(dig.digest(), exp);

		/*
		 * The cloning API.
		 */
        int blen = buf.length;
        dig.update(0, blen / 2,buf);
        Digest dig2 = dig.copy();
        dig.update( blen / 2, blen - (blen / 2),buf);
        assertEquals(dig.digest(), exp);
        dig2.update(blen / 2, blen - (blen / 2),buf);
        assertEquals(dig2.digest(), exp);
    }

     public static void testKat(Digest dig, String data, String ref) {
        testKat(dig, encodeLatin1(data), strtobin(ref));
    }

     public static void testKatHex(Digest dig, String data, String ref) {
        testKat(dig, strtobin(data), strtobin(ref));
    }

     public static void testKatMillionA(Digest dig, String ref) {
        byte[] buf = new byte[1000];
        for (int i = 0; i < 1000; i++)
            buf[i] = 'a';
        for (int i = 0; i < 1000; i++)
            dig.update(buf);
        assertEquals(dig.digest(), strtobin(ref));
    }

     public static void testCollision(Digest dig, String s1, String s2) {
        byte[] msg1 = strtobin(s1);
        byte[] msg2 = strtobin(s2);
        assertFalse(Arrays.equals(msg1, msg2));
        assertEquals(dig.digest(msg1), dig.digest(msg2));
    }}