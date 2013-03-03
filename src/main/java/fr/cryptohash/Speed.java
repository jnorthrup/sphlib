// $Id: Speed.java 229 2010-06-16 20:22:27Z tp $

package fr.cryptohash;

import java.util.Hashtable;
import java.util.Vector;

/**
 * <p>This class implements some speed tests for hash functions.</p>
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
 * @version $Revision: 229 $
 */

public class Speed {
  private static final String[] FUNS_ALIAS = {
            "rmd", "ripemd",
            "rmd128", "ripemd128",
            "rmd160", "ripemd160",
            "sha2", "sha",
            "shavite3", "shavite"
    };

    private static final Hashtable<String, String> ALIASES = new Hashtable<String, String>();

    static {
        for (int i = 0; i < FUNS_ALIAS.length; i += 2)
            ALIASES.put(FUNS_ALIAS[i], FUNS_ALIAS[i + 1]);
    }

    /**
     * Program entry point. The arguments should be function names,
     * for which speed is measured. If no argument is given, then
     * all implemented functions are benchmarked.
     *
     * @param args the program arguments
     * @throws Exception on (internal) error
     */
    public static void main(String[] args)
            throws Exception {
        SHA256.main();
        SHA256 d = new SHA256();
        speed(d.toString(), d);
        speed(d.toString(), d);
    }

    private static void speed(String name, SHA256 dig) {
        System.out.println("Speed check: " + name);
        byte[] buf = new byte[8192];
        for (int i = 0; i < buf.length; i++)
            buf[i] = 'a';
        int dlen = dig.getDigestLength();
        int j = 0;
        long num = 2L;
        for (int clen = 16; ; clen <<= 2) {
            switch (clen) {
                case 4096:
                    clen = 8192;
                    if (num > 1L)
                        num >>= 1;
                    break;
            }
            long tt;
            while (true) {
                tt = speedUnit(dig, j, buf, clen, num);
                j += dlen;
                if (j > (buf.length - dlen))
                    j = 0;
                if (tt > 6000L) {
                    if (num <= 1L)
                        break;
                    num >>= 1L;
                } else if (tt < 2000L) {
                    num <<= 1;
                } else {
                    break;
                }
            }
            long tlen = (long) clen * num;
            long div = 10L * tt;
            long rate = (tlen + (div - 1) / 2) / div;
            System.out.println("message length = "
                    + formatLong((long) clen, 5)
                    + " -> "
                    + prependSpaces(Long.toString(rate / 100L), 4)
                    + "."
                    + prependZeroes(Long.toString(rate % 100L), 2)
                    + " MBytes/s");
            if (clen == 8192) {
                tt = speedLong(dig, buf, clen, num);
                tlen = (long) clen * num;
                div = 10L * tt;
                rate = (tlen + (div - 1) / 2) / div;
                System.out.println("long messages          -> "
                        + prependSpaces(
                        Long.toString(rate / 100L), 4)
                        + "."
                        + prependZeroes(
                        Long.toString(rate % 100L), 2)
                        + " MBytes/s");
                break;
            }
            if (num > 4L)
                num >>= 2;
        }
    }

    private static long speedUnit(SHA256 dig, int j,
                                  byte[] buf, int len, long num) {
        int dlen = dig.getDigestLength();
        long orig = System.currentTimeMillis();
        while (num-- > 0) {
            dig.update(0, len, buf);
            dig.digest(j, dlen, buf);
            if ((j += dlen) > (buf.length - dlen))
                j = 0;
        }
        long end = System.currentTimeMillis();
        return end - orig;
    }

    private static long speedLong(SHA256 dig, byte[] buf, int len, long num) {
        byte[] out = new byte[dig.getDigestLength()];
        long orig = System.currentTimeMillis();
        while (num-- > 0) {
            dig.update(0, len, buf);
        }
        long end = System.currentTimeMillis();
        dig.digest(0, out.length, out);
        return end - orig;
    }

    private static String formatLong(long num, int len) {
        return prependSpaces(Long.toString(num), len);
    }

    private static String prependSpaces(String s, int len) {
        return prependChar(s, ' ', len);
    }

    private static String prependZeroes(String s, int len) {
        return prependChar(s, '0', len);
    }

    private static String prependChar(String s, char c, int len) {
        int slen = s.length();
        if (slen >= len)
            return s;
        StringBuffer sb = new StringBuffer();
        while (len-- > slen)
            sb.append(c);
        sb.append(s);
        return sb.toString();
    }
}
