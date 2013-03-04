// $Id: SHA2Core.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

import com.amd.aparapi.Device;
import com.amd.aparapi.Kernel;
import com.amd.aparapi.Range;

/**
 * This class implements SHA-224 and SHA-256, which differ only by the IV
 * and the output length.
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
 * @version $Revision: 214 $
 */

abstract class SHA2Core extends MDHelper {


    private int[] currentVal = null;
    private int[] W = null;

    /**
     * Create the object.
     */
    SHA2Core() {
        super(false, 8);
    }

    /**
     * Encode the 32-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in big-endian
     * convention (most significant byte first).
     *
     * @param val the value to encode
     * @param off the destination offset
     * @param buf the destination buffer
     */
    private static void encodeBEInt(int val, int off, byte... buf) {
        buf[off++] = (byte) (val >>> 24);
        buf[off++] = (byte) (val >>> 16);
        buf[off++] = (byte) (val >>> 8);
        buf[off] = (byte) val;
    }

    /**
     * Perform a circular rotation by {@code n} to the left
     * of the 32-bit word {@code x}. The {@code n} parameter
     * must lie between 1 and 31 (inclusive).
     *
     * @param x the value to rotate
     * @param n the rotation count (between 1 and 31)
     * @return the rotated value
     */
    private static int circularLeft(int x, int n) {
        return x >>> 32 - n | x << n;
    }

    private static int r3(int i1, int i2, int i3) {
        return i1 ^ i2 ^ i3;
    }

    /**
     * @see DigestEngine
     */
    protected Digest copyState(SHA2Core dst) {
        System.arraycopy(currentVal, 0, dst.currentVal, 0, currentVal.length);
        return super.copyState(dst);
    }

    /**
     * @see Digest
     */
    public int getBlockLength() {
        return 64;
    }

    /**
     * @see DigestEngine
     */
    protected void engineReset() {
        System.arraycopy(getInitVal(), 0, currentVal, 0, 8);
    }

    /**
     * Get the initial value for this algorithm.
     *
     * @return the initial value (eight 32-bit words)
     */
    abstract int[] getInitVal();

    /**
     * @see DigestEngine
     */
    protected void doPadding(int outputOffset, byte... output) {
        makeMDPadding();
        int olen = getDigestLength();
        for (int i = 0, j = 0; j < olen; i++, j += 4)
            encodeBEInt(currentVal[i], outputOffset + j, output);
    }

    /**
     * @see DigestEngine
     */
    protected void doInit() {
        currentVal = new int[8];
        W = new int[64];
        engineReset();
    }

    /**
     * @see DigestEngine
     */
    protected void processBlock(final byte[] input) {
                                                  final byte[]data=input;
        final int[] cv=this.currentVal;
        final int[]work=this.W;

        new Kernel() {
            /**
             * private special values.
             */
            private   final int[] K = {
                    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
                    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
                    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
                    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
                    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
                    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
                    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
                    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
                    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
                    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
                    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
                    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
                    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
                    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
                    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
                    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
            };

            public void run() {
                int H = cv[7];
                int G = cv[6];
                int F = cv[5];
                int E = cv[4];
                int D = cv[3];
                int C = cv[2];
                int B = cv[1];
                int A = cv[0];

                for (int i = 0; i < 16; i++) {
                    int off = i << 2;
                    work[i] = (data[off++] & 0xFF) << 24
                            | (data[off++] & 0xFF) << 16
                            | (data[off++] & 0xFF) << 8
                            | data[off] & 0xFF;
                }

                int T2 = 0;
                int T1 = 0;
                for (int i = 16; i < 64; i++) {
                    T1 = work[i - 2];
                    T2 = work[i - 15];
                    work[i] = r3(T1 << 15 | T1 >>> 17, T1 >>> 19 | T1 << 13, T1 >>> 10)
                            + work[i - 7]
                            + r3(T2 << 25 | T2 >>> 7, T2 >>> 18 | T2 << 14, T2 >>> 3)
                            + work[i - 16];
                }
                for (int i = 0; i < 64; i++) {
                    T1 = H + r3(E << 26 | E >>> 6, E >>> 11 | E << 21, E << 7 | E >>> 25) + (F & E ^ G & ~E)
                            + K[i] + work[i];
                    T2 = r3(A >>> 2 | A << 30, A << 19 | A >>> 13, A >>> 22 | A << 10)
                            + r3(A & B, A & C, B & C);
                    //todo: long rot
                    H = G;
                    G = F;
                    F = E;
                    E = D + T1;
                    D = C;
                    C = B;
                    B = A;
                    A = T1 + T2;
                }
                cv[7] += H;
                cv[6] += G;
                cv[5] += F;
                cv[4] += E;
                cv[3] += D;
                cv[2] += C;
                cv[1] += B;
                cv[0] += A;
            }
        }.execute(new Range(Device.best(), getBlockLength()));

    }

    /**
     * @see Digest
     */
    public String toString() {
        return "SHA-" + (getDigestLength() << 3);
    }
}
