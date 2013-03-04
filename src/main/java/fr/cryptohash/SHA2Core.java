// $Id: SHA2Core.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * This class implements SHA-224 and SHA-256, which differ only by the IV
 * and the output length.
 *
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
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class SHA2Core extends MDHelper {

	/** private special values. */
	private static final int[] K = {
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
	private int[] currentVal, W;

	/**
	 * Create the object.
	 */
	SHA2Core()
	{
		super(false, 8);
	}

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in big-endian
	 * convention (most significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeBEInt(int val, byte[] buf, int off)
	{
		buf[off ++] = (byte)(val >>> 24);
		buf[off ++] = (byte)(val >>> 16);
		buf[off ++] = (byte)(val >>> 8);
		buf[off  ] = (byte)val;
	}

    /**
	 * Perform a circular rotation by {@code n} to the left
	 * of the 32-bit word {@code x}. The {@code n} parameter
	 * must lie between 1 and 31 (inclusive).
	 *
	 * @param x   the value to rotate
	 * @param n   the rotation count (between 1 and 31)
	 * @return  the rotated value
	*/
	static private int circularLeft(int x, int n)
	{
		return x << n | x >>> 32 - n;
	}

    private static int r3(int i1, int i2, int i3) {
        return i1 ^ i2 ^ i3;
    }

	/** @see DigestEngine */
	protected Digest copyState(SHA2Core dst)
	{
		System.arraycopy(currentVal, 0, dst.currentVal, 0,
			currentVal.length);
		return super.copyState(dst);
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 64;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		System.arraycopy(getInitVal(), 0, currentVal, 0, 8);
	}

	/**
	 * Get the initial value for this algorithm.
	 *
	 * @return  the initial value (eight 32-bit words)
	 */
	abstract int[] getInitVal();

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		makeMDPadding();
		int olen = getDigestLength();
		for (int i = 0, j = 0; j < olen; i ++, j += 4)
			encodeBEInt(currentVal[i], output, outputOffset + j);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		currentVal = new int[8];
		W = new int[64];
		engineReset();
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
        int H = currentVal[7];
        int G = currentVal[6];
        int F = currentVal[5];
        int E = currentVal[4];
        int D = currentVal[3];
        int C = currentVal[2];
        int B = currentVal[1];
        int A = currentVal[0];

		for (int i = 0; i < 16; i ++) {
            int off = 4 * i;
            W[i] =    (data[off++] & 0xFF) << 24
                    | (data[off++] & 0xFF) << 16
                    | (data[off++] & 0xFF) << 8
                    | data[off] & 0xFF;
        }
		for (int i = 16; i < 64; i ++) {
            int x = W[i - 2];
            int x1 = W[i - 15];
            W[i] = r3(circularLeft(x, 15), circularLeft(x, 13), x >>> 10)
                    + W[i - 7]
                    + r3(circularLeft(x1, 25), circularLeft(x1, 14), x1 >>> 3)
                    + W[i - 16];
		}
		for (int i = 0; i < 64; i ++) {
			int T1 = H + r3(circularLeft(E, 26), circularLeft(E, 21), circularLeft(E, 7)) + (F & E ^ G & ~E)
				+ K[i] + W[i];
            int T2 = r3(circularLeft(A, 30), circularLeft(A, 19), circularLeft(A, 10))
				+ r3(A & B, A & C, B & C);
			H = G; G = F; F = E; E = D + T1;
			D = C; C = B; B = A; A = T1 + T2;
		}
        currentVal[7] += H;
        currentVal[6] += G;
        currentVal[5] += F;
        currentVal[4] += E;
        currentVal[3] += D;
        currentVal[2] += C;
        currentVal[1] += B;
        currentVal[0] += A;

	}

    /** @see Digest */
	public String toString()
	{
		return "SHA-" + (getDigestLength() << 3);
	}
}
