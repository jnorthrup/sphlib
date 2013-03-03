// $Id: SHA256.java 156 2010-04-26 17:55:11Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the SHA-256 digest algorithm under the
 * {@link Digest} API. SHA-256 is specified by FIPS 180-2.</p>
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
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class SHA256 {


    /** The initial value for SHA-256. */
    private static final int[] initVal = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };
    /**
* private special values.
*/
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
    int[] currentVal;
    int[] W;
    boolean littleEndian;
    byte[] countBuf;
    byte fbyte;
    private int digestLen;
    private int blockLen;
    private int inputLen;
    private byte[] inputBuf;
    private byte[] outputBuf;
    private long blockCount;

    /**
     * Create the object.
     */
    SHA256() {
        doInit();
        digestLen = getDigestLength();
        blockLen = getInternalBlockLength();
        inputBuf = new byte[blockLen];
        outputBuf = new byte[digestLen];
        inputLen = 0;
        blockCount = 0;
        init1(false, 8, (byte) 128);
    }

    /**
         * Encode the 32-bit word {@code val} into the array
         * {@code buf} at offset {@code off}, in big-endian
         * convention (most significant byte first).
         *
         * @param val   the value to encode
         * @param off   the destination offset
         * @param buf   the destination buffer
         */
    private static void encodeBEInt(int val, int off, byte... buf) {
        buf[off++] = (byte) (val >>> 24);
        buf[off ++] = (byte) (val >>> 16);
        buf[off ++] = (byte) (val >>> 8);
        buf[off  ] = (byte) val;
    }

    /**
     * Decode a 32-bit big-endian word from the array {@code buf}
     * at offset {@code off}.
     *
     * @param off the source offset
     * @param buf the source buffer
     * @return the decoded value
     */
    private static int decodeBEInt(int off, byte[] buf) {
        return (buf[off++] & 0xFF) << 24
                | (buf[off ++] & 0xFF) << 16
                | (buf[off ++] & 0xFF) << 8
                | buf[off ] & 0xFF;
    }

    private static int c10(int a) {
        return a >>> 22 | a << 10;
    }

    private static int c19(int a) {
        return a >>> 13 | a << 19;
    }

    private static int c30(int a) {
        return a >>> 2 | a << 30;
    }

    private static int c7(int e) {
        return e >>> 25 | e << 7;
    }

    private static int c21(int e) {
        return e >>> 11 | e << 21;
    }

    private static int c26(int e) {
        return e >>> 6 | e << 26;
    }

    /**
     * Encode the 32-bit word {@code val} into the array
     * {@code buf} at offset {@code off}, in little-endian
     * convention (least significant byte first).
     *
* @param val   the value to encode
* @param off   the destination offset
* @param buf   the destination buffer
*/
    private static void encodeLEInt(int val, int off, byte... buf)
    {
        buf[off] = (byte)val;
        buf[off + 1] = (byte)(val >>> 8);
        buf[off + 2] = (byte)(val >>> 16);
        buf[off + 3] = (byte)(val >>> 24);
    }

    /** @see SHA2Core */
    static int[] getInitVal()
	{
		return initVal;
	}

    private static int c14(int x1) {
        return x1 << 14 | x1 >>> 18;
    }

    private static int c25(int x1) {
        return x1 << 25 | x1 >>> 7;
    }

    private static int c13(int x) {
        return x << 13 | x >>> 19;
    }

    private static int c15(int x) {
        return x << 15 | x >>> 17;
    }

    private static int r3(int i1, int i2, int i3) {
        return i1 ^ i2 ^ i3;
    }

    /**
     * Program entry. Parameters are ignored.
     *
     * @param args   the parameter input (ignored)
     */
    public static void main(String[] args)
    {
        testSHA256();
    }

    private static void fail(String message)
    {
        throw new RuntimeException("test failed: " + message);
    }

    private static byte[] strtobin(String str)
    {
        int blen = str.length() / 2;
        byte[] buf = new byte[blen];
        for (int i = 0; i < blen; i ++) {
            String bs = str.substring(i * 2, i * 2 + 2);
            buf[i] = (byte)Integer.parseInt(bs, 16);
        }
        return buf;
    }

    private static byte[] encodeLatin1(String str)
    {
        int blen = str.length();
        byte[] buf = new byte[blen];
        for (int i = 0; i < blen; i ++)
            buf[i] = (byte)str.charAt(i);
        return buf;
    }

    private static boolean equals(byte[] b1, byte[] b2)
    {
        if (b1 != b2) if (b1 != null && b2 != null && b1.length == b2.length) {
            for (int i = 0; i < b1.length; i++)
                if (b1[i] != b2[i])
                    return false;
            return true;
        } else {
            return false;
        }
        else {
            return true;
        }
    }

    private static void assertTrue(boolean expr)
    {
        if (!expr)
            SHA256.fail("assertion failed");
    }

    private static void assertEquals(byte[] b1, byte[] b2)
    {
        if (!SHA256.equals(b1, b2))
            SHA256.fail("byte streams are not equal");
    }

    private static void assertNotEquals(byte[] b1, byte[] b2)
    {
        if (SHA256.equals(b1, b2))
            SHA256.fail("byte streams are equal");
    }

    private static void reportSuccess(String name)
    {
        System.out.println("===== test " + name + " passed");
    }

    private static void testKat(SHA256 dig, byte[] buf, byte[] exp)
    {
		/*
		 * First test the hashing itself.
		 */
        byte[] out = dig.digest(buf);
        SHA256.assertEquals(out, exp);

		/*
		 * Now the update() API; this also exercises auto-reset.
		 */
        for (int i = 0; i < buf.length; i ++)
            dig.update(buf[i]);
        SHA256.assertEquals(dig.digest(), exp);

		/*
		 * The cloning API.
		 */
        int blen = buf.length;
        dig.update( 0, blen / 2,buf);
        SHA256 dig2 = dig.copy();
        dig.update( blen / 2, blen - blen / 2,buf );
        SHA256.assertEquals(dig.digest(), exp);
        dig2.update(blen / 2, blen - blen / 2,buf);
        SHA256.assertEquals(dig2.digest(), exp);
    }

    private static void testKat(SHA256 dig, String data, String ref)
    {
        SHA256.testKat(dig, SHA256.encodeLatin1(data), SHA256.strtobin(ref));
    }

    private static void testKatHex(SHA256 dig, String data, String ref)
    {
        SHA256.testKat(dig, SHA256.strtobin(data), SHA256.strtobin(ref));
    }

    private static void testKatMillionA(SHA256 dig, String ref)
    {
        byte[] buf = new byte[1000];
        for (int i = 0; i < 1000; i ++)
            buf[i] = 'a';
        for (int i = 0; i < 1000; i ++)
            dig.update(buf);
        SHA256.assertEquals(dig.digest(), SHA256.strtobin(ref));
    }

    private static void testCollision(SHA256 dig, String s1, String s2)
    {
        byte[] msg1 = SHA256.strtobin(s1);
        byte[] msg2 = SHA256.strtobin(s2);
        SHA256.assertNotEquals(msg1, msg2);
        SHA256.assertEquals(dig.digest(msg1), dig.digest(msg2));
    }

    /**
     * Test SHA-256 implementation.
     */
    private static void testSHA256()
    {
        SHA256 dig = new SHA256();
        SHA256.testKat(dig, "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        SHA256.testKat(dig, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

        SHA256.testKatMillionA(dig,
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

        SHA256.reportSuccess("SHA-256");
    }

    public static void main1(String... a) {

        SHA256 sha256 = new SHA256();
        byte[] digest = sha256.digest("hi".getBytes());
        String s = "";
        for (byte b : digest) {
            s += Integer.toHexString(0xff & b + 0x100).substring(1);
        }
        System.err.println(": " + s);
    }

    /**
     * @see fr.cryptohash.DigestEngine
     */
    void engineReset() {
        System.arraycopy(SHA256.getInitVal(), 0, currentVal, 0, 8);
    }

    /**
     * @see fr.cryptohash.DigestEngine
     */
    void processBlock(byte... data) {
        int H = currentVal[7];
        int G = currentVal[6];
        int F = currentVal[5];
        int E = currentVal[4];
        int D = currentVal[3];
        int C = currentVal[2];
        int B = currentVal[1];
        int A = currentVal[0];
        int T1;
        int T2;

        for (int i = 0; i < 16; i++)
            W[i] = SHA256.decodeBEInt(i << 2,  data );
        for (int i = 16; i < 64; i++) {
            T1 = W[i - 2];
            T2 = W[i - 15];
            W[i] = SHA256.r3(T1 << 15 | T1 >>> 32 - 15, T1 << 13 | T1 >>> 32 - 13, T1 >>> 10)
                    + W[i - 7]
                    + SHA256.r3(T2 << 25 | T2 >>> 32 - 25, T2 << 14 | T2 >>> 32 - 14, T2 >>> 3)
                    + W[i - 16];
        }
        for (int i = 0; i < 64; i++) {
            T1 = H + SHA256.r3(SHA256.c26(E), SHA256.c21(E), SHA256.c7(E)) + (F & E ^ G & ~E)
                + K[i] + W[i];
            T2 = SHA256.r3(A & B, A & C, B & C)+ SHA256.r3(SHA256.c30(A), SHA256.c19(A), SHA256.c10(A));
            H = G;
            G = F;
            F = E;
            E = D + T1;
            D = C;
            C = B;
            B = A;
            A = T1 + T2;
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

    /**
     * @see fr.cryptohash.DigestEngine
     */
    void doPadding(int outputOffset, byte... output) {
        makeMDPadding();
        int olen = getDigestLength();
        for (int i = 0, j = 0; j < olen; i++, j += 4)
            SHA256.encodeBEInt(currentVal[i], outputOffset + j, output);
    }

    /**
     * @see fr.cryptohash.DigestEngine
     */
    void doInit() {
        currentVal = new int[8];
        W = new int[64];
        engineReset();
    }

    private void adjustDigestLen()
    {
        if (digestLen == 0) {
            digestLen = getDigestLength();
            outputBuf = new byte[digestLen];
        }
    }

    /** @see Digest */
    public byte[] digest()
    {
        adjustDigestLen();
        byte[] result = new byte[digestLen];
        digest(0, digestLen, result);
        return result;
    }

    /** @see Digest */
    public byte[] digest(byte[] input)
    {
        update(0, input.length, input);
        return digest();
    }

    /** @see Digest */
    public int digest(int offset, int len, byte[] buf)
    {
        adjustDigestLen();
        if (len >= digestLen) {
            doPadding(offset, buf);
            reset();
            return digestLen;
        } else {
            doPadding(0, outputBuf);
            System.arraycopy(outputBuf, 0, buf, offset, len);
            reset();
            return len;
        }
    }

    /** @see Digest */
    public void reset()
    {
        engineReset();
        inputLen = 0;
        blockCount = 0;
    }

    /** @see Digest */
    public void update(byte input)
    {
        inputBuf[inputLen ++] = (byte)input;
        if (inputLen == blockLen) {
            processBlock(inputBuf);
            blockCount ++;
            inputLen = 0;
        }
    }

    /** @see Digest */
    public void update(byte[] input)
    {
        update(0, input.length, input);
    }

    /** @see Digest */
    public void update(int offset, int len, byte[] input)
    {
        while (len > 0) {
            int copyLen = blockLen - inputLen;
            if (copyLen > len)
                copyLen = len;
            System.arraycopy(input, offset, inputBuf, inputLen,
                copyLen);
            offset += copyLen;
            inputLen += copyLen;
            len -= copyLen;
            if (inputLen == blockLen) {
                processBlock(inputBuf);
                blockCount ++;
                inputLen = 0;
            }
        }
    }

    /**
     * Get the internal block length. This is the length (in
     * bytes) of the array which will be passed as parameter to
     * {@link #processBlock}. The default implementation of this
     * method calls {@link #getBlockLength} and returns the same
     * value. Overriding this method is useful when the advertised
     * block length (which is used, for instance, by HMAC) is
     * suboptimal with regards to internal buffering needs.
     *
     * @return  the internal block length (in bytes)
     */
    int getInternalBlockLength()
    {
        return getBlockLength();
    }

    /**
     * Flush internal buffers, so that less than a block of data
     * may at most be upheld.
     *
     * @return  the number of bytes still unprocessed after the flush
     */
    int flush()
    {
        return inputLen;
    }

    /**
     * Get a reference to an internal buffer with the same size
     * than a block. The contents of that buffer are defined only
     * immediately after a call to {@link #flush()}: if
     * {@link #flush()} return the value {@code n}, then the
     * first {@code n} bytes of the array returned by this method
     * are the {@code n} bytes of input data which are still
     * unprocessed. The values of the remaining bytes are
     * undefined and may be altered at will.
     *
     * @return  a block-sized internal buffer
     */
    byte[] getBlockBuffer()
    {
        return inputBuf;
    }

    /**
     * Get the "block count": this is the number of times the
     * {@link #processBlock} method has been invoked for the
     * current hash operation. That counter is incremented
     * <em>after</em> the call to {@link #processBlock}.
     *
     * @return  the block count
     */
    long getBlockCount()
    {
        return blockCount;
    }



    /** @see Digest */
	public int getDigestLength()
	{
		return 32;
	}

    /** @see Digest */
	public SHA256 copy()
	{
		return copyState(new SHA256());
	}

    /**
     * @see fr.cryptohash.Digest
     */
    public int getBlockLength() {
        return 64;
    }

    /**
     * @see fr.cryptohash.Digest
     */
    public String toString() {
        return "SHA-" + (getDigestLength() << 3);
    }

    /**
     * @see fr.cryptohash.DigestEngine
     */
    SHA256 copyState(SHA256 dest) {
        System.arraycopy(currentVal, 0, dest.currentVal, 0,
                currentVal.length);

        dest.inputLen = inputLen;
        dest.blockCount = blockCount;
        System.arraycopy(inputBuf, 0, dest.inputBuf, 0,
                inputBuf.length);
        adjustDigestLen();
        dest.adjustDigestLen();
        System.arraycopy(outputBuf, 0, dest.outputBuf, 0,
                outputBuf.length);
        return dest;
    }

    protected void init1(boolean littleEndian, int lenlen, byte fbyte) {
        this.littleEndian = littleEndian;
        countBuf = new byte[lenlen];
        this.fbyte = fbyte;
    }

    /**
     * Compute the padding. The padding data is input into the engine,
     * which is flushed.
     */
    void makeMDPadding()
    {
        int dataLen = flush();
        int blen = getBlockLength();
        long currentLength = getBlockCount() * (long)blen;
        currentLength = (currentLength + (long)dataLen) * 8L;
        int lenlen = countBuf.length;
        if (littleEndian) {
            SHA256.encodeLEInt((int)currentLength, 0, countBuf);
            SHA256.encodeLEInt((int)(currentLength >>> 32), 4, countBuf);
        } else {
            SHA256.encodeBEInt((int) (currentLength >>> 32),
                    lenlen - 8, countBuf);
            SHA256.encodeBEInt((int) currentLength,
                    lenlen - 4, countBuf);
        }
        int endLen = dataLen + lenlen + blen & ~(blen - 1);
        update(fbyte);
        for (int i = dataLen + 1; i < endLen - lenlen; i ++)
            update((byte)0);
        update(countBuf);

        /*
         * This code is used only for debugging purposes.
         *
        if (flush() != 0)
            throw new Error("panic: buffering went astray");
         *
         */
    }
}
