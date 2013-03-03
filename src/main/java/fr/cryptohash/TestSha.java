package fr.cryptohash;

import java.util.Arrays;

/**
 * Created with IntelliJ IDEA.
 * User: jim
 * Date: 3/3/13
 * Time: 1:01 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestSha {
    /**
     * Program entry. Parameters are ignored.
     *
     * @param args   the parameter input (ignored)
     */
    public static void main(String... args)
    {
        SHA256 dig = new SHA256();
        testKat(dig, encodeLatin1("abc"),  strtobin("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        testKat(dig, encodeLatin1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),  strtobin("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

        testKatMillionA(dig,
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

        System.out.println("===== test " + "SHA-256" + " passed");
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


    private static void testKat(SHA256 dig, byte[] buf, byte[] exp)
    {
		/*
		 * First test the hashing itself.
		 */
        byte[] out = dig.digest(buf);
        assert  Arrays.equals(out, exp) : "fail "+ bintostr(out)+"!="+bintostr(exp);

		/*
		 * Now the update() API; this also exercises auto-reset.
		 */
        for (int i = 0; i < buf.length; i ++)
            dig.update(buf[i]);
        assert  Arrays.equals(dig.digest(), exp) : "byte streams are not equal";

		/*
		 * The cloning API.
		 */
        int blen = buf.length;
        dig.update( 0, blen / 2,buf);
    }

    private static String bintostr(byte[] out) {
        StringBuilder x=new StringBuilder();
        for (byte b : out) {x.append(
                Integer.toHexString((b + 0x100) & 0xff).substring(0));
        }


        return x.toString();
    }

    private static void testKatMillionA(SHA256 dig, String ref)
    {
        byte[] buf = new byte[1000];
        Arrays.fill(buf, (byte) 'a');
        for (int i = 0; i < 1000; i ++)
            dig.update(buf);
        assert  Arrays.equals(dig.digest(),  strtobin(ref)) : "byte streams are not equal";
    }


}
