package fr.cryptohash.test;

import fr.cryptohash.Digest;
import fr.cryptohash.SHA224;
import org.testng.annotations.Test;

import static fr.cryptohash.TestSupportUtils.*;

public class SHA224Test {
    @Test
    public void testSHA224() {
        Digest dig = new SHA224();
        testKat(dig, "abc",
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
        testKat(dig, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlm"
                + "nomnopnopq",
                "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");

        testKatMillionA(dig,
                "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67");

        reportSuccess("SHA-224");
    }
}
