package fr.cryptohash.test;

import fr.cryptohash.Digest;
import fr.cryptohash.RIPEMD;
import fr.cryptohash.RIPEMD128;
import fr.cryptohash.RIPEMD160;
import org.testng.annotations.Test;

import static fr.cryptohash.TestSupportUtils.*;

public class RIPEMDTest {
    @Test
    public void testRIPEMD() {
        Digest dig = new RIPEMD();
        testKat(dig, "",
                "9f73aa9b372a9dacfb86a6108852e2d9");
        testKat(dig, "a",
                "486f74f790bc95ef7963cd2382b4bbc9");
        testKat(dig, "abc",
                "3f14bad4c2f9b0ea805e5485d3d6882d");
        testKat(dig, "message digest",
                "5f5c7ebe1abbb3c7036482942d5f9d49");
        testKat(dig, "abcdefghijklmnopqrstuvwxyz",
                "ff6e1547494251a1cca6f005a6eaa2b4");
        testKat(dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
                + "stuvwxyz0123456789",
                "ff418a5aed3763d8f2ddf88a29e62486");
        testKat(dig, "12345678901234567890123456789012345678901234"
                + "567890123456789012345678901234567890",
                "dfd6b45f60fe79bbbde87c6bfc6580a5");

        testCollision(dig,
                "8eaf9f5779f5ec09ba6a4a5711354178a410b4a29f6c2fad2c"
                        + "20560b1179754de7aade0bf291bc787d6dbc47b1d1bd9a15"
                        + "205da4ff047181a8584726a54e0661",
                "8eaf9f5779f5ec09ba6a4a5711355178a410b4a29f6c2fad2c"
                        + "20560b1179754de7aade0bf291bc787d6dc0c7b1d1bd9a15"
                        + "205da4ff047181a8584726a54e06e1");

        testCollision(dig,
                "8eaf9f5779f5ec09ba6a4a5711354178a410b4a29f6c2fad2c"
                        + "20560b1179754de7aade0bf291bc787d6dbc47b1d1bd9a15"
                        + "205da4ff04a5a0a8588db1b6660ce7",
                "8eaf9f5779f5ec09ba6a4a5711355178a410b4a29f6c2fad2c"
                        + "20560b1179754de7aade0bf291bc787d6dc0c7b1d1bd9a15"
                        + "205da4ff04a5a0a8588db1b6660c67");

        reportSuccess("RIPEMD");
    }

    @Test
    public void testRIPEMD128() {
        Digest dig = new RIPEMD128();
        testKat(dig, "",
                "cdf26213a150dc3ecb610f18f6b38b46");
        testKat(dig, "a",
                "86be7afa339d0fc7cfc785e72f578d33");
        testKat(dig, "abc",
                "c14a12199c66e4ba84636b0f69144c77");
        testKat(dig, "message digest",
                "9e327b3d6e523062afc1132d7df9d1b8");
        testKat(dig, "abcdefghijklmnopqrstuvwxyz",
                "fd2aa607f71dc8f510714922b371834e");
        testKat(dig, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmn"
                + "lmnomnopnopq",
                "a1aa0689d0fafa2ddc22e88b49133a06");
        testKat(dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
                + "stuvwxyz0123456789",
                "d1e959eb179c911faea4624c60c5c702");
        testKat(dig, "12345678901234567890123456789012345678901234"
                + "567890123456789012345678901234567890",
                "3f45ef194732c2dbb2c4a2c769795fa3");

        testKatMillionA(dig,
                "4a7f5723f954eba1216c9d8f6320431f");

        reportSuccess("RIPEMD-128");
    }

    @Test
    public void testRIPEMD160() {
        Digest dig = new RIPEMD160();
        testKat(dig, "",
                "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        testKat(dig, "a",
                "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
        testKat(dig, "abc",
                "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        testKat(dig, "message digest",
                "5d0689ef49d2fae572b881b123a85ffa21595f36");
        testKat(dig, "abcdefghijklmnopqrstuvwxyz",
                "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
        testKat(dig, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmn"
                + "lmnomnopnopq",
                "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
        testKat(dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
                + "stuvwxyz0123456789",
                "b0e20b6e3116640286ed3a87a5713079b21f5189");
        testKat(dig, "12345678901234567890123456789012345678901234"
                + "567890123456789012345678901234567890",
                "9b752e45573d4b39f4dbd3323cab82bf63326bfb");

        testKatMillionA(dig,
                "52783243c1697bdbe16d37f97f68f08325dc1528");

        reportSuccess("RIPEMD-160");
    }
}
