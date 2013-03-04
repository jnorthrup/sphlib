package fr.cryptohash.test;

import fr.cryptohash.Digest;
import fr.cryptohash.SHA384;
import org.testng.annotations.Test;

import static fr.cryptohash.TestSupportUtils.*;

public class SHA384Test {
    @Test
    public void testSHA384() {
        Digest dig = new SHA384();
        testKat(dig, "abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                        + "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
        testKat(dig, "abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                + "klmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
                + "qrsmnopqrstnopqrstu",
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"
                        + "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");

        testKatMillionA(dig,
                "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"
                        + "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985");

        reportSuccess("SHA-384");
    }
}
