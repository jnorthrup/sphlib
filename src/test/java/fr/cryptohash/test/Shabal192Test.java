package fr.cryptohash.test;

import fr.cryptohash.Shabal192;
import org.testng.annotations.Test;

import static fr.cryptohash.TestSupportUtils.reportSuccess;
import static fr.cryptohash.TestSupportUtils.testKat;

public class Shabal192Test {
    @Test
    public void testShabal192() {
        testKat(new Shabal192(),
                "abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLM"
                        + "NOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
                "690FAE79226D95760AE8FDB4F58C0537111756557D307B15");
        reportSuccess("Shabal-192");
    }
}
