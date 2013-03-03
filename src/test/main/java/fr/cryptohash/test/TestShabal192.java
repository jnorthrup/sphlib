 package fr.cryptohash.test; import fr.cryptohash.*; import junit.framework.TestCase; import static  fr.cryptohash.TestDigest.*; public class TestShabal192 extends TestCase{     void testShabal192() {
        testKat(new Shabal192(),
                "abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLM"
                        + "NOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
                "690FAE79226D95760AE8FDB4F58C0537111756557D307B15");
        reportSuccess("Shabal-192");
    }}
