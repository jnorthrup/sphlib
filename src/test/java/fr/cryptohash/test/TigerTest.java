package fr.cryptohash.test;

import fr.cryptohash.Digest;
import fr.cryptohash.Tiger;
import fr.cryptohash.Tiger2;
import org.testng.annotations.Test;

import static fr.cryptohash.TestSupportUtils.*;

public class TigerTest {
    @Test
    public void testTiger() {
        Digest dig = new Tiger();
        testKat(dig, "",
                "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3");
        testKat(dig, "a",
                "77BEFBEF2E7EF8AB2EC8F93BF587A7FC613E247F5F247809");
        testKat(dig, "abc",
                "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93");
        testKat(dig, "message digest",
                "D981F8CB78201A950DCF3048751E441C517FCA1AA55A29F6");
        testKat(dig, "abcdefghijklmnopqrstuvwxyz",
                "1714A472EEE57D30040412BFCC55032A0B11602FF37BEEE9");
        testKat(dig, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmn"
                + "lmnomnopnopq",
                "0F7BF9A19B9C58F2B7610DF7E84F0AC3A71C631E7B53F78E");
        testKat(dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz0123456789",
                "8DCEA680A17583EE502BA38A3C368651890FFBCCDC49A8CC");
        testKat(dig, "1234567890123456789012345678901234567890"
                + "1234567890123456789012345678901234567890",
                "1C14795529FD9F207A958F84C52F11E887FA0CABDFD91BFD");

        testKatMillionA(dig,
                "6DB0E2729CBEAD93D715C6A7D36302E9B3CEE0D2BC314B41");

        reportSuccess("Tiger");
    }

    @Test
    public void testTiger2() {
        Digest dig = new Tiger2();
        testKat(dig, "",
                "4441BE75F6018773C206C22745374B924AA8313FEF919F41");
        testKat(dig, "a",
                "67E6AE8E9E968999F70A23E72AEAA9251CBC7C78A7916636");
        testKat(dig, "abc",
                "F68D7BC5AF4B43A06E048D7829560D4A9415658BB0B1F3BF");
        testKat(dig, "message digest",
                "E29419A1B5FA259DE8005E7DE75078EA81A542EF2552462D");
        testKat(dig, "abcdefghijklmnopqrstuvwxyz",
                "F5B6B6A78C405C8547E91CD8624CB8BE83FC804A474488FD");
        testKat(dig, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmn"
                + "lmnomnopnopq",
                "A6737F3997E8FBB63D20D2DF88F86376B5FE2D5CE36646A9");
        testKat(dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "abcdefghijklmnopqrstuvwxyz0123456789",
                "EA9AB6228CEE7B51B77544FCA6066C8CBB5BBAE6319505CD");
        testKat(dig, "1234567890123456789012345678901234567890"
                + "1234567890123456789012345678901234567890",
                "D85278115329EBAA0EEC85ECDC5396FDA8AA3A5820942FFF");

        testKatMillionA(dig,
                "E068281F060F551628CC5715B9D0226796914D45F7717CF4");

        reportSuccess("Tiger2");
    }
}
