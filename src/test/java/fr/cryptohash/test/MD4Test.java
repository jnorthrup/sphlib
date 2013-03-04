package fr.cryptohash.test;

import fr.cryptohash.Digest;
import fr.cryptohash.MD4;
import org.testng.annotations.Test;

import static fr.cryptohash.TestSupportUtils.*;

public class MD4Test {
    @Test
    public void testMD4() {
        Digest dig = new MD4();
        testKat(dig, "", "31d6cfe0d16ae931b73c59d7e0c089c0");
        testKat(dig, "a", "bde52cb31de33e46245e05fbdbd6fb24");
        testKat(dig, "abc", "a448017aaf21d8525fc10ae87aa6729d");
        testKat(dig, "message digest",
                "d9130a8164549fe818874806e1c7014b");
        testKat(dig, "abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9");
        testKat(dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu"
                + "vwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4");
        testKat(dig, "1234567890123456789012345678901234567890123456789"
                + "0123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536");

        testKatMillionA(dig, "bbce80cc6bb65e5c6745e30d4eeca9a4");

        testCollision(dig,
                "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20"
                        + "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631"
                        + "8edd45e51fe39708bf9427e9c3e8b9",
                "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20"
                        + "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631"
                        + "8edc45e51fe39708bf9427e9c3e8b9");

        testCollision(dig,
                "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20"
                        + "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631"
                        + "8edd45e51fe39740c213f769cfb8a7",
                "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20"
                        + "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631"
                        + "8edc45e51fe39740c213f769cfb8a7");

        reportSuccess("MD4");
    }
}
