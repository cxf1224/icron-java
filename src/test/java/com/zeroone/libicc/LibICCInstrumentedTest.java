package com.zeroone.libicc;

import com.zeroone.libicc.LibICC.BitSecurityLevel;
import com.zeroone.libicc.LibICC.EncryptionType;
import com.zeroone.libicc.LibICC.HashType;
import com.zeroone.libicc.LibICC.SignatureType;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;


import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Collection;


@RunWith(Parameterized.class)
public class LibICCInstrumentedTest {

    @Before
    public void beforeAll(){

//        java.library.path=E:\icron-icc-workspace\icron-java\src\main\jni\ICC.h
//        System.setProperty("java.library.path", "E:\\icron-icc-workspace\\icron-java\\src\\main\\jni");
//        System.out.println(System.getProperty("java.library.path"));
    }

    @Parameter
    public CryptoType cryptoType;
    @Parameters
    public static Collection<CryptoType> params() {
        Collection<CryptoType> result = new ArrayList<>();
        result.add(new CryptoType(EncryptionType.MM, SignatureType.SPHINCSPLUS_SIMPLE, HashType.SHA256));
        result.add(new CryptoType(EncryptionType.MM, SignatureType.SPHINCSPLUS_SIMPLE, HashType.SHAKE256));
        result.add(new CryptoType(EncryptionType.MM, SignatureType.DILITHIUM, HashType.SHAKE256));
        result.add(new CryptoType(EncryptionType.MM, SignatureType.FALCON, HashType.SHAKE256));
        result.add(new CryptoType(EncryptionType.KYBER, SignatureType.SPHINCSPLUS_SIMPLE, HashType.SHAKE256));
        result.add(new CryptoType(EncryptionType.KYBER, SignatureType.DILITHIUM, HashType.SHAKE256));
        result.add(new CryptoType(EncryptionType.KYBER, SignatureType.FALCON, HashType.SHAKE256));
        result.add(new CryptoType(EncryptionType.CM, SignatureType.SPHINCSPLUS_SIMPLE, HashType.SHAKE256));
        result.add(new CryptoType(EncryptionType.CM, SignatureType.DILITHIUM, HashType.SHAKE256));
        result.add(new CryptoType(EncryptionType.CM, SignatureType.FALCON, HashType.SHAKE256));

        return result;
    }

    @Ignore
    @Test
    public void testBslIsEnough() throws Exception {
        byte[] pubKey;
        try (LibICC icc = LibICC.newKeypair(
                cryptoType.encryptionType,
                cryptoType.signatureType,
                cryptoType.hashType,
                BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            pubKey = icc.getPublicKey();
        }
        try (LibICC icc = LibICC.withPublicKey(pubKey, BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            assertTrue(true); // no exceptions
        }
    }

    @Ignore
    @Test(expected = LibIccException.class)
    public void testBslIsNotEnough() throws Exception {
        byte[] pubKey;
        try (LibICC icc = LibICC.newKeypair(
                cryptoType.encryptionType,
                cryptoType.signatureType,
                cryptoType.hashType,
                BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            pubKey = icc.getPublicKey();
        }
        try (LibICC icc = LibICC.withPublicKey(pubKey, BitSecurityLevel.ICC_BIT_SECURITY_256)) {
            fail(); // should throw exception in the line above
        }
    }

    @Test
    public void testSignOk() throws Exception {
        byte[] pubKey;
        byte[] signature;
        byte[] input = new byte[32];
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) (i + 3);
        }
        try (LibICC signer = LibICC.newKeypair(
                cryptoType.encryptionType,
                cryptoType.signatureType,
                cryptoType.hashType,
                BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            pubKey = signer.getPublicKey();
            signature = signer.sign(input);
        }

        try (LibICC verifier = LibICC.withPublicKey(pubKey, BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            boolean ok = verifier.verify(input, signature);
            assertTrue(ok);
        }
    }

    @Ignore
    @Test
    public void testSignWrongKey() throws Exception {
        byte[] wrongKey;
        byte[] signature;
        byte[] input = new byte[32];
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) (i + 3);
        }
        try (LibICC signer = LibICC.newKeypair(
                cryptoType.encryptionType,
                cryptoType.signatureType,
                cryptoType.hashType,
                BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            signature = signer.sign(input);
        }

        try (LibICC anotherICC = LibICC.newKeypair(
                cryptoType.encryptionType,
                cryptoType.signatureType,
                cryptoType.hashType,
                BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            wrongKey = anotherICC.getPublicKey();
        }

        try (LibICC verifier = LibICC.withPublicKey(wrongKey, BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            boolean ok = verifier.verify(input, signature);
            assertFalse(ok);
        }
    }

    @Ignore
    @Test
    public void testSignWrongData() throws Exception {
        byte[] pubKey;
        byte[] signature;
        byte[] input1 = new byte[32];
        for (int i = 0; i < input1.length; i++) {
            input1[i] = (byte) (i + 3);
        }
        byte[] input2 = new byte[32];
        for (int i = 0; i < input2.length; i++) {
            input2[i] = (byte) (i + 4);
        }
        try (LibICC signer = LibICC.newKeypair(
                cryptoType.encryptionType,
                cryptoType.signatureType,
                cryptoType.hashType,
                BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            pubKey = signer.getPublicKey();
            signature = signer.sign(input2);
        }

        try (LibICC verifier = LibICC.withPublicKey(pubKey, BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            boolean ok = verifier.verify(input1, signature);
            assertFalse(ok);
        }
    }

    @Ignore
    @Test
    public void testEncrypt() throws Exception {
        try (LibICC icc = LibICC.newKeypair(
                cryptoType.encryptionType,
                cryptoType.signatureType,
                cryptoType.hashType,
                BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            byte[] input = new byte[32];
            for (int i = 0; i < input.length; i++) {
                input[i] = (byte) (i + 3);
            }


            byte[] encrypted = icc.encrypt(input);

            byte[] decrypted = icc.decrypt(encrypted);
            assertEquals(32, decrypted.length);
            assertArrayEquals(input, decrypted);
        }
    }

    @Ignore
    @Test
    public void testExportKeys() throws Exception {
        byte[] privKey;
        byte[] pubKey;
        LibICC.BitSecurityLevel bsl;

        byte[] input = new byte[32];
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) (i + 2);
        }
        byte[] encrypted;

        try (LibICC icc = LibICC.newKeypair(
                cryptoType.encryptionType,
                cryptoType.signatureType,
                cryptoType.hashType,
                BitSecurityLevel.ICC_BIT_SECURITY_128)) {
            privKey = icc.getPrivateKey();
            pubKey = icc.getPublicKey();
            bsl = icc.getBitSecurityLevel();

            encrypted = icc.encrypt(input);
        }

        try (LibICC cloned = LibICC.withKeypair(pubKey, privKey, bsl)) {
            byte[] decrypted = cloned.decrypt(encrypted);
            assertEquals(32, decrypted.length);
            assertArrayEquals(input, decrypted);
        }
    }

    private static class CryptoType {
        public final EncryptionType encryptionType;
        public final SignatureType signatureType;
        public final HashType hashType;
        public CryptoType(EncryptionType encryptionType,
                          SignatureType signatureType,
                          HashType hashType) {
            this.encryptionType = encryptionType;
            this.signatureType = signatureType;
            this.hashType = hashType;
        }
    }

}