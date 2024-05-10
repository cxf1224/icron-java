/*
 *  LIBICC -- IronCap Crypto library
 *
 *  Copyright (C) 2019-2021 01 Communique Laboratory Inc
 */

package com.zeroone.libicc;


import java.net.URL;

/**
 * Class that encapsulates LibICC interface
 */
public class LibICC implements AutoCloseable {
    /**
     * Encryption types.
     * Should be in sync with ICC_ENCRYPTION_TYPE
     */
    public enum EncryptionType {
        VOID(0),
        MM(1),
        KYBER(2),
        CM(3);
        private final int val;
        EncryptionType(int val) {
            this.val = val;
        }
        int value() {
            return val;
        }
    }

    /**
     * Signature type.
     * Should be in sync with ICC_SIGNATURE_TYPE
     */
    public enum SignatureType {
        VOID(0),
        DILITHIUM(2),
        FALCON(3),
        SPHINCSPLUS_SIMPLE(5);
        private final int val;
        SignatureType(int val) {
            this.val = val;
        }
        int value() {
            return val;
        }
    }

    /**
     * Hash algorithm type.
     * Should be in sync with ICC_HASH_TYPE
     */
    public enum HashType {
        VOID(0),
        SHA256(1),
        SHAKE256(2);
        private final int val;
        HashType(int val) {
            this.val = val;
        }
        int value() {
            return val;
        }
    }

    /**
     * ICC supported bit security levels
     */
    public enum BitSecurityLevel {
        ICC_BIT_SECURITY_UNKNOWN(0),
        ICC_BIT_SECURITY_128(128),
        ICC_BIT_SECURITY_192(192),
        ICC_BIT_SECURITY_256(256);

        private int mValue;
        BitSecurityLevel(int value) {
            mValue = value;
        }
        int getValue() {
            return mValue;
        }
    }

    /**
     * Returns Bit Security Level
     * @return bit security level
     */
    public BitSecurityLevel getBitSecurityLevel() {
        int bitSecurityLevel = nativeGetSecurityLevel(mContext);
        for (BitSecurityLevel bsl: BitSecurityLevel.values()) {
            if (bsl.getValue() == bitSecurityLevel) {
                return bsl;
            }
        }
        throw new IllegalStateException("Wrong BitSecurityLevel");
    }

    /**
     * Sign a message.
     *
     * @param msg message for signing
     * @return result of signing
     * @throws LibIccException in case of error
     */
    public byte[] sign(byte[] msg) throws LibIccException {
        if (msg == null) {
            throw new NullPointerException("msg == null");
        }
        return nativeSign(mContext, msg);
    }

    /**
     * Verify a message signature.
     *
     * @param msg message for signing
     * @param signature message signature
     * @return true if the signature is successfully verified, false otherwise
     * @throws LibIccException in case of error
     */
    public boolean verify(byte[] msg, byte[] signature) throws LibIccException {
        if (msg == null) {
            throw new NullPointerException("msg == null");
        }
        if (signature == null) {
            throw new NullPointerException("signature == null");
        }
        return nativeVerify(mContext, msg, signature);
    }

    /**
     * Encrypt a message.
     *
     * @param msg 32-byte long session key for encryption
     * @return result of encoding
     * @throws LibIccException in case of error
     */
    public byte[] encrypt(byte[] msg) throws LibIccException {
        if (msg == null) {
            throw new NullPointerException("msg == null");
        }
        return nativeEncrypt(mContext, msg);
    }

    /**
     * Decrypt a message.
     * @param msg message for decryption
     * @return result of decoding
     * @throws LibIccException in case of error
     */
    public byte[] decrypt(byte[] msg) throws LibIccException {
        if (msg == null) {
            throw new NullPointerException("msg == null");
        }
        return nativeDecrypt(mContext, msg);
    }

    /**
     * Export DER representation of ICC public key.
     *
     * @return DER representation of public key
     * @throws LibIccException in case of error
     */
    public byte[] getPublicKey()  throws LibIccException {
        return nativeExportPublic(mContext);
    }

    /**
     * Export DER representation of ICC private key.
     *
     * @return DER representation of private key
     * @throws LibIccException in case of error
     */
    public byte[] getPrivateKey()  throws LibIccException {
        return nativeExportPrivate(mContext);
    }

    /**
     * Closes the instance releasing allocated resources.
     */
    @Override
    public void close() {
        if (mContext != 0) {
            long ctx = mContext;
            mContext = 0;
            nativeFree(ctx);
        }
    }

    /**
     * Create an instance of LibICC with newly generated keypair.
     *
     * @param bitSecurityLevel bit security level for new keypair
     * @return instance of LibICC
     * @throws LibIccException in case of error
     */
    public static LibICC newKeypair(BitSecurityLevel bitSecurityLevel) throws LibIccException {
        return newKeypair(
                EncryptionType.MM,
                SignatureType.SPHINCSPLUS_SIMPLE,
                HashType.SHA256,
                bitSecurityLevel);
    }

    /**
     * Create an instance of LibICC with newly generated keypair.
     *
     * @param encryptionType encryption type
     * @param signatureType signature type
     * @param hashType hash type
     * @param bitSecurityLevel bit security level for new keypair
     * @return instance of LibICC
     * @throws LibIccException in case of error
     */
    public static LibICC newKeypair(
            EncryptionType encryptionType,
            SignatureType signatureType,
            HashType hashType,
            BitSecurityLevel bitSecurityLevel) throws LibIccException {
        if (encryptionType == null) {
            throw new NullPointerException("encryptionType == null");
        }
        if (signatureType == null) {
            throw new NullPointerException("signatureType == null");
        }
        if (hashType == null) {
            throw new NullPointerException("hashType == null");
        }
        if (bitSecurityLevel == null) {
            throw new NullPointerException("bitSecurityLevel == null");
        }
        LibICC key = new LibICC(
                null,
                null,
                bitSecurityLevel,
                encryptionType,
                signatureType,
                hashType);
        key.createKeypair(bitSecurityLevel);
        return key;
    }

    /**
     * Create an instance of LibICC with provided keypair.
     *
     * @param pubKey public key of the keypair in DER format
     * @param privKey private key of the keypair in DER format
     * @param minBitSecurityLevel minimum expected bit security level of the keypair
     * @return instance of LibICC
     * @throws LibIccException in case of error
     */
    public static LibICC withKeypair(byte[] pubKey, byte[] privKey, BitSecurityLevel minBitSecurityLevel) throws LibIccException {
        if (pubKey == null) {
            throw new NullPointerException("pubKey == null");
        }
        if (privKey == null) {
            throw new NullPointerException("privKey == null");
        }
        if (minBitSecurityLevel == null) {
            throw new NullPointerException("bitSecurityLevel == null");
        }
        return new LibICC(
                pubKey,
                privKey,
                minBitSecurityLevel,
                EncryptionType.VOID,
                SignatureType.VOID,
                HashType.VOID);
    }

    /**
     * Create an instance of LibICC with provided public key.
     *
     * @param pubKey public key in DER format
     * @param bitSecurityLevel minimum expected bit security level of public key
     * @return instance of LibICC
     * @throws LibIccException in case of error
     */
    public static LibICC withPublicKey(byte[] pubKey, BitSecurityLevel bitSecurityLevel) throws LibIccException {
        if (pubKey == null) {
            throw new NullPointerException("pubKey == null");
        }
        if (bitSecurityLevel == null) {
            throw new NullPointerException("bitSecurityLevel == null");
        }
        return new LibICC(
                pubKey,
                null,
                bitSecurityLevel,
                EncryptionType.VOID,
                SignatureType.VOID,
                HashType.VOID);
    }

    static {

//         String lib = System.getenv("lib"); aaaaaa
//        System.out.println("lib >>>>>>>>>"+lib);
//        String libPath = System.getProperty("java.library.path");
//        System.out.println("libPath >>>>>>>>> "+libPath);



//        String lib = System.getenv("lib");
//        System.load(lib);
//        System.loadLibrary("E:\\icron-icc-workspace\\icron-java\\src\\main\\java\\libs\\x86_64\\libicc.so");
        System.loadLibrary("icc-jni");
        libInit();
    }

    private long mContext;

    private LibICC(
                byte[] pubKey,
                byte[] privKey,
                BitSecurityLevel minBitSecurityLevel,
                EncryptionType encryptionType,
                SignatureType signatureType,
                HashType hashType) throws LibIccException {
        mContext = nativeInit(
                pubKey,
                privKey,
                minBitSecurityLevel.getValue(),
                encryptionType.value(),
                signatureType.value(),
                hashType.value());
    }

    private void createKeypair(BitSecurityLevel bitSecurityLevel) throws LibIccException {
        nativeCreateKeypair(mContext, bitSecurityLevel.getValue());
    }

    private static native void libInit();
    private static native long nativeInit(byte[] pkDer, byte[] skDer, int minBitSecurityLevel, int enc, int sig, int hash) throws LibIccException;
    private static native void nativeFree(long context);
    private static native void nativeCreateKeypair(long context, int bitSecurityLevel) throws LibIccException;
    private static native byte[] nativeEncrypt(long context, byte[] buf) throws LibIccException;
    private static native byte[] nativeDecrypt(long context, byte[] buf) throws LibIccException;
    private static native byte[] nativeSign(long context, byte[] buf) throws LibIccException;
    private static native boolean nativeVerify(long context, byte[] msg, byte[] signature) throws LibIccException;
    private static native byte[] nativeExportPublic(long context) throws LibIccException;
    private static native byte[] nativeExportPrivate(long context) throws LibIccException;
    private static native int nativeGetSecurityLevel(long context);
}
