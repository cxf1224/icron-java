#include <jni.h>
#include <stdlib.h>
#include "ICC.h"
#include <android/log.h>



/* Source of entropy FOR TESTING ONLY (Replace it before use in production!) */
static int test_random(uint8_t *buffer, uint32_t size)
{
    for (; size != 0; size--)
        buffer[size-1] = (uint8_t) rand();
    return 0;
}

#define EXCEPTION_CLASS "com/zeroone/libicc/LibIccException"

static jclass class_LibIccException;
static jmethodID ctor_LibIccException;

static void throwException(JNIEnv *env, ICC_ERR code) {
    jobject exceptionObject = (*env)->NewObject(env, class_LibIccException, ctor_LibIccException, (jint)code);
    if (exceptionObject == NULL) {
        return;
    }
    (*env)->Throw(env, exceptionObject);
}

void
Java_com_zeroone_libicc_LibICC_libInit(JNIEnv *env, __unused jclass clazz)
{
    jclass exceptionClass = (*env)->FindClass(env, EXCEPTION_CLASS);
    if (exceptionClass == NULL) {
        return;
    }
    ctor_LibIccException = (*env)->GetMethodID(env, exceptionClass, "<init>", "(I)V");
    class_LibIccException = (*env)->NewGlobalRef(env, exceptionClass);
    (*env)->DeleteLocalRef(env, exceptionClass);
}

jlong
Java_com_zeroone_libicc_LibICC_nativeInit(JNIEnv *env, __unused jclass clazz,
                                          jbyteArray pkDer, jbyteArray skDer,
                                          jint minBitSecurityLevel,
                                          jint enc,
                                          jint sig,
                                          jint hash)
{
    jboolean isCopy;
    jbyte *pk_der = pkDer ? (*env)->GetByteArrayElements(env, pkDer, &isCopy) : NULL;
    jint pk_der_len = pkDer ? (*env)->GetArrayLength(env, pkDer) : 0;
    jbyte *sk_der = skDer ? (*env)->GetByteArrayElements(env, skDer, &isCopy) : NULL;
    jint sk_der_len = skDer ? (*env)->GetArrayLength(env, skDer) : 0;

    uint32_t key_type = MAKE_ICC_HASH_ENCRYPTION_SIGNATURE_TYPE(hash, enc, sig);
    if (key_type == ICC_HSH_ENC_SIG_VOID_VOID_VOID) {
        if (pk_der != NULL) {
            key_type = ICC_get_pk_type(pk_der, pk_der_len);
            if (key_type == ICC_HSH_ENC_SIG_VOID_VOID_VOID) {
                throwException(env, ICC_UNRECOGNIZED);
                return 0;
            }
            if (sk_der != NULL) {
                uint32_t sk_key_type = ICC_get_sk_type(sk_der, sk_der_len);
                if (key_type != sk_key_type) {
                    throwException(env, ICC_KEYPAIR);
                    return 0;
                }
            }
        }
    }
    ICC_ERR err = ICC_is_type_enabled(key_type);
    if (err != ICC_OK) {
        throwException(env, err);
        return 0;
    }

    ICC_CONTEXT *ctx = ICC_init(
            test_random,
            key_type,
            pk_der,
            pk_der_len,
            sk_der,
            sk_der_len,
            minBitSecurityLevel);

    if (pkDer != NULL)
        (*env)->ReleaseByteArrayElements(env, pkDer, pk_der, JNI_ABORT);
    if (skDer != NULL)
        (*env)->ReleaseByteArrayElements(env, skDer, sk_der, JNI_ABORT);
    if (ctx == NULL) {
        throwException(env, ICC_get_last_error(NULL));
    }
    return (jlong) ctx;
}

void
Java_com_zeroone_libicc_LibICC_nativeFree(JNIEnv *env, __unused jclass clazz, jlong param)
{
    ICC_CONTEXT *ctx = (ICC_CONTEXT *) param;
    ICC_ERR err = ICC_free(ctx, ICC_FREE_PURGE_CONTEXT);
    if (err != ICC_OK) {
        throwException(env, err);
    }
}

void
Java_com_zeroone_libicc_LibICC_nativeCreateKeypair(JNIEnv *env, __unused jclass clazz, jlong context, jint bitSecurityLevel)
{
    ICC_CONTEXT *ctx = (ICC_CONTEXT *) context;
    ICC_ERR err = ICC_create_keypair(ctx, bitSecurityLevel);
    if (err != ICC_OK) {
        throwException(env, err);
        return;
    }
}

jbyteArray
Java_com_zeroone_libicc_LibICC_nativeEncrypt(JNIEnv *env, __unused jclass clazz, jlong param, jbyteArray inBuf) {
    if (inBuf == NULL) {
        return NULL;
    }

    jboolean isCopy;
    jbyte *in_buf = (*env)->GetByteArrayElements(env, inBuf, &isCopy);
    if (in_buf == NULL) {
        return NULL;
    }
    jint in_buf_len = (*env)->GetArrayLength(env, inBuf);
    ICC_CONTEXT *ctx = (ICC_CONTEXT *) param;
    ICC_bit_security_level bitSecurityLevel = ICC_get_bit_security(ctx);
    int enc_size = ICC_get_ciphertext_size(ctx, in_buf_len, bitSecurityLevel);
    if (enc_size < 0) {
        throwException(env, ICC_ENCRYPT);
        return NULL;
    }
    char *encrypted = malloc((size_t)enc_size);
    if (encrypted == NULL) {
        throwException(env, ICC_MEMORY);
        return NULL;
    }
    ICC_ERR err = ICC_encrypt(ctx, in_buf, in_buf_len, encrypted, &enc_size);
    (*env)->ReleaseByteArrayElements(env, inBuf, in_buf, JNI_ABORT);
    if (err != ICC_OK) {
        throwException(env, err);
        free(encrypted);
        return NULL;
    }
    jbyteArray *outBuf = (*env)->NewByteArray(env, enc_size);
    if (outBuf == NULL) {
        free(encrypted);
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, outBuf, 0, enc_size, encrypted);
    free(encrypted);
    return outBuf;
}

jbyteArray
Java_com_zeroone_libicc_LibICC_nativeDecrypt(JNIEnv *env, __unused jclass clazz, jlong param, jbyteArray inBuf) {
    if (inBuf == NULL) {
        return NULL;
    }

    jboolean isCopy;
    jbyte *in_buf = (*env)->GetByteArrayElements(env, inBuf, &isCopy);
    if (in_buf == NULL) {
        return NULL;
    }
    jint in_buf_len = (*env)->GetArrayLength(env, inBuf);
    ICC_CONTEXT *ctx = (ICC_CONTEXT *) param;
    ICC_bit_security_level bitSecurityLevel = ICC_get_bit_security(ctx);
    int dec_size = ICC_get_plaintext_size(ctx, in_buf_len, bitSecurityLevel);
    if (dec_size < 0) {
        throwException(env, ICC_DECRYPT);
        return NULL;
    }
    char *decrypted = malloc(dec_size);
    if (decrypted == NULL) {
        throwException(env, ICC_MEMORY);
        return NULL;
    }
    ICC_ERR err = ICC_decrypt(ctx, in_buf, in_buf_len, decrypted, &dec_size);
    (*env)->ReleaseByteArrayElements(env, inBuf, in_buf, JNI_ABORT);
    if (err != ICC_OK) {
        throwException(env, err);
        free(decrypted);
        return NULL;
    }
    jbyteArray *outBuf = (*env)->NewByteArray(env, dec_size);
    if (outBuf == NULL) {
        free(decrypted);
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, outBuf, 0, dec_size, decrypted);
    free(decrypted);
    return outBuf;
}

jbyteArray
Java_com_zeroone_libicc_LibICC_nativeSign(JNIEnv *env, __unused jclass clazz, jlong param, jbyteArray inBuf) {
    if (inBuf == NULL) {
        return NULL;
    }

    ICC_CONTEXT *ctx = (ICC_CONTEXT *) param;
    ICC_bit_security_level bitSecurityLevel = ICC_get_bit_security(ctx);
    int sign_size = ICC_get_signature_size(ctx, bitSecurityLevel);
    if (sign_size <= 0) {
        throwException(env, ICC_SIGN);
        return NULL;
    }

    char *sign_buf = malloc(sign_size);
    if (sign_buf == NULL) {
        throwException(env, ICC_MEMORY);
        return NULL;
    }

    jboolean isCopy;
    jbyte *in_buf = (*env)->GetByteArrayElements(env, inBuf, &isCopy);
    if (in_buf == NULL) {
        free(sign_buf);
        return NULL;
    }
    jint in_buf_len = (*env)->GetArrayLength(env, inBuf);

    ICC_ERR err = ICC_sign(ctx, in_buf, in_buf_len, sign_buf, &sign_size);
    (*env)->ReleaseByteArrayElements(env, inBuf, in_buf, JNI_ABORT);
    if (err != ICC_OK) {
        free(sign_buf);
        throwException(env, err);
        return NULL;
    }
    jbyteArray outBuf = (*env)->NewByteArray(env, sign_size);
    if (outBuf == NULL) {
        free(sign_buf);
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, outBuf, 0, sign_size, sign_buf);
    free(sign_buf);
    return outBuf;
}

jboolean
Java_com_zeroone_libicc_LibICC_nativeVerify(JNIEnv *env, __unused jclass clazz, jlong param,
        jbyteArray msg, jbyteArray signature) {
    if (msg == NULL || signature == NULL) {
        return JNI_FALSE;
    }

    jboolean isCopy;
    jbyte *msg_buf = (*env)->GetByteArrayElements(env, msg, &isCopy);
    if (msg_buf == NULL) {
        return JNI_FALSE;
    }
    jint msg_buf_len = (*env)->GetArrayLength(env, msg);

    jbyte *sig_buf = (*env)->GetByteArrayElements(env, signature, &isCopy);
    if (sig_buf == NULL) {
        return JNI_FALSE;
    }
    jint sig_buf_len = (*env)->GetArrayLength(env, signature);

    ICC_CONTEXT *ctx = (ICC_CONTEXT *) param;
    ICC_ERR err = ICC_verify(ctx, msg_buf, msg_buf_len, sig_buf, sig_buf_len);
    (*env)->ReleaseByteArrayElements(env, msg, msg_buf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, signature, sig_buf, JNI_ABORT);
    if (err != ICC_OK && err != ICC_VERIFY) {
        throwException(env, err);
        return JNI_FALSE;
    }
    return err == ICC_OK ? JNI_TRUE : JNI_FALSE;
}

jbyteArray
Java_com_zeroone_libicc_LibICC_nativeExportPublic(JNIEnv *env, __unused jclass clazz, jlong param) {
    ICC_CONTEXT *ctx = (ICC_CONTEXT *) param;
    uint32_t der_size;
    unsigned char *der_buf = ICC_export_public(ctx, &der_size);
    if (der_buf == NULL) {
        throwException(env, ICC_get_last_error(ctx));
        return NULL;
    }
    jbyteArray *outBuf = (*env)->NewByteArray(env, (jsize)der_size);
    if (outBuf == NULL) {
        ICC_free_export(der_buf);
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, outBuf, 0, (jsize)der_size, der_buf);
    ICC_free_export(der_buf);
    return outBuf;
}

jbyteArray
Java_com_zeroone_libicc_LibICC_nativeExportPrivate(JNIEnv *env, __unused jclass clazz, jlong param) {
    ICC_CONTEXT *ctx = (ICC_CONTEXT *) param;
    uint32_t der_size;
    unsigned char *der_buf = ICC_export_private(ctx, &der_size);
    if (der_buf == NULL) {
        throwException(env, ICC_get_last_error(ctx));
        return NULL;
    }
    jbyteArray *outBuf = (*env)->NewByteArray(env, (jsize)der_size);
    if (outBuf == NULL) {
        ICC_free_export(der_buf);
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, outBuf, 0, (jsize)der_size, der_buf);
    ICC_free_export(der_buf);
    return outBuf;
}

JNIEXPORT jint JNICALL
Java_com_zeroone_libicc_LibICC_nativeGetSecurityLevel(JNIEnv *env, jclass clazz, jlong context) {
    ICC_CONTEXT *ctx = (ICC_CONTEXT *) context;
    ICC_bit_security_level bitSecurityLevel = ICC_get_bit_security(ctx);
    return (jint)bitSecurityLevel;
}