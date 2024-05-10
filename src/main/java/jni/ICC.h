/*
 *  LIBICC -- IronCap Crypto library
 *
 *  Copyright (C) 2019-2023 01 Communique Laboratory Inc
 */

#ifndef ICCLIB_API_H
#define ICCLIB_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdlib.h>
#ifdef CONSOLE_LOG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

#define ICC_VERSION     5

typedef enum _ICC_ERR {
    ICC_OK = 0,
    ICC_KEYPAIR,
    ICC_ENCRYPT,
    ICC_DECRYPT,
    ICC_IND_CCA2,
    ICC_INVALID_DATA,
    ICC_HASH,
    ICC_WEIGHT,
    ICC_RANDOM,
    ICC_BAD_CONTEXT,
    ICC_MEMORY,
    ICC_UNRECOGNIZED,
    ICC_SIGN,
    ICC_VERIFY,
    ICC_BAD_PK,
    ICC_BAD_SK,
    ICC_UNKNOWN
} ICC_ERR;

typedef enum _ICC_ENCRYPTION_TYPE {
    ICC_ENC_VOID  = 0,
    ICC_ENC_MM    = 1,
	ICC_ENC_KYBER = 2,
	ICC_ENC_CM = 3
} ICC_ENCRYPTION_TYPE;
#define ICC_ENC_DEFAULT ICC_ENC_MM

typedef enum _ICC_SIGNATURE_TYPE {
    ICC_SIG_VOID                 = 0,
    ICC_SIG_DILITHIUM            = 2,
	ICC_SIG_FALCON               = 3,
	ICC_SIG_SPHINCSPLUS_SIMPLE   = 5
} ICC_SIGNATURE_TYPE;
#define ICC_SIG_DEFAULT ICC_SIG_SPHINCSPLUS_SIMPLE

typedef enum _ICC_HASH_TYPE {
    ICC_HASH_VOID     = 0,
    ICC_HASH_SHA256   = 1,
    ICC_HASH_SHAKE256 = 2,
} ICC_HASH_TYPE;
#define ICC_HASH_DEFAULT ICC_HASH_SHA256

/* Defaulting hash type to ICC_HASH_SHA256
 */
typedef enum _ICC_HASH_ENCRYPTION_SIGNATURE_TYPE {
    ICC_HSH_ENC_SIG_VOID_VOID_VOID             = ICC_SIG_VOID        | (ICC_ENC_VOID << 8)    | (ICC_HASH_VOID << 16),
	ICC_HSH_ENC_SIG_SHA256_MM_SPHINCSPLUS_SIMPLE = ICC_SIG_SPHINCSPLUS_SIMPLE | (ICC_ENC_MM << 8) | (ICC_HASH_SHA256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_MM_SPHINCSPLUS_SIMPLE = ICC_SIG_SPHINCSPLUS_SIMPLE | (ICC_ENC_MM << 8) | (ICC_HASH_SHAKE256 << 16),
    ICC_HSH_ENC_SIG_SHAKE256_MM_DILITHIUM      = ICC_SIG_DILITHIUM   | (ICC_ENC_MM << 8)      | (ICC_HASH_SHAKE256 << 16),
    ICC_HSH_ENC_SIG_SHA256_MM_VOID             = ICC_SIG_VOID        | (ICC_ENC_MM << 8)      | (ICC_HASH_SHA256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_MM_VOID = ICC_SIG_VOID | (ICC_ENC_MM << 8) | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_KYBER_SPHINCSPLUS_SIMPLE = ICC_SIG_SPHINCSPLUS_SIMPLE | (ICC_ENC_KYBER << 8) | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_KYBER_DILITHIUM   = ICC_SIG_DILITHIUM   | (ICC_ENC_KYBER << 8)   | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_KYBER_VOID        = ICC_SIG_VOID        | (ICC_ENC_KYBER << 8)   | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHA256_VOID_SPHINCSPLUS_SIMPLE = ICC_SIG_SPHINCSPLUS_SIMPLE | (ICC_ENC_VOID << 8) | (ICC_HASH_SHA256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_VOID_SPHINCSPLUS_SIMPLE = ICC_SIG_SPHINCSPLUS_SIMPLE | (ICC_ENC_VOID << 8) | (ICC_HASH_SHAKE256 << 16),
    ICC_HSH_ENC_SIG_SHAKE256_VOID_DILITHIUM    = ICC_SIG_DILITHIUM   | (ICC_ENC_VOID << 8)    | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_MM_FALCON         = ICC_SIG_FALCON      | (ICC_ENC_MM << 8)      | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_KYBER_FALCON      = ICC_SIG_FALCON      | (ICC_ENC_KYBER << 8)   | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_VOID_FALCON       = ICC_SIG_FALCON      | (ICC_ENC_VOID << 8)    | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_CM_VOID           = ICC_SIG_VOID        | (ICC_ENC_CM << 8)      | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_CM_SPHINCSPLUS_SIMPLE = ICC_SIG_SPHINCSPLUS_SIMPLE | (ICC_ENC_CM << 8) | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_CM_DILITHIUM      = ICC_SIG_DILITHIUM   | (ICC_ENC_CM << 8)      | (ICC_HASH_SHAKE256 << 16),
	ICC_HSH_ENC_SIG_SHAKE256_CM_FALCON         = ICC_SIG_FALCON      | (ICC_ENC_CM << 8)      | (ICC_HASH_SHAKE256 << 16)
} ICC_HASH_ENCRYPTION_SIGNATURE_TYPE;

/* ICC OIDs
 * 01 Communique         1.3.6.1.4.1.53226
 * 01 Communique Crypto  1.3.6.1.4.1.53226.1.Hash.Encryption.Signature
 */
static const unsigned int ICC_OID[11] =                          { 1, 3, 6, 1, 4, 1, 53226, 1, 0, 0, 0 };
static const unsigned int ICC_OID_SHA256_MM[11] =                { 1, 3, 6, 1, 4, 1, 53226, 1, 1, 1, 0 };
static const unsigned int ICC_OID_SHAKE256_MM[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 1, 0 };
static const unsigned int ICC_OID_SHA256_MM_SPHICSPLUS_SIMPLE[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 1, 1, 5 };
static const unsigned int ICC_OID_SHAKE256_MM_SPHICSPLUS_SIMPLE[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 1, 5 };
static const unsigned int ICC_OID_SHAKE256_MM_DILITHIUM[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 1, 4 };
static const unsigned int ICC_OID_SHA256_SPHICSPLUS_SIMPLE[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 1, 0, 5 };
static const unsigned int ICC_OID_SHAKE256_SPHICSPLUS_SIMPLE[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 0, 5 };
static const unsigned int ICC_OID_SHAKE256_DILITHIUM[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 0, 4 };
static const unsigned int ICC_OID_SHAKE256_KYBER[11] =           { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 2, 0 };
static const unsigned int ICC_OID_SHAKE256_KYBER_SPHICSPLUS_SIMPLE[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 2, 5 };
static const unsigned int ICC_OID_SHAKE256_KYBER_DILITHIUM[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 2, 4 };
static const unsigned int ICC_OID_SHAKE256_FALCON[11] =          { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 0, 3 };
static const unsigned int ICC_OID_SHAKE256_MM_FALCON[11] =       { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 1, 3 };
static const unsigned int ICC_OID_SHAKE256_KYBER_FALCON[11] =    { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 2, 3 };
static const unsigned int ICC_OID_SHAKE256_CM[11] =              { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 3, 0 };
static const unsigned int ICC_OID_SHAKE256_CM_SPHICSPLUS_SIMPLE[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 3, 5 };
static const unsigned int ICC_OID_SHAKE256_CM_DILITHIUM[11] = { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 3, 4 };
static const unsigned int ICC_OID_SHAKE256_CM_FALCON[11] =       { 1, 3, 6, 1, 4, 1, 53226, 1, 2, 3, 3 };

#define GET_ICC_HASH_ENCRYPTION_SIGNATURE_TYPE(flags)          ((flags) & 0xFFFFFF)
#define GET_ICC_ENCRYPTION_SIGNATURE_TYPE(flags)               ((flags) & 0xFFFF)
#define GET_ICC_SIGNATURE_TYPE(hsh_enc_sig)                    (hsh_enc_sig & 0xFF)
#define GET_ICC_ENCRYPTION_TYPE(hsh_enc_sig)                   ((hsh_enc_sig >> 8) & 0xFF)
#define GET_ICC_HASH_TYPE(hsh_enc_sig)                         ((hsh_enc_sig >> 16) & 0xFF)
#define MAKE_ICC_HASH_ENCRYPTION_SIGNATURE_TYPE(hsh, enc, sig) ((ICC_HASH_ENCRYPTION_SIGNATURE_TYPE)((ICC_SIGNATURE_TYPE)sig | \
                                                                                                     (((ICC_ENCRYPTION_TYPE)enc) << 8) | \
                                                                                                     (((ICC_HASH_TYPE)hsh) << 16)))
#define ICC_FLAG_DONT_DERIVE_PK 0x1000000

/* ICC parameters
 */
#pragma pack(push,1)
typedef struct _mm_parameters {
    uint32_t m;
    uint32_t n;
    uint32_t t;
} mm_parameters;

typedef struct _sphincsplus_parameters {
    uint32_t n;
    uint32_t full_height;
    uint32_t d;
    uint32_t fors_height;
    uint32_t fors_trees;
    uint32_t w;
} sphincsplus_parameters;

#ifdef USE_CM
typedef struct _cm_parameters {
	uint32_t gfbits;
	uint32_t sysn;
	uint32_t syst;
} cm_parameters;
#endif

#ifdef USE_FALCON
typedef struct _falcon_parameters {
	uint32_t logn;
} falcon_parameters;
#endif

#ifdef USE_DILITHIUM
typedef struct _dilithium_parameters {
    uint32_t k;
    uint32_t l;
    uint32_t eta;
    uint32_t tau;
    uint32_t beta;
    uint32_t gamma1;
    uint32_t gamma2;
    uint32_t omega;
	uint32_t ctildebytes;
} dilithium_parameters;
#endif

#ifdef USE_KYBER
typedef struct _kyber_parameters {
	uint32_t eta1;
	uint32_t pcb;
	uint32_t pvcb;
} kyber_parameters;
#endif

typedef struct _ICC_parameters {
    uint32_t version;
    uint32_t bit_security;
    uint32_t sign_pars_offset;
    /* Encryption parameters
     */
    union {
        /* Modern McEliece parameters
         */
        mm_parameters mm;
#ifdef USE_KYBER
		kyber_parameters kyber;
#endif
#ifdef USE_CM
		cm_parameters cm;
#endif
    };
    /* Signature parameters
     */
    union {
        /* Sphincs+ parameters
         */
        sphincsplus_parameters sphincsplus;
#ifdef USE_DILITHIUM
        /* Dillithium parameters
         */
        dilithium_parameters dilithium;
#endif
#ifdef USE_FALCON
		falcon_parameters falcon;
#endif
    };
} ICC_parameters;
#pragma pack(pop)

/* ICC supported bit security levels
 */
typedef enum _ICC_bit_security_level {
    ICC_BIT_SECURITY_UNKNOWN = 0,
    ICC_BIT_SECURITY_128 = 128,
    ICC_BIT_SECURITY_192 = 192,
    ICC_BIT_SECURITY_256 = 256,
} ICC_bit_security_level;

typedef enum _ICC_FREE_TYPE {
    ICC_FREE_KEYPAIR = 0,
    ICC_FREE_PURGE_CONTEXT
} ICC_FREE_TYPE;

#ifndef ICC_CONTEXT
#define ICC_CONTEXT void
#endif

/**
 * Description: initialize LIBICC
 * In: rnd - pointer to entropy source
 *     flags - bitfield of flags
 *     pk_der - pointer to public key's DER buffer of pk_size bytes
 *     sk_der - pointer to secret key's DER buffer of sk_size bytes
 *     bsl - when non-0, defines minimal acceptable bit security for the given PK and SK
 * Out: ICC context allocated on success, NULL on failure
 */
ICC_CONTEXT *ICC_init(int (*rnd)(uint8_t *, uint32_t),
                      uint32_t flags,
                      const uint8_t *pk_der, size_t pk_size,
                      const uint8_t *sk_der, size_t sk_size,
                      ICC_bit_security_level bsl);

/**
 * Description: free LIBICC
 * In: ctx - ICC context
 *     purge - if 0, keep the context but free any its keys, otherwise purge all
 * Out: 0 on success or error code
 */
ICC_ERR ICC_free(ICC_CONTEXT *ctx, ICC_FREE_TYPE purge);



/**
 * Description: get last error either for a context or globally
 * In: ctx - ICC context or NULL when global
 * Out: 0 on success or error code
 */
ICC_ERR ICC_get_last_error(ICC_CONTEXT *ctx);

/**
 * Description: get ICC parameters for the backend cryptography
 * In: ctx - initialized ICC context
 *     bsl - bit security level
 *     pars - pointer to ICC parameters
 * Out: ICC parameters or error code
 */
ICC_ERR ICC_get_parameters(ICC_CONTEXT *ctx, ICC_bit_security_level bsl, ICC_parameters *pars);

/**
 * Description: get bit security level of the context
 * In: ctx - ICC context
 * Out: bit security level or 0 on error
 */
ICC_bit_security_level ICC_get_bit_security(ICC_CONTEXT *ctx);

/**
 * Description: get signature size
 * In: ctx - ICC context
 *     bsl - bit security level
 * Out: signature size or -1 if error
 */
int ICC_get_signature_size(ICC_CONTEXT *ctx, ICC_bit_security_level bsl);

/**
 * Description: get ciphertext size for a given plain text size
 * In: ctx - ICC context
 *     in_size - size of plain text in bytes
 *     bsl - bit security level
 * Out: ciphertext size or -1 if error
 */
int ICC_get_ciphertext_size(ICC_CONTEXT *ctx, uint32_t in_size, ICC_bit_security_level bsl);

/**
 * Description: get plain text size for a given ciphertext size
 * In: ctx - ICC context
 *     in_size - size of ciphertext in bytes
 *     bsl - bit security level
 * Out: plain text size or -1 if error
 */
int ICC_get_plaintext_size(ICC_CONTEXT *ctx, uint32_t in_size, ICC_bit_security_level bsl);

/**
 * Description: Create a keypair (private & public key) and store it in the empty context
 * In: ctx - ICC context
 *     bsl - bit security level
 * Out: 0 on success or error code
 */
ICC_ERR ICC_create_keypair(ICC_CONTEXT *ctx, ICC_bit_security_level bsl);

/**
 * Description: encrypt message
 * In: ctx - ICC context
 *     in_buf - 32-byte long session key for encryption or NULL
 *     in_size - size of session key in bytes (only 32 supported)
 *     enc_buf - result of encoding
 *     out_size - size of enc_buf
 * Out: 0 on success or error code
 */
ICC_ERR ICC_encrypt(ICC_CONTEXT *ctx, const uint8_t *in_buf, uint32_t in_size, uint8_t *enc_buf, uint32_t *out_size);

/**
 * Description: decrypt message
 * In: ctx - ICC context
 *     s - message for decryption
 *     in_size - size of s
 *     decod_buf - result of decoding
 *     size - size of decod_buf
 * Out: 0 on success or error code
 */
ICC_ERR ICC_decrypt(ICC_CONTEXT *ctx, const uint8_t *msg, uint32_t in_size, uint8_t *decod_buf, uint32_t *size);

/**
 * Description: sign a message
 * In: ctx - ICC context
 *     msg - message for signing
 *     in_size - size of msg
 *     signature_buf - result of signing
 *     size - size of signature_buf
 * Out: 0 on success or error code
 */
ICC_ERR ICC_sign(ICC_CONTEXT *ctx, const uint8_t *msg, uint32_t in_size, uint8_t *signature_buf, uint32_t *size);

/**
 * Description: verify a message signature
 * In: ctx - ICC context
 *     msg - message for signing
 *     in_size - size of msg,
 *     signature_buf - result of signing
 *     size - size of signature_buf
 * Out: 0 on success or error code
 */
ICC_ERR ICC_verify(ICC_CONTEXT *ctx, const uint8_t *msg, uint32_t in_size, const uint8_t *signature_buf, uint32_t size);

/**
 * Description: export DER representation of ICC public key from the context
 * In: ctx - ICC context
 *     size - pointer to variable receiving size of the resulted DER buffer
 * Out: heap-allocated DER buffer on success, otherwise NULL
 */
uint8_t *ICC_export_public(ICC_CONTEXT *ctx, uint32_t *size);

/**
 * Description: export DER representation of ICC private key from the context
 * In: ctx - ICC context
 *     size - pointer to variable receiving size of the resulted DER buffer
 * Out: heap-allocated DER buffer on success, otherwise NULL
 */
uint8_t *ICC_export_private(ICC_CONTEXT *ctx, uint32_t *size);

/**
 * Description: free the allocated DER buffer
 * In: exportedKey - pointer on allocated buffer
 * Out: 0 on success or error code
 */
ICC_ERR ICC_free_export(uint8_t *exportedKey);

/**
* Description: get the type of the context
* In: ctx - pointer on context
* Out: ICC_HASH_ENCRYPTION_SIGNATURE_TYPE
*/
ICC_HASH_ENCRYPTION_SIGNATURE_TYPE ICC_get_type(ICC_CONTEXT *ctx);

/**
* Description: get the public key type
* In: pk - pointer on PK buffer
*     pk_size - size of the PK buffer
* Out: ICC_HASH_ENCRYPTION_SIGNATURE_TYPE
*/
ICC_HASH_ENCRYPTION_SIGNATURE_TYPE ICC_get_pk_type(const uint8_t* pk, uint32_t pk_size);

/**
* Description: get the secret key type
* In: sk - pointer on SK buffer
*     sk_size - size of the SK buffer
* Out: ICC_HASH_ENCRYPTION_SIGNATURE_TYPE
*/
ICC_HASH_ENCRYPTION_SIGNATURE_TYPE ICC_get_sk_type(const uint8_t* sk, uint32_t sk_size);

/**
* Description: get the public key bit security level
* In: pk - pointer on PK buffer
*     pk_size - size of the PK buffer
* Out: ICC_bit_security_level
*/
ICC_bit_security_level ICC_get_pk_bsl(const uint8_t* pk, uint32_t pk_size);

/**
* Description: get the secret key bit security level
* In: sk - pointer on SK buffer
*     sk_size - size of the SK buffer
* Out: ICC_bit_security_level
*/
ICC_bit_security_level ICC_get_sk_bsl(const uint8_t* sk, uint32_t sk_size);

/**
 * Description: checks if the requested type is enabled
 * In: type - hash-encryption-signature combination
 * Out: 0 on success or error code
 */
ICC_ERR ICC_is_type_enabled(ICC_HASH_ENCRYPTION_SIGNATURE_TYPE type);

#ifdef __cplusplus
}
#endif

#endif // ICCLIB_API_H

