/* Quantum-vulnerable public-key crypto: RSA, ECDSA, ECDH, DH, DSA */
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

/* RSA-1024 key generation (legacy API) */
RSA *gen_rsa_1024(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, e, NULL);
    BN_free(e);
    return rsa;
}

/* RSA-2048 key generation (EVP API) */
EVP_PKEY *gen_rsa_2048(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* RSA encryption with PKCS#1 v1.5 padding */
int rsa_encrypt(RSA *rsa, const unsigned char *in, int len, unsigned char *out) {
    return RSA_public_encrypt(len, in, out, rsa, RSA_PKCS1_PADDING);
}

/* RSA signature over SHA-1 */
int rsa_sign_sha1(RSA *rsa, const unsigned char *digest, unsigned char *sig, unsigned int *siglen) {
    return RSA_sign(NID_sha1, digest, 20, sig, siglen, rsa);
}

/* ECDSA on P-256 */
EC_KEY *gen_ecdsa_p256(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    return key;
}

/* ECDH on secp384r1 */
int ecdh_derive(EC_KEY *priv, const EC_POINT *peer, unsigned char *secret) {
    return ECDH_compute_key(secret, 48, peer, priv, NULL);
}

/* Diffie-Hellman 1024-bit */
DH *gen_dh_1024(void) {
    DH *dh = DH_new();
    DH_generate_parameters_ex(dh, 1024, DH_GENERATOR_2, NULL);
    DH_generate_key(dh);
    return dh;
}

/* DSA 1024-bit */
DSA *gen_dsa_1024(void) {
    DSA *dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, 1024, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(dsa);
    return dsa;
}
