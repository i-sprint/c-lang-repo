/* Weak hashes and symmetric ciphers: MD5, SHA-1, DES, 3DES, RC4, AES-ECB */
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

/* MD5 */
void hash_md5(const unsigned char *data, size_t len, unsigned char out[MD5_DIGEST_LENGTH]) {
    MD5(data, len, out);
}

/* SHA-1 */
void hash_sha1(const unsigned char *data, size_t len, unsigned char out[SHA_DIGEST_LENGTH]) {
    SHA1(data, len, out);
}

/* SHA-256 (acceptable, included as a control) */
void hash_sha256(const unsigned char *data, size_t len, unsigned char out[SHA256_DIGEST_LENGTH]) {
    SHA256(data, len, out);
}

/* EVP digest by name: MD5 and SHA-1 */
void hash_evp(const unsigned char *data, size_t len, unsigned char *out, unsigned int *outlen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, outlen);
    EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, outlen);
    EVP_MD_CTX_free(ctx);
}

/* HMAC-SHA1 */
void hmac_sha1(const unsigned char *key, int keylen, const unsigned char *data, size_t len, unsigned char *out) {
    unsigned int outlen;
    HMAC(EVP_sha1(), key, keylen, data, len, out, &outlen);
}

/* DES-ECB */
void des_encrypt(const unsigned char *in, unsigned char *out, DES_key_schedule *ks) {
    DES_ecb_encrypt((const_DES_cblock *)in, (DES_cblock *)out, ks, DES_ENCRYPT);
}

/* Triple DES CBC */
void triple_des_encrypt(const unsigned char *in, unsigned char *out, long len,
                        DES_key_schedule *k1, DES_key_schedule *k2, DES_key_schedule *k3,
                        DES_cblock *iv) {
    DES_ede3_cbc_encrypt(in, out, len, k1, k2, k3, iv, DES_ENCRYPT);
}

/* RC4 */
void rc4_encrypt(const unsigned char *key, int keylen, const unsigned char *in, unsigned char *out, size_t len) {
    RC4_KEY rc4;
    RC4_set_key(&rc4, keylen, key);
    RC4(&rc4, len, in, out);
}

/* AES-128-ECB */
void aes_ecb_encrypt(const unsigned char *key, const unsigned char *in, unsigned char *out) {
    AES_KEY aes;
    AES_set_encrypt_key(key, 128, &aes);
    AES_ecb_encrypt(in, out, &aes, AES_ENCRYPT);
}

/* AES-256-GCM via EVP (acceptable, included as a control) */
void aes_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
}

/* Blowfish and RC2 via EVP */
void legacy_ciphers(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv);
    EVP_EncryptInit_ex(ctx, EVP_rc2_cbc(), NULL, key, iv);
}
