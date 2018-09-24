
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"


int negotiated_prf(Context *ctx, SSL *ssl) {

    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case 0x03001301u: // TLS_AES_128_GCM_SHA256
    case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
        ctx->prf = EVP_sha256();
        return 0;
    case 0x03001302u: // TLS_AES_256_GCM_SHA384
        ctx->prf = EVP_sha384();
        return 0;
    default:
        return -1;
    }
}

int negotiated_aead(Context *ctx, SSL *ssl) {
    switch (SSL_CIPHER_get_id(SSL_get_current_cipher(ssl))) {
    case 0x03001301u: // TLS_AES_128_GCM_SHA256
        ctx->aead = EVP_aes_128_gcm();
        ctx->pn = EVP_aes_128_ctr();
        return 0;
    case 0x03001302u: // TLS_AES_256_GCM_SHA384
        ctx->aead = EVP_aes_256_gcm();
        ctx->pn = EVP_aes_256_ctr();
        return 0;
    case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
        ctx->aead = EVP_chacha20_poly1305();
        ctx->pn = EVP_chacha20();
        return 0;
    default:
        return -1;
    }
}

static size_t 
aead_tag_length(const Context *ctx) 
{

  if (ctx->aead == EVP_aes_128_gcm() || ctx->aead == EVP_aes_256_gcm()) {
    return EVP_GCM_TLS_TAG_LEN;
  }

  if (ctx->aead == EVP_chacha20_poly1305()) {
    return EVP_CHACHAPOLY_TLS_TAG_LEN;
  }

  assert(0);
}

ssize_t encrypt(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                size_t plaintextlen, const Context *ctx, const uint8_t *key,
                size_t keylen, const uint8_t *nonce, size_t noncelen,
                const uint8_t *ad, size_t adlen) 
{
    size_t           taglen;
    ssize_t          ret = -1;
    size_t           outlen = 0;
    int              len;
    EVP_CIPHER_CTX  *actx = NULL;

    taglen = aead_tag_length(ctx);
    if (destlen < plaintextlen + taglen) {
        return -1;
    }

    actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }


    if (EVP_EncryptInit_ex(actx, ctx->aead, NULL, NULL, NULL) != 1) {
        goto out;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != 1) {
        goto out;
    }

    if (EVP_EncryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
        goto out;
    }

    if (EVP_EncryptUpdate(actx, NULL, &len, ad, adlen) != 1) {
        goto out;
    }

    if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
        goto out;
    }

    outlen = len;
    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
        goto out;
    }

    outlen += len;
    assert(outlen + taglen <= destlen);

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) != 1) {
        goto out;
    }

    outlen += taglen;
    ret = outlen;

out:
    if(actx){
        EVP_CIPHER_CTX_free(actx);
    }

    return ret;
}

ssize_t decrypt(uint8_t *dest, size_t destlen, const uint8_t *ciphertext,
        size_t ciphertextlen, const Context *ctx, const uint8_t *key,
        size_t keylen, const uint8_t *nonce, size_t noncelen,
        const uint8_t *ad, size_t adlen) 
{
    const uint8_t         *tag;
    size_t           taglen;
    ssize_t          ret = -1;
    size_t           outlen = 0;
    int              len;
    EVP_CIPHER_CTX  *actx = NULL;


    taglen = aead_tag_length(ctx);
    if (taglen > ciphertextlen || destlen + taglen < ciphertextlen) {
        return -1;
    }

    ciphertextlen -= taglen;
    tag = ciphertext + ciphertextlen;

    actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }


    if (EVP_DecryptInit_ex(actx, ctx->aead, NULL, NULL, NULL) != 1) {
        goto out;
    }

    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != 1) {
        goto out;
    }

    if (EVP_DecryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
        goto out;
    }

    if (EVP_DecryptUpdate(actx, NULL, &len, ad, adlen) != 1) {
        goto out;
    }

    if (EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != 1) {
        goto out;
    }

    outlen = len;
    if (EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen, (void*)tag) != 1) {
        goto out;
    }

    if (EVP_DecryptFinal_ex(actx, dest + outlen, &len) != 1) {
        goto out;
    }

    outlen += len;
    ret = outlen;

out:
    if(actx){
        EVP_CIPHER_CTX_free(actx);
    }

    return ret;
}

size_t aead_max_overhead(const Context *ctx) 
{ 
    return aead_tag_length(ctx); 
}

size_t aead_key_length(const Context *ctx) 
{
    return EVP_CIPHER_key_length(ctx->aead);
}

size_t aead_nonce_length(const Context *ctx) 
{
    return EVP_CIPHER_iv_length(ctx->aead);
}

ssize_t encrypt_pn(uint8_t *dest, size_t destlen, const uint8_t *plaintext,
                   size_t plaintextlen, const Context *ctx, const uint8_t *key,
                   size_t keylen, const uint8_t *nonce, size_t noncelen) {

    size_t outlen = 0;
    int len;
    ssize_t ret = -1;
    EVP_CIPHER_CTX  *actx = NULL;
  
    actx = EVP_CIPHER_CTX_new();
    if (actx == NULL) {
        return -1;
    }

    if (EVP_EncryptInit_ex(actx, ctx->pn, NULL, key, nonce) != 1) {
        goto out;
    }

    if (EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
        goto out;
    }

    assert(len > 0);

    outlen = len;

    if (EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
        goto out;
    }

    assert(len == 0);

    ret = outlen;
  /* outlen += len; */
out:

    if(actx){
        EVP_CIPHER_CTX_free(actx);
    }
    return ret;
}

static int 
hkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                size_t secretlen, const uint8_t *info, size_t infolen,
                const Context *ctx) {

    int ret = -1;
    EVP_PKEY_CTX * pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
    return -1;
    }

    if (EVP_PKEY_derive_init(pctx) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->prf) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != 1) {
        goto out;
    }

    if (EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
        goto out;
    }
    
    ret = 0;
out:
    if(pctx){
        EVP_PKEY_CTX_free(pctx);
    }

    return ret;
}

static int 
hkdf_extract(uint8_t *dest, size_t destlen, const uint8_t *secret,
                 size_t secretlen, const uint8_t *salt, size_t saltlen,
                 const Context * ctx) {
    int ret;
    EVP_PKEY_CTX * pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        return -1;
    }


    if (EVP_PKEY_derive_init(pctx) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, ctx->prf) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != 1) {
        goto out;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1) {
        goto out;
    }

    if (EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
        goto out;
    }

    ret = 0;

out:

    if(pctx){
        EVP_PKEY_CTX_free(pctx);
    }
    
    return ret;
}


int qhkdf_expand(uint8_t *dest, size_t destlen, const uint8_t *secret,
                 size_t secretlen, const char *qlabel, size_t qlabellen,
                 const Context *ctx) {

    uint8_t      info[256];
    char*        lable = "quic ";
    uint8_t     *p = info;
    int          lable_len = strlen(lable);


    *p++ = destlen / 256;
    *p++ = destlen % 256;
    *p++ = lable_len + qlabellen;
    memcpy(p, lable, lable_len);
    p += lable_len;
    p = memcpy(p, qlabel, qlabellen);
    p += qlabellen;
    *p++ = 0;   /* "" */

/*
       struct {
           uint16 length = Length;
           opaque label<7..255> = "tls13 " + Label;
           opaque context<0..255> = Context;
       } HkdfLabel;
*/

    return hkdf_expand(dest, destlen, secret, secretlen, info, p - info, ctx);
}


void prf_sha256(Context *ctx) 
{ 
    ctx->prf = EVP_sha256(); 
}

void aead_aes_128_gcm(Context *ctx) {
    ctx->aead = EVP_aes_128_gcm();
    ctx->pn = EVP_aes_128_ctr();
}


const unsigned char * g_empty_str = (const unsigned char *)"";

int export_secret(uint8_t *dest, size_t destlen, SSL *ssl, const char *label,
                  size_t labellen) {
    int rv;

    rv = SSL_export_keying_material(ssl, dest, destlen, label, labellen, g_empty_str, 0, 1);
    if (rv != 1) {
        return -1;
    }

    return 0;
}

int export_client_secret(uint8_t *dest, size_t destlen, SSL *ssl) {
    char * label = "EXPORTER-QUIC client 1rtt";
    return export_secret(dest, destlen, ssl, label, strlen(label));
}

int export_server_secret(uint8_t *dest, size_t destlen, SSL *ssl) {
    char *label = "EXPORTER-QUIC server 1rtt";
    return export_secret(dest, destlen, ssl, label, strlen(label));
}

int export_early_secret(uint8_t *dest, size_t destlen, SSL *ssl) {
    int rv;
    char label[] = "EXPORTER-QUIC 0rtt";

    rv = SSL_export_keying_material_early(ssl, dest, destlen, label, strlen(label),g_empty_str, 0);

    if (rv != 1) {
        return -1;
    }

    return 0;
}

int derive_initial_secret(uint8_t *dest, size_t destlen, const uint8_t * secret, size_t secret_len,
    const uint8_t *salt, size_t saltlen) 
{
  Context ctx;

  prf_sha256(&ctx);
  return hkdf_extract(dest, destlen, secret, secret_len, salt, saltlen, &ctx);
}

int derive_client_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen) {
    const char * LABEL = "client in";
    Context ctx;
    prf_sha256(&ctx);
    return qhkdf_expand(dest, destlen, secret, secretlen, LABEL, strlen(LABEL), &ctx);
}

int derive_server_initial_secret(uint8_t *dest, size_t destlen,
                                 const uint8_t *secret, size_t secretlen) {
  const char * LABEL = "server in";
  Context ctx;
  prf_sha256(&ctx);
  return qhkdf_expand(dest, destlen, secret, secretlen, LABEL,
                              strlen(LABEL), &ctx);
}

ssize_t derive_packet_protection_key(uint8_t *dest, size_t destlen,
                                     const uint8_t *secret, size_t secretlen,
                                     const Context *ctx) {
    int rv;
    const char * LABEL_KEY = "key";

    size_t keylen = aead_key_length(ctx);
    
    if (keylen > destlen) {
        return -1;
    }

    rv =  qhkdf_expand(dest, keylen, secret, secretlen, LABEL_KEY,
                            strlen(LABEL_KEY), ctx);
    if (rv != 0) {
        return -1;
    }

    return keylen;
}

ssize_t derive_packet_protection_iv(uint8_t *dest, size_t destlen,
                                    const uint8_t *secret, size_t secretlen,
                                    const Context *ctx) {
    int     rv;
    const char* LABEL_IV = "iv";
    size_t  ivlen = max(8, aead_nonce_length(ctx));

    if (ivlen > destlen) {
        return -1;
    }

    rv = qhkdf_expand(dest, ivlen, secret, secretlen, LABEL_IV,
                            strlen(LABEL_IV), ctx);
    if (rv != 0) {
        return -1;
    }

    return ivlen;
}

ssize_t derive_pkt_num_protection_key(uint8_t *dest, size_t destlen,
                                      const uint8_t *secret, size_t secretlen,
                                      const Context *ctx) {
    int rv;
    const char * LABEL_PKNKEY = "pn";
    size_t  keylen = aead_key_length(ctx);


    if (keylen > destlen) {
        return -1;
    }

    rv = qhkdf_expand(dest, keylen, secret, secretlen, LABEL_PKNKEY, strlen(LABEL_PKNKEY), ctx);

    if (rv != 0) {
        return -1;
    }

    return keylen;
}

