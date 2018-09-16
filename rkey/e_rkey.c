#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/modes.h>

#include <openssl/ec.h>



/* Engine Id and Name */
static const char *engine_id = "rkey";
static const char *engine_name = "rkey";

static RSA_METHOD *rkey_rsa_method = NULL;

SSL_CTX * g_ssl_ctx = NULL;
SSL_CTX * g_ssl_ctx_fake = NULL;
const char * g_pub = "/root/async/net-utils/ssl-ca-crl/multiCA/rootcase3/rootcase3.crt";
const char * g_key = "/root/async/net-utils/ssl-ca-crl/multiCA/rootcase3/rootcase3.key";

const char * g_pub_fake = "/root/async/net-utils/ssl-ca-crl/multiCA/rootcase4/rootcase4.crt";
const char * g_key_fake = "/root/async/net-utils/ssl-ca-crl/multiCA/rootcase4/rootcase4.key";



SSL_CTX * new_ssl_ctx(const char * crt, const char  *key)
{
    SSL_CTX * ctx;

    ctx = SSL_CTX_new(SSLv23_method()); 
    SSL_CTX_use_certificate_chain_file(ctx, crt);
    SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);

    return ctx;
}


RSA * get_priv_rsa(SSL_CTX * ctx)
{
    EVP_PKEY * pkey = SSL_CTX_get0_privatekey(ctx);
    RSA * rsa = EVP_PKEY_get0_RSA(pkey);
 
    return rsa;
}

void rsa_srv()
{
   
    g_ssl_ctx = new_ssl_ctx(g_pub, g_key);
    g_ssl_ctx_fake = new_ssl_ctx(g_pub_fake, g_key_fake);


    RSA * rsa = get_priv_rsa(g_ssl_ctx_fake);
    RSA_set_method(rsa, rkey_rsa_method);
}


static int rkey_rsa_priv_enc(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    printf("priv enc\n");
    RSA * rsa2 =  get_priv_rsa(g_ssl_ctx);
    return RSA_meth_get_priv_enc(RSA_PKCS1_OpenSSL())
        (flen, from, to, rsa2, padding);
}

static int rkey_rsa_priv_dec(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    printf("priv dec\n");
    RSA * rsa2 =  get_priv_rsa(g_ssl_ctx);
  
    return RSA_meth_get_priv_dec(RSA_PKCS1_OpenSSL())
        (flen, from, to, rsa2, padding);
}


static int rkey_rsa_pub_enc(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {

    printf("pub enc\n");
    /* Ignore errors - we carry on anyway */
    return RSA_meth_get_pub_enc(RSA_PKCS1_OpenSSL())
        (flen, from, to, rsa, padding);
}

static int rkey_rsa_pub_dec(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {

    printf("pub dec\n");
    /* Ignore errors - we carry on anyway */
    return RSA_meth_get_pub_dec(RSA_PKCS1_OpenSSL())
        (flen, from, to, rsa, padding);
}

static int rkey_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    printf("mod exp\n");
    /* Ignore errors - we carry on anyway */
    return RSA_meth_get_mod_exp(RSA_PKCS1_OpenSSL())(r0, I, rsa, ctx);
}

static int rkey_rsa_init(RSA *rsa)
{
    printf("init\n");
    return RSA_meth_get_init(RSA_PKCS1_OpenSSL())(rsa);
}
static int rkey_rsa_finish(RSA *rsa)
{
    printf("finish\n");
    return RSA_meth_get_finish(RSA_PKCS1_OpenSSL())(rsa);
}




int rkey_rsa_new(ENGINE *e)
{
    rkey_rsa_method = RSA_meth_new("RKEY RSA method", RSA_METHOD_FLAG_NO_CHECK);

    RSA_meth_set_pub_enc(rkey_rsa_method,       rkey_rsa_pub_enc);
    RSA_meth_set_pub_dec(rkey_rsa_method,       rkey_rsa_pub_dec);
    RSA_meth_set_priv_enc(rkey_rsa_method,      rkey_rsa_priv_enc);
    RSA_meth_set_priv_dec(rkey_rsa_method,      rkey_rsa_priv_dec);
    RSA_meth_set_mod_exp(rkey_rsa_method,       rkey_rsa_mod_exp);
    RSA_meth_set_bn_mod_exp(rkey_rsa_method,    BN_mod_exp_mont);
    RSA_meth_set_init(rkey_rsa_method,          rkey_rsa_init);
    RSA_meth_set_finish(rkey_rsa_method,        rkey_rsa_finish);

    ENGINE_set_RSA(e, rkey_rsa_method);

    return 1;
}



static EVP_PKEY*
rkey_load_privkey(ENGINE *e, const char *data, UI_METHOD *ui_method, void *callback_data)
{
    EVP_PKEY * pkey = NULL;
    

    if(g_ssl_ctx_fake == NULL){
        rsa_srv();
    }

    pkey = SSL_CTX_get0_privatekey(g_ssl_ctx_fake);

    return pkey; 
}

struct my_engine {
    const char *id;
    const char *name;
    const RSA_METHOD *rsa_meth;
    const DSA_METHOD *dsa_meth;
    const DH_METHOD *dh_meth;
    const EC_KEY_METHOD *ec_meth;
    const RAND_METHOD *rand_meth;
    /* Cipher handling is via this callback */
    ENGINE_CIPHERS_PTR ciphers;
    /* Digest handling is via this callback */
    ENGINE_DIGESTS_PTR digests;
    /* Public key handling via this callback */
    ENGINE_PKEY_METHS_PTR pkey_meths;
    /* ASN1 public key handling via this callback */
    ENGINE_PKEY_ASN1_METHS_PTR pkey_asn1_meths;
    ENGINE_GEN_INT_FUNC_PTR destroy;
    ENGINE_GEN_INT_FUNC_PTR init;
    ENGINE_GEN_INT_FUNC_PTR finish;
    ENGINE_CTRL_FUNC_PTR ctrl;
    ENGINE_LOAD_KEY_PTR load_privkey;
    ENGINE_LOAD_KEY_PTR load_pubkey;
    ENGINE_SSL_CLIENT_CERT_PTR load_ssl_client_cert;
    const ENGINE_CMD_DEFN *cmd_defns;
    int flags;
    /* reference count on the structure itself */
    int struct_ref;
    /*
     * reference count on usability of the engine type. NB: This controls the
     * loading and initialisation of any functionality required by this
     * engine, whereas the previous count is simply to cope with
     * (de)allocation of this structure. Hence, running_ref <= struct_ref at
     * all times.
     */
    int funct_ref;
    /* A place to store per-ENGINE data */
    CRYPTO_EX_DATA ex_data;
    /* Used to maintain the linked-list of engines. */
    struct engine_st *prev;
    struct engine_st *next;
};


static int rkey_init(ENGINE *e)
{
    ((struct my_engine*)e)->funct_ref = 2;
    return 1;
}


static int rkey_finish(ENGINE *e)
{
    return 1;
}

static int rkey_destroy(ENGINE *e)
{
    return 1;
}


static int rkey_bind_engine(ENGINE *e)
{
    printf("load rkey\n");

    ENGINE_set_id(e, engine_id);
    ENGINE_set_name(e, engine_name);

    ENGINE_set_load_privkey_function(e, rkey_load_privkey);
   
    ENGINE_set_destroy_function(e, rkey_destroy);
    ENGINE_set_init_function(e, rkey_init);
    ENGINE_set_finish_function(e, rkey_finish);
    
    rkey_rsa_new(e);



    return 1;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int rkey_bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_id) != 0))
        return 0;
    if (!rkey_bind_engine(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(rkey_bind_helper)
# endif



