#ifndef __MYQUIC_CRYPTO_H
#define __MYQUIC_CRYPTO_H

#include <openssl/ssl.h>
#include <stdint.h>

typedef struct{
  const EVP_CIPHER  *aead;
  const EVP_CIPHER  *pn;
  const EVP_MD      *prf;
  uint8_t            tx_secret[64];
  uint8_t            rx_secret[64];
  size_t             secretlen;
}Context;

#define max(a,b)    (((a) > (b)) ? (a) : (b)) 
#define min(a,b)    (((a) < (b)) ? (a) : (b))







#endif

