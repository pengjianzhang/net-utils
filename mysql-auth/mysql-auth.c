#include <stdio.h>  
#include <string.h>  
#include <openssl/sha.h>  
  

#define CHALLENGE_LEN   20
#define BUF_LEN         40

int main()  
{  
    unsigned char passwd_1[SHA_DIGEST_LENGTH];  
    unsigned char passwd_2[SHA_DIGEST_LENGTH];  
    unsigned char ret[SHA_DIGEST_LENGTH];
    unsigned char tmp[SHA_DIGEST_LENGTH];  
    unsigned char challenge[20] = {0x03,0x12,0x35,0x0a,0x7a,0x2b,0x6f,0x0d,0x3f,
        0x25,0x46,0x5f,0x34,0x28,0x19,0x52,0x0a,0x2e,0x77,0x7f};
    unsigned char buf[128];
    char * passwd = "default";  
    int i;

    SHA1((unsigned char*)passwd, strlen(passwd), (unsigned char*)passwd_1);  
    SHA1((unsigned char*)passwd_1, SHA_DIGEST_LENGTH, (unsigned char*)passwd_2);  
    memcpy(buf,challenge,CHALLENGE_LEN);
    memcpy(buf+CHALLENGE_LEN,passwd_2, SHA_DIGEST_LENGTH);
    SHA1((unsigned char*)buf, BUF_LEN, tmp);  

    for(i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        ret[i] = passwd_1[i] ^ tmp[i];
        printf("%02x",ret[i]);
    }
    printf("\n");

    return 0;  
}  
