/* gcc -g3 -O1 -Wall -std=c99 -I/usr/local/ssl/darwin/include t-rsa.c /usr/local/ssl/darwin/lib/libcrypto.a -o t-rsa.exe */
/* gcc -g2 -Os -Wall -DNDEBUG=1 -std=c99 -I/usr/local/ssl/darwin/include t-rsa.c /usr/local/ssl/darwin/lib/libcrypto.a -o t-rsa.exe */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

typedef unsigned char byte;
#define UNUSED(x) ((void)x)
const char hn[] = "SHA256";

/* Returns 0 for success, non-0 otherwise */
int make_keys(EVP_PKEY** skey, EVP_PKEY** vkey);

/* Returns 0 for success, non-0 otherwise */
int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey);

/* Returns 0 for success, non-0 otherwise */
int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey);

/* Prints a buffer to stdout. Label is optional */
void print_it(const char* label, const byte* buff, size_t len);

int main(int argc, char* argv[])
{
    EVP_PKEY *skey;
    EVP_PKEY *vkey;
    byte *sig;
    size_t slen;
    int rc;
    const byte msg[] = "Now is the time for all good men to come to the aide of their country";

    printf("Testing RSA functions with EVP_DigestSign and EVP_DigestVerify\n");

    OpenSSL_add_all_algorithms();

    /* Sign and Verify HMAC keys */
    skey = NULL;
    vkey = NULL;

    rc = make_keys(&skey, &vkey);
    assert(rc == 0);
    if(rc != 0)
        exit(1);

    assert(skey != NULL);
    if(skey == NULL)
        exit(1);

    assert(vkey != NULL);
    if(vkey == NULL)
        exit(1);

    sig = NULL;
    slen = 0;

    /* Using the skey or signing key */
    rc = sign_it(msg, sizeof(msg), &sig, &slen, skey);
    assert(rc == 0);
    if(rc == 0) {
        printf("Created signature\n");
    } else {
        printf("Failed to create signature, return code %d\n", rc);
        exit(1); /* Should cleanup here */
    }

    print_it("Signature", sig, slen);

#if 0
    /* Tamper with signature */
    printf("Tampering with signature\n");
    sig[0] ^= 0x01;
#endif

#if 0
    /* Tamper with signature */
    printf("Tampering with signature\n");
    sig[slen - 1] ^= 0x01;
#endif

    /* Using the vkey or verifying key */
    rc = verify_it(msg, sizeof(msg), sig, slen, vkey);
    if(rc == 0) {
        printf("Verified signature\n");
    } else {
        printf("Failed to verify signature, return code %d\n", rc);
    }

    if(sig)
        OPENSSL_free(sig);

    if(skey)
        EVP_PKEY_free(skey);

    if(vkey)
        EVP_PKEY_free(vkey);

    return 0;
}

int sign_it(const byte* msg, size_t mlen, byte** sig, size_t* slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    EVP_MD_CTX *ctx ;
    const EVP_MD *md;
    int rc;
    size_t req;

    if(!msg || !mlen || !sig || !pkey) {
        assert(0);
        return -1;
    }

    if(*sig)
        OPENSSL_free(*sig);

    *sig = NULL;
    *slen = 0;

    ctx = NULL;

    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        assert(req > 0);
        if(!(req > 0)) {
            printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if(*sig == NULL) {
            printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }

        assert(req == *slen);
        if(rc != 1) {
            printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }

        result = 0;

    } while(0);

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    return !!result;
}

int verify_it(const byte* msg, size_t mlen, const byte* sig, size_t slen, EVP_PKEY* pkey)
{
    /* Returned to caller */
    int result = -1;
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    int rc;

    if(!msg || !mlen || !sig || !slen || !pkey) {
        assert(0);
        return -1;
    }

    ctx = NULL;

    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if(ctx == NULL) {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        md = EVP_get_digestbyname(hn);
        assert(md != NULL);
        if(md == NULL) {
            printf("EVP_get_digestbyname failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestInit_ex(ctx, md, NULL);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Clear any errors for the call below */
        ERR_clear_error();

	printf("EVP_DigestVerifyFinal: slen: %d\n", (int)slen);
	print_it("Debug Signature", sig, slen);

        rc = EVP_DigestVerifyFinal(ctx, sig, slen);
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        result = 0;

    } while(0);

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    return !!result;

}

void print_it(const char* label, const byte* buff, size_t len)
{
    size_t i;
    if(!buff || !len)
        return;

    if(label)
        printf("%s: ", label);

    for(i=0; i < len; ++i)
        printf("%02X", buff[i]);

    printf("\n");
}

int make_keys(EVP_PKEY** skey, EVP_PKEY** vkey)
{
    int result = -1;
    int rc;
    RSA* rsa;

    if(!skey || !vkey)
        return -1;

    if(*skey != NULL) {
        EVP_PKEY_free(*skey);
        *skey = NULL;
    }

    if(*vkey != NULL) {
        EVP_PKEY_free(*vkey);
        *vkey = NULL;
    }

    rsa = NULL;

    do
    {
        *skey = EVP_PKEY_new();
        assert(*skey != NULL);
        if(*skey == NULL) {
            printf("EVP_PKEY_new failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        *vkey = EVP_PKEY_new();
        assert(*vkey != NULL);
        if(*vkey == NULL) {
            printf("EVP_PKEY_new failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rsa = RSA_generate_key(512, RSA_F4, NULL, NULL);
        assert(rsa != NULL);
        if(rsa == NULL) {
            printf("RSA_generate_key failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Set signing key */
        rc = EVP_PKEY_assign_RSA(*skey, RSAPrivateKey_dup(rsa));
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_PKEY_assign_RSA (1) failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Sanity check. Verify private exponent is present */
        /* assert(EVP_PKEY_get0_RSA(*skey)->d != NULL); */

        /* Set verifier key */
        rc = EVP_PKEY_assign_RSA(*vkey, RSAPublicKey_dup(rsa));
        assert(rc == 1);
        if(rc != 1) {
            printf("EVP_PKEY_assign_RSA (2) failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Sanity check. Verify private exponent is missing */
        /* assert(EVP_PKEY_get0_RSA(*vkey)->d == NULL); */

        result = 0;

    } while(0);

    if(rsa) {
        RSA_free(rsa);
        rsa = NULL;
    }

    return !!result;
}
