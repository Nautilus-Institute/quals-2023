#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

typedef struct {
    uint64_t serial;
    uint32_t creation_date;
    char extension_data[];
} owner_cert_t;

typedef enum SFM_HASH_ALGORITHM{
    HASH_ALG_SHA1   = 0,
    HASH_ALG_SHA256 = 1,
    HASH_ALG_SHA384 = 2,
    HASH_ALG_SHA512 = 3,
} sfm_hash_alg_t;


EVP_PKEY *sfm_init_ek(void) {
    EVP_PKEY *pkey = NULL;

    pkey = EVP_RSA_gen(2048);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to generate RSA EK\n");
    }

    // below just for sanity checking that it's working
    /*
    RSA *r = EVP_PKEY_get1_RSA(pkey);
    RSA_print_fp(stdout, r, 0);
    */
    return pkey;
}

int sfm_get_public_key(EVP_PKEY *pkey, unsigned char *outbuf)
{
    int ret = 1;
    int rc = 0;

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);

    const BIGNUM *e = RSA_get0_e(rsa);
    const BIGNUM *n = RSA_get0_n(rsa);

    size_t num_bytes_e = BN_num_bytes(e);
    size_t num_bytes_n = BN_num_bytes(n);

    unsigned char *e_str = NULL;
    unsigned char *n_str = NULL;
    e_str = OPENSSL_malloc(num_bytes_e);
    if (e_str == NULL)
    {
	fprintf(stderr, "Failed to malloc\n");
	goto out;
    }

    rc = BN_bn2bin(e, e_str);
    if (rc < 0)
    {
	fprintf(stderr, "Failed to convert e to string\n");
	goto out;
    }

    n_str = OPENSSL_malloc(num_bytes_n);
    if (n_str == NULL)
    {
	fprintf(stderr, "Failed to malloc\n");
	goto out;
    }

    rc = BN_bn2bin(n, n_str);
    if (rc < 0)
    {
	fprintf(stderr, "Failed to convert n to string\n");
	goto out;
    }

    memcpy(outbuf, e_str, num_bytes_e);
    memcpy(outbuf+num_bytes_e, n_str, num_bytes_n);

    ret = 0;
out:
    RSA_free(rsa);
    OPENSSL_free(e_str);
    OPENSSL_free(n_str);
    return ret;
}

unsigned char *sign_data(EVP_PKEY *pkey,
                         EVP_MD_CTX *ctx,
                         const EVP_MD *alg,
                         unsigned char *data,
                         size_t data_len,
                         size_t *digest_size)
{
    unsigned char *ret = NULL;

    int rc = EVP_DigestSignInit(ctx, NULL, alg, NULL, pkey);
    if (rc != 1) {
        fprintf(stderr, "Failed init\n");
        goto out;
    }

    rc = EVP_DigestSignUpdate(ctx, data, data_len);
    if (rc != 1) {
        fprintf(stderr, "Failed update\n");
        goto out;
    }

    rc = EVP_DigestSignFinal(ctx, NULL, digest_size);
    if (rc != 1) {
        fprintf(stderr, "Failed final\n");
        goto out;
    }

    unsigned char *signed_data = OPENSSL_malloc(*digest_size + data_len);
    if (signed_data == NULL) {
        fprintf(stderr, "Failed allocate out\n");
        goto out;
    }

    rc = EVP_DigestSignFinal(ctx, signed_data, digest_size);
    if (rc != 1) {
        fprintf(stderr, "Failed to sign final blob\n");
        goto out;
    }

    memcpy(signed_data + *digest_size, data, data_len);

    ret = signed_data;
out:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int append_kv_to_cert(owner_cert_t **cert, size_t *cert_len, char *key, char *value)
{
    size_t addition = strlen(key) + strlen(value);
    char *new = realloc(*cert, *cert_len + addition + 1);
    if (new == NULL) {
        return 1;
    }

    strcpy(new + *cert_len, key);
    strcpy(new + *cert_len + strlen(key), value);

    *cert = (owner_cert_t *)new;
    *cert_len += addition;
    return 0;
}

int append_separator_to_cert(owner_cert_t **cert, size_t *cert_len, char *separator)
{
    size_t addition = strlen(separator);
    char *new = realloc(*cert, *cert_len + addition + 1);
    if (new == NULL) {
        return 1;
    }

    strcpy(new + *cert_len, separator);

    *cert = (owner_cert_t *)new;
    *cert_len += addition;
    return 0;
}

void *create_owner_cert(char *owner_name,
                        char *device_name,
                        uint64_t serial,
                        size_t *cert_len)
{
    owner_cert_t *cert = malloc(sizeof(owner_cert_t));
    if (cert == NULL) {
        return NULL;
    }
    *cert_len = sizeof(owner_cert_t);

    cert->serial = serial;
    cert->creation_date = time(NULL);

    if (append_kv_to_cert(&cert, cert_len, "O=", owner_name) != 0) {
        free(cert);
        return NULL;
    }

    if (append_separator_to_cert(&cert, cert_len, ",") != 0) {
	free(cert);
	return NULL;
    }

    if (append_kv_to_cert(&cert, cert_len, "CN=", device_name) != 0) {
        free(cert);
        return NULL;
    }

    return cert;
}

// this must be the number of banks
void *sign_attestation_quote(EVP_PKEY *pkey,
                              sfm_hash_alg_t hash_alg,
                              unsigned char *report,
                              size_t report_size,
                              size_t *digest_size)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    switch(hash_alg) {
        case HASH_ALG_SHA1:
	    return sign_data(pkey, ctx, EVP_sha1(), report, report_size, digest_size);
	case HASH_ALG_SHA256:
	    return sign_data(pkey, ctx, EVP_sha256(), report, report_size, digest_size);
	case HASH_ALG_SHA384:
	    return sign_data(pkey, ctx, EVP_sha384(), report, report_size, digest_size);
	case HASH_ALG_SHA512:
	    return sign_data(pkey, ctx, EVP_sha512(), report, report_size, digest_size);
    }
}

#define BANK_SIZE 64
int sfm_attest_to_quote(EVP_PKEY *pkey,
                         sfm_hash_alg_t hash_alg,
                         unsigned char *bank_contents,
                         size_t num_banks,
                         unsigned char *output)
{
    size_t report_size = num_banks * BANK_SIZE;

    size_t digest_size = 0;
    void *signed_report = sign_attestation_quote(pkey,
                                                  hash_alg,
                                                  bank_contents,
                                                  report_size,
                                                  &digest_size);

    memcpy(output, signed_report, report_size + digest_size);
    OPENSSL_free(signed_report);
    return 0;
}

int sfm_certify_owner_record(EVP_PKEY *pkey,
                             char *owner_name,
                             char *device_name,
                             uint64_t serial,
                             uint32_t creation_date,
                             unsigned char *outbuf)
{
    int result = 1;
    size_t owner_cert_len = 0;
    unsigned char *signed_cert = NULL;
    EVP_MD_CTX *ctx = NULL;

    (void)creation_date;

    void *owner_cert = create_owner_cert(owner_name,
                                         device_name,
                                         serial,
                                         &owner_cert_len);
    if (owner_cert == NULL) {
        fprintf(stderr, "Failed to create SFM certificate layout\n");
        return 1;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed allotcate\n");
        goto out;
    }

    int rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    if (rc != 1) {
        fprintf(stderr, "Failed init\n");
        goto out;
    }

    rc = EVP_DigestSignUpdate(ctx, owner_cert, owner_cert_len);
    if (rc != 1) {
        fprintf(stderr, "Failed update\n");
        goto out;
    }

    size_t req;
    rc = EVP_DigestSignFinal(ctx, NULL, &req);
    if (rc != 1) {
        fprintf(stderr, "Failed final\n");
        goto out;
    }

    signed_cert = OPENSSL_malloc(req);
    if (signed_cert == NULL) {
        fprintf(stderr, "Failed allocate out\n");
        goto out;
    }

    rc = EVP_DigestSignFinal(ctx, signed_cert, &req);
    if (rc != 1) {
        fprintf(stderr, "Failed to sign final blob\n");
        goto out;
    }

    memcpy(outbuf, signed_cert, req);
    memcpy(outbuf+req, owner_cert, owner_cert_len);

    result = 0;
out:
    free(owner_cert);
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(signed_cert);
    return result;
}

int sfm_certify_key(EVP_PKEY *pkey,
                    unsigned char *key_data,
                    unsigned char *outbuf)
{
    size_t digest_size = 0;
    unsigned char *signature = NULL;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed allocate\n");
        return 1;
    }

	signature = sign_data(pkey, ctx, EVP_sha256(), key_data, 32, &digest_size);
    if (signature == NULL) {
        fprintf(stderr, "Failed to sign data\n");
        return 1;
    }

    memcpy(outbuf, signature, digest_size);
    memcpy(outbuf+digest_size, key_data, 32);
    OPENSSL_free(signature);

    return 0;
}

int sfm_certify_nv_storage(EVP_PKEY *pkey,
                           unsigned char *data,
                           size_t data_len,
                           unsigned char *outbuf)
{
    size_t digest_size = 0;
    unsigned char *signature = NULL;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed allocate\n");
        return 1;
    }

    signature = sign_data(pkey, ctx, EVP_sha256(), data, data_len, &digest_size);
    if (signature == NULL) {
        fprintf(stderr, "Failed to sign data\n");
        return 1;
    }

    memcpy(outbuf, signature, digest_size);
    memcpy(outbuf+digest_size, data, data_len);
    OPENSSL_free(signature);

    return 0;
}
