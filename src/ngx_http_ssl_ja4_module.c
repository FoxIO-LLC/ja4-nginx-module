#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_md5.h>
#include <openssl/sha.h>
#include <stdint.h>
#include "ngx_http_ssl_ja4_module.h"

/**
 * This is a list of Nginx variables that will be registered with Nginx.
 * The `ngx_http_add_variable` function will be used to register each
 * variable in the `ngx_http_ssl_ja4_init` function.
 */
static ngx_http_variable_t ngx_http_ssl_ja4_variables_list[] = {

    {ngx_string("http_ssl_ja4"),
     NULL,
     ngx_http_ssl_ja4,
     0, 0, 0},
    {ngx_string("http_ssl_ja4_string"),
     NULL,
     ngx_http_ssl_ja4_string,
     0, 0, 0},
    {ngx_string("http_ssl_ja4s"),
     NULL,
     ngx_http_ssl_ja4s,
     0, 0, 0},
    {ngx_string("http_ssl_ja4s_string"),
     NULL,
     ngx_http_ssl_ja4s_string,
     0, 0, 0},
    {ngx_string("http_ssl_ja4h"),
     NULL,
     ngx_http_ssl_ja4h,
     0, 0, 0},
    {ngx_string("http_ssl_ja4h_string"),
     NULL,
     ngx_http_ssl_ja4h_string,
     0, 0, 0},
    {ngx_string("http_ssl_ja4t"),
     NULL,
     ngx_http_ssl_ja4t,
     0, 0, 0},
    {ngx_string("http_ssl_ja4t_string"),
     NULL,
     ngx_http_ssl_ja4t_string,
     0, 0, 0},
    {ngx_string("http_ssl_ja4ts"),
     NULL,
     ngx_http_ssl_ja4ts,
     0, 0, 0},
    {ngx_string("http_ssl_ja4ts_string"),
     NULL,
     ngx_http_ssl_ja4ts_string,
     0, 0, 0},
    {ngx_string("http_ssl_ja4l"),
     NULL,
     ngx_http_ssl_ja4l,
     0, 0, 0},
    {ngx_string("https_ssl_ja4x"),
     NULL,
     ngx_http_ssl_ja4x,
     0, 0, 0},
    {ngx_string("https_ssl_ja4x_string"),
     NULL,
     ngx_http_ssl_ja4x_string,
     0, 0, 0},

};

// FUNCTIONS
int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{
    // this function sets stuff on the ja4 struct so the fingerprint can easily, and clearly be formed in a separate function
    SSL *ssl;
    size_t i;
    size_t len = 0;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }

    // TODO: Need to detect QUIC
    // 1. Determine the transport protocol:
    // (This is a placeholder and might need to be replaced depending on how you determine the protocol in your environment.)
    ja4->transport = 't'; // default is TCP.

    // TODO: verify this
    // 2. Determine if SNI is present or not:
    const char *sni_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    ja4->has_sni = (sni_name != NULL) ? 'd' : 'i';

    // 3. Fetch the ALPN value:
    ja4->alpn_first_value = c->ssl->first_alpn;

    /* SSLVersion*/
    // get string version:
    const char *version_str = SSL_get_version(ssl);

    if (strcmp(version_str, SSL3_VERSION_STR) == 0)
    {
        ja4->version = "s3";
    }
    else if (strcmp(version_str, TLS1_VERSION_STR) == 0)
    {
        ja4->version = "10";
    }
    else if (strcmp(version_str, TLS1_1_VERSION_STR) == 0)
    {
        ja4->version = "11";
    }
    else if (strcmp(version_str, TLS1_2_VERSION_STR) == 0)
    {
        ja4->version = "12";
    }
    else if (strcmp(version_str, TLS1_3_VERSION_STR) == 0)
    {
        ja4->version = "13";
    }
    else if (strcmp(version_str, QUICV1_VERSION_STR) == 0)
    {
        ja4->version = "q1";
    }
    else
    {
        ja4->version = "00"; // Unknown or unhandled version
    }
    /* Cipher suites */
    ja4->ciphers = NULL;
    ja4->ciphers_sz = 0;
    /*
    Allocate memory for and populate a list of ciphers from 'c->ssl->ciphers'.
    The resulting ciphers are stored in host byte
    order in 'ja4->ciphers'. If memory allocation fails, the function returns NGX_DECLINED.
    */
    if (c->ssl->ciphers && c->ssl->ciphers_sz)
    {
        // Allocate memory for the array of cipher strings
        len = c->ssl->ciphers_sz * sizeof(char *);
        ja4->ciphers = ngx_pnalloc(pool, len);
        if (ja4->ciphers == NULL)
        {
            return NGX_DECLINED;
        }

        // Add c->ssl->ciphers to ja4->ciphers
        for (i = 0; i < c->ssl->ciphers_sz; ++i)
        {
            size_t hex_str_len = strlen(c->ssl->ciphers[i]) + 1; // +1 for null terminator

            // Allocate memory for the hex string and copy it
            ja4->ciphers[ja4->ciphers_sz] = ngx_pnalloc(pool, hex_str_len);
            if (ja4->ciphers[ja4->ciphers_sz] == NULL)
            {
                // Handle allocation failure and clean up previously allocated memory
                for (size_t j = 0; j < ja4->ciphers_sz; j++)
                {
                    ngx_pfree(pool, ja4->ciphers[j]);
                }
                ngx_pfree(pool, ja4->ciphers);
                ja4->ciphers = NULL;
                return NGX_DECLINED;
            }
            ngx_memcpy(ja4->ciphers[ja4->ciphers_sz], c->ssl->ciphers[i], hex_str_len);
            ja4->ciphers_sz++;
        }

        /* Now, let's sort the ja4->ciphers array */
        qsort(ja4->ciphers, ja4->ciphers_sz, sizeof(char *), compare_hexes);
    }

    // Check if we got ciphers
    if (ja4->ciphers && ja4->ciphers_sz)
    {
        // SHA256_DIGEST_LENGTH should be 32 bytes (256 bits)
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        // Declare a context structure needed by OpenSSL to compute hash
        SHA256_CTX sha256;
        // Initialize the context
        SHA256_Init(&sha256);

        // Iterate each cipher and add data to the context
        for (i = 0; i < ja4->ciphers_sz; i++)
        {
            SHA256_Update(&sha256, ja4->ciphers[i], strlen(ja4->ciphers[i]));
            // Add a comma separator between ciphers
            if (i < ja4->ciphers_sz - 1)
            {
                SHA256_Update(&sha256, ",", 1);
            }
        }
        // Compute hash, stored in hash_result
        SHA256_Final(hash_result, &sha256);
        // Convert the hash result to hex
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(&ja4->cipher_hash[i * 2], "%02x", hash_result[i]);
        }
        ja4->cipher_hash[2 * SHA256_DIGEST_LENGTH] = '\0'; // Null-terminate the hex string

        // Copy the first 6 bytes (12 characters) for the truncated hash
        ngx_memcpy(ja4->cipher_hash_truncated, ja4->cipher_hash, 12);
        ja4->cipher_hash_truncated[12] = '\0'; // Null-terminate the truncated hex string
    }

    /* Extensions */
    ja4->extensions = NULL;
    ja4->extensions_sz = 0;
    ja4->extensions_count = 0;
    if (c->ssl->extensions_sz && c->ssl->extensions)
    {
        len = c->ssl->extensions_sz * sizeof(char *);
        ja4->extensions = ngx_pnalloc(pool, len);
        if (ja4->extensions == NULL)
        {
            return NGX_DECLINED;
        }
        for (i = 0; i < c->ssl->extensions_sz; ++i)
        {
            if (!ngx_ssl_ja4_is_ext_greased(c->ssl->extensions[i]))
            {
                ja4->extensions_count++;
                if (ngx_ssl_ja4_is_ext_ignored(c->ssl->extensions[i]))
                {
                    // don't consider in list of extensions, but still count it
                    continue;
                }
                char *ext = c->ssl->extensions[i];
                size_t ext_len = strlen(ext) + 1; // +1 for null terminator

                // Allocate memory for the extension string and copy it
                ja4->extensions[ja4->extensions_sz] = ngx_pnalloc(pool, ext_len);
                if (ja4->extensions[ja4->extensions_sz] == NULL)
                {
                    // Handle allocation failure and clean up previously allocated memory
                    for (size_t j = 0; j < ja4->extensions_sz; j++)
                    {
                        ngx_pfree(pool, ja4->extensions[j]);
                    }
                    ngx_pfree(pool, ja4->extensions);
                    ja4->extensions = NULL;
                    return NGX_DECLINED;
                }
                ngx_memcpy(ja4->extensions[ja4->extensions_sz], ext, ext_len);
                ja4->extensions_sz++;
            }
        }
        /* Now, let's sort the ja4->extensions array */
        qsort(ja4->extensions, ja4->extensions_sz, sizeof(char *), compare_hexes);
    }

    // signature algorithms
    ja4->sigalgs = NULL;
    ja4->sigalgs_sz = 0;
    if (c->ssl->sigalgs_sz && c->ssl->sigalgs_hash_values)
    {
        len = c->ssl->sigalgs_sz * sizeof(char *);
        ja4->sigalgs = ngx_pnalloc(pool, len);
        if (ja4->sigalgs == NULL)
        {
            return NGX_DECLINED;
        }
        for (i = 0; i < c->ssl->sigalgs_sz; ++i)
        {
            size_t sigalg_len = strlen(c->ssl->sigalgs_hash_values[i]) + 1; // +1 for null terminator

            // Allocate memory for the signature algorithm string and copy it
            ja4->sigalgs[ja4->sigalgs_sz] = ngx_pnalloc(pool, sigalg_len);
            if (ja4->sigalgs[ja4->sigalgs_sz] == NULL)
            {
                // Handle allocation failure and clean up previously allocated memory
                for (size_t j = 0; j < ja4->sigalgs_sz; j++)
                {
                    ngx_pfree(pool, ja4->sigalgs[j]);
                }
                ngx_pfree(pool, ja4->sigalgs);
                ja4->sigalgs = NULL;
                return NGX_DECLINED;
            }
            ngx_memcpy(ja4->sigalgs[ja4->sigalgs_sz], c->ssl->sigalgs_hash_values[i], sigalg_len);
            ja4->sigalgs_sz++;
        }
    }

    if (ja4->extensions && ja4->extensions_sz)
    {
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        if (SHA256_Init(&sha256) != 1)
        {
            return NGX_DECLINED;
        }

        for (i = 0; i < ja4->extensions_sz; i++)
        {
            SHA256_Update(&sha256, ja4->extensions[i], strlen(ja4->extensions[i]));
            if (i < ja4->extensions_sz - 1)
            {
                SHA256_Update(&sha256, ",", 1);
            }
        }

        if (ja4->sigalgs_sz)
        {
            // add underscore
            SHA256_Update(&sha256, "_", 1);
            for (i = 0; i < ja4->sigalgs_sz; i++)
            {
                SHA256_Update(&sha256, ja4->sigalgs[i], strlen(ja4->sigalgs[i]));
                if (i < ja4->sigalgs_sz - 1)
                {
                    SHA256_Update(&sha256, ",", 1);
                }
            }
        }

        SHA256_Final(hash_result, &sha256);

        // Convert the full hash to hexadecimal format
        char hex_hash[2 * SHA256_DIGEST_LENGTH + 1]; // +1 for null-terminator
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(hex_hash + 2 * i, "%02x", hash_result[i]);
        }
        ngx_memcpy(ja4->extension_hash, hex_hash, 2 * SHA256_DIGEST_LENGTH);

        // Convert the truncated hash to hexadecimal format
        char hex_hash_truncated[2 * 6 + 1]; // 6 bytes, 2 characters each = 12 characters plus null-terminator
        for (i = 0; i < 6; i++)
        {
            sprintf(hex_hash_truncated + 2 * i, "%02x", hash_result[i]);
        }
        // Copy the first 6 bytes (12 characters) for the truncated hash
        ngx_memcpy(ja4->extension_hash_truncated, hex_hash_truncated, 12);
        ja4->extension_hash_truncated[12] = '\0';
    }

    return NGX_OK;
}
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // Calculate memory requirements for output
    size_t len = 256; // Big enough

    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }
    out->len = len;

    size_t cur = 0;

    // q for QUIC or t for TCP
    // Assuming is_quic is a boolean.
    // out->data[cur++] = (ja4->is_quic) ? 'q' : 't';
    // TODO: placeholder
    out->data[cur++] = 't';

    // 2 character TLS version
    memcpy(out->data + cur, ja4->version, 2);
    cur += 2;

    // SNI = d, no SNI = i
    out->data[cur++] = ja4->has_sni;

    // 2 character count of ciphers
    if (ja4->ciphers_sz == 0)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        ngx_snprintf(out->data + cur, 3, "%02zu", ja4->ciphers_sz);
    }
    cur += 2;

    // 2 character count of extensions
    if (ja4->extensions_count == 0)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        ngx_snprintf(out->data + cur, 3, "%02zu", ja4->extensions_count);
    }
    cur += 2;

    // Add ALPN first value
    if (ja4->alpn_first_value == NULL)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        ngx_snprintf(out->data + cur, 3, "%s", ja4->alpn_first_value);
    }
    cur += 2;

    // Add underscore
    out->data[cur++] = '_';

    // Add cipher hash, 12 characters for truncated hash
    ngx_snprintf(out->data + cur, 13, "%s", ja4->cipher_hash_truncated);
    cur += 12;

    // Add underscore
    out->data[cur++] = '_';

    // Add extension hash, 12 characters for truncated hash
    ngx_snprintf(out->data + cur, 13, "%s", ja4->extension_hash_truncated);
    cur += 12;

    // Null-terminate the string
    out->data[cur] = '\0';
    out->len = cur;

#if (NGX_DEBUG)
    ngx_ssl_ja4_detail_print(pool, ja4);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: fp: [%V]\n", out);
#endif
}
static ngx_int_t
ngx_http_ssl_ja4(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }
    if (ngx_ssl_ja4(r->connection, r->pool, &ja4) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4_fp(r->pool, &ja4, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

// JA4 STRING
void ngx_ssl_ja4_fp_string(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // This function calculates the ja4 fingerprint but it doesn't hash extensions and ciphers
    // Instead, it just comma separates them

    char **sigalgs_copy = malloc(ja4->sigalgs_sz * sizeof(char *));
    for (size_t i = 0; i < ja4->sigalgs_sz; ++i)
    {
        sigalgs_copy[i] = strdup(ja4->sigalgs[i]);
    }

    // Initial size calculation
    // Base size for fixed elements: 't', version (2 chars), has_sni, ciphers_sz (2 chars), extensions_sz (2 chars),
    // alpn (2 chars), separators ('_' x3), null-terminator
    size_t len = 1 + 2 + 1 + 2 + 2 + 2 + 3 + 1;
    // Dynamic size for variable elements: ciphers, extensions, signature algorithms
    for (size_t i = 0; i < ja4->ciphers_sz; ++i)
    {
        len += strlen(ja4->ciphers[i]) + 1; // strlen of cipher + comma
    }
    for (size_t i = 0; i < ja4->extensions_sz; ++i)
    {
        len += strlen(ja4->extensions[i]) + 1; // strlen of extension + comma
    }
    for (size_t i = 0; i < ja4->sigalgs_sz; ++i)
    {
        len += strlen(ja4->sigalgs[i]) + 1; // strlen of sigalg + comma
    }

    len += 256; // Safety padding

    // Allocate memory based on calculated size
    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }

    size_t cur = 0;

    // t for TCP
    out->data[cur++] = 't';

    // 2 character TLS version
    if (ja4->version == NULL)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        ngx_snprintf(out->data + cur, 3, "%s", ja4->version);
    }
    cur += 2;

    // SNI = d, no SNI = i
    out->data[cur++] = ja4->has_sni;

    // 2 character count of ciphers
    if (ja4->ciphers_sz == 0)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        ngx_snprintf(out->data + cur, 3, "%02zu", ja4->ciphers_sz);
    }
    cur += 2;

    // 2 character count of extensions
    if (ja4->extensions_count == 0)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        ngx_snprintf(out->data + cur, 3, "%02zu", ja4->extensions_count);
    }
    cur += 2;

    // Add 2 characters for the ALPN ja4->alpn_first_value;
    if (ja4->alpn_first_value == NULL)
    {
        ngx_snprintf(out->data + cur, 2, "00");
    }
    else
    {
        ngx_snprintf(out->data + cur, 2, "%s", ja4->alpn_first_value);
    }
    cur += 2;

    // Separator
    out->data[cur++] = '_';

    // Add ciphers
    if (ja4->ciphers_sz > 0)
    {
        for (size_t i = 0; i < ja4->ciphers_sz; ++i)
        {
            size_t n = ngx_snprintf(out->data + cur, strlen(ja4->ciphers[i]) + 2, "%s,", ja4->ciphers[i]) - out->data - cur;
            cur += n;
        }
        cur--; // Remove the trailing comma
    }

    // Separator
    out->data[cur++] = '_';

    // Add extensions
    if (ja4->extensions_sz > 0)
    {
        for (size_t i = 0; i < ja4->extensions_sz; ++i)
        {
            size_t n = ngx_snprintf(out->data + cur, strlen(ja4->extensions[i]) + 2, "%s,", ja4->extensions[i]) - out->data - cur;
            cur += n;
        }
        cur--; // Remove the trailing comma
    }

    // Add signature algorithms
    if (ja4->sigalgs_sz > 0)
    {
        out->data[cur++] = '_'; // Add separator only if signature algorithms are present
        for (size_t i = 0; i < ja4->sigalgs_sz; ++i)
        {
            size_t n = ngx_snprintf(out->data + cur, strlen(sigalgs_copy[i]) + 2, "%s,", sigalgs_copy[i]) - out->data - cur;
            cur += n;
        }
        cur--; // Remove the trailing comma
    }

    for (size_t i = 0; i < ja4->sigalgs_sz; ++i)
    {
        free(sigalgs_copy[i]);
    }
    free(sigalgs_copy);

    // Null-terminate the string
    out->data[cur] = '\0';
    out->len = cur;

#if (NGX_DEBUG)
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: fp_string: [%V]\n", out);
#endif
}

static ngx_int_t
ngx_http_ssl_ja4_string(ngx_http_request_t *r,
                        ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4_t ja4;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(r->connection, r->pool, &ja4) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4_fp_string(r->pool, &ja4, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

// JA4S
int ngx_ssl_ja4s(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4s)
{
    // this function sets stuff on the ja4s struct so the fingerprint can easily, and clearly be formed in a separate function
    SSL *ssl;
    // size_t i;
    // size_t len = 0;
    // unsigned short us = 0;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}
static ngx_int_t
ngx_http_ssl_ja4s(ngx_http_request_t *r,
                  ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4s(r->connection, r->pool, &ja4s) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4s_fp(r->pool, &ja4s, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4s_fp(ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4, ngx_str_t *out)
{
}

// JA4S STRING
static ngx_int_t
ngx_http_ssl_ja4s_string(ngx_http_request_t *r,
                         ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4s_t ja4s;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4s(r->connection, r->pool, &ja4s) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4s_fp_string(r->pool, &ja4s, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4s_fp_string(ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4, ngx_str_t *out)
{
    // this function calculates the ja4s fingerprint but it doesn't hash extensions and ciphers
    // instead, it just comma separates them

    // Estimate memory requirements for output
    size_t len = 1;

    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }

    // size_t cur = 0;
}

// JA4X
int ngx_ssl_ja4x(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4x_t *ja4x)
{
    // this function sets stuff on the ja4x struct so the fingerprint can easily, and clearly be formed in a separate function
    SSL *ssl;
    // size_t i;
    // size_t len = 0;
    // unsigned short us = 0;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}
static ngx_int_t
ngx_http_ssl_ja4x(ngx_http_request_t *r,
                  ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4x_t ja4x;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4x(r->connection, r->pool, &ja4x) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4x_fp(r->pool, &ja4x, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4x_fp(ngx_pool_t *pool, ngx_ssl_ja4x_t *ja4x, ngx_str_t *out) {}

// JA4X STRING
static ngx_int_t
ngx_http_ssl_ja4x_string(ngx_http_request_t *r,
                         ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4x_t ja4x;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4x(r->connection, r->pool, &ja4x) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4x_fp_string(r->pool, &ja4x, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4x_fp_string(ngx_pool_t *pool, ngx_ssl_ja4x_t *ja4x, ngx_str_t *out) {}

// JA4H
int ngx_ssl_ja4h(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h)
{
    // this function sets stuff on the ja4s struct so the fingerprint can easily, and clearly be formed in a separate function
    SSL *ssl;
    // size_t i;
    // size_t len = 0;
    // unsigned short us = 0;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}
static ngx_int_t
ngx_http_ssl_ja4h(ngx_http_request_t *r,
                  ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4h_t ja4h;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4h(r->connection, r->pool, &ja4h) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4h_fp(r->pool, &ja4h, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4h_fp(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h, ngx_str_t *out) {}

// JA4H STRING
static ngx_int_t
ngx_http_ssl_ja4h_string(ngx_http_request_t *r,
                         ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4h_t ja4h;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4h(r->connection, r->pool, &ja4h) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4h_fp_string(r->pool, &ja4h, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4h_fp_string(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h, ngx_str_t *out) {}

// JA4T
int ngx_ssl_ja4t(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4t_t *ja4t)
{
    // this function sets stuff on the ja4s struct so the fingerprint can easily, and clearly be formed in a separate function
    SSL *ssl;
    // size_t i;
    // size_t len = 0;
    // unsigned short us = 0;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}
static ngx_int_t
ngx_http_ssl_ja4t(ngx_http_request_t *r,
                  ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4t_t ja4t;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4t(r->connection, r->pool, &ja4t) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4t_fp(r->pool, &ja4t, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4t_fp(ngx_pool_t *pool, ngx_ssl_ja4t_t *ja4t, ngx_str_t *out) {}

// JA4T STRING
static ngx_int_t
ngx_http_ssl_ja4t_string(ngx_http_request_t *r,
                         ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4t_t ja4t;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4t(r->connection, r->pool, &ja4t) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4t_fp_string(r->pool, &ja4t, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4t_fp_string(ngx_pool_t *pool, ngx_ssl_ja4t_t *ja4t, ngx_str_t *out) {}

// JA4TS
int ngx_ssl_ja4ts(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4ts_t *ja4ts)
{
    // this function sets stuff on the ja4s struct so the fingerprint can easily, and clearly be formed in a separate function
    SSL *ssl;
    // size_t i;
    // size_t len = 0;
    // unsigned short us = 0;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }
    return NGX_OK;
}
static ngx_int_t
ngx_http_ssl_ja4ts(ngx_http_request_t *r,
                   ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4t_t ja4t;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4t(r->connection, r->pool, &ja4t) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4t_fp(r->pool, &ja4t, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4ts_fp(ngx_pool_t *pool, ngx_ssl_ja4ts_t *ja4ts, ngx_str_t *out) {}

// JA4TS STRING
static ngx_int_t
ngx_http_ssl_ja4ts_string(ngx_http_request_t *r,
                          ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4ts_t ja4ts;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4ts(r->connection, r->pool, &ja4ts) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4ts_fp_string(r->pool, &ja4ts, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}
void ngx_ssl_ja4ts_fp_string(ngx_pool_t *pool, ngx_ssl_ja4ts_t *ja4ts, ngx_str_t *out) {}

// JA4L
int ngx_ssl_ja4l(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4l_t *ja4l)
{

    SSL *ssl;

    if (!c->ssl)
    {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked)
    {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl)
    {
        return NGX_DECLINED;
    }

    // transfer ssl connection variables to the ja4l struct
    ja4l->handshake_roundtrip_microseconds = c->ssl->handshake_roundtrip_microseconds;
    ja4l->ttl = c->ssl->ttl;

    return NGX_OK;
}
void ngx_ssl_ja4l_fp(ngx_pool_t *pool, ngx_ssl_ja4l_t *ja4l, ngx_str_t *out)
{
    // Calculate the maximum lengths of the variables
    const size_t max_time_len = 5;      // uint16_t max is 65535, which is 5 characters
    const size_t max_ttl_len = 3;       // uint8_t max is 255, which is 3 characters
    const size_t max_hop_count_len = 3; // uint8_t max is 255, which is 3 characters

    // init stuff
    double propagation_delay_factor; // Declare the variable to store the propagation delay factor
    uint8_t initial_ttl;

    // Include space for 2 underscores and the null-terminator
    size_t total_len = max_time_len + max_ttl_len + max_hop_count_len + 2 + 1;

    // Allocate memory
    out->data = ngx_palloc(pool, total_len);
    if (out->data == NULL)
    {
        // Handle memory allocation failure
        return;
    }

    // All routes on the Internet have less than 64 hops.
    // Therefore if the TTL value is within 65-128, the estimated initial TTL is 128.
    // If the TTL value is 0-64, the estimated initial TTL is 64.
    // And if the TTL is >128 then the estimated initial TTL is 255.
    if (ja4l->ttl > 128)
    {
        initial_ttl = 255;
    }
    else if (ja4l->ttl > 64)
    {
        initial_ttl = 128;
    }
    else
    {
        initial_ttl = 64;
    }

    ja4l->hop_count = initial_ttl - ja4l->ttl;

    if (ja4l->hop_count <= 21)
    {
        propagation_delay_factor = 1.5;
    }
    else if (ja4l->hop_count == 22)
    {
        propagation_delay_factor = 1.6;
    }
    else if (ja4l->hop_count == 23)
    {
        propagation_delay_factor = 1.7;
    }
    else if (ja4l->hop_count == 24)
    {
        propagation_delay_factor = 1.8;
    }
    else if (ja4l->hop_count == 25)
    {
        propagation_delay_factor = 1.9;
    }
    else if (ja4l->hop_count >= 26)
    {
        propagation_delay_factor = 2.0;
    }

    // This is effectively
    // time message takes to get from client to server * miles light travels per microsecond adjusted with propagation delay factor
    ja4l->distance_miles = (ja4l->handshake_roundtrip_microseconds / 2) * 0.13 / propagation_delay_factor;

    // Create the concatenated string
    int written = snprintf((char *)out->data, total_len, "%u_%u_%u",
                           ja4l->handshake_roundtrip_microseconds / 2,
                           ja4l->ttl,
                           ja4l->hop_count);

    if (written < 0)
    {
        // Handle snprintf failure
        return;
    }

    out->len = (size_t)written;

#if (NGX_DEBUG)
    ngx_ssl_ja4l_detail_print(pool, ja4l);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4l: fp: [%V]\n", out);
#endif
}
static ngx_int_t
ngx_http_ssl_ja4l(ngx_http_request_t *r,
                  ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_ja4l_t ja4l;
    ngx_str_t fp = ngx_null_string;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4l(r->connection, r->pool, &ja4l) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ngx_ssl_ja4l_fp(r->pool, &ja4l, &fp);

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    return NGX_OK;
}

// HELPERS AND CONFIG

/**
 * ngx_http_ssl_ja4_init - Initialize Nginx variables for JA4.
 *
 * This function initializes Nginx variables so that they can be accessed
 * and used in the Nginx configuration files. It iterates over a predefined
 * list of variables (`ngx_http_ssl_ja4_variables_list`) and registers each
 * variable using the `ngx_http_add_variable` function.
 *
 * @param cf A pointer to the Nginx configuration structure.
 * @return NGX_OK on successful initialization.
 */
static ngx_int_t
ngx_http_ssl_ja4_init(ngx_conf_t *cf)
{

    ngx_http_variable_t *v;
    size_t l = 0;
    size_t vars_len;

    vars_len = (sizeof(ngx_http_ssl_ja4_variables_list) /
                sizeof(ngx_http_ssl_ja4_variables_list[0]));

    /* Register variables */
    for (l = 0; l < vars_len; ++l)
    {
        v = ngx_http_add_variable(cf,
                                  &ngx_http_ssl_ja4_variables_list[l].name,
                                  ngx_http_ssl_ja4_variables_list[l].flags);
        if (v == NULL)
        {
            continue;
        }
        *v = ngx_http_ssl_ja4_variables_list[l];
    }

    return NGX_OK;
}

/* http_json_log config preparation */
// adds a function that executes after configuraiton finishes..? not sure
static ngx_http_module_t ngx_http_ssl_ja4_module_ctx = {
    NULL,                  /* preconfiguration */
    ngx_http_ssl_ja4_init, /* postconfiguration */
    NULL,                  /* create main configuration */
    NULL,                  /* init main configuration */
    NULL,                  /* create server configuration */
    NULL,                  /* merge server configuration */
    NULL,                  /* create location configuration */
    NULL                   /* merge location configuration */
};

/* http_json_log delivery */
// creates a module w/ a context/configuration? maybe?
ngx_module_t ngx_http_ssl_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_ja4_module_ctx, /* module context */
    NULL,                         /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING};
