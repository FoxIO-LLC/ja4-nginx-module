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
    {ngx_string("http_ssl_ja4one"),
     NULL,
     ngx_http_ssl_ja4one,
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

// JA4
int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{
    // this function sets stuff on the ja4 struct so the fingerprint can easily, and clearly be formed in a separate function
    SSL *ssl;
    size_t i, j;
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
    int client_version_int = SSL_client_version(ssl);
    int max_version_int = SSL_get_max_proto_version(ssl);
    int version_int = 0;

    if (c->ssl->version) {
        version_int = max_version_int;
    } else {
        version_int = client_version_int;
    }

    switch(version_int)
    {
        case SSL3_VERSION_INT:
            ja4->version = "s3";
            break;
        case TLS1_VERSION_INT:
            ja4->version = "10";
            break;
        case TLS1_1_VERSION_INT:
            ja4->version = "11";
            break;
        case TLS1_2_VERSION_INT:
            ja4->version = "12";
            break;
        case TLS1_3_VERSION_INT:
            ja4->version = "13";
            break;
        case QUICV1_VERSION_INT:
            ja4->version = "q1";
            break;
        default:
            ja4->version = "00";
            break;
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
            if (ngx_ssl_ja4_is_ext_greased(c->ssl->ciphers[i])) {
                continue;
            }

            // Allocate memory for the hex string and copy it
            ja4->ciphers[ja4->ciphers_sz] = ngx_pnalloc(pool, hex_str_len);
            if (ja4->ciphers[ja4->ciphers_sz] == NULL)
            {
                // Handle allocation failure and clean up previously allocated memory
                for (j = 0; j < ja4->ciphers_sz; j++)
                {
                    ngx_pfree(pool, ja4->ciphers[j]);
                }
                ngx_pfree(pool, ja4->ciphers);
                ja4->ciphers = NULL;
                return NGX_DECLINED;
            }
            ngx_memcpy(ja4->ciphers[ja4->ciphers_sz], (char *)c->ssl->ciphers[i], hex_str_len);
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

    // extensions_no_psk
    // no need for sz here bc not counting ignored extensions
    ja4->extensions_no_psk = NULL;
    ja4->extensions_no_psk_count = 0;
    if (c->ssl->extensions_sz && c->ssl->extensions)
    {
        len = c->ssl->extensions_sz * sizeof(char *);
        ja4->extensions = ngx_pnalloc(pool, len);
        ja4->extensions_no_psk = ngx_pnalloc(pool, len);
        if (ja4->extensions == NULL)
        {
            return NGX_DECLINED;
        }
        for (i = 0; i < c->ssl->extensions_sz; ++i)
        {
            if (!ngx_ssl_ja4_is_ext_greased(c->ssl->extensions[i]))

            {
                char *ext = (char *)c->ssl->extensions[i];
                size_t ext_len = strlen(ext) + 1; // +1 for null terminator

                ja4->extensions_count++;

                // ignored extensions are only counted, not hashed
                if (!ngx_ssl_ja4_is_ext_ignored(c->ssl->extensions[i]))
                {

                    // Allocate memory for the extension string and copy it
                    ja4->extensions[ja4->extensions_sz] = ngx_pnalloc(pool, ext_len);
                    if (ja4->extensions[ja4->extensions_sz] == NULL)
                    {
                        // Handle allocation failure and clean up previously allocated memory
                        for (j = 0; j < ja4->extensions_sz; j++)
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
                // for no psk ignored extensions are not counted, not hashed
                if (ngx_ssl_ja4_is_ext_ignored(c->ssl->extensions[i]))
                {
                    continue;
                }
                // check if the extension is not a PSK extension
                if (!ngx_ssl_ja4_is_ext_dynamic(c->ssl->extensions[i]))
                {
                    // Allocate memory for the extension string and copy it
                    ja4->extensions_no_psk[ja4->extensions_no_psk_count] = ngx_pnalloc(pool, ext_len);
                    // handle allocation failure
                    if (ja4->extensions_no_psk[ja4->extensions_no_psk_count] == NULL)
                    {
                        // Handle allocation failure and clean up previously allocated memory
                        for (j = 0; j < ja4->extensions_no_psk_count; j++)
                        {
                            ngx_pfree(pool, ja4->extensions_no_psk[j]);
                        }
                        ngx_pfree(pool, ja4->extensions_no_psk);
                        ja4->extensions_no_psk = NULL;
                        return NGX_DECLINED;
                    }
                    ngx_memcpy(ja4->extensions_no_psk[ja4->extensions_no_psk_count], ext, ext_len);
                    ja4->extensions_no_psk_count++;
                }
            }
        }
        /* Now, let's sort the ja4->extensions array */
        // what is going on with the mem alloc in these arguments...
        qsort(ja4->extensions, ja4->extensions_sz, sizeof(char *), compare_hexes);
        // sort extensions_no_psk
        qsort(ja4->extensions_no_psk, ja4->extensions_no_psk_count, sizeof(char *), compare_hexes);
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
                for (j = 0; j < ja4->sigalgs_sz; j++)
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

    // generate hash for extensions
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
        ja4->extension_hash[2 * SHA256_DIGEST_LENGTH] = '\0';

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

    // generate hash for extensions_no_psk
    // also doesn't include signature algorithms
    if (ja4->extensions_no_psk && ja4->extensions_no_psk_count)
    {
        unsigned char hash_result[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256_psk;
        if (SHA256_Init(&sha256_psk) != 1)
        {
            return NGX_DECLINED;
        }

        for (i = 0; i < ja4->extensions_no_psk_count; i++)
        {
            SHA256_Update(&sha256_psk, ja4->extensions_no_psk[i], strlen(ja4->extensions_no_psk[i]));
            // add comma separator if not last val
            if (i < ja4->extensions_no_psk_count - 1)
            {
                SHA256_Update(&sha256_psk, ",", 1);
            }
        }

        SHA256_Final(hash_result, &sha256_psk);

        // Convert the full hash to hexadecimal (human readable) format
        char hex_hash[2 * SHA256_DIGEST_LENGTH + 1]; // +1 for null-terminator
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(hex_hash + 2 * i, "%02x", hash_result[i]);
        }
        ngx_memcpy(ja4->extension_hash_no_psk, hex_hash, 2 * SHA256_DIGEST_LENGTH);
        ja4->extension_hash_no_psk[2 * SHA256_DIGEST_LENGTH] = '\0';

        // Convert the truncated hash to hexadecimal format
        char hex_hash_truncated[2 * 6 + 1]; // 6 bytes, 2 characters each = 12 characters plus null-terminator
        for (i = 0; i < 6; i++)
        {
            sprintf(hex_hash_truncated + 2 * i, "%02x", hash_result[i]);
        }
        // Copy the first 6 bytes (12 characters) for the truncated hash
        ngx_memcpy(ja4->extension_hash_no_psk_truncated, hex_hash_truncated, 12);
        ja4->extension_hash_no_psk_truncated[12] = '\0';
    }
    return NGX_OK;
}
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // this function uses stuff on the ja4 struct to create a fingerprint
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

    // Add ALPN first and last value
    if (ja4->alpn_first_value == NULL || ngx_strlen(ja4->alpn_first_value) < 2)
    {
        ngx_snprintf(out->data + cur, 3, "00");  // Default to "00" if null or too short
    }
    else
    {
        // Get the first and last character from ja4->alpn_first_value
        char first = ja4->alpn_first_value[0];
        char last = ja4->alpn_first_value[ngx_strlen(ja4->alpn_first_value) - 1];
        ngx_snprintf(out->data + cur, 3, "%c%c", first, last);  // Format them into out->data
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
    size_t i;
    char **sigalgs_copy = malloc(ja4->sigalgs_sz * sizeof(char *));
    for (i = 0; i < ja4->sigalgs_sz; ++i)
    {
        sigalgs_copy[i] = strdup(ja4->sigalgs[i]);
    }

    // Initial size calculation
    // Base size for fixed elements: 't', version (2 chars), has_sni, ciphers_sz (2 chars), extensions_sz (2 chars),
    // alpn (2 chars), separators ('_' x3), null-terminator
    size_t len = 1 + 2 + 1 + 2 + 2 + 2 + 3 + 1;
    // Dynamic size for variable elements: ciphers, extensions, signature algorithms
    for (i = 0; i < ja4->ciphers_sz; ++i)
    {
        len += strlen(ja4->ciphers[i]) + 1; // strlen of cipher + comma
    }
    for (i = 0; i < ja4->extensions_sz; ++i)
    {
        len += strlen(ja4->extensions[i]) + 1; // strlen of extension + comma
    }
    for (i = 0; i < ja4->sigalgs_sz; ++i)
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
        for (i = 0; i < ja4->ciphers_sz; ++i)
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
        for (i = 0; i < ja4->extensions_sz; ++i)
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
        for (i = 0; i < ja4->sigalgs_sz; ++i)
        {
            size_t n = ngx_snprintf(out->data + cur, strlen(sigalgs_copy[i]) + 2, "%s,", sigalgs_copy[i]) - out->data - cur;
            cur += n;
        }
        cur--; // Remove the trailing comma
    }

    for (i = 0; i < ja4->sigalgs_sz; ++i)
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

// JA4ONE
// creates fp
void ngx_ssl_ja4one_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out)
{
    // this function uses stuff on the ja4 struct to create a ja4one fingerprint
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
        ngx_snprintf(out->data + cur, 3, "%02zu", ja4->extensions_no_psk_count);
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
    ngx_snprintf(out->data + cur, 13, "%s", ja4->extension_hash_no_psk_truncated);
    cur += 12;

    // Null-terminate the string
    out->data[cur] = '\0';
    out->len = cur;

#if (NGX_DEBUG)
    ngx_ssl_ja4_detail_print(pool, ja4);
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0, "ssl_ja4: fp: [%V]\n", out);
#endif
}
// assigns fp to variable
static ngx_int_t
ngx_http_ssl_ja4one(ngx_http_request_t *r,
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

    ngx_ssl_ja4one_fp(r->pool, &ja4, &fp);

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
int ngx_ssl_ja4h(ngx_http_request_t *r, ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h)
{
    ngx_str_t *entry;
    size_t i;

    if (r->method_name.len < 2) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "JA4H failed: Unknown request method");
        return NGX_DECLINED;
    }

    // JA4H_a
    ngx_memset(ja4h->http_method, 0, 3);
    ngx_strlow((u_char *) ja4h->http_method, (u_char *) r->method_name.data, 2);

    ngx_memset(ja4h->http_version, 0, 3);
    ngx_snprintf((u_char *) ja4h->http_version, 2, "%d%d", r->http_version / 1000, r->http_version % 1000);

    ja4h->cookie_presence = r->headers_in.cookie ? 'c' : 'n';
    ja4h->referrer_presence = r->headers_in.referer ? 'r' : 'n';

    ngx_memset(ja4h->num_headers, 0, 3);
    ngx_snprintf((u_char *) ja4h->num_headers, 2, "%02d", r->headers_in.headers.part.nelts - (r->headers_in.cookie ? 1 : 0) - (r->headers_in.referer ? 1 : 0));

    ngx_memcpy(ja4h->primary_accept_language, "0000", 5);

    // JA4H_b
    SHA256_CTX sha256;
    unsigned char hash_result[SHA256_DIGEST_LENGTH];
    memset(hash_result, 0, SHA256_DIGEST_LENGTH);

    if (SHA256_Init(&sha256) != 1) {
        return NGX_DECLINED;
    }

    ngx_list_part_t *headers_part = &r->headers_in.headers.part;
    ngx_table_elt_t *header_item = headers_part->elts;

    size_t raw_http_headers_len = 0;
    // Count the total length of all header key separated by a ','
    for (i = 0; /* void */; i++) {
        if (i >= headers_part->nelts) {
            if (headers_part->next == NULL){
                break;
            }
            headers_part = headers_part->next;
            header_item = headers_part->elts;
            i = 0;
        }
        raw_http_headers_len += header_item[i].key.len + 1;
    }

    // Allocate memory for the raw_http_headers
    ja4h->raw_http_headers = ngx_pcalloc(pool, raw_http_headers_len + 1);
    if (ja4h->raw_http_headers == NULL) {
        return NGX_ERROR;
    }

    headers_part = &r->headers_in.headers.part;
    header_item = headers_part->elts;
    u_char *current = NULL;
    for (i = 0; /* void */; i++) {
        if (i >= headers_part->nelts) {
            if (headers_part->next == NULL){
                break;
            }
            headers_part = headers_part->next;
            header_item = headers_part->elts;
            i = 0;
        }

        if ((ja4h->primary_accept_language[0] == '0')
            && (header_item[i].key.len == sizeof("Accept-Language") - 1)
            && (ngx_strncasecmp(header_item[i].key.data, (u_char *) "Accept-Language", sizeof("Accept-Language") - 1) == 0)) {
            size_t idx, c;
            // Get the first 4 character of primary Accept-Language
            for( c=0, idx=0; idx < 4; c++ ) {
                if (header_item[i].value.data[c] == '-') {
                    continue;
                } else if (header_item[i].value.data[c] == ','
                    || header_item[i].value.data[c] == ';'
                    || header_item[i].value.data[c] == '\0') {
                    break;
                }
                ja4h->primary_accept_language[idx++] = ngx_tolower(header_item[i].value.data[c]);
            }
        }
        if (current == NULL) {
            current = (u_char *) ja4h->raw_http_headers;
        } else {
            *current++ = ',';
        }
        ngx_memcpy(current, header_item[i].key.data, header_item[i].key.len);
        current += header_item[i].key.len;
        SHA256_Update(&sha256, header_item[i].key.data, header_item[i].key.len);
    }
    SHA256_Final(hash_result, &sha256);

    // Convert the first 6 bytes of hash to hex for JA4H_b
    ngx_memset(ja4h->http_header_hash, 0, 13);
    for (i = 0; i < 6; i++) {
        sprintf(&ja4h->http_header_hash[i * 2], "%02x", hash_result[i]);
    }

    // JA4H_c_d
    size_t raw_cookie_fields_len = 0;
    size_t raw_cookie_values_len = 0;

    ngx_array_t *cookie_key_list = ngx_array_create(pool, 10, sizeof(ngx_str_t));
    if (cookie_key_list == NULL) {
        return NGX_ERROR;
    }
    ngx_array_t *cookie_key_value_list = ngx_array_create(pool, 10, sizeof(ngx_str_t));
    if (cookie_key_value_list == NULL) {
        return NGX_ERROR;
    }

    // Parse cookies value assignment
    ngx_table_elt_t *req_header_cookie;

    for(req_header_cookie = r->headers_in.cookie; req_header_cookie; req_header_cookie = req_header_cookie->next) {
        ngx_str_t *item;
        u_char *start, *end, *assignment;
        size_t key_len, value_len;

        start = req_header_cookie->value.data;
        end = start + req_header_cookie->value.len;
        for (current = start; current <= end; current++) {
            if (*current == ';' || current == end) {
                for(; *start && isspace(*start) && start < end; start++);
                item = (ngx_str_t *) ngx_array_push(cookie_key_value_list);
                if (item == NULL) {
                    return NGX_ERROR;
                }
                item->len = current - start;
                item->data = ngx_pcalloc(pool, item->len + 1);
                if (item->data == NULL) {
                    return NGX_ERROR;
                }
                ngx_memcpy(item->data, start, item->len);
                start = current + 1;
                assignment = (u_char *) strchr((char *) item->data, '=');
                if (assignment != NULL) {
                    key_len = assignment - item->data;
                } else {
                    key_len = item->len;
                }
                value_len = item->len - key_len - 1;
                raw_cookie_fields_len += key_len + 1;
                raw_cookie_values_len += value_len + 1;
            }
        }
    }

    // Sort the Cookie Fields + Value for JA4H
    ngx_qsort(cookie_key_value_list->elts, cookie_key_value_list->nelts, sizeof(ngx_str_t), compare_ngx_str);

    unsigned char hash_result_fields[SHA256_DIGEST_LENGTH];
    unsigned char hash_result_fields_values[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_fields;
    SHA256_CTX sha256_fields_values;

    memset(hash_result_fields, 0, SHA256_DIGEST_LENGTH);
    memset(hash_result_fields_values, 0, SHA256_DIGEST_LENGTH);

    if (SHA256_Init(&sha256_fields) != 1) {
        return NGX_DECLINED;
    }
    if (SHA256_Init(&sha256_fields_values) != 1) {
        return NGX_DECLINED;
    }

    ja4h->raw_cookie_fields = ngx_pcalloc(pool, raw_cookie_fields_len + 1);
    if (ja4h->raw_cookie_fields == NULL) {
        return NGX_ERROR;
    }
    ja4h->raw_cookie_values = ngx_pcalloc(pool, raw_cookie_values_len + 1);
    if (ja4h->raw_cookie_values == NULL) {
        return NGX_ERROR;
    }

    u_char *current_raw_cookie_field, *current_raw_cookie_value;
    size_t key_len, value_len;

    current_raw_cookie_field = (u_char *) ja4h->raw_cookie_fields;
    current_raw_cookie_value = (u_char *) ja4h->raw_cookie_values;

    for (i = 0; i < cookie_key_value_list->nelts; i++) {
        u_char *value, *assignment;
        entry = (ngx_str_t *) cookie_key_value_list->elts + i;
        SHA256_Update(&sha256_fields_values, entry->data, entry->len);
        assignment = (u_char *) strchr((char *) entry->data, '=');
        if (assignment != NULL) {
            value = assignment + 1;
            // Split key value assignment into two strings
            *assignment = '\0';
            key_len = assignment - entry->data;
            value_len = entry->len - key_len - 1;
        } else {
            key_len = entry->len;
            value_len = 0;
            value = NULL;
        }

        SHA256_Update(&sha256_fields, entry->data, entry->len);

        // Copy the key to the raw_cookie_fields
        if (current_raw_cookie_field != (u_char *) ja4h->raw_cookie_fields) {
            // Add comma separator if not the first entry
            *current_raw_cookie_field++ = ',';
        }
        ngx_memcpy(current_raw_cookie_field, entry->data, key_len);
        current_raw_cookie_field += key_len;

        if (value != NULL) {
            // Copy the value to the raw_cookie_values
            if (current_raw_cookie_value != (u_char *) ja4h->raw_cookie_values) {
                // Add comma separator if not the first entry
                *current_raw_cookie_value++ = ',';
            }
            ngx_memcpy(current_raw_cookie_value, value, value_len);
            current_raw_cookie_value += value_len;
        }
        if (assignment != NULL) {
            // Restore original key value assignment string
            *assignment = '=';
        }
    }
    SHA256_Final(hash_result_fields, &sha256_fields);
    SHA256_Final(hash_result_fields_values, &sha256_fields_values);

    // Convert the first 6 bytes of hash to hex for JA4H_c
    ngx_memset(ja4h->cookie_field_hash, 0, 13);
    for (i = 0; i < 6; i++) {
        sprintf(&ja4h->cookie_field_hash[i * 2], "%02x", hash_result_fields[i]);
    }

    // Convert the first 6 bytes of hash to hex for JA4H_d
    ngx_memset(ja4h->cookie_value_hash, 0, 13);
    for (i = 0; i < 6; i++) {
        sprintf(&ja4h->cookie_value_hash[i * 2], "%02x", hash_result_fields_values[i]);
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

    if (ngx_ssl_ja4h(r, r->pool, &ja4h) == NGX_DECLINED)
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
void ngx_ssl_ja4h_fp(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h, ngx_str_t *out) {
    out->data = ngx_pnalloc(pool, JA4H_FINGERPRINT_LENGTH + 1);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }
    memset(out->data, 0, JA4H_FINGERPRINT_LENGTH + 1);
    ngx_snprintf(out->data, JA4H_FINGERPRINT_LENGTH, "%s%s%c%c%s%s_%s_%s_%s",
        ja4h->http_method, ja4h->http_version,
        ja4h->cookie_presence, ja4h->referrer_presence,
        ja4h->num_headers, ja4h->primary_accept_language,
        ja4h->http_header_hash,
        ja4h->cookie_field_hash,
        ja4h->cookie_value_hash);
    out->len = ngx_strlen(out->data);
}
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

    if (ngx_ssl_ja4h(r, r->pool, &ja4h) == NGX_DECLINED)
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
void ngx_ssl_ja4h_fp_string(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h, ngx_str_t *out) {
    u_char *current;
    size_t len;
    len = JA4H_A_FINGERPRINT_LENGTH + 1 + ngx_strlen(ja4h->raw_http_headers) + 1 + ngx_strlen(ja4h->raw_cookie_fields) + 1 + ngx_strlen(ja4h->raw_cookie_values);
    out->data = ngx_pnalloc(pool, len + 1);
    if (out->data == NULL)
    {
        out->len = 0;
        return;
    }

    memset(out->data, 0, len + 1);
    current = out->data;
    ngx_snprintf(current, JA4H_A_FINGERPRINT_LENGTH, "%s%s%c%c%s%s_%s_%s_%s",
        ja4h->http_method, ja4h->http_version,
        ja4h->cookie_presence, ja4h->referrer_presence,
        ja4h->num_headers, ja4h->primary_accept_language);
    current += JA4H_A_FINGERPRINT_LENGTH;
    *current++ = '_';
    ngx_memcpy(current, ja4h->raw_http_headers, ngx_strlen(ja4h->raw_http_headers));
    current += ngx_strlen(ja4h->raw_http_headers);
    *current++ = '_';
    ngx_memcpy(current, ja4h->raw_cookie_fields, ngx_strlen(ja4h->raw_cookie_fields));
    current += ngx_strlen(ja4h->raw_cookie_fields);
    *current++ = '_';
    ngx_memcpy(current, ja4h->raw_cookie_values, ngx_strlen(ja4h->raw_cookie_values));
    current += ngx_strlen(ja4h->raw_cookie_values);
    *current = '\0';

    out->len = ngx_strlen(out->data);
}

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
    double propagation_delay_factor = 1.0; // Declare the variable to store the propagation delay factor
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
