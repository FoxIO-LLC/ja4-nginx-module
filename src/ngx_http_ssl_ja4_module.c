#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_md5.h>
#include <openssl/sha.h>
#include <stdint.h>
#include "ngx_http_ssl_ja4_module.h"
#include "ngx_http_ja4t.h"

static void ngx_ssl_ja4h_fp(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h,
    ngx_str_t *out);
static void ngx_ssl_ja4h_fp_string(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h,
    ngx_str_t *out);

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
     ngx_http_ssl_ja4t,
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
    {ngx_string("http_ssl_ja4x"),
     NULL,
     ngx_http_ssl_ja4x,
     0, 0, 0},
    {ngx_string("http_ssl_ja4x_string"),
     NULL,
     ngx_http_ssl_ja4x_string,
     0, 0, 0},

};

// FUNCTIONS
static ngx_inline ngx_uint_t
ngx_ssl_ja4_is_ascii_alnum(u_char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z'));
}

static void
ngx_ssl_ja4_write_alpn_code(u_char *dst, const char *alpn)
{
    static const u_char hex[] = "0123456789abcdef";

    if (alpn == NULL) {
        dst[0] = '0';
        dst[1] = '0';
        return;
    }

    size_t len = ngx_strlen(alpn);
    if (len == 0) {
        dst[0] = '0';
        dst[1] = '0';
        return;
    }

    u_char first = (u_char) alpn[0];
    u_char last = (u_char) alpn[len - 1];

    if (ngx_ssl_ja4_is_ascii_alnum(first) && ngx_ssl_ja4_is_ascii_alnum(last)) {
        dst[0] = first;
        dst[1] = last;
        return;
    }

    dst[0] = hex[(first >> 4) & 0x0F];
    dst[1] = hex[last & 0x0F];
}

// JA4
int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{
    SSL *ssl;
    size_t i, j;
    size_t len = 0;

    if (!c->ssl) {
        return NGX_DECLINED;
    }

    if (!c->ssl->handshaked) {
        return NGX_DECLINED;
    }

    ssl = c->ssl->connection;
    if (!ssl) {
        return NGX_DECLINED;
    }
#if (NGX_QUIC || NGX_COMPAT)
    ja4->transport = (c->quic) ? 'q' : 't';
#else
    ja4->transport = 't';
#endif
    ja4->has_sni = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name) ? 'd' : 'i';
    ja4->alpn_first_value = c->ssl->first_alpn;


    /* SSLVersion*/

    int client_version_int = SSL_client_version(ssl);
    int max_version_int = c->ssl->highest_supported_tls_client_version;
    int version_int = 0;

    version_int = (max_version_int) ? max_version_int : client_version_int;

    switch (version_int)
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


    const unsigned char *raw_ciphers = NULL;
    size_t tls_cipher_len = SSL_get0_raw_cipherlist(ssl, &raw_ciphers);
    if (!raw_ciphers || tls_cipher_len < 2) {
        return NGX_DECLINED;
    }

    size_t raw_cipher_count = tls_cipher_len / 2;

    ja4->ciphers = ngx_pnalloc(pool, raw_cipher_count * sizeof(char *));
    if (ja4->ciphers == NULL) {
        return NGX_DECLINED;
    }
    else
    {
        ngx_memset(ja4->cipher_hash, '0', 2 * SHA256_DIGEST_LENGTH);
        ja4->cipher_hash[2 * SHA256_DIGEST_LENGTH] = '\0';
        ngx_memset(ja4->cipher_hash_truncated, '0', 12);
        ja4->cipher_hash_truncated[12] = '\0'; // Null-terminate the truncated hex string
    }

    size_t *k = &ja4->ciphers_sz;
    for (i = 0; i + 1 < tls_cipher_len; i += 2)
    {
        char hex[5];
        u_int16_t id = ((u_int16_t) raw_ciphers[i] << 8) | raw_ciphers[i + 1];

        ngx_sprintf((u_char *)&hex[0], "%04xd", id);
        hex [4] = '\0';
        if (ngx_ssl_ja4_is_ext_greased (hex)) {
            continue;
        }
        ja4->ciphers[*k] = ngx_palloc (pool, 4 + 1);

        if (ja4->ciphers[*k] == NULL) {
            ngx_log_error(NGX_LOG_ERR, pool->log, -1, "Failed to allocate memory for a ciphers hex string");
            return NGX_ERROR;
        }

        /* hex is 4 chars + NUL; copy only the used portion */
        ngx_memcpy(ja4->ciphers[*k], hex, 5);
        (void)(*k)++;
    }

    qsort(ja4->ciphers, ja4->ciphers_sz, sizeof(char *), compare_hexes);

#if (NGX_DEBUG)
    ngx_log_debug1 (NGX_LOG_DEBUG_EVENT, c->log, 0, "ja4: sorted cipher suites: (%d)", ja4->ciphers_sz);
    for (int i = 0; i < (int) ja4->ciphers_sz; i++) {
        ngx_log_debug2 (NGX_LOG_DEBUG_EVENT, c->log, 0, "-- [%2d]: %s", i, ja4->ciphers[i]);
    }
#endif

    if (!ja4->ciphers || !ja4->ciphers_sz) {
        return NGX_ERROR;
    }

    unsigned char hash_result[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init (&sha256);

    for (i = 0; i < ja4->ciphers_sz; i++)
    {
        SHA256_Update (&sha256, ja4->ciphers[i], strlen(ja4->ciphers[i]));
        if (i < ja4->ciphers_sz - 1) {
            SHA256_Update(&sha256, ",", 1);
        }
    }

    SHA256_Final(hash_result, &sha256);

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&ja4->cipher_hash[i * 2], "%02x", hash_result[i]);
    }
    ja4->cipher_hash[2 * SHA256_DIGEST_LENGTH] = '\0';

    ngx_memcpy (ja4->cipher_hash_truncated, ja4->cipher_hash, 12);
    ja4->cipher_hash_truncated[12] = '\0';


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
        ja4->extensions = ngx_pnalloc (pool, c->ssl->extensions_sz * sizeof(char*));
        ja4->extensions_no_psk = ngx_pnalloc (pool, c->ssl->extensions_sz * sizeof(char*));
        if (ja4->extensions == NULL || ja4->extensions_no_psk == NULL) {
            return NGX_ERROR;
        }

        for (i = 0; i < c->ssl->extensions_sz; ++i) {

            if (ngx_ssl_ja4_is_ext_greased (c->ssl->extensions[i])) {
                continue;
            }

            char *ext = (char *)c->ssl->extensions[i];
            size_t ext_len = strlen (ext) + 1;

            ja4->extensions_count++;

            // ignored extensions are only counted, not hashed
            if (ngx_ssl_ja4_is_ext_ignored(c->ssl->extensions[i])) {
                continue;
            }

            // Allocate memory for the extension string and copy it
            ja4->extensions[ja4->extensions_sz] = ngx_pnalloc(pool, ext_len);
            if (ja4->extensions[ja4->extensions_sz] == NULL) {
                ngx_log_error (NGX_LOG_ERR, c->log, -1, "Failed to allocate memory");
                return NGX_ERROR;
            }
            ngx_memcpy(ja4->extensions[ja4->extensions_sz], ext, ext_len);
            ja4->extensions_sz++;

            // for no psk ignored extensions are not counted, not hashed

            // check if the extension is not a PSK extension
            if (ngx_ssl_ja4_is_ext_dynamic(c->ssl->extensions[i])) {
                continue;
            }

            ja4->extensions_no_psk[ja4->extensions_no_psk_count] = ngx_pnalloc(pool, ext_len);

            if (ja4->extensions_no_psk[ja4->extensions_no_psk_count] == NULL) {
                ngx_log_error (NGX_LOG_ERR, c->log, -1, "Failed to allocate memory");
                return NGX_ERROR;
            }
            ngx_memcpy(ja4->extensions_no_psk[ja4->extensions_no_psk_count], ext, ext_len);
            ja4->extensions_no_psk_count++;
        }

        qsort(ja4->extensions, ja4->extensions_sz, sizeof(char *), compare_hexes);
        qsort(ja4->extensions_no_psk, ja4->extensions_no_psk_count, sizeof(char *), compare_hexes);
    }


    /* Signature Algorithms */

    int num_sigalgs = SSL_get_sigalgs (ssl, 0, NULL, NULL, NULL, NULL, NULL);

    if (num_sigalgs > -1) {

        char **sigalgs_hex_strings = ngx_pnalloc(c->pool, num_sigalgs * sizeof(char *));
        if (sigalgs_hex_strings == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, -1, "Failed to allocate memory.");
            return NGX_ERROR;
        }

        for (int i = 0; i < num_sigalgs; ++i) {

            int psign, phash, psignhash;
            unsigned char rsig, rhash;
            SSL_get_sigalgs (ssl, i, &psign, &phash, &psignhash, &rsig, &rhash);

            char hex_string[5];
            ngx_sprintf ((u_char *)&hex_string[0],  "%02xd%02xd", rhash, rsig);
            hex_string[4] = '\0';

            sigalgs_hex_strings[i] = ngx_pnalloc(c->pool, sizeof(hex_string));
            if (sigalgs_hex_strings[i] == NULL) {
                ngx_log_error (NGX_LOG_ERR, c->log, -1, "Failed to allocate memory");
                return NGX_ERROR;
            }

            ngx_memcpy (sigalgs_hex_strings[i], hex_string, sizeof(hex_string));
        }

        c->ssl->sigalgs_hash_values = sigalgs_hex_strings;
    }

    c->ssl->sigalgs_sz = num_sigalgs;

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
            ngx_memcpy (ja4->sigalgs[ja4->sigalgs_sz], c->ssl->sigalgs_hash_values[i], sigalg_len);
            ja4->sigalgs_sz++;
        }
    }

#if (NGX_DEBUG)
    ngx_log_debug1 (NGX_LOG_DEBUG_EVENT, c->log, 0, "ja4: sigalgs (%d): ", ja4->sigalgs_sz);
    for (int i = 0; i < (int) c->ssl->sigalgs_sz; i++)
        ngx_log_debug2 (NGX_LOG_DEBUG_EVENT, c->log, 0, "-- [%2d]: %s", i, ja4->sigalgs[i]);
#endif

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
    else
    {
        ngx_memset(ja4->extension_hash, '0', 2 * SHA256_DIGEST_LENGTH);
        ja4->extension_hash[2 * SHA256_DIGEST_LENGTH] = '\0';
        ngx_memset(ja4->extension_hash_truncated, '0', 12);
        ja4->extension_hash_truncated[12] = '\0'; // Null-terminate the truncated hex string
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
    else
    {
        ngx_memset(ja4->extension_hash_no_psk, '0', 2 * SHA256_DIGEST_LENGTH);
        ja4->extension_hash_no_psk[2 * SHA256_DIGEST_LENGTH] = '\0';
        ngx_memset(ja4->extension_hash_no_psk_truncated, '0', 12);
        ja4->extension_hash_no_psk_truncated[12] = '\0'; // Null-terminate the truncated hex string
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

    out->data[cur++] = ja4->transport;

    // 2 character TLS version
    memcpy(out->data + cur, ja4->version, 2);
    cur += 2;

    // SNI = d, no SNI = i
    out->data[cur++] = ja4->has_sni;

    // 2 character count of ciphers
    size_t ciphers_sz = ja4->ciphers_sz;
    if (ciphers_sz > 99) {
        ciphers_sz = 99;
    }
    ngx_snprintf (out->data + cur, 3, "%02d", ciphers_sz);
    cur += 2;

    // 2 character count of extensions
    ngx_snprintf (out->data + cur, 3, "%02d", ja4->extensions_count);
    cur += 2;

    // Add ALPN first/last value per JA4 spec
    ngx_ssl_ja4_write_alpn_code(out->data + cur, ja4->alpn_first_value);
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
    ngx_http_ssl_ja4_ctx_t *ctx;
    ngx_ssl_ja4_t ja4;

    if (r->connection == NULL) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(r->connection, r->pool, &ja4) == NGX_DECLINED) {
        return NGX_ERROR;
    }

    ctx = ngx_get_or_create_ja4_ctx (r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->ja4.len == 0) {

        ngx_str_t fp = ngx_null_string;

        ngx_ssl_ja4_fp(r->pool, &ja4, &fp);
        ctx->ja4.len = fp.len;
        ctx->ja4.data = ngx_pnalloc(r->pool, fp.len);

        ngx_memcpy(ctx->ja4.data, fp.data, fp.len);
    }

    v->data = ctx->ja4.data;
    v->len = ctx->ja4.len;
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
    out->data[cur++] = ja4->transport;

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
    size_t ciphers_sz = ja4->ciphers_sz;
    if (ciphers_sz == 0)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        if (ciphers_sz > 99) {
            ciphers_sz = 99;
        }
        ngx_snprintf(out->data + cur, 3, "%02zu", ciphers_sz);
    }
    cur += 2;

    // 2 character count of extensions
    ngx_snprintf (out->data + cur, 3, "%02d", ja4->extensions_count);
    cur += 2;

    // Add 2 characters for the ALPN ja4->alpn_first_value
    ngx_ssl_ja4_write_alpn_code(out->data + cur, ja4->alpn_first_value);
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
    ngx_http_ssl_ja4_ctx_t *ctx;
    ngx_ssl_ja4_t ja4;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }

    if (ngx_ssl_ja4(r->connection, r->pool, &ja4) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ctx = ngx_get_or_create_ja4_ctx (r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->ja4_string.len == 0) {
        ngx_str_t fp = ngx_null_string;
        ngx_ssl_ja4_fp_string(r->pool, &ja4, &fp);
        ctx->ja4_string.len = fp.len;
        ctx->ja4_string.data = ngx_pnalloc(r->pool, fp.len);
        ngx_memcpy(ctx->ja4_string.data, fp.data, fp.len);
    }

    v->data = ctx->ja4_string.data;
    v->len = ctx->ja4_string.len;
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
    size_t ciphers_sz = ja4->ciphers_sz;
    if (ciphers_sz == 0)
    {
        ngx_snprintf(out->data + cur, 3, "00");
    }
    else
    {
        if (ciphers_sz > 99) {
            ciphers_sz = 99;
        }
        ngx_snprintf(out->data + cur, 3, "%02zu", ciphers_sz);
    }
    cur += 2;

    // 2 character count of extensions
    ngx_snprintf(out->data + cur, 3, "%02d", ja4->extensions_no_psk_count);
    cur += 2;

    // Add ALPN first/last value per JA4 spec
    ngx_ssl_ja4_write_alpn_code(out->data + cur, ja4->alpn_first_value);
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
    ngx_http_ssl_ja4_ctx_t *ctx;
    ngx_ssl_ja4_t ja4;

    if (r->connection == NULL)
    {
        return NGX_OK;
    }
    if (ngx_ssl_ja4(r->connection, r->pool, &ja4) == NGX_DECLINED)
    {
        return NGX_ERROR;
    }

    ctx = ngx_get_or_create_ja4_ctx (r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->ja4one.len == 0) {
        ngx_str_t fp = ngx_null_string;
        ngx_ssl_ja4one_fp(r->pool, &ja4, &fp);
        ctx->ja4one.len = fp.len;
        ctx->ja4one.data = ngx_pnalloc(r->pool, fp.len);
        ngx_memcpy(ctx->ja4one.data, fp.data, fp.len);
    }

    v->data = ctx->ja4one.data;
    v->len = ctx->ja4one.len;
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

// Cookie and Referer are recorded only as a-flags; omit them from the header-name list.
static ngx_int_t
ngx_ssl_ja4h_is_cookie_or_referer(ngx_table_elt_t *h)
{
    if (h->key.len == sizeof("Cookie") - 1
        && ngx_strncasecmp(h->key.data, (u_char *) "Cookie", sizeof("Cookie") - 1) == 0)
    {
        return 1;
    }

    if (h->key.len == sizeof("Referer") - 1
        && ngx_strncasecmp(h->key.data, (u_char *) "Referer", sizeof("Referer") - 1) == 0)
    {
        return 1;
    }

    return 0;
}

/* JA4H language field: FoxIO Wireshark decode_http_lang.
 * Skip whitespace and '-'; stop at ',' / ';'. ASCII letters are lowercased;
 * any other byte (including digits) is two lowercase hex digits. Digits are
 * encoded so they are not confused with hex nibbles (FoxIO-LLC/ja4#230).
 * Right-pad with '0' to 4 chars. */
static void
ngx_ssl_ja4h_decode_http_lang(ngx_str_t *val, ngx_ssl_ja4h_t *ja4h)
{
    static const u_char hex[] = "0123456789abcdef";
    size_t i, n;

    ngx_memcpy(ja4h->primary_accept_language, "0000", 5);

    for (i = 0, n = 0; n < 4 && i < val->len; i++) {
        u_char c = val->data[i];

        if (c == ',' || c == ';') {
            break;
        }

        if (c == '-' || c == ' ' || c == '\t' || c == '\n' || c == '\r'
            || c == '\f' || c == '\v')
        {
            continue;
        }

        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            ja4h->primary_accept_language[n++] = (char) ngx_tolower(c);
            continue;
        }

        /* Non-alpha, including digits: two lowercase hex digits. */
        if (n < 4) {
            ja4h->primary_accept_language[n++] = (char) hex[(c >> 4) & 0x0F];
        }
        if (n < 4) {
            ja4h->primary_accept_language[n++] = (char) hex[c & 0x0F];
        }
    }
}

/* FoxIO hash12: 12 hex chars of SHA-256; empty input is 000000000000, not SHA256(""). */
static ngx_int_t
ngx_ssl_ja4h_hash12(ngx_str_t *in, char out[13])
{
    SHA256_CTX sha256;
    u_char hash[SHA256_DIGEST_LENGTH];
    size_t i;

    ngx_memzero(out, 13);

    if (in->len == 0) {
        ngx_memcpy(out, "000000000000", 12);
        return NGX_OK;
    }

    if (SHA256_Init(&sha256) != 1) {
        return NGX_DECLINED;
    }
    SHA256_Update(&sha256, in->data, in->len);
    SHA256_Final(hash, &sha256);

    for (i = 0; i < 6; i++) {
        ngx_sprintf((u_char *) &out[i * 2], "%02xd", hash[i]);
    }

    return NGX_OK;
}

typedef struct {
    ngx_str_t pair;
    size_t    name_len;
} ngx_ssl_ja4h_cookie_t;

static ngx_int_t
ngx_ssl_ja4h_push_cookie(ngx_pool_t *pool, ngx_array_t *list,
    u_char *start, u_char *end, size_t *fields_len, size_t *pairs_len)
{
    ngx_ssl_ja4h_cookie_t *item;
    u_char *eq;

    while (start < end && isspace(*start)) {
        start++;
    }

    item = ngx_array_push(list);
    if (item == NULL) {
        return NGX_ERROR;
    }

    item->pair.len = end - start;
    item->pair.data = ngx_pcalloc(pool, item->pair.len + 1);
    if (item->pair.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(item->pair.data, start, item->pair.len);

    eq = ngx_strlchr(item->pair.data, item->pair.data + item->pair.len, '=');
    if (eq != NULL) {
        item->name_len = eq - item->pair.data;
    } else {
        item->name_len = item->pair.len;
    }

    *fields_len += item->name_len + 1;
    *pairs_len += item->pair.len + 1;
    return NGX_OK;
}

/* FoxIO / Wireshark sort by cookie name, not the full name=value pair.
 * Cookie: a-b=1; a=2 must become a,a-b (not a-b,a): '-' sorts before '='. */
static int ngx_libc_cdecl
ngx_ssl_ja4h_cmp_cookie(const void *one, const void *two)
{
    const ngx_ssl_ja4h_cookie_t *a = one;
    const ngx_ssl_ja4h_cookie_t *b = two;
    size_t n;
    int rc;

    n = ngx_min(a->name_len, b->name_len);
    rc = ngx_strncmp(a->pair.data, b->pair.data, n);
    if (rc != 0) {
        return rc;
    }

    if (a->name_len == b->name_len) {
        return 0;
    }

    return a->name_len < b->name_len ? -1 : 1;
}

/* FoxIO JA4H method codes (Wireshark packet-ja4.c http_method_map).
 * Unknown methods that still parse (e.g. FOO) use "00". */
static const struct {
    ngx_str_t  method;
    u_char     code[2];
} ngx_ssl_ja4h_method_map[] = {
    { ngx_string("ACL"),               { 'a', 'c' } },
    { ngx_string("BASELINE-CONTROL"),  { 'b', 'a' } },
    { ngx_string("BIND"),              { 'b', 'i' } },
    { ngx_string("CHECKIN"),           { 'c', 'n' } },
    { ngx_string("CHECKOUT"),          { 'c', 't' } },
    { ngx_string("CONNECT"),           { 'c', 'o' } },
    { ngx_string("COPY"),              { 'c', 'y' } },
    { ngx_string("DELETE"),            { 'd', 'e' } },
    { ngx_string("GET"),               { 'g', 'e' } },
    { ngx_string("HEAD"),              { 'h', 'e' } },
    { ngx_string("LABEL"),             { 'l', 'a' } },
    { ngx_string("LINK"),              { 'l', 'i' } },
    { ngx_string("LOCK"),              { 'l', 'o' } },
    { ngx_string("MERGE"),             { 'm', 'e' } },
    { ngx_string("MKACTIVITY"),        { 'm', 'a' } },
    { ngx_string("MKCALENDAR"),        { 'm', 'c' } },
    { ngx_string("MKCOL"),             { 'm', 'l' } },
    { ngx_string("MKREDIRECTREF"),     { 'm', 'r' } },
    { ngx_string("MKWORKSPACE"),       { 'm', 'w' } },
    { ngx_string("MOVE"),              { 'm', 'o' } },
    { ngx_string("M-SEARCH"),          { 'm', 's' } },
    { ngx_string("NOTIFY"),            { 'n', 'o' } },
    { ngx_string("OPTIONS"),           { 'o', 'p' } },
    { ngx_string("PATCH"),             { 'p', 'a' } },
    { ngx_string("POST"),              { 'p', 'o' } },
    { ngx_string("PRI"),               { 'p', 'r' } },
    { ngx_string("PROPFIND"),          { 'p', 'f' } },
    { ngx_string("PROPPATCH"),         { 'p', 'p' } },
    { ngx_string("PURGE"),             { 'p', 'r' } },
    { ngx_string("PUT"),               { 'p', 'u' } },
    { ngx_string("REBIND"),            { 'r', 'b' } },
    { ngx_string("REPORT"),            { 'r', 'p' } },
    { ngx_string("SEARCH"),            { 's', 'e' } },
    { ngx_string("SUBSCRIBE"),         { 's', 'u' } },
    { ngx_string("TRACE"),             { 't', 'r' } },
    { ngx_string("UNBIND"),            { 'u', 'b' } },
    { ngx_string("UNCHECKOUT"),        { 'u', 'c' } },
    { ngx_string("UNLINK"),            { 'u', 'i' } },
    { ngx_string("UNLOCK"),            { 'u', 'o' } },
    { ngx_string("UNSUBSCRIBE"),       { 'u', 'n' } },
    { ngx_string("UPDATE"),            { 'u', 'p' } },
    { ngx_string("UPDATEREDIRECTREF"), { 'u', 'r' } },
    { ngx_string("VERSION-CONTROL"),   { 'v', 'e' } },
};

static void
ngx_ssl_ja4h_method_code(ngx_str_t *method_name, ngx_ssl_ja4h_t *ja4h)
{
    size_t  i;

    ja4h->http_method[0] = '0';
    ja4h->http_method[1] = '0';
    ja4h->http_method[2] = '\0';

    for (i = 0; i < sizeof(ngx_ssl_ja4h_method_map)
                    / sizeof(ngx_ssl_ja4h_method_map[0]); i++)
    {
        if (method_name->len == ngx_ssl_ja4h_method_map[i].method.len
            && ngx_strncasecmp(method_name->data,
                               ngx_ssl_ja4h_method_map[i].method.data,
                               method_name->len) == 0)
        {
            ja4h->http_method[0] = ngx_ssl_ja4h_method_map[i].code[0];
            ja4h->http_method[1] = ngx_ssl_ja4h_method_map[i].code[1];
            return;
        }
    }
}

// JA4H
int
ngx_ssl_ja4h(ngx_http_request_t *r, ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h)
{
    ngx_ssl_ja4h_cookie_t *cookie;
    size_t i;
    ngx_uint_t lang_set = 0;

    ngx_memzero(ja4h, sizeof(ngx_ssl_ja4h_t));

    // JA4H_a
    ngx_ssl_ja4h_method_code(&r->method_name, ja4h);

    ja4h->http_version[0] = (char) ('0' + r->http_version / 1000);
    ja4h->http_version[1] = (char) ('0' + r->http_version % 1000);
    ja4h->http_version[2] = '\0';

    ja4h->cookie_presence = r->headers_in.cookie ? 'c' : 'n';
    ja4h->referrer_presence = r->headers_in.referer ? 'r' : 'n';

    // First 4 language chars via decode_http_lang; missing/short stay/pad 0000.
    ngx_memcpy(ja4h->primary_accept_language, "0000", 5);

    // JA4H_b: comma-joined header names with Cookie/Referer dropped, then hash that buffer.
    ngx_list_part_t *headers_part = &r->headers_in.headers.part;
    ngx_table_elt_t *header_item = headers_part->elts;

    ngx_uint_t n_headers = 0;
    size_t raw_http_headers_len = 0;
    for (i = 0; /* void */; i++) {
        if (i >= headers_part->nelts) {
            if (headers_part->next == NULL){
                break;
            }
            headers_part = headers_part->next;
            header_item = headers_part->elts;
            i = 0;
        }
        if (!lang_set
            && (header_item[i].key.len == sizeof("Accept-Language") - 1)
            && (ngx_strncasecmp(header_item[i].key.data, (u_char *) "Accept-Language",
                                sizeof("Accept-Language") - 1) == 0))
        {
            ngx_ssl_ja4h_decode_http_lang(&header_item[i].value, ja4h);
            lang_set = 1;
        }

        if (ngx_ssl_ja4h_is_cookie_or_referer(&header_item[i])) {
            continue;
        }
        raw_http_headers_len += header_item[i].key.len + 1;
        n_headers++;
    }

    if (n_headers > 99) {
        n_headers = 99;
    }
    ja4h->num_headers[0] = (char) ('0' + n_headers / 10);
    ja4h->num_headers[1] = (char) ('0' + n_headers % 10);
    ja4h->num_headers[2] = '\0';

    ja4h->raw_http_headers.data = ngx_pcalloc(pool, raw_http_headers_len + 1);
    if (ja4h->raw_http_headers.data == NULL) {
        return NGX_ERROR;
    }
    ja4h->raw_http_headers.len = 0;

    headers_part = &r->headers_in.headers.part;
    header_item = headers_part->elts;
    u_char *current = ja4h->raw_http_headers.data;
    for (i = 0; /* void */; i++) {
        if (i >= headers_part->nelts) {
            if (headers_part->next == NULL){
                break;
            }
            headers_part = headers_part->next;
            header_item = headers_part->elts;
            i = 0;
        }

        if (ngx_ssl_ja4h_is_cookie_or_referer(&header_item[i])) {
            continue;
        }

        if (current != ja4h->raw_http_headers.data) {
            *current++ = ',';
        }
        ngx_memcpy(current, header_item[i].key.data, header_item[i].key.len);
        current += header_item[i].key.len;
    }
    ja4h->raw_http_headers.len = current - ja4h->raw_http_headers.data;

    if (ngx_ssl_ja4h_hash12(&ja4h->raw_http_headers, ja4h->http_header_hash)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    // JA4H_c_d
    size_t raw_cookie_fields_len = 0;
    size_t raw_cookie_pairs_len = 0;

    ngx_array_t *cookie_list = ngx_array_create(pool, 10, sizeof(ngx_ssl_ja4h_cookie_t));
    if (cookie_list == NULL) {
        return NGX_ERROR;
    }

    ngx_table_elt_t *req_header_cookie;

    for (req_header_cookie = r->headers_in.cookie;
         req_header_cookie;
         req_header_cookie = req_header_cookie->next)
    {
        u_char *start, *end, *p;

        start = req_header_cookie->value.data;
        end = start + req_header_cookie->value.len;
        for (p = start; p < end; p++) {
            if (*p == ';') {
                if (ngx_ssl_ja4h_push_cookie(pool, cookie_list, start, p,
                                             &raw_cookie_fields_len,
                                             &raw_cookie_pairs_len)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
                start = p + 1;
            }
        }
        if (ngx_ssl_ja4h_push_cookie(pool, cookie_list, start, end,
                                     &raw_cookie_fields_len,
                                     &raw_cookie_pairs_len)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ngx_qsort(cookie_list->elts, cookie_list->nelts,
              sizeof(ngx_ssl_ja4h_cookie_t), ngx_ssl_ja4h_cmp_cookie);

    ja4h->raw_cookie_fields.data = ngx_pcalloc(pool, raw_cookie_fields_len + 1);
    if (ja4h->raw_cookie_fields.data == NULL) {
        return NGX_ERROR;
    }
    ja4h->raw_cookie_pairs.data = ngx_pcalloc(pool, raw_cookie_pairs_len + 1);
    if (ja4h->raw_cookie_pairs.data == NULL) {
        return NGX_ERROR;
    }

    u_char *current_raw_cookie_field, *current_raw_cookie_pair;

    current_raw_cookie_field = ja4h->raw_cookie_fields.data;
    current_raw_cookie_pair = ja4h->raw_cookie_pairs.data;

    for (i = 0; i < cookie_list->nelts; i++) {
        cookie = &((ngx_ssl_ja4h_cookie_t *) cookie_list->elts)[i];

        if (current_raw_cookie_pair != ja4h->raw_cookie_pairs.data) {
            *current_raw_cookie_pair++ = ',';
        }
        ngx_memcpy(current_raw_cookie_pair, cookie->pair.data, cookie->pair.len);
        current_raw_cookie_pair += cookie->pair.len;

        if (current_raw_cookie_field != ja4h->raw_cookie_fields.data) {
            *current_raw_cookie_field++ = ',';
        }
        ngx_memcpy(current_raw_cookie_field, cookie->pair.data, cookie->name_len);
        current_raw_cookie_field += cookie->name_len;
    }
    ja4h->raw_cookie_fields.len = current_raw_cookie_field - ja4h->raw_cookie_fields.data;
    ja4h->raw_cookie_pairs.len = current_raw_cookie_pair - ja4h->raw_cookie_pairs.data;

    if (ngx_ssl_ja4h_hash12(&ja4h->raw_cookie_fields, ja4h->cookie_field_hash)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    if (ngx_ssl_ja4h_hash12(&ja4h->raw_cookie_pairs, ja4h->cookie_value_hash)
        != NGX_OK)
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

    if (ngx_ssl_ja4h(r, r->pool, &ja4h) != NGX_OK)
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

static void
ngx_ssl_ja4h_fp(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h, ngx_str_t *out)
{
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

    if (ngx_ssl_ja4h(r, r->pool, &ja4h) != NGX_OK)
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

static void
ngx_ssl_ja4h_fp_string(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h, ngx_str_t *out)
{
    u_char *current;
    size_t len;
    len = JA4H_A_FINGERPRINT_LENGTH + 1
        + ja4h->raw_http_headers.len + 1
        + ja4h->raw_cookie_fields.len + 1
        + ja4h->raw_cookie_pairs.len;
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
    ngx_memcpy(current, ja4h->raw_http_headers.data, ja4h->raw_http_headers.len);
    current += ja4h->raw_http_headers.len;
    *current++ = '_';
    ngx_memcpy(current, ja4h->raw_cookie_fields.data, ja4h->raw_cookie_fields.len);
    current += ja4h->raw_cookie_fields.len;
    *current++ = '_';
    ngx_memcpy(current, ja4h->raw_cookie_pairs.data, ja4h->raw_cookie_pairs.len);
    current += ja4h->raw_cookie_pairs.len;
    *current = '\0';

    out->len = current - out->data;
}

// JA4T — parse/format live in ngx_http_ja4t.c

static ngx_int_t
ngx_http_ssl_ja4t(ngx_http_request_t *r,
                  ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  fp;
    ngx_int_t  rc;

    if (r->connection == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

#ifdef NGX_HAVE_TCP_SAVE_SYN
    rc = ngx_http_ja4t(r->connection, &fp);
#else
    rc = NGX_DECLINED;
#endif

    if (rc != NGX_OK) {
        v->not_found = 1;
        return rc == NGX_ERROR ? NGX_ERROR : NGX_OK;
    }

    v->data = fp.data;
    v->len = fp.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

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

    ngx_ssl_ja4ts_fp(r->pool, &ja4ts, &fp);

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


static ngx_http_ssl_ja4_ctx_t*
ngx_get_or_create_ja4_ctx (ngx_http_request_t *r)
{
    ngx_http_ssl_ja4_ctx_t *ctx = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_ja4_module);

    if (ctx == NULL) {

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ssl_ja4_ctx_t));

        if (ctx != NULL) {

            ctx->ja4 = (ngx_str_t){0, NULL};
            ctx->ja4_string = (ngx_str_t){0, NULL};
            ctx->ja4one = (ngx_str_t){0, NULL};

            ngx_http_set_ctx (r, ctx, ngx_http_ssl_ja4_module);
        }
    }

    return ctx;
}
