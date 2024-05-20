#include <stdint.h> // for uint8_t, uint16_t, etc.
#include <ngx_core.h>
#include <ngx_http.h>

// STRUCTS
typedef struct ngx_ssl_ja4_s
{
    char *version; // TLS version

    unsigned char transport; // 'q' for QUIC, 't' for TCP

    unsigned char has_sni; // 'd' if SNI is present, 'i' otherwise

    size_t ciphers_sz; // Count of ciphers
    char **ciphers;    // List of ciphers

    size_t extensions_count; // Count of signature algorithms
    size_t extensions_sz;    // Count of extensions
    char **extensions;       // List of extensions

    size_t sigalgs_sz; // Count of signature algorithms
    char **sigalgs;    // List of signature algorithms

    // For the first and last ALPN extension values
    char *alpn_first_value;

    char cipher_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char cipher_hash_truncated[13]; // 12 bytes * 2 characters/byte + 1 for '\0'

    char extension_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char extension_hash_truncated[13]; // 6 bytes * 2 characters/byte + 1 for '\0'

} ngx_ssl_ja4_t;

typedef struct ngx_ssl_ja4s_s
{
    char *version; // TLS version

    unsigned char transport; // 'q' for QUIC, 't' for TCP

    // Cipher suite chosen by the server in hex
    char chosen_cipher_suite[5]; // Assuming 4 hex characters + null terminator

    size_t extensions_sz;       // Count of extensions
    unsigned short *extensions; // List of extensions

    // For the ALPN chosen by the server
    unsigned char alpn_chosen_first; // First character of the ALPN chosen
    unsigned char alpn_chosen_last;  // Last character of the ALPN chosen

    char extension_hash[65];           // Full SHA256 hash (32 bytes * 2 characters/byte + 1 for '\0')
    char extension_hash_truncated[13]; // Truncated SHA256 hash (12 bytes * 2 characters/byte + 1 for '\0')

    // Raw fingerprint components
    char *raw_extension_data; // Raw extension data as a string, dynamically allocated
} ngx_ssl_ja4s_t;

typedef struct ngx_ssl_ja4h_s
{
    char http_method[3];             // 2 characters for HTTP method + null terminator
    char http_version[3];            // 2 characters for HTTP version + null terminator
    unsigned char cookie_presence;   // 'c' for cookie, 'n' for no cookie
    unsigned char referrer_presence; // 'r' for referrer, 'n' for no referer
    char num_headers[3];             // 2 characters for number of headers + null terminator
    char primary_accept_language[5]; // 4 characters for first accept-language code + null terminator

    char http_header_hash[13];  // 12 characters for truncated sha256 hash of HTTP headers + null terminator
    char cookie_field_hash[13]; // 12 characters for truncated sha256 hash of cookie fields + null terminator
    char cookie_value_hash[13]; // 12 characters for truncated sha256 hash of cookie fields+values + null terminator

    // Raw data fields for the -r and -o options
    char *raw_http_headers;  // Dynamically allocated string for raw HTTP headers
    char *raw_cookie_fields; // Dynamically allocated string for raw cookie fields
    char *raw_cookie_values; // Dynamically allocated string for raw cookie field values
} ngx_ssl_ja4h_t;

typedef struct ngx_ssl_ja4t_s
{
    unsigned int window_size;         // TCP Window Size
    unsigned int window_size_present; // Flag to indicate if window size is present

    u_char tcp_options[40];    // TCP Options (max 40 bytes as a safe upper limit)
    size_t tcp_options_length; // Length of the TCP options used

    unsigned int mss_value;         // MSS Value
    unsigned int mss_value_present; // Flag to indicate if MSS value is present

    unsigned int window_scale;         // Window Scale
    unsigned int window_scale_present; // Flag to indicate if window scale is present
} ngx_ssl_ja4t_t;

typedef struct ngx_ssl_ja4ts_s
{
    unsigned int window_size;  // TCP Window Size
    u_char tcp_options[40];    // TCP Options (max 40 bytes as a safe upper limit)
    unsigned int mss_value;    // MSS Value
    unsigned int window_scale; // Window Scale

    unsigned int synack_retrans_count;   // Count of SYNACK TCP retransmissions
    unsigned int synack_time_delays[10]; // Time delays between each retransmission, max 10
    unsigned int rst_flag;               // Flag to indicate if RST is sent
} ngx_ssl_ja4ts_t;

typedef struct ngx_ssl_ja4x_s
{
    char issuer_rdns_hash[13];  // 12 characters for truncated sha256 hash of Issuer RDNs + null terminator
    char subject_rdns_hash[13]; // 12 characters for truncated sha256 hash of Subject RDNs + null terminator
    char extensions_hash[13];   // 12 characters for truncated sha256 hash of Extensions + null terminator

    char *raw_issuer_rdns;  // Dynamically allocated string for raw Issuer RDNs
    char *raw_subject_rdns; // Dynamically allocated string for raw Subject RDNs
    char *raw_extensions;   // Dynamically allocated string for raw Extensions
} ngx_ssl_ja4x_t;

typedef struct ngx_ssl_ja4l_s
{
    uint16_t distance_miles;                   // a whole number - max is in the thousands
    uint16_t handshake_roundtrip_microseconds; // a whole number - max is probably thousands
    uint8_t ttl;                               // time to live - a whole number - max is 255
    uint8_t hop_count;                         // a whole number - max is less than 255
} ngx_ssl_ja4l_t;

// CONSTANTS
#define SSL3_VERSION_STR "SSLv3"
#define TLS1_VERSION_STR "TLSv1"
#define TLS1_1_VERSION_STR "TLSv1.1"
#define TLS1_2_VERSION_STR "TLSv1.2"
#define TLS1_3_VERSION_STR "TLSv1.3"
#define DTLS1_VERSION_STR "DTLSv1"
#define DTLS1_2_VERSION_STR "DTLSv1.2"
#define QUICV1_VERSION_STR "QUICv1"

/**
 * Grease values to be ignored.
 */
static const char *GREASE[] = {
    "0a0a",
    "1a1a",
    "2a2a",
    "3a3a",
    "4a4a",
    "5a5a",
    "6a6a",
    "7a7a",
    "8a8a",
    "9a9a",
    "aaaa",
    "baba",
    "caca",
    "dada",
    "eaea",
    "fafa",
};

static const char *EXT_IGNORE[] = {
    "0010", // ALPN IGNORE
    "0000", // SNI IGNORE
};

// HELPERS

static int ngx_ssl_ja4_is_ext_ignored(const char *ext)
{
    size_t i;
    for (i = 0; i < (sizeof(EXT_IGNORE) / sizeof(EXT_IGNORE[0])); ++i)
    {
        if (strcmp(ext, EXT_IGNORE[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static int
ngx_ssl_ja4_is_ext_greased(const char *ext)
{
    size_t i;
    for (i = 0; i < (sizeof(GREASE) / sizeof(GREASE[0])); ++i)
    {
        if (strcmp(ext, GREASE[i]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static int compare_hexes(const void *a, const void *b)
{
    const char *ext_a = *(const char **)a;
    const char *ext_b = *(const char **)b;

    unsigned int hex_a = strtoul(ext_a, NULL, 16);
    unsigned int hex_b = strtoul(ext_b, NULL, 16);

    if (hex_a < hex_b)
        return -1;
    if (hex_a > hex_b)
        return 1;
    return 0;
}

#if (NGX_DEBUG)
static void
ngx_ssl_ja4l_detail_print(ngx_pool_t *pool, ngx_ssl_ja4l_t *ja4l)
{

    /* Distance in miles */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4l: Distance in miles: %d",
                   ja4l->distance_miles);

    /* Time in microseconds */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4l: Time in microseconds: %d",
                   ja4l->handshake_roundtrip_microseconds);

    /* TTL */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4l: TTL: %d",
                   ja4l->ttl);

    /* Hop Count */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4l: Hop Count: %d",
                   ja4l->hop_count);
}

static void
ngx_ssl_ja4_detail_print(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4)
{
    size_t i;

    /* Transport Protocol (QUIC or TCP) */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4: Transport Protocol: %c",
                   ja4->transport);

    /* SNI presence or absence */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pool->log, 0,
                   "ssl_ja4: SNI: %c",
                   ja4->has_sni);

    /* Version */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: Version:  %d\n", ja4->version);

    /* Ciphers */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: ciphers: length: %d\n",
                   ja4->ciphers_sz);

    for (i = 0; i < ja4->ciphers_sz; ++i)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    cipher: %s",
                       ja4->ciphers[i]);
    }

    // cipher hash
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: cipher hash: %s\n",
                   ja4->cipher_hash);

    // cipher hash truncated
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: cipher hash truncated: %s\n",
                   ja4->cipher_hash_truncated);

    // extension hash
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extension hash: %s\n",
                   ja4->extension_hash);

    // extension hash truncated
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extension hash truncated: %s\n",
                   ja4->extension_hash_truncated);

    /* Extensions */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: extensions: length: %d\n",
                   ja4->extensions_count);

    for (i = 0; i < ja4->extensions_sz; ++i)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    extension: %s",
                       ja4->extensions[i]);
    }

    // Signature Algorithms
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: sigalgs: length: %d\n",
                   ja4->sigalgs_sz);

    for (i = 0; i < ja4->sigalgs_sz; ++i)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                       pool->log, 0, "ssl_ja4: |    sigalgs: %s",
                       ja4->sigalgs[i]);
    }

    /* ALPN Values */
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,
                   pool->log, 0, "ssl_ja4: ALPN Value: %s\n",
                   ja4->alpn_first_value);
}
#endif

// FUNCTION PROTOTYPES
// INIT
static ngx_int_t ngx_http_ssl_ja4_init(ngx_conf_t *cf);

// JA4
int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4);
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
// JA4 STRING
void ngx_ssl_ja4_fp_string(ngx_pool_t *pool, ngx_ssl_ja4_t *ja4, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

// JA4S
int ngx_ssl_ja4s(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4);
void ngx_ssl_ja4s_fp(ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4s(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
// JA4S STRING
void ngx_ssl_ja4s_fp_string(ngx_pool_t *pool, ngx_ssl_ja4s_t *ja4, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4s_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

// JA4H
int ngx_ssl_ja4h(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h);
void ngx_ssl_ja4h_fp(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4h(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
// JA4H STRING
void ngx_ssl_ja4h_fp_string(ngx_pool_t *pool, ngx_ssl_ja4h_t *ja4h, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4h_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

// JA4T
int ngx_ssl_ja4t(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4t_t *ja4t);
void ngx_ssl_ja4t_fp(ngx_pool_t *pool, ngx_ssl_ja4t_t *ja4t, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4t(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
// JA4T STRING
void ngx_ssl_ja4t_fp_string(ngx_pool_t *pool, ngx_ssl_ja4t_t *ja4t, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4t_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

// JA4TS
int ngx_ssl_ja4ts(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4ts_t *ja4ts);
void ngx_ssl_ja4ts_fp(ngx_pool_t *pool, ngx_ssl_ja4ts_t *ja4ts, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4ts(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
// JA4TS STRING
void ngx_ssl_ja4ts_fp_string(ngx_pool_t *pool, ngx_ssl_ja4ts_t *ja4ts, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4ts_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

// JA4X
int ngx_ssl_ja4x(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4x_t *ja4x);
void ngx_ssl_ja4x_fp(ngx_pool_t *pool, ngx_ssl_ja4x_t *ja4x, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4x(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
// JA4X STRING
void ngx_ssl_ja4x_fp_string(ngx_pool_t *pool, ngx_ssl_ja4x_t *ja4x, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4x_string(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

// JA4L
int ngx_ssl_ja4l(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4l_t *ja4l);
void ngx_ssl_ja4l_fp(ngx_pool_t *pool, ngx_ssl_ja4l_t *ja4l, ngx_str_t *out);
static ngx_int_t ngx_http_ssl_ja4l(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
