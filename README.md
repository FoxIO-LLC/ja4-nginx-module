# JA4 on Nginx

This repository contains an nginx module that generates fingerprints from the JA4 suite. Additionally, a small patch to the nginx core is provided and necessary to for the module to function.

## Usage

Docker images and compose files are available in `./docker`. The QUIC and ModSecurity images are still WIP.

You can quickly test out this module with:
1. `cd docker`
2. `docker-compose up --build`

You can also build from source with:

1. `docker build -t ja4-nginx:source .`
2. `docker run -p 80:80 -p 443:443 ja4-nginx:source`

## Docker

We publish and host Docker images of release versions on GitHub Container Registry. You can pull the image with the following command:

`docker pull ghcr.io/foxio-llc/ja4-nginx-module:v0.9.0-beta`

### Debugging

To develop and debug the Dockerfile container, I find it useful to run docker with `--progress=plain`.

## Developer Guide

If you want to develop this module, you should head to the [ja4-nginx fork](https://github.com/FoxIO-LLC/ja4-nginx). There, you can load this module into a fork of the nginx source code and build it.

## Creating a Release

1. Tag the release
`git tag -a vx.y.z-beta -m "Release version x.y.z"`
2. Run script
`./release.sh`
3. Push tag to GitHub
`git push origin vx.y.z-beta`
4. Create a release on GitHub
Manually upload the tar.gz file and the sha256sum

### Release a Docker Image to GitHub Container Registry

Update the file `docker/Dockerfile` to pull from the most recently published release. Then build and tag the image:
`cd docker`
UPDATE JA4_MODULE_VERSION IN DOCKERFILE TO BUILD FROM NEW RELEASE
`docker build -t ghcr.io/foxio-llc/ja4-nginx-module:vx.y.z-beta .`

Then push the image to the GitHub Container Registry:
`docker push ghcr.io/foxio-llc/ja4-nginx-module:vx.y.z-beta`

## Architecture

### Nginx Variables

We create an Nginx variable for each JA4 fingerprint.

These can be accessed through configuration files for logging purposes, in server definition blocks for custom headers, etc.

All of the logic around these variables are in two files:

1. `ngx_http_ja4_module.c`
2. `ngx_http_ja4_module.h`

#### Nginx Configuration

An Nginx variable simply needs a string for its name, and a function that calculates and returns the value.

By using this syntax:

```C
static ngx_http_variable_t ngx_http_ssl_ja4_variables_list[] = {
    {ngx_string("http_ssl_ja4"),
     NULL,
     ngx_http_ssl_ja4,
     0, 0, 0},
}
```

The function the variable maps to, in this case `ngx_http_ssl_ja4`, receives the request sent to Nginx, a variable that will store the result, and a pointer to the variable's data.

```C
static ngx_int_t ngx_http_ssl_ja4(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
```

So, this function is called for each request and it is expected to return the data intended for the variable.

In this function, we call two important functions. First:

```C
int ngx_ssl_ja4(ngx_connection_t *c, ngx_pool_t *pool, ngx_ssl_ja4_t *ja4);
```

The first gets the connection object from the request (This is an Nginx native structure that we've modified with the `ja4-nginx` repository to store additional data for the JA4 fingerprint), pulls in SSL data from that object, and processes it to be stored in a custom structure (defined in the header file) for this module's Nginx variable.

For this example:

```C
typedef struct ngx_ssl_ja4_s
{
    const char *version; // TLS version

    unsigned char transport; // 'q' for QUIC, 't' for TCP

    unsigned char has_sni; // 'd' if SNI is present, 'i' otherwise

    size_t ciphers_sz;       // Count of ciphers
    unsigned short *ciphers; // List of ciphers

    size_t extensions_sz;       // Count of extensions
    unsigned short *extensions; // List of extensions

    size_t sigalgs_sz;       // Count of signature algorithms
    char **sigalgs; // List of signature algorithms

    // For the first and last ALPN extension values
    char *alpn_first_value;

    char cipher_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char cipher_hash_truncated[13]; // 12 bytes * 2 characters/byte + 1 for '\0'

    char extension_hash[65];           // 32 bytes * 2 characters/byte + 1 for '\0'
    char extension_hash_truncated[13]; // 6 bytes * 2 characters/byte + 1 for '\0'

} ngx_ssl_ja4_t;
```

The second important function is the one that actually calculates the JA4 fingerprint:

```C
void ngx_ssl_ja4_fp(ngx_pool_t *pool, ngx_ssl_ja4_t*ja4, ngx_str_t *out);
```

It simply takes the data structure and uses it to calculate what the single string value of the JA4 fingerprint should be.
