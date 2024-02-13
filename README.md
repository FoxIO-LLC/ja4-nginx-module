# JA4 on Nginx

This repository contains an nginx module that generates fingerprints from the JA4 suite. Additionally, a small patch to the nginx core is provided and necessary to for the module to function.

## Usage

Simply use the Docker images provided on GitHub, clone this module into your nginx build, or manually build your own Docker image by installing the source code from our releases on GitHub.

## Docker

We publish and host Docker images of release versions on GitHub.

### Debugging

To debug the container while developing, run docker with `--progress=plain --no-cache`

## Developer Guide

## Releasing

1. Tag the release
`git tag -a vx.y.z-alpha -m "Release version x.y.z"`
2. Run script
`./release.sh`
3. Push tag to GitHub
`git push origin vx.y.z`
4. Create a release on GitHub
Manually upload the tar.gz file, the sha256sum, and the nginx.patch file.
