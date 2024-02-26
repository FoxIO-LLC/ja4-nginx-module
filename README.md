# JA4 on Nginx

This repository contains an nginx module that generates fingerprints from the JA4 suite. Additionally, a small patch to the nginx core is provided and necessary to for the module to function.

## Usage

Docker images are available in `./docker`. The QUIC and ModSecurity images are still WIP.

## Docker

We publish and host Docker images of release versions on GitHub Container Registry. You can pull the image with the following command:

### Debugging

To develop and debug the Dockerfile container, I find it useful to run docker with `--progress=plain`.

## Developer Guide

If you want to develop this module, you should head to the [ja4-nginx fork](https://github.com/FoxIO-LLC/ja4-nginx). There, you can load this module into a fork of the nginx source code and build it.

To quickly try out ja4 on nginx, just run the `docker-compose.yaml` file with:
`cd docker`
`docker-compose up --build`

## Creating a Release

1. Tag the release
`git tag -a vx.y.z-alpha -m "Release version x.y.z"`
2. Run script
`./release.sh`
3. Push tag to GitHub
`git push origin vx.y.z`
4. Create a release on GitHub
Manually upload the tar.gz file and the sha256sum

### Release a Docker Image to GitHub Container Registry

Update the file `docker/Dockerfile` to pull from the most recently published release. Then build and tag the image:
`docker build -t ghcr.io/foxio-llc/ja4-nginx-module:vx.y.z-beta .`

Then push the image to the GitHub Container Registry:
`docker push ghcr.io/foxio-llc/ja4-nginx-module:vx.y.z-beta`
