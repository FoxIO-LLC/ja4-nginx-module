#!/bin/bash

VERSION=$(git tag -l --sort=-v:refname | head -n 1)
DIR_NAME="ja4-plus-nginx-$VERSION"
TAR_NAME="ja4-plus-nginx-$VERSION.tar.gz"

MY_DIR=${PWD##*/}

# Save the tarball in the current directory
tar --transform "s/^$MY_DIR/$DIR_NAME/" -cvzf $TAR_NAME --exclude .git $MY_DIR

# Generate the sha256sum and gpg signature in the current directory
sha256sum $TAR_NAME > $TAR_NAME.sha256
gpg --detach-sign -a $TAR_NAME

echo $TAR_NAME ": done."
echo "Files created:"
echo "$(pwd)/$TAR_NAME"
echo "$(pwd)/$TAR_NAME.sha256"
echo "$(pwd)/$TAR_NAME.asc"
