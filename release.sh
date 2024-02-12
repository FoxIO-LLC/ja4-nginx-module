#!/bin/bash

VERSION=`git tag`
DIR_NAME="ja4-plus-nginx-$VERSION"
TAR_NAME="ja4-plus-nginx-$VERSION.tar.gz"

MY_DIR=${PWD##*/}

cd ..
tar --transform "s/^$MY_DIR/$DIR_NAME/" -cvzf $TAR_NAME --exclude .git $MY_DIR

sha256sum $TAR_NAME > $TAR_NAME.sha256
gpg --detach-sign -a $TAR_NAME

cd -
echo $TAR_NAME ": done."
