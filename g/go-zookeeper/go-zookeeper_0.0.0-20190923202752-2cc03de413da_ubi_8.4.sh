# ----------------------------------------------------------------------------
#
# Package        : go-zookeeper
# Version        : v0.0.0-20190923202752-2cc03de413da
# Source repo    : https://github.com/samuel/go-zookeeper
# Tested on      : UBI 8.4
# Language      : go
# Travis-Check  : True
# Script License : Apache License, Version 2 or later
# Maintainer     : Vaibhav Bhadade <vaibhav.bhadade@ibm.com>
#
# Disclaimer: This script has been tested in root mode on given
# ==========  platform using the mentioned version of the package.
#             It may not work as expected with newer versions of the
#             package and/or distribution. In such case, please
#             contact "Maintainer" of this script.
#
# ----------------------------------------------------------------------------
#!/bin/bash -e


PACKAGE_URL=https://github.com/samuel/go-zookeeper
PACKAGE_NAME=go-zookeeper
PACKAGE_VERSION=${1:-v0.0.0-20190923202752-2cc03de413da}

PACKAGE_COMMIT_HASH=`echo $PACKAGE_VERSION | cut -d'-' -f3`

GO_VERSION=go1.17.5

yum install -y git wget tar make gcc-c++

#install go
rm -rf /bin/go
wget https://golang.org/dl/$GO_VERSION.linux-ppc64le.tar.gz
tar -C /bin -xzf $GO_VERSION.linux-ppc64le.tar.gz
rm -f $GO_VERSION.linux-ppc64le.tar.gz

#set go path
export PATH=$PATH:/bin/go/bin
export GOPATH=/home/tester/go
mkdir -p /home/tester/go
cd $GOPATH

#clone package
mkdir -p $GOPATH/src/github.com/go-zookeeper
cd $GOPATH/src/github.com/go-zookeeper
git clone $PACKAGE_URL
cd $PACKAGE_NAME
git checkout $PACKAGE_COMMIT_HASH


go mod init
go mod tidy

go test -v ./...
