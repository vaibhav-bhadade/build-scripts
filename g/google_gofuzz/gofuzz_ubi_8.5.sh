#!/bin/bash -e

# ----------------------------------------------------------------------------
#
# Package        : github.com/google/gofuzz
# Version        : 24818f796faf91cd76ec7bddd72458fbced7a6c1
# Source repo    : https://github.com/google/gofuzz
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

set -e
PACKAGE_NAME=${2:-gofuzz}
PACKAGE_PATH=https://github.com/google/gofuzz
PACKAGE_VERSION=${1:-24818f796faf91cd76ec7bddd72458fbced7a6c1}

PACKAGE_COMMIT_HASH=`echo $PACKAGE_VERSION | cut -d'-' -f3`

#install dependencies
yum install -y  go git dnf

#removed old data 
#set GO PATH
export PATH=$PATH:/bin/go/bin
export GOPATH=/home/tester/go/

#clone package
mkdir -p $GOPATH/src/github.com/
cd $GOPATH/src/github.com/
git clone $PACKAGE_PATH
cd $PACKAGE_NAME
git checkout $PACKAGE_COMMIT_HASH


go mod init
go mod tidy

if ! go test -v ./... ; then
echo "------------------$PACKAGE_NAME:test_fails---------------------"
	echo "$PACKAGE_VERSION $PACKAGE_NAME"
	echo "$PACKAGE_NAME  | $PACKAGE_VERSION | $OS_NAME | GitHub | Fail |  Test_Fails"
	exit 1
else
	echo "------------------$PACKAGE_NAME:install_and_test_success-------------------------"
	echo "$PACKAGE_VERSION $PACKAGE_NAME"
	echo "$PACKAGE_NAME  | $PACKAGE_VERSION | $OS_NAME | GitHub | Pass |  Install_and_Test_Success"
	exit 0
fi

bash
EOF
exit 0


