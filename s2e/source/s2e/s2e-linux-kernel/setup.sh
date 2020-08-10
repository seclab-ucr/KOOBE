#! /bin/bash

set -e

VERSION=$1
num=$(awk -F. '{print NF-1}' <<< ${VERSION})
if [[ $num -eq 1 ]]; then
    C_VERSION=${VERSION}.0
else
    C_VERSION=${VERSION}
fi
echo ${C_VERSION}

if [[ ! -f "patch-${C_VERSION}" ]]; then
    echo "Do not support version ${VERSION}" && exit 1
fi

wget https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/snapshot/linux-${VERSION}.tar.gz
tar -xzf linux-${VERSION}.tar.gz
if [[ $VERSION != $C_VERSION ]]; then
    mv linux-${VERSION} linux-${C_VERSION}
fi
cd linux-${C_VERSION}
patch -p 1 -i ../patch-${C_VERSION}
patch -N -p 1 -i ../ilog2_NaN.patch || true
cp -r ../../../s2e-linux-kernel/linux-4.9.3/kernel/s2e kernel/
cp -r ../../../s2e-linux-kernel/include ../
cp ../config_${C_VERSION} .config
rm ../linux-${VERSION}.tar.gz
