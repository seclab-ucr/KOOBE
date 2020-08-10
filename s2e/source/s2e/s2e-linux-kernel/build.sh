#! /bin/bash

set -e

VERSION=$1
if [[ ! -f "patch-${VERSION}" ]]; then
    echo "Do not support version ${VERSION}" && exit 1
fi

if [[ -z "${S2EDIR}" ]]; then
    echo "ENV variable S2EDIR is unset" && exit 1
fi

cd linux-${VERSION}

# build debs
C_INCLUDE_PATH=../include:$C_INCLUDE_PATH fakeroot -- make deb-pkg LOCALVERSION=-s2e

cd ..
rm -f linux-${VERSION}-s2e_${VERSION}-s2e-*_amd64.changes
rm -f linux-${VERSION}-s2e_${VERSION}-s2e-*.debian.tar.gz
rm -f linux-${VERSION}-s2e_${VERSION}-s2e.orig.tar.gz
rm -f linux-${VERSION}-s2e_${VERSION}-s2e-*.dsc

# copy image
cp -rp $S2EDIR/images/debian-9.2.1-x86_64 $S2EDIR/images/debian-9.2.1-x86_64-${VERSION}

# install debs
cp ${S2EDIR}/source/guest-images/Linux/s2e_home/launch.sh ./
sed -i "/^install_i386$/s/^/#/g" launch.sh
sed -i "/^install_systemtap$/s/^/#/g" launch.sh
sed -i "/MENU_ENTRY=/s/$/\n    MENU_ENTRY=\"Debian GNU\/Linux, with Linux ${VERSION}-s2e\"/g" launch.sh
if [[ ! -f "linux-headers-4.9.3-s2e_4.9.3-s2e-1_amd64.deb" ]]; then
    sed -i "/^install_kernel() {$/s/$/\n    rm linux-headers-4.9.3-s2e_4.9.3-s2e-1_amd64.deb/g" launch.sh
    sed -i "/^install_kernel() {$/s/$/\n    rm linux-image-4.9.3-s2e_4.9.3-s2e-1_amd64.deb/g" launch.sh
    sed -i "/^install_kernel() {$/s/$/\n    rm linux-image-4.9.3-s2e-dbg_4.9.3-s2e-1_amd64.deb/g" launch.sh
    sed -i "/^install_kernel() {$/s/$/\n    rm linux-libc-dev_4.9.3-s2e-1_amd64.deb/g" launch.sh
fi

sudo virt-copy-in -a ${S2EDIR}/images/debian-9.2.1-x86_64-${VERSION}/image.raw.s2e launch.sh /home/s2e
sudo virt-copy-in -a ${S2EDIR}/images/debian-9.2.1-x86_64-${VERSION}/image.raw.s2e *.deb /home/s2e

export S2E_CONFIG=s2e-config.lua
export S2E_SHARED_DIR=$S2EDIR/install/share/libs2e
export S2E_MAX_PROCESSES=1
export S2E_UNBUFFERED_STREAM=1

GRAPHICS=-nographic
DRIVE="-drive file=$S2EDIR/images/debian-9.2.1-x86_64-${VERSION}/image.raw.s2e,format=raw,cache=writeback"
QEMU="$S2EDIR/install/bin/qemu-system-x86_64"
LIBS2E="$S2EDIR/install/share/libs2e/libs2e-x86_64.so"
NET="-net none -net nic,model=e1000"

sudo $QEMU $DRIVE \
    -k en-us $GRAPHICS -monitor null -m 4096M -enable-kvm \
    -serial file:serial.txt $NET -no-reboot

echo "Successfully install debs"

# recover launch.sh
cp ${S2EDIR}/source/s2e/guest/linux/scripts/launch.sh ./
sudo virt-copy-in -a ${S2EDIR}/images/debian-9.2.1-x86_64-${VERSION}/image.raw.s2e launch.sh /home/s2e

# Take a new snapshot
DRIVE="-drive file=$S2EDIR/images/debian-9.2.1-x86_64-${VERSION}/image.raw.s2e,format=s2e,cache=writeback"
LD_PRELOAD=$LIBS2E $QEMU $DRIVE \
    -k en-us $GRAPHICS -monitor null -m 1024M -enable-kvm \
    -serial file:serial_ready.txt $NET -enable-serial-commands

echo "Successfully take a snapshot!"

# clean
rm *.deb
rm serial.txt
rm serial_ready.txt
rm launch.sh

