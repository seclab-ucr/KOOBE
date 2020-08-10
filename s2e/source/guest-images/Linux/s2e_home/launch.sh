#!/bin/sh

# S2E Selective Symbolic Execution Platform
#
# Copyright (c) 2017, Dependable Systems Laboratory, EPFL
# Copyright (c) 2017, Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -ex

# Install 32-bit user space for 64-bit kernels
install_i386() {
    if uname -a | grep -q x86_64; then
        sudo dpkg --add-architecture i386
        sudo apt-get update

        # libelf is required for s2e.so
        sudo apt-get -y install gcc-multilib g++-multilib libc6-dev-i386 lib32stdc++-6-dev libstdc++6:i386 \
            libelf1:i386
    fi
}


# Install systemtap from source
# The one that's packaged does not support our kernel
# Note: systemtap requires a lot of memory to compile, so we need swap
install_systemtap() {
    git clone https://sourceware.org/git/systemtap.git
    cd systemtap
    git checkout release-3.2
    cd ..

    mkdir systemtap-build
    cd systemtap-build
    ../systemtap/configure --disable-docs
    make -j2
    sudo make install
    cd ..
}

# Install kernels last, the cause downgrade of libc,
# which will cause issues when installing other packages
install_kernel() {
    sudo dpkg -i *.deb

    MENU_ENTRY="$(grep menuentry /boot/grub/grub.cfg  | grep s2e | cut -d "'" -f 2 | head -n 1)"
    echo "Default menu entry: $MENU_ENTRY"
    echo "GRUB_DEFAULT=\"1>$MENU_ENTRY\"" | sudo tee -a /etc/default/grub
    sudo update-grub
}

has_cgc_kernel() {
    if ls *.deb | grep -q ckt32-s2e; then
        echo 1
    else
        echo 0
    fi
}

# Install the prerequisites for cgc packages
install_apt_packages() {
    APT_PACKAGES="
    python-apt
    python-crypto
    python-daemon
    python-lockfile
    python-lxml
    python-matplotlib
    python-yaml
    tcpdump
    "

    sudo apt-get -y install ${APT_PACKAGES}

    # This package no longer exists on recent debian version
    wget http://ftp.us.debian.org/debian/pool/main/p/python-support/python-support_1.0.15_all.deb
    sudo dpkg -i python-support_1.0.15_all.deb
}

install_cgc_packages() {
    CGC_PACKAGES="
    binutils-cgc-i386_2.24-10551-cfe-rc8_i386.deb
    cgc2elf_10551-cfe-rc8_i386.deb
    libcgcef0_10551-cfe-rc8_i386.deb
    libcgcdwarf_10551-cfe-rc8_i386.deb
    readcgcef_10551-cfe-rc8_i386.deb
    python-defusedxml_10551-cfe-rc8_all.deb
    libcgc_10551-cfe-rc8_i386.deb
    cgc-network-appliance_10551-cfe-rc8_all.deb
    cgc-service-launcher_10551-cfe-rc8_i386.deb
    poll-generator_10551-cfe-rc8_all.deb
    cb-testing_10551-cfe-rc8_all.deb
    cgc-release-documentation_10560-cfe-rc8_all.deb
    cgcef-verify_10551-cfe-rc8_all.deb
    cgc-pov-xml2c_10551-cfe-rc8_i386.deb
    strace-cgc_4.5.20-10551-cfe-rc8_i386.deb
    libpov_10551-cfe-rc8_i386.deb
    clang-cgc_3.4-10551-cfe-rc8_i386.deb
    cgc-virtual-competition_10551-cfe-rc8_all.deb
    magic-cgc_10551-cfe-rc8_all.deb
    services-cgc_10551-cfe-rc8_all.deb
    linux-image-3.13.11-ckt32-cgc_10551-cfe-rc8_i386.deb
    linux-libc-dev_10551-cfe-rc8_i386.deb
    "

    local CUR_DIR
    CUR_DIR="$(pwd)"

    # Download packages in temp folder
    cd /tmp

    # Install the CGC packages
    for PACKAGE in ${CGC_PACKAGES}; do
        wget --no-check-certificate https://cgcdist.s3.amazonaws.com/release-final/deb/${PACKAGE}
        sudo dpkg -i --force-confnew ${PACKAGE}
        rm -f ${PACKAGE}
    done

    cd "$CUR_DIR"
}

sudo apt-get update
install_i386
install_systemtap

# Install CGC tools if we have a CGC kernel
if [ $(has_cgc_kernel) -eq 1 ]; then
    install_apt_packages
    install_cgc_packages
fi

install_kernel

# QEMU will stop (-no-reboot)
sudo reboot
