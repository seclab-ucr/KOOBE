#! /bin/bash

set -e

source common.sh

# build syzkaller
/bin/bash -c "source ${VIRTUAL_ENV} && cd ${SYZKALLER_DIR} && make"

# build s2e
/bin/bash -c "source ${VIRTUAL_ENV} && cd ${S2EDIR} && s2e build"

# build kernel
sudo chmod ugo+r /boot/vmlinu*
/bin/bash -c "source ${VIRTUAL_ENV} && cd ${S2EDIR} && s2e image_build debian-9.2.1-x86_64"

