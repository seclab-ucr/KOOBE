#! /bin/bash

set -e

sudo apt-get install python3-dev libffi-dev build-essential virtualenvwrapper debootstrap qemu-system-x86 clang-format libguestfs-tools dwarves

source common.sh

virtualenv ${KOOBE} --python=$(which python3)
# install s2e-env
/bin/bash -c "source ${VIRTUAL_ENV} && cd s2e/source/s2e-env && pip install ."
echo "S2EDIR=\"${S2EDIR}\"" >> $VIRTUAL_ENV
echo "export S2EDIR" >> $VIRTUAL_ENV
echo "KOOBE=\"${KOOBE}\"" >> $VIRTUAL_ENV
echo "export KOOBE" >> $VIRTUAL_ENV
echo "WORKDIR=\"${WORKDIR}\"" >> $VIRTUAL_ENV
echo "export WORKDIR" >> $VIRTUAL_ENV

# install dependence
/bin/bash -c "source ${VIRTUAL_ENV} && s2e init -f s2e"
/bin/bash -c "source ${VIRTUAL_ENV} && cd aeg-analysis && pip install -r requirements.txt"

# install golang
if [[ ! -f "go1.14.4.linux-amd64.tar.gz" ]]; then
    wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz
    tar -xzf go1.14.4.linux-amd64.tar.gz
fi

echo "GOROOT=\"${GOROOT}\"" >> $VIRTUAL_ENV
echo "export GOROOT" >> $VIRTUAL_ENV
echo "GOPATH=\"${GOPATH}\"" >> $VIRTUAL_ENV
echo "export GOPATH" >> $VIRTUAL_ENV

# create image for syzkaller
# see more instructions in https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md
IMAGE_DIR="${WORKDIR}/debian"
IMAGE=${IMAGE_DIR}/stretch.img
IMAGE_KEY=${IMAGE_DIR}/stretch.id_rsa
mkdir $IMAGE_DIR && cd $IMAGE_DIR
wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh

# generate syzkaller config template
cd ${WORKDIR}
cp syzkaller.template syzkaller.cfg
sed -i 's,{{IMAGE}},'"${IMAGE}"',g' syzkaller.cfg
sed -i 's,{{KEY}},'"${IMAGE_KEY}"',g' syzkaller.cfg
sed -i 's,{{SYZKALLER}},'"${SYZKALLER_DIR}"',g' syzkaller.cfg
sed -i 's,{{S2EDIR}},'"${S2EDIR}"',g' syzkaller.cfg
mv syzkaller.cfg aeg-analysis/template/

