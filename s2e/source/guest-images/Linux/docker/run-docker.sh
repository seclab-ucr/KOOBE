#!/bin/bash

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

# Runs command inside docker image
# Usage: ./run-docker.sh /path/to/guest-images/src /path/to/s2e-linux-kernel docker-image working_dir [COMMAND]
# To build a 32-bit linux package:
#   ./run-docker.sh /home/user/env/source/guest-images /home/user/env/source/s2e-linux-kernel linux-build-32 ../decree-cgc-cfe ./make-kernel.sh $(pwd)/../include

SRC_DIR=$1
shift

S2E_LINUX_KERNEL=$1
shift

DOCKER_IMAGE=$1
shift

WORKING_DIR="$(cd $1 && echo $(pwd))"
shift

COMMAND="$(readlink -f $1)"
shift

echo "Working dir: $WORKING_DIR"
docker run --rm -i \
  -v "$(pwd):$(pwd)" \
  -v "$WORKING_DIR:$WORKING_DIR" -v "$SRC_DIR:$SRC_DIR" \
  -v "$S2E_LINUX_KERNEL:$S2E_LINUX_KERNEL" \
  -w "$WORKING_DIR" \
  $DOCKER_IMAGE:latest \
  $COMMAND $*
