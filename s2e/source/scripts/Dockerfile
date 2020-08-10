# Copyright (C) 2017-2020, Cyberhaven
# All rights reserved.
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

# Installs S2E and its associated libraries and tools to /opt/s2e

FROM cyberhaven/libs2e-build

COPY .repo /.repo
COPY scripts /scripts
COPY qemu /qemu

RUN cd s2e-build && \
    make -f /scripts/Makefile BUILD_ARCH=x86_64 S2E_PREFIX=/opt/s2e QEMU_SRC=/qemu stamps/qemu-release-install

# Install s2e-env
COPY s2e-env s2e/s2e-env
RUN apt-get -y install python3-pip && \
    cd s2e/s2e-env && \
    pip3 install --process-dependency-links .
