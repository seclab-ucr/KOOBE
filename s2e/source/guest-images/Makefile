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

SRC?=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifeq ($(shell id -u),0)
$(error Please do not run this makefile as root)
endif

include $(SRC)/Makefile.common
include $(SRC)/Makefile.linux
include $(SRC)/Makefile.windows

.DEFAULT_GOAL := linux
.DELETE_ON_ERROR:

### Check that required variables are set up properly

ifneq ($(MAKECMDGOALS),clean)

ifeq ("$(wildcard $(QEMU64))","")
$(error $(QEMU64) does not exist. Make sure S2E_INSTALL_ROOT is set properly)
endif

ifeq ("$(wildcard $(GUEST_TOOLS32_ROOT))","")
$(error $(GUEST_TOOLS32_ROOT) does not exist. Make sure S2E_INSTALL_ROOT is set properly and guest tools are installed)
endif

ifeq ("$(wildcard $(GUEST_TOOLS64_ROOT))","")
$(error $(GUEST_TOOLS32_ROOT) does not exist. Make sure S2E_INSTALL_ROOT is set properly and guest tools are installed)
endif


ifneq (,$(findstring -enable-kvm,$(QEMU_KVM)))
  ifeq ("$(wildcard /dev/kvm)","")
    $(error /dev/kvm does not exist. You need KVM to build images)
  endif

  ifeq (,$(findstring libvirtd,$(shell groups)))
    ifeq (,$(findstring kvm,$(shell groups)))
      $(error You must be member of the libvirtd or kvm groups to build images)
    endif
  endif

  ifneq (,$(findstring VBoxHeadless,$(shell ps aux)))
    $(error VirtualBox is not compatible with KVM. Please stop all running VirtualBox instances first)
  endif
endif

ifeq (,$(findstring docker,$(shell groups)))
  $(error You must be member of the docker group to build images)
endif

endif #clean


# these targets must correspond to the image_group key in images.json
all: windows linux

archives: windows_archives linux_archives

ifeq ($(OUTDIR),$(SRC)/output)
CLEAN_DIR=$(OUTDIR)
else
CLEAN_DIR=$(OUTDIR)/*
endif

clean: windows_clean
	rm -rf $(CLEAN_DIR) $(OUTDIR)/* $(TMPDIR) $(STAMPS)
