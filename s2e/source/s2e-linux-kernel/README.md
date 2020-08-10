# S2E Linux Source

This repository contains modified versions of the Linux kernel enhanced for
use with the [S2E](http://s2e.systems) software analysis platform. The kernel extensions
mainly include tracking process and thread creation/termination as well as signal monitoring
(segfaults, etc.). The LinuxMonitor/DecreeMonitor plugins capture these events and expose
them to other analysis plugins.

## Building the kernel

This section describes how to build the kernel manually. We recommend that you
use the appropriate docker scripts in the [guest-images](http://github.com/s2e/guest-images)
repository.

If you just want to build the kernel without building a complete S2E image
(e.g. if you want to experiment with kernel changes without rebuilding a new
image each time), then you can do the following:

```
sudo apt-get build-dep fakeroot linux-image$(uname -r)

cd $KERNEL_DIR
make defconfig

# This will generate a default config that you can make changes to as
# necessary. For example, you may want to enable the S2E debug option.

# Build the kernel in a fakeroot environment
C_INCLUDE_PATH=../include:$C_INCLUDE_PATH fakeroot -- make deb-pkg LOCALVERSION=-s2e

cd ..
```
You can then transfer the generated deb files to your image and install with
`dpkg -i`.

## Extending

We recommend that you follow these steps for modifying your own kernel for use
with S2E:

1. Add the kernel source code directory at the root of this repo

2. Copy `include/s2e/*/*_monitor.h` from an existing kernel

3. Add/remove/modify any commands (and their invoke functions) that you require
   in `include/s2e/*/*_monitor.h`

4. Copy `kernel/s2e` and modify any relevant kernel code to issue commands to
   S2E

5. Write an S2E plugin that includes the same `*_monitor.h` file. The
   plugin class should extend the `BaseLinuxMonitor` class and implement the
   virtual `handleCommand` method to handle a command sent from the modified
   kernel
