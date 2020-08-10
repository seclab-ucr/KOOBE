
# Create image with different Linux kernel versions

# Supported Version
So far, we only support Linux kernel 4.9.3 and 4.14.

```
source koobe/bin/activate
./setup.sh 4.9.3 (or 4.14)
S2EDIR=$S2EDIR ./build.sh 4.9.3 (or 4.14.0)
```

# Unsupported Version
Please take a look at the patch `patch-4.9.3` we provide to have a sense of what changes should be made to support S2E. Once you have patched the kernel source, you can adjust the script `build.sh` to build a new image for S2E.

The following config options must be enabled (or disabled) when compiling Linux kernel:
```
CONFIG_DEBUG_INFO=y

CONFIG_ARCH_HAS_KCOV=y
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y

CONFIG_HAVE_ARCH_KASAN=y
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y

# Help to unwind stack
CONFIG_FRAME_POINTER=y
CONFIG_UNWINDER_FRAME_POINTER=y  (if appliable)

# Required for Debian Stretch
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y

# CONFIG_RANDOMIZE_BASE is not set
```
