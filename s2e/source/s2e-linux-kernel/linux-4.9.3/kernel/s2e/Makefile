obj-$(CONFIG_S2E) += vars.o

#
# Only build the S2E kernel module if S2E support is enabled.
#
# The S2E kernel module is always built as a dynamic module so that we can
# load it at any time (e.g. after resuming from a snapshot) and still send the
# required data to the LinuxMonitor plugin (e.g. addresses and offsets).
#
ifeq ($(CONFIG_S2E),y)
obj-m += s2e.o
endif
