# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2013-2016 OpenWrt.org

include $(TOPDIR)/rules.mk

ARCH:=arm
BOARD:=sophgo
BOARDNAME:=Sophgo ARM SoCs
FEATURES:=usb ext4 display rootfs-part rtc squashfs
SUBTARGETS:=cortexa53

KERNEL_PATCHVER:=6.6

KERNELNAME:=zImage dtbs


# SG2000 : Single Cortex-A53

include $(INCLUDE_DIR)/target.mk

DEFAULT_PACKAGES += uboot-envtools
DEFAULT_PACKAGES += partx-utils mkf2fs e2fsprogs

$(eval $(call BuildTarget))
