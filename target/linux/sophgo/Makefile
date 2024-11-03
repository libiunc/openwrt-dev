# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 Yan Lu <yan.lu@sophgo.com>
#

include $(TOPDIR)/rules.mk

ARCH:=riscv64
BOARD:=sophgo
BOARDNAME:=Sophgo Risc-V
FEATURES:=ext4
KERNELNAME:=Image dtbs
SUBTARGETS:=generic


KERNEL_PATCHVER:=6.6
#KERNEL_PATCHVER:=5.10
#KERNEL_TESTING_PATCHVER:=6.6

include $(INCLUDE_DIR)/target.mk

define Target/Description
	Build firmware images for Sophgo RISC-V Boards. 
endef

$(eval $(call BuildTarget))
