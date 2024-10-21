# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017 Hauke Mehrtens

include $(TOPDIR)/rules.mk

ARCH:=aarch64
BOARDNAME:=Sophgo
CPU_TYPE:=cortex-a53
KERNELNAME:=Image dtbs
FEATURES+=fpu
