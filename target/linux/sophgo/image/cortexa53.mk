# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2013-2016 OpenWrt.org
# Copyright (C) 2016 Yousong Zhou

KERNEL_LOADADDR:=0x40008000

define Device/sun50i-h618
  SOC := sun50i-h618
  $(Device/sun50i)
endef

define Device/xunlong_orangepi-zero3
  DEVICE_VENDOR := Xunlong
  DEVICE_MODEL := Orange Pi Zero 3
  $(Device/sun50i-h618)
endef
TARGET_DEVICES += xunlong_orangepi-zero3

