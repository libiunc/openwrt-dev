# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2017 Yousong Zhou

define Profile/Default
  NAME:=Default Profile (all drivers)
  PACKAGES:= \
  	bash \
  	fish \
  	usbutils \
	swconfig \
	wpad-basic-mbedtls
  PRIORITY := 1
endef

define Profile/Default/Description
  Default profile with package set compatible with most boards.
endef
$(eval $(call Profile,Default))
