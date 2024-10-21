# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2013-2016 OpenWrt.org
# Copyright (C) 2016 Yousong Zhou

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

FAT32_BLOCK_SIZE=1024
FAT32_BLOCKS=$(shell echo $$(($(CONFIG_SOPHGO_SD_BOOT_PARTSIZE)*1024*1024/$(FAT32_BLOCK_SIZE))))

DEVICE_VARS := SUNXI_DTS SUNXI_DTS_DIR

define Build/sphgo-sdcard
	rm -f $@.boot
	mkfs.fat $@.boot -C $(FAT32_BLOCKS)

	mcopy -i $@.boot $(STAGING_DIR_IMAGE)/$(DEVICE_NAME)-boot.scr ::boot.scr
	mcopy -i $@.boot $(DTS_DIR)/$(SOPHGO_DTS).dtb ::dtb
	mcopy -i $@.boot $(IMAGE_KERNEL) ::uImage
	./gen_sphgo_sdcard_img.sh $@ \
		$@.boot \
		$(IMAGE_ROOTFS) \
		$(CONFIG_SOPHGO_SD_BOOT_PARTSIZE) \
		$(CONFIG_TARGET_ROOTFS_PARTSIZE) \
		$(STAGING_DIR_IMAGE)/$(DEVICE_NAME)-u-boot-with-spl.bin
	rm -f $@.boot
endef

# why \x00\x00\x00\x00 for zImage-initramfs
define Device/Default
  PROFILES := Default
  KERNEL_NAME := zImage
  KERNEL := kernel-bin | uImage none
  IMAGES := sdcard.img.gz
  IMAGE/sdcard.img.gz := sphgo-sdcard | append-metadata | gzip
  SOPHGO_DTS_DIR :=sphgo/
  SOPHGO_DTS = $$(SOPHGO_DTS_DIR)$$(SOC)-$(lastword $(subst _, ,$(1)))
endef

include $(SUBTARGET).mk

$(eval $(call BuildImage))
