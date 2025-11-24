# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

FAT32_BLOCK_SIZE=1024
FAT32_BLOCKS=$(shell echo $$((32*1024*1024/$(FAT32_BLOCK_SIZE))))

define Build/boot-scr-k1
	rm -f $@-boot.scr
	mkimage -A riscv -O linux -T script -C none -a 0 -e 0 -d mmc.bootscript.k1 $@-boot.scr
endef

define Build/riscv-sdcard
	rm -f $@.boot #$(KDIR_TMP)/$(IMG_PREFIX)-$(PROFILE)-boot.img
	mkfs.fat $@.boot -C $(FAT32_BLOCKS)
	mcopy -i $@.boot $(LINUX_DIR)/arch/riscv/boot/dts/$(DEVICE_DTS).dtb ::dtb
	mcopy -i $@.boot $@-boot.scr ::boot.scr.uimg
	mcopy -i $@.boot $(IMAGE_KERNEL) ::Image
	./gen_starfive_sdcard_img.sh \
		$@ \
		$@.boot \
		$(IMAGE_ROOTFS) \
		32 \
		$(CONFIG_TARGET_ROOTFS_PARTSIZE)
endef

define Device/Default
  PROFILES := Default
  KERNEL_NAME := Image
  KERNEL := kernel-bin
  IMAGES := sdcard.img.gz
  IMAGE/sdcard.img.gz := boot-scr-k1 | riscv-sdcard | append-metadata | gzip
endef

define Device/bpi-f3
  DEVICE_VENDOR := BananaPi
  DEVICE_MODEL := BPI-F3
  DEVICE_DTS := spacemit/k1-bananapi-f3
endef
TARGET_DEVICES += bpi-f3

define Device/orangepi-rv2
  DEVICE_VENDOR := OrangePi
  DEVICE_MODEL := OPI-RV2
  DEVICE_DTS := spacemit/k1-orangepi-rv2
endef
TARGET_DEVICES += orangepi-rv2

$(eval $(call BuildImage))
