TARGET ?= xbee2
TARGET_KO := $(TARGET).ko
V = 0

EXTRA_CFLAGS += -Wformat=2 -Wall
EXTRA_CFLAGS += -DDEBUG
ifneq ($(MODTEST_ENABLE),)
EXTRA_CFLAGS += -DMODTEST_ENABLE=$(MODTEST_ENABLE)
endif
KVER ?= `uname -r`

KBUILD = /lib/modules/$(KVER)/build
INSTALL_DIR = /lib/modules/$(KVER)/kernel/drivers/video

all: ${TARGET_KO}

ifneq ($(MODTEST_ENABLE),)
$(TARGET).ko: $(TARGET).c $(TARGET)_test.c
else
$(TARGET).ko: $(TARGET).c
endif
	make -C $(KBUILD) M=`pwd` V=$(V) modules

clean:
	make -C $(KBUILD) M=`pwd` V=$(V) clean

obj-m := $(TARGET).o

clean-files := *.o *.ko *.mod.[co] *~ version.h

version.h:
	eval `sed -e "s/\[0\]//" ./dkms.conf`; \
	GREV=`git rev-list HEAD | wc -l 2> /dev/null`; \
	if [ $$GREV != 0 ] ; then \
		printf "#define DRV_VERSION \"$${PACKAGE_VERSION}rev$$GREV\"\n#define DRV_RELDATE \"`git show --date=short --format=%ad | sed -n '1p' 2> /dev/null`\"\n#define DRV_NAME \"$${BUILT_MODULE_NAME}\"\n" > $@; \
	else \
		printf "#define DRV_VERSION \"$${PACKAGE_VERSION}\"\n#define DRV_RELDATE \"$$PACKAGE_RELDATE\"\n#define DRV_NAME \"$${BUILT_MODULE_NAME}\"\n" > $@; \
	fi

uninstall:

dkms: $(TARGET_KO)

install: uninstall dkms
	install -d $(INSTALL_DIR)
	install -m 644 $(TARGET_KO) $(INSTALL_DIR)
	depmod -a $(KVER)

install_compress: install
	. $(KBUILD)/.config ; \
	if [ $$CONFIG_DECOMPRESS_XZ = "y" ] ; then \
		xz   -9e $(INSTALL_DIR)/$(TARGET_KO); \
	elif [ $$CONFIG_DECOMPRESS_BZIP2 = "y" ] ; then \
		bzip2 -9 $(INSTALL_DIR)/$(TARGET_KO); \
	elif [ $$CONFIG_DECOMPRESS_GZIP = "y" ] ; then \
		gzip  -9 $(INSTALL_DIR)/$(TARGET_KO); \
	fi
	depmod -a $(KVER)
