DRIVER_DIR  = driver/kern
PAL_DIR     = lakko/platform/pal
UMH_DIR     = lakko/platform/umh
SANDBOX_DIR = sandbox

SOCKET_DIR  = lakko/socket

SUBDIRS = $(DRIVER_DIR) $(PAL_DIR) $(UMH_DIR) $(SOCKET_DIR) $(SANDBOX_DIR)
all: $(SUBDIRS)

driver_uninstall:
	rmmod walnut

driver_install:
	insmod driver/kern/walnut.ko

$(SUBDIRS):
	$(MAKE) -C $(@)

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $(@); \
	done

.PHONY: $(SUBDIRS) clean distclean
