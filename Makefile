export V ?= 0

OUTPUT_DIR := $(CURDIR)/out

APP_LIST := $(subst /,,$(dir $(wildcard */Makefile)))

.PHONY: all
all: my-package prepare-for-rootfs

.PHONY: clean
clean: my-package-clean prepare-for-rootfs-clean

my-package:
	@for app in $(APP_LIST); do \
		$(MAKE) -C $$app CROSS_COMPILE="$(HOST_CROSS_COMPILE)" || exit -1; \
	done

my-package-clean:
	@for app in $(APP_LIST); do \
		$(MAKE) -C $$app clean || exit -1; \
	done

prepare-for-rootfs: my-package
	@echo "Copying app CA and TA binaries to $(OUTPUT_DIR)..."
	@mkdir -p $(OUTPUT_DIR)
	@mkdir -p $(OUTPUT_DIR)/ta
	@mkdir -p $(OUTPUT_DIR)/ca
	@for app in $(app_LIST); do \
		if [ -e $$app/host/$$app ]; then \
			cp -p $$app/host/$$app $(OUTPUT_DIR)/ca/; \
		fi; \
		cp -pr $$app/ta/*.ta $(OUTPUT_DIR)/ta/; \
	done

prepare-for-rootfs-clean:
	@rm -rf $(OUTPUT_DIR)/ta
	@rm -rf $(OUTPUT_DIR)/ca
	@rmdir --ignore-fail-on-non-empty $(OUTPUT_DIR) || test ! -e $(OUTPUT_DIR)
