# Makefile to build zephyr ZPerf
#
BUILD_DIR := _build
PROJECT   := zephyr
BOARD     := nrf52840dk_nrf52840

WEST_CONF := -DNCS_TOOLCHAIN_VERSION=NONE 
WEST_CONF += -DEXTRA_CONF_FILE="overlay-usbd_next_ecm.conf boards/$(BOARD).conf"
WEST_CONF += -DDTC_OVERLAY_FILE="usbd_next_ecm.overlay boards/$(BOARD).overlay"
WEST_CONF += -DBOARD_ROOT=. -DCACHED_CONF_FILE=prj.conf

SHELL     := /usr/bin/bash


.PHONY: aaa
aaa:
	source ../zephyr-env.sh; west -V


.PHONY: clean
clean:
	. ../zephyr-env.sh; west build -t clean --build-dir $(BUILD_DIR)


.PHONY: create-config
create-config:
	. ../zephyr-env.sh; west build --build-dir $(BUILD_DIR) . --pristine --board $(BOARD) --no-sysbuild --cmake-only -- $(WEST_CONF) -DCONFIG_SIZE_OPTIMIZATIONS=y

.PHONY: create-config-debug
create-config-debug:
	. ../zephyr-env.sh; west build --build-dir $(BUILD_DIR) . --pristine --board $(BOARD) --no-sysbuild --cmake-only -- $(WEST_CONF) -DCONFIG_DEBUG_OPTIMIZATIONS=y -DCONFIG_DEBUG_THREAD_INFO=y -DCONFIG_CORTEX_M_DEBUG_MONITOR_HOOK=y -DCONFIG_SEGGER_DEBUGMON=y

.PHONY: create-config-speed
create-config-speed:
	. ../zephyr-env.sh; west build --build-dir $(BUILD_DIR) . --pristine --board $(BOARD) --no-sysbuild --cmake-only -- $(WEST_CONF) -DCONFIG_SPEED_OPTIMIZATIONS=y


.PHONY: all
all:
	#. ../zephyr-env.sh; west build --build-dir $(BUILD_DIR) .
	. ../zephyr-env.sh; ninja -C _build -v all
	@echo "--------------------------"
	@arm-none-eabi-size -Ax $(BUILD_DIR)/zephyr/$(PROJECT).elf | awk '/^[a-z]/ {size=strtonum($$2); addr=strtonum($$3); if (addr>=0x20000000 && addr<0x20040000) ram += size; if (addr>=0x00000000 && addr<0x20000000) rom += size; } END {print "Flash: " rom "  RAM: " ram}'
	@echo "--------------------------"


.PHONY: details
details: all
	@arm-none-eabi-size -Ax $(BUILD_DIR)/zephyr/$(PROJECT).elf


.PHONY: flash
flash: all
	cp $(BUILD_DIR)/zephyr/$(PROJECT).uf2 /media/picoprobe
	@echo "ok."


.PHONY: reset
reset:
	pyocd reset -f 10m

