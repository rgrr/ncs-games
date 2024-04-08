# Makefile to build zephyr ZPerf
#
BUILD_DIR := _build
PROJECT   := zephyr

SHELL     := /usr/bin/bash


.PHONY: aaa
aaa:
	source ../zephyr-env.sh; west -V


.PHONY: clean
clean:
	. ../zephyr-env.sh; west build -t clean --build-dir $(BUILD_DIR)


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
