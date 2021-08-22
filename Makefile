# Build script for kmbridge
#
# Copyright (C) 2021 Fabian Mastenbroek.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

.PHONY: all module clean prepare

obj-m := kmbridge.o
kmbridge-objs := ./src/kmbridge.o ./src/router.o ./src/igmp.o

ccflags-y := -g

all: module

module:
	make -C $(KDIR) M=$(CURDIR) modules

clean:
	make -C $(KDIR) M=$(CURDIR) clean

prepare:
	make -C $(KDIR) modules_prepare
