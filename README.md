# kmbridge 
In-kernel IGMP Proxy for Linux.

[![GPLv2 License](https://img.shields.io/badge/License-GPLv2-green.svg)](/COPYING.txt)

-----

`kmbridge` is a loadable kernel module for Linux that bridges multicast
traffic between two networks. It works similar to the user-space
[igmpproxy](https://github.com/pali/igmpproxy), but does not require the Linux
advanced multicast API (`CONFIG_IP_MROUTE`) to be available.

## Building
Before you start building the module, make sure you have installed the necessary
packages for building Linux kernel modules on your system (e.g., `make` and `gcc`).

Then, build the module using `make`:
```bash
make KDIR=/path/to/linux
```
This will build `kmbridge.ko` which can be loaded into the Linux kernel.

## License
The code is released under the GPLv2 license. See [COPYING.txt](/COPYING.txt).
