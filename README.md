Digi XBee 802.15.4 device driver
========================

Build and Install
-----------------
Just execute make & make install.
After installing, update module dependency with depmod.
```
make
sudo make install
sudo depmod
```

If using Raspbian system, set KBUILD environment variable to 
kernel header directory (/usr/src/linux-header...) on make command execute.

Module setup
-------

Call modprobe by dependency order.
Finally, call `ldattach` to attach a tty to XBee device.

```
sudo modprobe ieee802154
sudo modprobe ieee802154_socket
sudo modprobe ieee802154_6lowpan
sudo modprobe mac802154
sudo insmod xbee802154.ko
sudo ldattach -s 9600 -8 -n -1 28 /dev/ttyUSB0
```

WPAN,LoWPAN setup
------
Use `ip` command to configure network interface.

```
sudo ip link set wpan0 up
sudo ip link add link wpan0 name lowpan0 type lowpan
sudo ip link set lowpan0 up
```
