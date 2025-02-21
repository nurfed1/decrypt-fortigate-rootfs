# FortiGate `rootfs.gz` decryption tool

Fortinet regularly updates crypto obfuscation for their firmware.

`decrypt_rootfs.py` is an all-in-one tool allowing decryption of `rootfs.gz` (ramdisk file).

Tested on:
  - FortiGate 7.4.7

## Setup

```bash
$ python3 -m venv .venv
$ . .venv/bin/activate
(.venv) $ pip install -r requirements.txt
```

## Usage

```bash
user@randorisec:~/fortigate-crypto$ python decrypt_rootfs.py flatkc.elf.x64.7.4.7 ./vmdk/fs/rootfs.gz rootfs.gz.dec
 ____      _    _   _ ____   ___  ____  ___ ____  _____ ____
|  _ \    / \  | \ | |  _ \ / _ \|  _ \|_ _/ ___|| ____/ ___|
| |_) |  / _ \ |  \| | | | | | | | |_) || |\___ \|  _|| |
|  _ <  / ___ \| |\  | |_| | |_| |  _ < | | ___) | |__| |___
|_| \_\/_/   \_\_| \_|____/ \___/|_| \_\___|____/|_____\____|


                   https://randorisec.fr


[INFO] Retrieving crypto material...
[INFO] Decrypting ./vmdk/fs/rootfs.gz...
73822496it [00:19, 3812345.28it/s]
[INFO] DONE.
user@randorisec:~/fortigate-crypto$ file rootfs.gz.dec
rootfs.gz.dec: gzip compressed data, last modified: Mon Jan 20 18:44:06 2025, from Unix, original size modulo 2^32 119727260
user@randorisec:~/fortigate-crypto$ gzip -dc -S .dec < rootfs.gz.dec > rootfs.cpio
user@randorisec:~/fortigate-crypto/tmp$ mkdir tmp; cd tmp; sudo cpio -idv < ../rootfs.cpio
user@randorisec:~/fortigate-crypto/tmp$ ll
total 47212
drwxr-xr-x 13 user user     4096 Feb 20 13:32 ./
drwxr-xr-x  5 user user     4096 Feb 20 13:32 ../
-r--r--r--  1 root root 33109932 Feb 20 13:32 bin.tar.xz
drwxr-xr-x  2 root root     4096 Feb 20 13:32 boot/
drwxr-xr-x  3 root root     4096 Feb 20 13:32 data/
drwxr-xr-x  2 root root     4096 Feb 20 13:32 data2/
drwxr-xr-x  8 root root    20480 Feb 20 13:32 dev/
lrwxrwxrwx  1 root root        8 Feb 20 13:32 etc -> data/etc/
lrwxrwxrwx  1 root root        1 Feb 20 13:32 fortidev -> //
lrwxrwxrwx  1 root root       10 Feb 20 13:32 init -> /sbin/init*
drwxr-xr-x  5 root root     4096 Feb 20 13:32 lib/
lrwxrwxrwx  1 root root        4 Feb 20 13:32 lib64 -> /lib/
-r--r--r--  1 root root 14456836 Feb 20 13:32 migadmin.tar.xz
-r--r--r--  1 root root   549180 Feb 20 13:32 node-scripts.tar.xz
drwxr-xr-x  2 root root     4096 Feb 20 13:32 proc/
drwxr-xr-x  2 root root     4096 Feb 20 13:32 sbin/
drwxr-xr-x  2 root root     4096 Feb 20 13:32 sys/
drwxr-xr-x  2 root root     4096 Feb 20 13:32 tmp/
drwxr-xr-x  3 root root     4096 Feb 20 13:32 usr/
-r--r--r--  1 root root   148572 Feb 20 13:32 usr.tar.xz
drwxr-xr-x  9 root root     4096 Feb 20 13:32 var/
```
