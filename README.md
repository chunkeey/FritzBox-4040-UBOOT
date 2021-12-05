# FritzBox-4040-UBOOT

This repository contains resources to build a second stage U-Boot bootloader for Qualcomm IPQ40xx based AVM routers.

## How to build

1. Create a symlink which points to your toolchain

2. Execute make-uboot.sh with your desired board as positional argument. Valid boardnames are the following:

   - fritz1200
   - fritz3000
   - fritz4040
   - fritz7520
   - fritz7530

3. The finished U-Boot will be placed in the root directory as `uboot-<boardname>.bin`.

## How to install
### NOR-based
This is compatible with the following models

 - FRITZ!Box 4040

For devices with an SPI-NOR chip the U-Boot can be uploaded using the upload-to-f4040.sh script. This way, the bootloader will be peristently installed.

Example for the FRITZ!Box 4040:

```
$ ./upload-to-f4040.sh

This will take ages (2 minutes+)! If you want a status bar:
Please attach a serial to the device and look there.

Note:This script does not terminate on its own.. :/
Once you see a message like this appear on the console:
150 Flash check 0x...

you can power-cycle your fritzbox and force-quit this script.

Note2: If this fails, you can just replug the power cable and
give it one more try. To go back to AVM's stock firmware you
have to download and run AVM's recover utility.

Connected to 192.168.178.1.
220 ADAM2 FTP Server ready
331 Password required for adam2
230 User adam2 successfully logged in
200 Media set to MEDIA_FLASH
200 Type set to BINARY
Passive mode on.
227 Entering Passive Mode (192,168,178,1,12,0)
150 Opening BINARY data connection
226 Transfer complete
524288 bytes sent in 1.52 seconds (337 kbytes/s)
```


### NAND-based
This is compatible with the following models

 - FRITZ!Box 7520
 - FRITZ!Box 7530
 - FRITZ!Repeater 1200
 - FRITZ!Repeater 3000

The Bootloader can be loaded into the devices RAM using the EVA-ramboot script. From there, you are able to boot an OpenWRT initramfs image. The U-Boot can be installed persistently from OpenWRT as EVA does not support writing the NAND chip directly.

Example for the FRITZ!Box 7530:
```
$ ./upload-to-ram.py --offset 0x88600000 192.168.178.1 uboot-fritz7530.bin
```
