#!/bin/sh

die() {
	(>&2 echo $@)
	exit 1
}

FRITZBOX='192.168.178.1'
USER='adam2'
PASSWD='adam2'
FTP=$(command -v ftp)
FILE=${1-'uboot-fritz4040.bin'}

[ -n "$FTP" ] || die -e "no ftp programm installed.\naborting."

[ -r "$FILE" ] || die -e "image '$FILE' is not readable.\naborting."

ping -q -4 -w 1 -c 1 "$FRITZBOX" &> /dev/null || die -e "Fritzbox at $FRITZBOX is not reachable (yet). \nMake sure to use the yellow LAN ports!.\naborting."

cat << EOS

This will take ages (2 minutes+)! If you want a status bar:
Please attach a serial to the device and look there.

Note:This script does not terminate on its own.. :/
Once you see a message like this appear on the console:
150 Flash check 0x...

you can power-cycle your fritzbox and force-quit this script.

Note2: If this fails, you can just replug the power cable and
give it one more try. To go back to AVM's stock firmware you
have to download and run AVM's recover utility.

EOS

$FTP -n -v -4 "$FRITZBOX" << END_SCRIPT
quote USER $USER
quote PASS $PASSWD
quote MEDIA FLSH
binary
passive
put $FILE mtd1
quote check mtd1
bye
END_SCRIPT
exit 0
