#!/bin/bash

REMOTE=Alpha

sudo true # get password out of way

echo -n Waiting for "$REMOTE"...
while [ -z "$DEVNODE" ]; do
	DEVNODE="$(diskutil list external | grep "$REMOTE" | head -n1 | awk '{print $NF}')"
	if [ -z "$DEVNODE" ]; then sleep 0.15; fi
done

DEVNODE="/dev/$DEVNODE"
sudo diskutil unmountDisk $DEVNODE
sudo hmount $DEVNODE
for x in "$@"; do
	sudo hcopy "$x" ':System Folder:'
done
humount
sync

echo -n -e "\a"
say copied
