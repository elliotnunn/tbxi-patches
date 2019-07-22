#!/bin/bash

REMOTE_DISK_NAME=Alpha

until mount | grep -q "/Volumes/$REMOTE_DISK_NAME"; do sleep 0.15; done
rm -f "/Volumes/$REMOTE_DISK_NAME/System Folder/Mac OS ROM"
binhex -o "/Volumes/$REMOTE_DISK_NAME/System Folder/Mac OS ROM" $<
diskutil unmountDisk force /dev/`diskutil info /Volumes/Alpha/ | grep "Part of Whole" | sed 's/.*:\s*//'`
say copied
