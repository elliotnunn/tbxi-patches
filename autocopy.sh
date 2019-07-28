#!/bin/bash

REMOTE=/Volumes/Alpha

echo -n Waiting for "$REMOTE"...
until mount | grep -q "$REMOTE"; do sleep 0.15; done
echo ok

for x in "$@"; do
	td="$(mktemp -d)"
	binhex -C "$td" "$x" # hack to find out file name!
	rm -f "$REMOTE/System Folder/$(ls "$td")"
	rm -rf "$td"
	binhex -C "$REMOTE/System Folder/" "$x"
done

diskutil unmountDisk force /dev/`diskutil info "$REMOTE" | grep "Part of Whole" | tr '[[:space:]]' '\n' | tail -n1`
echo -n -e "\a"
say copied
