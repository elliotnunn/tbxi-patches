#!/usr/bin/env python3

import patch_common

from os import path
import os
import struct
import shutil
import re
import binascii


src, cleanup = patch_common.get_src(desc='''
Support ATA startup disks without an Apple_Driver_ATA partition. This allows Mac
OS to be installed on a disk without repartitioning it. Accomplished by
shoehorning the Drive Setup 2.1 ATA driver into the ROM ATALoad driver, to
replace missing driver partitions.
''')


def align_bytearray(ary, factor):
    while len(ary) % factor != 0:
        ary.append(0)


def find_InitDevice(code):
    for i in range(0, len(code), 2):
        # checking Driver Descriptor Map magic number (there are two but this one always first)
        if code[i:i+2] == b'ER':
            for j in reversed(range(0, i, 2)):
                if code[j:j+2] == b'NV': # LINK A6,#$xxxx
                    return j

    raise ValueError('Function InitDevice not found')


def patch_ataload(code):
    code = bytearray(code)
    align_bytearray(code, 2)
    cut1 = len(code) # boundary between original and glue

    # Parse the DumpObj'd file
    with open(path.join(path.dirname(__file__), 'ATALoad.dmp')) as f:
        for l in f:
            m = re.match(r'^[0-9A-F]{8}: ([0-9A-F ]+)', l) or re.match('^ {13}([0-9A-F][0-9A-F ]*)', l)
            if m:
                code.extend(binascii.unhexlify(m.group(1).replace(' ', '')))

    align_bytearray(code, 2)
    cut2 = len(code) # boundary between glue and driver

    with open(path.join(path.dirname(__file__), 'AppleATADisk'), 'rb') as f:
        code.extend(f.read())

    InitDevice = find_InitDevice(code[:cut1])

    print('ATALoad patch: InitDevice=0x%X, glue=0x%X, driver=0x%X' % (InitDevice, cut1, cut2))

    # "Link" the new code into the old
    for i in range(cut1, len(code), 2):
        if code[i:i+4] == b'Nsrt':
            code[i:i+4] = code[InitDevice:InitDevice+4] # copy the first LINK from the original function
            code[InitDevice:InitDevice+2] = b'\x60\x00' # BRA.W opcode, to...
            code[InitDevice+2:InitDevice+4] = struct.pack('>h', cut1 - (InitDevice+2)) # ...the start of the new code

        if code[i:i+2] == b'At':
            code[i:i+2] = struct.pack('>h', cut2 - i)

        if code[i:i+4] == b'Size':
            code[i:i+4] = struct.pack('>L', len(code) - cut2)

        if code[i:i+2] == b'ID': # reference to original InitDevice, skipping the mangled 4-byte LINK
            code[i:i+2] = struct.pack('>h', (InitDevice+4) - i)

    return bytes(code)


found_drvr = False

for (parent, folders, files) in os.walk(src):
    folders.sort(); files.sort() # make it kinda deterministic
    for filename in files:
        full = path.join(src, parent, filename)

        if filename == 'DRVR_-20175_ATALoad':
            code = open(full, 'rb').read()
            code = patch_ataload(code)
            open(full, 'wb').write(code)
            found_drvr = True


if not found_drvr:
    raise ValueError('ATALoad DRVR not found')


cleanup()
