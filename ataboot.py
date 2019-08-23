#!/usr/bin/env python3

import patch_common

from os import path
import os
import struct
import shutil
import re
import binascii


src, cleanup = patch_common.get_src(desc='''
Enable booting from ATA disks without an Apple_Driver_ATA partition. This is
done by patching the ROM-based .ATALoad DRVR to fall back on the ROM-based
.ATADisk DRVR when initially scanning a disk. The .ATADisk is added to the ROM
if missing. The disk still needs an Apple Partition Map.
''')


# long BOOT(void *DRVR, void *PartMapEntry, long flags)
# C calling convention: args pushed in reverse order and not popped by function, return value in d0
def find_BOOT(code):
    for i in range(0, len(code), 2):
        if code[i:i+4] == b'BOOT': # MOVE.L 'BOOT',D0  --or-- MOVE.L 'BOOT',-(SP)
            for j in reversed(range(0, i, 2)):
                # Count backwards and look for the target of *any* JSR, which is the start of the func
                for k in range(0, len(code), 2):
                    if code[k:k+2] == b'\x4E\xBA': # JSR opcode
                        if k+2 + struct.unpack('>h', code[k+2:k+4])[0] == j:
                            return j

    raise ValueError('Function BOOT not found')


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
    new = len(code) # boundary between old and new code

    # Parse the DumpObj'd file
    with open(path.join(path.dirname(__file__), 'ATALoad.dmp')) as f:
        for l in f:
            m = re.match(r'^[0-9A-F]{8}: ([0-9A-F ]+)', l) or re.match('^ {13}([0-9A-F][0-9A-F ]*)', l)
            if m:
                code.extend(binascii.unhexlify(m.group(1).replace(' ', '')))

    InitDevice = find_InitDevice(code[:new])
    BOOT = find_BOOT(code[:new])

    print('ATALoad patch: InitDevice=0x%X, NewInitDevice=0x%X, BOOT=0x%X' % (InitDevice, new, BOOT))

    # "Link" the new code into the old
    for i in range(new, len(code), 2):
        if code[i:i+4] == b'Nsrt':
            code[i:i+4] = code[InitDevice:InitDevice+4] # copy the first LINK from the original function
            code[InitDevice:InitDevice+2] = b'\x60\x00' # BRA.W opcode, to...
            code[InitDevice+2:InitDevice+4] = struct.pack('>h', new - (InitDevice+2)) # ...the start of the new code

        if code[i:i+2] == b'ID': # reference to original InitDevice, skipping the mangled 4-byte LINK
            code[i:i+2] = struct.pack('>h', (InitDevice+4) - i)

        if code[i:i+2] == b'BT': # reference to BOOT function
            code[i:i+2] = struct.pack('>h', BOOT - i)

    return bytes(code)


for (parent, folders, files) in os.walk(src):
    folders.sort(); files.sort() # make it kinda deterministic
    for filename in files:
        full = path.join(src, parent, filename)

        if filename == 'Romfile':
            ataload = path.join(src, parent, 'Rsrc', 'DRVR_-20175_ATALoad')
            atadisk = path.join(src, parent, 'Rsrc', 'DRVR_53_ATADisk')

            if path.exists(ataload):
                code = open(ataload, 'rb').read()
                code = patch_ataload(code)
                open(ataload, 'wb').write(code)

                if not path.exists(atadisk):
                    with open(full, 'a') as f: # append to Romfile
                        f.write('\ntype=DRVR   id=53       name=.ATADisk           src=Rsrc/DRVR_53_ATADisk # inserted by ataboot.py\n')
                print('ATALoad patch: using .ATADisk DRVR from Drive Setup 2.1')
                shutil.copy(path.join(path.dirname(__file__), 'DRVR_53_ATADisk'), atadisk)


cleanup()
