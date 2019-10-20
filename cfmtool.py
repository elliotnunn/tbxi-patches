#!/usr/bin/env python3

# Copyright (c) 2019 Elliot Nunn

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# This is a single-file library for manipulating Preferred Executable Format files
# A command line-interface is available (just call cfmtool.py --help)


import builtins
import argparse
import datetime
import struct
import os
import re
import textwrap
import functools
from os import path
from ast import literal_eval as eval


def dump(from_binary_or_path, to_path):
    """Dump a CFM/PEF binary to a directory

    Command line usage: cfmtool.py BINARY DIRECTORY

    The first argument can be a bytes-like object, or a path to read from.
    """

    try:
        bytes(from_binary_or_path)
        from_binary = from_binary_or_path
    except TypeError:
        with open(from_binary_or_path, 'rb') as f:
            from_binary = f.read()

    if not from_binary.startswith(b'J o y ! peffpwpc\x00\x00\x00\x01'.replace(b' ', b'')):
        raise ValueError('not a pef (PowerPC, v1)')

    os.makedirs(to_path, exist_ok=True)

    dateTimeStamp, *versions = struct.unpack_from('>4L', from_binary, 16)

    write_txt(format_mac_date(dateTimeStamp), to_path, 'date.txt')
    write_txt(repr(dict(zip(('oldDefVersion', 'oldImpVersion', 'currentVersion'), versions))), to_path, 'version.txt')

    section_list = []
    section_count, = struct.unpack_from('>H', from_binary, 32)
    offset = 40
    for i in range(section_count):
        sec = dict(zip(
            ('name', 'defaultAddress', 'totalLength', 'unpackedLength', 'containerLength',
                'containerOffset', 'sectionKind', 'shareKind', 'alignment'),
            struct.unpack_from('>lLLLLLbbb', from_binary, offset)))

        section_list.append(sec)

        offset += 28

    # Now offset points to the nasty table of section names

    for i, sec in enumerate(section_list):
        if sec['name'] > 0:
            name_offset = offset
            for j in range(sec['name']): name_offset = from_binary.index(b'\0', name_offset) + 1
            sec['name'] = from_binary[name_offset:from_binary.index(b'\0', name_offset)].decode('mac_roman')
        else:
            sec['name'] = ''

    for i, sec in enumerate(section_list):
        sec['sectionKind'] = ('code', 'data', 'pidata', 'rodata', 'loader',
            'debug', 'codedata', 'exception', 'traceback')[sec['sectionKind']]

        sec['shareKind'] = ('', 'process', '', '', 'global', 'protected')[sec['shareKind']]

    # What to call the final file...
    used_basenames = []
    for i, sec in enumerate(section_list):
        basename = sec['sectionKind']
        used_basenames.append(basename)
        if used_basenames.count(basename) > 1:
            basename += '-%d' % used_basenames.count(basename)

        sec['filename'] = basename

    # Now the conversion of sec keys to their readable form is complete

    # Are the damn sections ordered the wrong way?
    sorted_section_list = sorted(section_list, key=lambda sec: sec['containerOffset'])
    if sorted_section_list != section_list:
        for i, sec in enumerate(sorted_section_list):
            sec['_hackPackOrder'] = i

    should_end = sorted_section_list[-1]['containerOffset'] + sorted_section_list[-1]['containerLength']
    if should_end < len(from_binary):
        sorted_section_list[-1]['_hackPostAlign'] = _possible_intended_alignments(len(from_binary))[-1]

    for i, sec in enumerate(section_list):
        raw = from_binary[sec['containerOffset']:sec['containerOffset']+sec['containerLength']]

        possible_aligns = _possible_intended_alignments(sec['containerOffset'])
        if possible_aligns[-1] > _sec_kind_min_align(sec['sectionKind']):
            sec['_hackUnexpectedAlign'] = possible_aligns[-1]

        # Do we need to keep the packed data around?    
        unpacked = packed = raw

        if sec['sectionKind'] == 'pidata':
            packed = raw
            unpacked = unpack_pidata(raw)
        else:
            packed = None
            unpacked = raw

            if unpacked.endswith(b'\0'):
                sec['_hackExplicitTrailingZeros'] = len(unpacked) - len(unpacked.rstrip(b'\0'))

        if sec['unpackedLength']:
            zeropad = sec['totalLength'] - len(unpacked); unpacked += bytes(zeropad)

        write_bin(unpacked, to_path, sec['filename'])

        if packed is not None:
            write_bin(packed, to_path, 'packed-' + sec['filename'])

        del sec['totalLength']
        del sec['unpackedLength']
        del sec['containerLength']
        del sec['containerOffset']

    write_python(section_list, to_path, 'sections.txt')
    dump_lowlevel(to_path)
    dump_highlevel(to_path)


def build(from_path, to_path=None):
    """Rebuild a directory into a CFM/PEF binary

    Command line usage: cfmtool.py DIRECTORY BINARY

    If a second argument is supplied, the result will be written to that path
    instead of being returned as a bytes object.
    """

    try:
        dateTimeStamp = parse_mac_date(read_txt(from_path, 'date.txt'))
    except:
        raise
        dateTimeStamp = 0

    try:
        versions = read_python(from_path, 'version.txt')
        versions = (versions['oldDefVersion'], versions['oldImpVersion'], versions['currentVersion'])
    except:
        raise
        versions = (0, 0, 0)

    section_list = read_python(from_path, 'sections.txt')

    # Hit the ground running
    pef = bytearray(b'J o y ! peffpwpc\x00\x00\x00\x01'.replace(b' ', b''))

    pef.extend(struct.pack('>4L', dateTimeStamp, *versions)) # leaves us at offset 0x20
    instSectionCount = len([sec for sec in section_list if _sec_kind_is_instantiated(sec['sectionKind'])])
    pef.extend(struct.pack('>HHL', len(section_list), instSectionCount, 0)) # leaves us at offset 0x28, ready for the sections

    # Pad the section headers out with zeroes, and fill in a bit later
    offset = 40
    for sec in section_list:
        sec['_hack_header_offset'] = offset
        offset += 28
    pef.extend(bytes(offset - len(pef)))

    # Now do the stupid section name table (yuck)
    namecnt = 0
    for sec in section_list:
        if sec['name']:
            pef.extend(sec['name'].encode('mac_roman') + b'\0')
            sec['name'] = namecnt
            namecnt += 1
        else:
            sec['name'] = -1

    # Stable sort, so won't do anything if unnecessary
    section_list.sort(key=lambda sec: sec.get('_hackPackOrder', 0))

    # Now put in the section data (easier said than done!)
    for sec in section_list:
        with open(path.join(from_path, sec['filename']), 'rb') as f:
            data_total = f.read()

        data_packed = data_inited = _strip_zeroes_leaving_some(data_total, sec.get('_hackExplicitTrailingZeros', 0))

        # Special case the damned pidata
        if sec['sectionKind'] == 'pidata':
            with open(path.join(from_path, 'packed-' + sec['filename']), 'rb') as f:
                data_packed = f.read()
                data_inited = unpack_pidata(data_packed)

            # Check that we got that right (we cannot pack the data ourselves)
            if not data_total.startswith(data_inited) or any(data_total[len(data_inited):]):
                data_packed = data_inited = _strip_zeroes_leaving_some(data_total, 0)
                sec['sectionKind'] = 'data'

        align_now = max(_sec_kind_min_align(sec['sectionKind']), sec.get('_hackUnexpectedAlign', 1))

        while len(pef) % align_now != 0: pef.append(0)

        struct.pack_into('>l5L3B', pef, sec['_hack_header_offset'],
            sec['name'],
            sec['defaultAddress'],
            len(data_total) if _sec_kind_is_instantiated(sec['sectionKind']) else 0,
            len(data_inited) if _sec_kind_is_instantiated(sec['sectionKind']) else 0,
            len(data_packed),
            len(pef),
            ('code', 'data', 'pidata', 'rodata', 'loader',
            'debug', 'codedata', 'exception', 'traceback').index(sec['sectionKind']),
            ('', 'process', '', '', 'global', 'protected').index(sec['shareKind']),
            sec['alignment'],
        )

        pef.extend(data_packed)

    post_align = max(sec.get('_hackPostAlign', 1) for sec in section_list)
    while len(pef) % post_align != 0: pef.append(0)

    if to_path is None:
        return bytes(pef)
    else:
        with open(to_path, 'wb') as f:
            f.write(pef)


def repr(obj):
    """Custom repr to prettyprint the dicts that we use

    Useful if you want to write out your own edited dumps (but not essential)
    """

    if isinstance(obj, list):
        accum = '[\n'
        for el in obj:
            accum += textwrap.indent(repr(el) + ',', '  ') + '\n'
        accum += ']'
        return accum

    elif isinstance(obj, dict):
        if set(obj) == set(('kind', 'weakFlag', 'name')) or 'offset' in obj:
            oneline = True
        else:
            oneline = False

        try:
            obj = obj.items()
        except AttributeError:
            pass

        accum = []
        for k, v in obj:
            if k == 'defaultAddress':
                v = hex(v, 8)
            elif k.lower().endswith('align'):
                v = hex(v)
            elif k.lower().endswith('offset'):
                v = hex(v, 5)
            elif k in ('usbVendorID', 'usbProductID', 'usbDeviceReleaseNumber', 'usbDeviceProtocol'):
                v = hex(v, 4)
            elif k in ('usbConfigValue', 'usbInterfaceNum', 'usbInterfaceClass', 'usbInterfaceSubClass', 'usbInterfaceProtocol', 'usbDriverClass', 'usbDriverSubClass'):
                v = hex(v, 2)
            else:
                v = repr(v)
            accum.append('%r: %s' % (k, v))

        if oneline:
            return '{' + ', '.join(accum) + '}'
        else:
            return '{\n' + textwrap.indent(''.join(x + ',\n' for x in accum), '  ') + '}'

    elif isinstance(obj, tuple):
        obj = [hex(el) if (i == 0 and isinstance(el, int)) else repr(el) for (i, el) in enumerate(obj)]
        return '(' + ', '.join(obj) + ')'

    else:
        return builtins.repr(obj)


def hex(obj, num_digits=5):
    """Pad to 5 significant digits (up to a megabyte, plenty)
    """

    x = builtins.hex(obj)
    while len(x.partition('x')[2]) < num_digits:
        x = x.replace('x', 'x0')
    return x


def unpack_pidata(packed):
    """Unpack pattern-initialized (compressed) data
    """

    def pullarg(from_iter):
        arg = 0
        for i in range(4):
            cont = next(from_iter)
            arg <<= 7
            arg |= cont & 0x7f
            if not (cont & 0x80): break
        else:
            raise ValueError('arg spread over too many bytes')
        return arg

    packed = iter(packed)
    unpacked = bytearray()

    for b in packed:
        opcode = b >> 5
        arg = b & 0b11111 or pullarg(packed)

        if opcode == 0b000: # zero
            count = arg
            unpacked.extend(b'\0' * count)

        elif opcode == 0b001: # blockCopy
            blockSize = arg
            for i in range(blockSize):
                unpacked.append(next(packed))

        elif opcode == 0b010: # repeatedBlock
            blockSize = arg
            repeatCount = pullarg(packed) + 1
            rawData = bytes(next(packed) for n in range(blockSize))
            for n in range(repeatCount):
                unpacked.extend(rawData)

        elif opcode == 0b011 or opcode == 0b100: # interleaveRepeatBlockWithBlockCopy
            commonSize = arg                     # or interleaveRepeatBlockWithZero
            customSize = pullarg(packed)
            repeatCount = pullarg(packed)

            if opcode == 0b011:
                commonData = bytes(next(packed) for n in range(commonSize))
            else:
                commonData = b'\0' * commonSize

            for i in range(repeatCount):
                unpacked.extend(commonData)
                for j in range(customSize):
                    unpacked.append(next(packed))
            unpacked.extend(commonData)

        else:
            raise ValueError('unknown pidata opcode/arg %s/%d' % (bin(opcode), arg))
            return

    return bytes(unpacked)


def dump_lowlevel(basepath):
    """Dump from the loader section: exports.txt, imports.txt, mainvectors.txt, relocations.txt
    """

    section_list = read_python(basepath, 'sections.txt')

    for sec in section_list:
        if sec['sectionKind'] == 'loader':
            loader = read_bin(basepath, sec['filename'])
            break
    else:
        return # no loader section

    importedLibraryCount, totalImportedSymbolCount, relocSectionCount, relocInstrOffset, loaderStringsOffset, \
        exportHashOffset, exportHashTablePower, exportedSymbolCount = struct.unpack_from('>8L', loader, 24)

    def get_mainvectors():
        cardinals = {}
        for ofs, knd in [(0, 'main'), (8, 'init'), (16, 'term')]:
            vec_sec_idx, vec_offset = struct.unpack_from('>lL', loader, ofs)
            if vec_sec_idx != -1:
                cardinals[knd] = dict(section=section_list[vec_sec_idx]['filename'], offset=vec_offset)
        return cardinals

    def get_name(offset):
        return loader[loaderStringsOffset+offset:].partition(b'\0')[0].decode('mac_roman')

    def get_imported_symbol(idx):
        ofs = 56 + 24 * importedLibraryCount + 4 * idx
        wideval, = struct.unpack_from('>L', loader, ofs)
        return dict(
            kind = ('code', 'data', 'tvector', 'toc', 'glue')[(wideval >> 24) & 0xF],
            weakFlag = int(bool(wideval & 0x80000000)),
            name = get_name(wideval & 0xFFFFFF),
        )

    def get_imported_library(idx):
        ofs = 56 + 24 * idx
        nameOffset, oldImpVersion, currentVersion, importedSymbolCount, \
            firstImportedSymbol, options = struct.unpack_from('>5LB', loader, ofs)

        return dict(
            name = get_name(nameOffset),
            oldImpVersion = oldImpVersion,
            currentVersion = currentVersion,
            specialOrderFlag = int(bool(options & 0x80)),
            weakFlag = int(bool(options & 0x40)),
            symbols = [get_imported_symbol(n) for n in
                range(firstImportedSymbol, firstImportedSymbol + importedSymbolCount)],
        )

    def get_relocations():
        relocations = []

        for idx in range(relocSectionCount):
            ofs = 56 + 24 * importedLibraryCount + 4 * totalImportedSymbolCount + 12 * idx
            sectionIndex, _, relocCount, firstRelocOffset, = struct.unpack_from('>HHLL', loader, ofs)

            sectionIndex = section_list[sectionIndex]['filename']

            data = loader[relocInstrOffset+firstRelocOffset:][:2*relocCount]
            data = [struct.unpack_from('>H', data, i)[0] for i in range(0, len(data), 2)]

            done = []

            relocAddress = 0
            importIndex = 0

            if len(section_list) >= 1 and _sec_kind_is_instantiated(section_list[0]['sectionKind']):
                sectionC = section_list[0]['filename']

            if len(section_list) >= 2 and _sec_kind_is_instantiated(section_list[1]['sectionKind']):
                sectionD = section_list[1]['filename']

            def nextblock():
                if not data: return None
                x = data.pop(0)
                done.append(x)
                return x

            for short in iter(nextblock, None):
                #print('%04X  codeA=%r dataA=%r rSymI=%d rAddr=%08X' % (short, sectionC, sectionD, importIndex, relocAddress), end='  ')

                if short >> 14 == 0b00: # RelocBySectDWithSkip
                    skipCount = (short >> 6) & 0xFF
                    relocCount = short & 0x3F
                    #print('RelocBySectDWithSkip skipCount=%d relocCount=%d' % (skipCount, relocCount))

                    relocAddress += skipCount * 4
                    for i in range(relocCount):
                        relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4

                elif short >> 13 == 0b010: # The Relocate Value Group
                    subopcode = (short >> 9) & 0xF
                    runLength = (short & 0x1FF) + 1

                    if subopcode == 0b0000: # RelocBySectC
                        #print('RelocBySectC runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionC))); relocAddress += 4

                    elif subopcode == 0b0001: # RelocBySectD
                        #print('RelocBySectD runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4

                    elif subopcode == 0b0010: # RelocTVector12
                        #print('RelocTVector12 runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionC))); relocAddress += 4
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4
                            if 'code' in sectionC and 'data' in sectionD: relocations[-2]['likelytv'] = 1
                            relocAddress += 4

                    elif subopcode == 0b0011: # RelocTVector8
                        #print('RelocTVector8 runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionC))); relocAddress += 4
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4
                            if 'code' in sectionC and 'data' in sectionD: relocations[-2]['likelytv'] = 1

                    elif subopcode == 0b0100: # RelocVTable8
                        #print('RelocVTable8 runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4
                            relocAddress += 4

                    elif subopcode == 0b0101: # RelocImportRun
                        #print('RelocImportRun runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('import', importIndex))); relocAddress += 4; importIndex += 1

                    else:
                        raise ValueError('bad Relocate Value Group subopcode: %s' % bin(subopcode))

                elif short >> 13 == 0b011: # The Relocate By Index Group
                    subopcode = (short >> 9) & 0xF
                    index = short & 0x1FF

                    if subopcode == 0b0000: # RelocSmByImport
                        #print('RelocSmByImport index=%d' % (index))
                        relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('import', index))); relocAddress += 4; importIndex = index + 1

                    elif subopcode == 0b0001: # RelocSmSetSectC
                        #print('RelocSmSetSectC index=%d' % (index))
                        sectionC = section_list[index]['filename']

                    elif subopcode == 0b0010: # RelocSmSetSectD
                        #print('RelocSmSetSectD index=%d' % (index))
                        sectionD = section_list[index]['filename']

                    elif subopcode == 0b0011: # RelocSmBySection
                        #print('RelocSmBySection index=%d' % (index))
                        relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', index))); relocAddress += 4

                    else:
                        raise ValueError('bad Relocate By Index Group subopcode: %s' % bin(subopcode))

                elif short >> 12 == 0b1000: # RelocIncrPosition
                    offset = (short & 0x0FFF) + 1
                    #print('RelocIncrPosition offset=%d' % (offset))

                    relocAddress += offset

                elif short >> 12 == 0b1001: # RelocSmRepeat
                    blockCount = ((short >> 8) & 0xF) + 1
                    repeatCount = (short & 0xFF) + 1
                    #print('RelocSmRepeat blockCount=%d repeatCount=%d' % (blockCount, repeatCount))

                    data[0:0] = done[-blockCount-1:-1] * repeatCount

                elif short >> 10 == 0b101000: # RelocSetPosition
                    offset = ((short & 0x3FF) << 16) + nextblock()
                    #print('RelocSetPosition offset=%d' % (offset))

                    relocAddress = offset

                elif short >> 10 == 0b101001: # RelocLgByImport
                    index = ((short & 0x3FF) << 16) + nextblock()
                    #print('RelocLgByImport index=%d' % (index))

                    relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('import', index))); relocAddress += 4; importIndex = index + 1

                elif short >> 10 == 0b101100: # RelocLgRepeat
                    blockCount = ((short >> 6) & 0xF) + 1
                    repeatCount = ((short & 0x3F) << 16) + nextblock()
                    #print('RelocLgRepeat blockCount=%d repeatCount=%d' % (blockCount, repeatCount))

                    data[0:0] = done[-blockCount-1:-1] * repeatCount

                elif short >> 10 == 0b101101: # RelocLgSetOrBySection
                    subopcode = (short >> 6) & 0xF
                    index = ((short & 0x3F) << 16) + nextblock()

                    if subopcode == 0b0000: # Same as RelocSmBySection
                        #print('~RelocSmBySection index=%d' % (index))
                        relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', index))); relocAddress += 4

                    elif subopcode == 0b0001: # Same as RelocSmSetSectC
                        #print('~RelocSmSetSectC index=%d' % (index))
                        sectionC = section_list[index]['filename']

                    elif subopcode == 0b0010: # Same as RelocSmSetSectD
                        #print('~RelocSmSetSectD index=%d' % (index))
                        sectionD = section_list[index]['filename']

                    else:
                        raise ValueError('bad RelocLgSetOrBySection subopcode: %s' % bin(subopcode))

                else:
                    raise ValueError('bad relocation opcode: 0x%04x' % short)

        return relocations

    def get_exports():
        ofs = exportHashOffset

        num_keys = 0
        for i in range(2 ** exportHashTablePower):
            htab_entry, = struct.unpack_from('>L', loader, ofs)
            num_keys += htab_entry >> 18
            ofs += 4

        lengths = []
        for i in range(num_keys):
            sym_len, sym_hash = struct.unpack_from('>HH', loader, ofs)
            lengths.append(sym_len)
            ofs += 4

        exports = []
        for sym_len in lengths:
            kind_and_name, sym_offset, sec_idx = struct.unpack_from('>LLh', loader, ofs)
            kind = ('code', 'data', 'tvector', 'toc', 'glue')[kind_and_name >> 24]
            name = loader[loaderStringsOffset+(kind_and_name&0xFFFFFF):][:sym_len].decode('mac_roman')
            sec_name = section_list[sec_idx]['filename']
            if sec_idx == -2:
                # absolute address
                pass
            elif sec_idx == -3:
                # re-export
                pass
            else:
                exports.append(dict(section=sec_name, offset=sym_offset, kind=kind, name=name))
            ofs += 10

        exports.sort(key=lambda dct: tuple(dct.values()))
        return exports

    write_python(get_mainvectors(), basepath, 'ldump', 'mainvectors.txt')
    write_python(get_exports(), basepath, 'ldump', 'exports.txt')
    write_python(get_relocations(), basepath, 'ldump', 'relocations.txt')
    write_python([get_imported_library(n) for n in range(importedLibraryCount)],
        basepath, 'ldump', 'imports.txt')


def dump_highlevel(basepath):
    """Create some useful files: glue.txt
    """

    section_list = read_python(basepath, 'sections.txt')

    # Relocations in lookup-able form
    relocs = read_python(basepath, 'ldump', 'relocations.txt')
    likelytv = set((rl['section'], rl['offset']) for rl in relocs if rl.get('likelytv', False))
    relocs = {(rl['section'], rl['offset']): rl['to'] for rl in relocs}


    # Some helper functions so we can follow these relocations
    def is_null(tpl): # takes (section_name, offset) tuple
        section, ofs = tpl
        if 'data' not in section: return False
        for i in (-2, 0, 2):
            if (section, ofs+i) in relocs: return False
        secdata = read_bin(basepath, section)
        if secdata[ofs:ofs+4] != b'\0\0\0\0': return False

        return True

    def follow_pointer_to_section(tpl): # takes (section_name, offset) tuple
        src_section, src_ofs = tpl

        # Offset is read directly from the packed section
        secdata = read_bin(basepath, src_section)
        targ_ofs, = struct.unpack_from('>L', secdata, src_ofs)

        # Base is fetched from the relocation table
        targ_kind, targ_section = relocs[(src_section, src_ofs)]
        if targ_kind != 'section': raise ValueError('not to a section')

        return (targ_section, targ_ofs)

    def follow_tvector(tpl): # takes (section_name, offset) tuple
        src_section, src_ofs = tpl

        if 'data' not in src_section: raise ValueError('not a tvector pointer')

        # Offset is read directly from the packed section
        secdata = read_bin(basepath, src_section)
        targ_ofs, = struct.unpack_from('>L', secdata, src_ofs)

        # Base is fetched from the relocation table
        targ_kind, targ_section = relocs[(src_section, src_ofs)]
        if targ_kind != 'section' or 'code' not in targ_section: raise ValueError('not a real tvector')

        toc_kind, toc_section = relocs[(src_section, src_ofs + 4)]
        if toc_kind != 'section' or 'data' not in toc_section: raise ValueError('not a real tvector')

        return (targ_section, targ_ofs)


    # The base of the TOC is not guaranteed to be the base of the data section... what is the TOC of our exported funcs?
    tvectors = [dct for dct in read_python(basepath, 'ldump', 'exports.txt') if dct['kind'] == 'tvector']

    # Failing that, the TOC of our init/main/term funcs
    tvectors.extend(read_python(basepath, 'ldump', 'mainvectors.txt').values())

    tvectors = [(tv['section'], tv['offset']) for tv in tvectors]
    table_of_contents = {}
    for section, offset in tvectors: # (section, offset) tuple
        reloc_kind, toc_section = relocs.get((section, offset + 4), (None, None))
        if reloc_kind == 'section':
            secdata = read_bin(basepath, section)
            toc_offset, = struct.unpack_from('>L', secdata, offset + 4)

            table_of_contents = dict(section=toc_section, offset=toc_offset)
            break


    # When we export even a single TVector, the TOC can be easily found as
    # above. But some fragments, e.g. native sifters (nifts) and some USB
    # code, only export some sort of dispatch table in which TVector pointers
    # are difficult to identify. So we scan the entire relocation table to
    # find things that  look like TVectors, then try to identify a consensus
    # among the real-looking TVectors.
    if not table_of_contents:
        guesses = []
        for (reloc_sec, reloc_offset), (reloc_kind, reloc_targ_section) in relocs.items():
            if 'data' in reloc_sec and reloc_kind == 'section' and 'code' in reloc_targ_section and (reloc_sec, reloc_offset) in likelytv:
                toc_reloc_kind, toc_reloc_targ_section = relocs.get((reloc_sec, reloc_offset+4), (None, None))
                if toc_reloc_kind == 'section' and 'data' in toc_reloc_targ_section:
                    secdata = read_bin(basepath, reloc_sec)
                    toc_offset, = struct.unpack_from('>L', secdata, reloc_offset + 4)
                    guesses.append(dict(section=toc_reloc_targ_section, offset=toc_offset))

        for x in guesses:
            if guesses.count(x) >= len(guesses)//2:
                table_of_contents = dict(x)
                break

    # Somehow we got the table of contents
    if table_of_contents:
        write_python(table_of_contents, basepath, 'hdump', 'table-of-contents.txt')


    # Exports!
    exports = read_python(basepath, 'ldump', 'exports.txt')
    codelocs_exported = []
    # read_bin = functools.lru_cache(read_bin)

    for exp in exports:
        if exp['kind'] == 'tvector':
            reloc_kind, reloc_targ_section = relocs.get((exp['section'], exp['offset']), (None, None))
            if reloc_kind == 'section' and 'code' in reloc_targ_section:
                secdata = read_bin(basepath, exp['section'])
                code_offset, = struct.unpack_from('>L', secdata, exp['offset'])
                codelocs_exported.append(dict(section=reloc_targ_section, offset=code_offset, function=exp['name']))

    codelocs_exported.sort(key=lambda dct: tuple(dct.values()))
    write_python(codelocs_exported, basepath, 'hdump', 'codelocs-exported.txt')


    # Init, term and main functions
    codelocs_main = []
    for kind, dct in read_python(basepath, 'ldump', 'mainvectors.txt').items():
        reloc_kind, reloc_targ_section = relocs.get((dct['section'], dct['offset']), (None, None))
        if reloc_kind == 'section' and 'code' in reloc_targ_section:
            secdata = read_bin(basepath, dct['section'])
            code_offset, = struct.unpack_from('>L', secdata, dct['offset'])
            codelocs_main.append(dict(section=reloc_targ_section, offset=code_offset, function=kind))
    codelocs_main.sort(key=lambda dct: tuple(dct.values()))
    write_python(codelocs_main, basepath, 'hdump', 'codelocs-main.txt')


    # Cross-toc glue
    codelocs_xtocglue = []

    if table_of_contents: # we might not have one if we export no functions!
        imports = read_python(basepath, 'ldump', 'imports.txt')
        imports = [sym['name'] for lib in imports for sym in lib['symbols']]

        toc_imports = {}
        for (reloc_sec, reloc_offset), (reloc_kind, reloc_import_num) in relocs.items():
            if reloc_sec == table_of_contents['section'] and reloc_kind == 'import':
                toc_imports[reloc_offset - table_of_contents['offset']] = imports[reloc_import_num]

        for sec in section_list:
            if 'code' not in sec['filename']: continue
            code = read_bin(basepath, sec['filename'])

            gluescan = []
            for ofs in range(0, len(code) - 23, 4):
                for a, b in zip(code[ofs:ofs+24], b'\x81\x82\xff\xff\x90\x41\x00\x14\x80\x0c\x00\x00\x80\x4c\x00\x04\x7c\x09\x03\xa6\x4e\x80\x04\x20'):
                    if a != b and b != 0xFF: break
                else:
                    toc_ofs, = struct.unpack_from('>h', code, ofs+2)
                    try:
                        codelocs_xtocglue.append(dict(section=sec['filename'], offset=ofs, function=toc_imports[toc_ofs]))
                    except KeyError:
                        # The glue points inwards. This is quite rare, so just ignore it
                        pass


    codelocs_xtocglue.sort(key=lambda dct: tuple(dct.values()))
    write_python(codelocs_xtocglue, basepath, 'hdump', 'codelocs-xtocglue.txt')


    # MacsBug symbol locations
    codelocs_macsbug = []

    for idx, sec in enumerate(section_list):
        if sec['sectionKind'] != 'code': continue

        code = read_bin(basepath, sec['filename'])

        end_offset = 0
        for i in range(0, len(code) - 17, 4):
            guts = struct.unpack_from('>IIIIxB', code, i)

            if guts[0] != 0: continue

            if len(code) < i + 18 + guts[-1]: continue
            name = code[i + 18:][:guts[-1]]

            if i - guts[3] < end_offset: continue
            if guts[3] % 4 != 0: continue

            if not re.match(rb'^\w+$', name): continue

            end_offset = i + 18 # whatever

            # now interpret properly
            code_ofs = i - guts[3]
            code_len = guts[3]

            codelocs_macsbug.append(dict(section=sec['filename'], offset=code_ofs, function=name.decode('ascii')))

    codelocs_macsbug.sort(key=lambda dct: tuple(dct.values()))
    write_python(codelocs_macsbug, basepath, 'hdump', 'codelocs-macsbug.txt')


    # Driver description
    desc = None
    for exp in exports:
        if exp['kind'] == 'data' and exp['name'] == 'TheDriverDescription':
            secdata = read_bin(basepath, exp['section'])
            ofs = exp['offset']

            desc = list(struct.unpack_from('>4s L 32s L L 32s 32x L', secdata, ofs))

            known_bits = {
                0x1: 'kDriverIsLoadedUponDiscovery',
                0x2: 'kDriverIsOpenedUponLoad',
                0x4: 'kDriverIsUnderExpertControl',
                0x8: 'kDriverIsConcurrent',
                0x10: 'kDriverQueuesIOPB',
                0x20: 'kDriverIsLoadedAtBoot',
                0x40: 'kDriverIsForVirtualDevice',
            }

            bits = []
            for i in range(32):
                if desc[4] & (1 << i):
                    bits.append(known_bits.get(1 << i, hex(1 << i)))
            bits = '|'.join(bits) or '0'

            ofs += 0x74
            services = []
            for i in range(desc[6]): # nServices
                svc = struct.unpack_from('>4s 4s L', secdata, ofs)
                services.append({
                    'serviceCategory': svc[0].decode('mac_roman'),
                    'serviceType': svc[1].decode('mac_roman'),
                    'serviceVersion': parse_mac_version(svc[2]),
                })
                ofs += 12

            desc = {
                'driverDescSignature': desc[0].decode('mac_roman'),
                'driverDescVersion': desc[1],
                'driverType': {
                    'nameInfoStr': pstring_or_cstring(desc[2]).decode('mac_roman'),
                    'version': parse_mac_version(desc[3]),
                },
                'driverOSRuntimeInfo': {
                    'driverRuntime': bits,
                    'driverName': pstring_or_cstring(desc[5]).decode('mac_roman'),
                },
                'driverServices': services,
            }

            write_python(desc, basepath, 'hdump', 'driver-description.txt')
            break


    # Specialised dispatch tables
    codelocs_disptable = []


    # ATA Interface Manager dispatch table
    if desc and 'ata-' in [serv['serviceCategory'] for serv in desc['driverServices']]:
        for exp in exports:
            if exp['kind'] == 'data' and exp['name'] == 'ThePluginDispatchTable':
                dispnames = ['Init', 'Close', 'Action', 'HandleBusEvent', 'Poll',
                    'EjectDevice', 'DeviceLight', 'DeviceLock', 'Suspend', 'Resume']

                for i, name in enumerate(dispnames):
                    try:
                        targ_sec, targ_ofs = follow_tvector(follow_pointer_to_section((exp['section'], exp['offset'] + 16 + 4*i)))
                    except:
                        continue

                    codelocs_disptable.append(dict(section=targ_sec, offset=targ_ofs, function='ATAPlugin' + name))

                break


    # Power Management dispatch table
    # The structure is variable-length and not versioned (ouch), so we do sanity checks
    if desc and 'powr' in [serv['serviceCategory'] for serv in desc['driverServices']]:
        for exp in exports:
            if exp['kind'] == 'data' and exp['name'] == 'ThePluginDispatchTable':
                dispnames = {
                    0x00: 'PrimaryInit', 0x01: 'SecondaryInit', 0x02: 'Finalize', 0x03: 'CallPMU',
                    0x04: 'PowerOff', 0x05: 'Restart', 0x06: 'EnterIdle2', 0x07: 'HandleIdle2',
                    0x08: 'ExitIdle2',
                    0x09: '__Selector09', 0x0a: '__Selector0A', 0x0b: '__Selector0B', # probably getting processor temp, not sure
                    0x0c: 'Doze', 0x0d: 'WakeFromDoze', 0x0e: 'Sleep',
                    0x0f: 'Wake', 0x10: 'SuspendResumeHW', 0x11: 'GetStartupTimer',
                    0x12: 'SetStartupTimer', 0x13: 'GetWakeTimer', 0x14: 'SetWakeTimer',
                    0x15: 'GetFirstPowerSource', 0x16: 'GetNextPowerSource',
                    0x17: 'GetProcessorSpeed', 0x18: 'SetProcessorSpeed',
                    0x19: 'GetMaxProcessorSpeed', 0x1a: 'SetMaxProcessorSpeed',
                    0x1b: 'GetPrimInfoEntry', 0x1c: 'RegisterInterruptCallback',
                    0x1d: 'IsClamshellClosed', 0x1e: 'GetSleepActionBits', 0x1f: 'GetWakeInfo',
                    0x20: 'ConfigForHardware', 0x21: 'DriverReplacement', 0x22: 'ActivateClock',
                    0x23: 'DeactivateClock', 0x24: 'DeactivateCurrentClock',
                    0x25: 'GetCurrentClockID', 0x26: 'EnteredADBHandler',
                    0x27: 'EnablePowerUpEvents', 0x28: 'ArePowerUpEventsEnabled',
                    0x29: 'EnableWakeUpEvents', 0x2a: 'AreWakeUpEventsEnabled',
                    0x2b: 'SetWakeOnNetActOptions', 0x2c: 'GetWakeOnNetActOptions',
                    0x2d: 'GetIntModemInfo', 0x2e: 'SetIntModemState', 0x2f: 'PowerOnModem',
                    0x30: 'PowerOffModem', 0x31: 'SystemReady', 0x32: 'UpdatePowerSources',
                    0x33: 'EnableThermalMgt', 0x34: 'ThermalEvent', 0x35: 'GetThermalLevel',
                    0x36: 'NumFans', 0x37: 'FanControl', 0x38: 'NumThermostats',
                    0x39: 'ThermostatControl', 0x3a: 'ReadThermostat', 0x3b: 'GetRangeForLevel',
                    0x3c: 'GetMinProcessorSpeed', 0x3d: 'EnqueueWakeHandler',
                    0x3e: 'DequeueWakeHandler', 0x3f: 'OverrideClamshellClosedBehavior',
                    0x40: 'DoClamshellClosedChores', 0x41: 'ResetModemLow', 0x42: 'ResetModemHigh',
                    0x43: 'CheckForForcedReducedSpeed',
                }

                for i, name in dispnames.items():
                    ofs = exp['offset'] + 16 + 4*i

                    if is_null((exp['section'], ofs)): continue # missing entry in the table

                    try:
                        targ_sec, targ_ofs = follow_tvector(follow_pointer_to_section((exp['section'], ofs)))
                    except:
                        break # the table probably stops here

                    codelocs_disptable.append(dict(section=targ_sec, offset=targ_ofs, function='PMPlugin' + name))

                break


    # Uncomment to find plugin dispatch tables that still need reversing
    # for exp in exports:
    #     if exp['name'] == 'ThePluginDispatchTable' and not codelocs_disptable:
    #         print('Note: ThePluginDispatchTable not parsed')
    #         break


    codelocs_disptable.sort(key=lambda dct: tuple(dct.values()))
    write_python(codelocs_disptable, basepath, 'hdump', 'codelocs-disptable.txt')


    # USB driver description
    for exp in exports:
        if exp['kind'] == 'data' and exp['name'] == 'TheUSBDriverDescription':

            usbd_count = 1 # This is not documented anywhere, pity.
            for cnt_exp in exports:
                if cnt_exp['kind'] == 'data' and cnt_exp['name'] == 'TheUSBDriverDescriptionCount':
                    cnt_secdata = read_bin(basepath, cnt_exp['section'])
                    usbd_count, = struct.unpack_from('>L', cnt_secdata, cnt_exp['offset'])

            secdata = read_bin(basepath, exp['section'])
            ofs = exp['offset']

            descriptors = []
            for i in range(usbd_count):
                desc = list(struct.unpack_from('>4sL HHHH BBBBBx 32sBBL L', secdata, ofs))

                known_bits = {
                    0x1: 'kUSBDoNotMatchGenericDevice',
                    0x2: 'kUSBDoNotMatchInterface',
                    0x4: 'kUSBProtocolMustMatch',
                    0x8: 'kUSBInterfaceMatchOnly',
                }

                bits = []
                for i in range(32):
                    if desc[15] & (1 << i):
                        bits.append(known_bits.get(1 << i, hex(1 << i)))
                bits = '|'.join(bits) or '0'

                desc = {
                    'usbDriverDescSignature': desc[0].decode('mac_roman'),
                    'usbDriverDescVersion': desc[1],
                    'usbDeviceInfo': {
                        'usbVendorID': desc[2],
                        'usbProductID': desc[3],
                        'usbDeviceReleaseNumber': desc[4],
                        'usbDeviceProtocol': desc[5],
                    },
                    'usbInterfaceInfo': {
                        'usbConfigValue': desc[6],
                        'usbInterfaceNum': desc[7],
                        'usbInterfaceClass': desc[8],
                        'usbInterfaceSubClass': desc[9],
                        'usbInterfaceProtocol': desc[10],
                    },
                    'usbDriverType': {
                        'nameInfoStr': pstring_or_cstring(desc[11]).decode('mac_roman'),
                        'usbDriverClass': desc[12],
                        'usbDriverSubClass': desc[13],
                        'usbDriverVersion': parse_mac_version(desc[14]),
                    },
                    'usbDriverLoadingOptions': bits,
                }

                descriptors.append(desc)

                ofs += 0x40

            write_python(descriptors, basepath, 'hdump', 'usb-driver-description.txt')
            break


def format_mac_date(srcint):
    """Render a 32-bit MacOS date to ISO 8601 format
    """

    dt = datetime.datetime(1904, 1, 1) + datetime.timedelta(seconds=srcint)
    return dt.isoformat().replace('T', ' ')


def parse_mac_date(x):
    """Pack an ISO 8601 date into a 32-bit MacOS date
    """

    epoch = '19040101000000' # ISO8601 with the non-numerics stripped

    # strip non-numerics and pad out using the epoch (cheeky)
    stripped = ''.join(c for c in x if c in '0123456789')
    stripped = stripped[:len(epoch)] + epoch[len(stripped):]

    tformat = '%Y%m%d%H%M%S'

    delta = datetime.datetime.strptime(stripped, tformat) - datetime.datetime.strptime(epoch, tformat)
    delta = int(delta.total_seconds())

    delta = min(delta, 0xFFFFFFFF)
    delta = max(delta, 0)

    return delta


def parse_mac_version(num):
    maj, minbug, stage, unreleased = num.to_bytes(4, byteorder='big')

    maj = '%x' % maj
    minor, bugfix = '%02x' % minbug

    if stage == 0x80:
        stage = 'f'
    elif stage == 0x60:
        stage = 'b'
    elif stage == 0x40:
        stage = 'a'
    elif stage == 0x20:
        stage = 'd'
    else:
        return '%08x' % num

    unreleased = '%d' % unreleased

    vers = maj + '.' + minor

    if bugfix != '0':
        vers += '.' + bugfix

    if (stage, unreleased) != ('f', '0'):
        vers += stage + unreleased

    return vers


def pstring_or_cstring(s):
    plen = s[0]
    pstr = s[1:][:plen]
    cstr = s.rstrip(b'\0')
    if b'\0' in pstr or plen + 1 > len(s):
        return cstr
    else:
        return pstr


def _sec_kind_is_instantiated(sec_kind):
    return sec_kind not in ('loader', 'debug', 'exception', 'traceback')


def _strip_zeroes_leaving_some(data, leaving):
    stripped = data.rstrip(b'\0')

    while len(stripped) < len(data) and data[len(stripped)] == 0:
        stripped += b'\0'

    return stripped


def _possible_intended_alignments(offset):
    possible = list(1 << n for n in range(32))

    possible = [p for p in possible if offset % p == 0]

    return possible


def _sec_kind_min_align(sec_kind):
    if sec_kind in ('code', 'data', 'rodata', 'codedata'):
        return 16
    else:
        return 4


def read_python(*path_parts):
    return eval(read_txt(*path_parts))

def read_txt(*path_parts):
    with open(path.join(*path_parts), 'r') as f:
        return f.read().rstrip('\n')

def read_bin(*path_parts):
    with open(path.join(*path_parts), 'rb') as f:
        return f.read()


def write_python(python, *path_parts):
    write_txt(repr(python), *path_parts)

def write_txt(txt, *path_parts):
    write_bin((txt + '\n').encode('utf-8'), *path_parts)

def write_bin(bin, *path_parts):
    path_parts = path.join(*path_parts)
    os.makedirs(path.dirname(path_parts), exist_ok=True)

    # Write only if changed (slightly hacky)
    try:
        if path.getsize(path_parts) != len(bin): raise Exception
        with open(path_parts, 'rb') as f:
            if f.read() != bin: raise Exception
    except:
        with open(path_parts, 'wb') as f:
            f.write(bin)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''
        Convert between a Code Fragment Manager binary and an easily-edited dump directory.
        The extra info (low/high-level) in ldump/ and hdump/ is ignored when rebuilding.
    ''')

    # parser.add_argument('--gather', action='store_true', help='Binary or directory')
    parser.add_argument('src', metavar='SOURCE', action='store', help='Binary or directory')
    parser.add_argument('dest', metavar='DEST', action='store', help='Directory or binary')

    args = parser.parse_args()

    if path.isdir(args.src):
        build(args.src, args.dest)
    else:
        dump(args.src, args.dest)
