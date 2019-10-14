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
from os import path
from ast import literal_eval as eval


def dump(from_binary_or_path, to_path):
    """Dump a CFM/PEF binary to a directory

    Command line usage: cfmtool.py BINARY DIRECTORY

    The first argument can be a bytes-like object, or a path to read from.
    """

    def write_txt(name, text):
        with open(path.join(to_path, name + '.txt'), 'w') as f:
            f.write(text + '\n')

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

    write_txt('date', format_mac_date(dateTimeStamp))
    write_txt('version', repr(dict(zip(('oldDefVersion', 'oldImpVersion', 'currentVersion'), versions))))

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

        with open(path.join(to_path, sec['filename']), 'wb') as f: f.write(unpacked)

        if packed is not None:
            with open(path.join(to_path, 'packed-' + sec['filename']), 'wb') as f: f.write(packed)

        del sec['totalLength']
        del sec['unpackedLength']
        del sec['containerLength']
        del sec['containerOffset']

    for i, sec in enumerate(section_list):
        if sec['sectionKind'] == 'loader':
            dump_loader_section(section_list, path.join(to_path, sec['filename']), to_path)

    write_txt('sections', repr(section_list))

    dump_locations(to_path, to_path)


def build(from_path, to_path=None):
    """Rebuild a directory into a CFM/PEF binary

    Command line usage: cfmtool.py DIRECTORY BINARY

    If a second argument is supplied, the result will be written to that path
    instead of being returned as a bytes object.
    """

    def read_txt(name):
        with open(path.join(from_path, name + '.txt')) as f:
            return f.read()

    try:
        dateTimeStamp = parse_mac_date(read_txt('date'))
    except:
        raise
        dateTimeStamp = 0

    try:
        versions = eval(read_txt('version'))
        versions = (versions['oldDefVersion'], versions['oldImpVersion'], versions['currentVersion'])
    except:
        raise
        versions = (0, 0, 0)

    section_list = eval(read_txt('sections'))

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
        if set(obj) in (set(('kind', 'weakFlag', 'name')), set(('section', 'offset', 'to')), set(('file', 'offset', 'function'))):
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
                v = ('0x%08x' % v)
            elif k in '_hackUnexpectedAlign _hackPostAlign' or k.lower().endswith('offset'):
                v = hex(v)
            else:
                v = repr(v)
            accum.append('%r: %s' % (k, v))

        if oneline:
            return '{' + ', '.join(accum) + '}'
        else:
            return '{\n' + textwrap.indent('\n'.join(x + ',' for x in accum), '  ') + '\n}'

    elif isinstance(obj, tuple):
        obj = [hex(el) if (i == 0 and isinstance(el, int)) else repr(el) for (i, el) in enumerate(obj)]
        return '(' + ', '.join(obj) + ')'

    else:
        return builtins.repr(obj)


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


def dump_loader_section(section_list, from_binary_or_path, to_dir):
    """For a given loader section, dump: imports.txt, exports.txt (not yet), relocations.txt
    """

    try:
        bytes(from_binary_or_path)
        loader = from_binary_or_path
    except TypeError:
        with open(from_binary_or_path, 'rb') as f:
            loader = f.read()

    sec = dict(zip(('mainSection', 'mainOffset', 'initSection', 'initOffset', 'termSection', 'termOffset'),
        struct.unpack_from('>lLlLlL', loader)))

    importedLibraryCount, totalImportedSymbolCount, relocSectionCount, relocInstrOffset, loaderStringsOffset, \
        exportHashOffset, exportHashTablePower, exportedSymbolCount = struct.unpack_from('>8L', loader, 24)

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

            relocations = []

            def nextblock():
                if not data: return None
                x = data.pop(0)
                done.append(x)
                return x

            for short in iter(nextblock, None):
                #print('%04X  codeA=%d dataA=%d rSymI=%d rAddr=%08X' % (short, sectionC, sectionD, importIndex, relocAddress), end='  ')

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
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4

                    elif subopcode == 0b0001: # RelocBySectD
                        #print('RelocBySectD runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionC))); relocAddress += 4

                    elif subopcode == 0b0010: # RelocTVector12
                        #print('RelocTVector12 runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionC))); relocAddress += 4
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4
                            relocAddress += 4

                    elif subopcode == 0b0011: # RelocTVector8
                        #print('RelocTVector8 runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionC))); relocAddress += 4
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4

                    elif subopcode == 0b0100: # RelocVTable8
                        #print('RelocVTable8 runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('section', sectionD))); relocAddress += 4
                            relocAddress += 4

                    elif subopcode == 0b0101: # RelocImportRun
                        #print('RelocImportRun runLength=%d' % (runLength))
                        for i in range(runLength):
                            relocations.append(dict(section=sectionIndex, offset=relocAddress, to=('import', importIndex))); relocAddress += 4; importIndex += 1

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

                elif short >> 12 == 0b1000: # RelocIncrPosition
                    offset = (short & 0x0FFF) + 1
                    #print('RelocIncrPosition offset=%d' % (offset))

                    relocAddress += offset

                elif short >> 12 == 0b1001: # RelocSmRepeat
                    blockCount = ((short >> 8) & 0xF) + 1
                    repeatCount = (short & 0xFF) + 1
                    #print('RelocSmRepeat blockCount=%d repeatCount=%d' % (blockCount, repeatCount))

                    data[0:0] = done[:blockCount] * repeatCount

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

                    data[0:0] = done[:blockCount] * repeatCount

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
                    raise ValueError('bad relocation opcode: 0x%04x' % short)

        return relocations

    to_dir = path.join(to_dir, 'loaderinfo')
    os.makedirs(to_dir, exist_ok=True)

    with open(path.join(to_dir, 'imports.txt'), 'w') as f:
        f.write(repr([get_imported_library(n) for n in range(importedLibraryCount)]) + '\n')

    with open(path.join(to_dir, 'relocations.txt'), 'w') as f:
        f.write(repr(get_relocations()) + '\n')


def dump_locations(from_path, to_path):
    """Create some useful files: glue.txt
    """

    to_path = path.join(to_path, 'locations')
    os.makedirs(to_path, exist_ok=True)

    with open(path.join(from_path, 'sections.txt')) as f: section_list = eval(f.read())

    gluelocs = []

    for idx, sec in enumerate(section_list):
        if sec['sectionKind'] != 'code': continue

        with open(path.join(from_path, sec['filename']), 'rb') as f: code = f.read()

        gluescan = []
        for i in range(0, len(code) - 24, 4):
            for a, b in zip(code[i:], b'\x81\x82\xff\xff\x90\x41\x00\x14\x80\x0c\x00\x00\x80\x4c\x00\x04\x7c\x09\x03\xa6\x4e\x80\x04\x20'):
                if a != b and b != 0xFF: break
            else:
                toc_ofs, = struct.unpack_from('>h', code, i+2)
                gluescan.append((i, toc_ofs))

        with open(path.join(from_path, 'loaderinfo', 'relocations.txt')) as f: relocs = eval(f.read())
        with open(path.join(from_path, 'loaderinfo', 'imports.txt')) as f: imports = eval(f.read())

        imports = [sym['name'] for lib in imports for sym in lib['symbols']]

        toc_vectors = {}
        for rel in relocs:
            if 'data' in rel['section'] and rel['to'][0] == 'import':
                toc_vectors[rel['offset']] = imports[rel['to'][1]]

        gluelocs = []
        for code_ofs, toc_ofs in gluescan:
            try:
                gluelocs.append(dict(file=sec['filename'], offset=code_ofs, function=toc_vectors[toc_ofs]))
            except KeyError:
                pass

    gluelocs.sort(key=lambda dct: tuple(dct.values()))

    with open(path.join(to_path, 'glue.txt'), 'w') as f:
        f.write(repr(gluelocs) + '\n')

    # MacsBug symbol locations
    dbgsymlocs = []

    for idx, sec in enumerate(section_list):
        if sec['sectionKind'] != 'code': continue

        with open(path.join(from_path, sec['filename']), 'rb') as f: code = f.read()

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

            dbgsymlocs.append(dict(file=sec['filename'], offset=code_ofs, function=name.decode('ascii')))

    dbgsymlocs.sort(key=lambda dct: tuple(dct.values()))

    with open(path.join(to_path, 'debugsyms.txt'), 'w') as f:
        f.write(repr(dbgsymlocs) + '\n')


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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='''
        Convert between a Code Fragment Manager binary and an easily-edited dump directory.
    ''')

    parser.add_argument('src', metavar='SOURCE', action='store', help='Binary or directory')
    parser.add_argument('dest', metavar='DEST', action='store', help='Directory or binary')

    args = parser.parse_args()

    if path.isdir(args.src):
        build(args.src, args.dest)
    else:
        dump(args.src, args.dest)
