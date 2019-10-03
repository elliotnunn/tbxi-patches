#!/usr/bin/env python3

# This is a single-file library for manipulating Preferred Executable Format files
# A command line-interface is available (just call cfmtool.py --help)


import argparse
import datetime
import struct
import os
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
    write_txt('version', _fmt_dict(zip(('oldDefVersion', 'oldImpVersion', 'currentVersion'), versions)))

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

    write_txt('sections', _fmt_list(_fmt_dict(d) for d in section_list))


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


def _fmt_dict(tuple_iterator):
    try:
        tuple_iterator = tuple_iterator.items()
    except AttributeError:
        pass

    accum = '{\n'
    for k, v in tuple_iterator:
        if k == 'defaultAddress':
            v = ('0x%08x' % v)
        elif k in '_hackUnexpectedAlign _hackPostAlign':
            v = hex(v)
        else:
            v = repr(v)
        accum += textwrap.indent('%r: %s,' % (k, v), '  ') + '\n'
    accum += '}'
    return accum


def _fmt_list(iterator):
    accum = '[\n'
    for el in iterator:
        accum += textwrap.indent(el + ',', '  ') + '\n'
    accum += ']'
    return accum


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
