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


# Dead-simple PowerPC assembler
# Usable as a library or an executable


import argparse
import sys
import re
import struct
import inspect


class AsmError(Exception):
    def __init__(self, msg, lineno=None, line=None):
        self.msg = msg
        self.lineno = lineno
        self.line = line

    def __str__(self):
        if self.lineno is None:
            return self.msg
        else:
            return '%s\n %d: %s' % (self.msg, self.lineno, self.line.strip())


def assemble(asm, return_labels=False):
    """Assemble a string into a bytes object
    """

    asm = asm.rstrip('\n').split('\n')

    # First pass: discern labels from instructions
    line_list = []
    offset = 0
    for lineno, orig_line in enumerate(asm, 1):
        line = orig_line # mutate line a bit
        line = line.lower() # normalize case
        line = line.partition('#')[0] # strip comments

        for line in line.split(';'):
            line_labels, line = re.match(r'^((?:\s*\w+:)*)(.*)', line).groups()

            line_labels = re.findall(r'\w+', line_labels)
            line = line.strip()

            line_list.append((lineno, offset, orig_line, line_labels, line))

            if line: offset += 4

    # Second pass: resolve labels (each instruction is 4 bytes, easy)
    all_labels = {}
    for lineno, offset, orig_line, line_labels, line in line_list:
        for label in line_labels:
            if label in all_labels:
                raise AsmError('redefined label', lineno, orig_line)
            all_labels[label] = offset

    # Third pass: assemble
    binary = bytearray()
    offset = 0
    for lineno, offset, orig_line, line_labels, line in line_list:
        if line:
            cur_labels = {lab: lab_offset - offset for (lab, lab_offset) in all_labels.items()}

            try:
                binary.extend(struct.pack('>L', instruction(line, cur_labels)))
            except AsmError as e:
                e.lineno, e.line = lineno, orig_line
                raise

    binary = bytes(binary)

    if return_labels:
        return binary, all_labels
    else:
        return binary


def instruction(line, variables):
    # Enforce: inst[dot] args...
    # with no whitespace anywhere
    op = line.split()[0]
    args = line[len(op):].split(',')
    args = [a.strip() for a in args]
    if args == ['']: args = []
    dot = op.endswith('.')
    if dot:
        op = op[:-1]

    # Get the function that will handle this instruction (special case for branches)
    funcname = 'inst_' + (op.rstrip('l') if op.startswith('b') else op)
    func = globals().get(funcname, None)
    if not func: raise AsmError('unknown instruction')

    # Special case: branch & link instructions take extra l as the first argument
    if op.startswith('b'):
        args.insert(0, str(int(op.endswith('l'))))

    # Get the signature of the function, use that to parse the arguments
    func_pattern = list(inspect.signature(func).parameters)

    # Special case: instructions with extra '.'
    if func_pattern[:1] == ['dot']:
        args.insert(0, str(dot))
    elif dot:
        raise AsmError('dot not allowed')

    # Expand bracketed arguments (load/store instructions) to two args
    for i in range(len(func_pattern)):
        if func_pattern[i].endswith('_bracket'):
            func_pattern[i] = func_pattern[i][:-8]
            m = re.match(r'^(.+?)\s*\(\s*(\w+)\s*\)$', args[i])
            if m:
                args[i:i+1] = m.groups() # expand to two arguments
            else:
                args[i:i+1] = ['', ''] # this will eventually fail...

    # Insert optional arguments (as zeroes)
    for i in range(len(func_pattern)):
        if func_pattern[i].endswith('_optional'):
            func_pattern[i] = func_pattern[i][:-9]
            if len(args) < len(func_pattern):
                args.insert(i, '0')
                func_pattern[i] = 'anything' # do not attempt to validate

    # Did the user give us the right number of commas?
    if len(args) != len(func_pattern): raise AsmError('wrong number of args')

    def eval_register_arg(x):
        if x == 'sp': return 1
        if x == 'rtoc': return 2
        return int(x.lstrip('cr'))

    def eval_expression(x):
        def label_replacer(label):
            label = label.group(0)
            if label not in variables:
                raise AsmError('undefined label: %s' % label)
            return hex(variables[label])

        replaced = re.sub(r'\b[^\W\d]\w*', label_replacer, x)
        return eval(replaced, {"__builtins__": {}}, {})

    # Create a validation regex and an evaluation function for each arg
    validation_list = []
    for pat in func_pattern:
        if re.match(r'^r[A-Z]$', pat):
            regex = r'^(sp|rtoc|r([0-9]|[12][0-9]|3[01]))$'
            eval_func = eval_register_arg
        elif re.match(r'^r[A-Z]0$', pat):
            regex = r'^(0|sp|rtoc|r([1-9]|[12][0-9]|3[01]))$'
            eval_func = eval_register_arg
        elif re.match(r'^cr[A-Z]$', pat):
            regex = r'^cr([0-7])$'
            eval_func = eval_register_arg
        else:
            regex = r'^[\w' + re.escape('()+-*/%|&~^') + r']+$'
            eval_func = eval_expression

        validation_list.append((regex, eval_func))

    # Check the regex, apply the evaluation
    final_args = []
    for arg, (regex, eval_func) in zip(args, validation_list):
        m = re.match(regex, arg)
        if not m: raise AsmError('bad argument')

        try:
            final_args.append(eval_func(arg))
        except AsmError:
            raise
        except:
            raise AsmError('very bad argument')

    return func(*final_args)


def _b(value, startbit, endbit=None):
    if endbit is None: endbit = startbit
    numbits = endbit + 1 - startbit
    mask = (1 << numbits) - 1
    shift = 31 - endbit
    return (value & mask) << shift


def command_line():
    parser = argparse.ArgumentParser(description='''
        Assemble PowerPC assembly code into a raw binary. Supports instructions, labels: and #comments.
    ''')

    parser.add_argument('src', metavar='ASSEMBLY', nargs='?', action='store', help='PowerPC assembly code (stdin if omitted)')
    parser.add_argument('-o', dest='dest', metavar='BINARY', action='store', help='Raw PowerPC binary (stdout if omitted)')

    args = parser.parse_args()

    if args.src is None:
        asm = sys.stdin.read()
    else:
        with open(args.src) as f:
            asm = f.read()

    try:
        binary = assemble(asm)
    except AsmError as e:
        sys.exit(str(e))

    if args.dest is None:
        sys.stdout.buffer.write(binary)
    else:
        with open(args.dest, 'wb') as f:
            af.write(binary)

# All supported instructions, alphabetically

def inst_add(dot, rD, rA, rB):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(266,22,30)|_b(dot,31)

def inst_addis(rD, rA, simm):
    return _b(15,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(simm,16,31)

def inst_addi(rD, rA0, simm):
    return _b(14,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(simm,16,31)

def inst_and(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(28,21,30)|_b(dot,31)

def inst_andc(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(60,21,30)|_b(dot,31)

def inst_andi(dot, rA, rS, uimm):
    if not dot: raise AsmError('dot required')
    return _b(28,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(uimm,16,31)

def inst_andis(dot, rA, rS, uimm):
    if not dot: raise AsmError('dot required')
    return _b(29,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(uimm,16,31)

def inst_b(link, bd):
    if bd & 3: raise AsmError('branch target not 4-aligned')
    return _b(18,0,5)|_b(bd>>2,6,29)|_b(link,31)

def inst_bc(link, bo, bi, bd):
    if bd & 3: raise AsmError('branch target not 4-aligned')
    return _b(16,0,5)|_b(bo,6,10)|_b(bi,11,15)|_b(bd>>2,16,29)|_b(link,31)

def inst_bcctr(link, bo, bi):
    return _b(19,0,5)|_b(bo,6,10)|_b(bi,11,15)|_b(528,21,30)|_b(link,31)

def inst_bclr(link, bo, bi):
    return _b(19,0,5)|_b(bo,6,10)|_b(bi,11,15)|_b(16,21,30)|_b(link,31)

def inst_cmpw(crD_optional, rA, rB):
    return _b(31,0,5)|_b(crD_optional,6,8)|_b(rA,11,15)|_b(rB,16,20)

def inst_cmpwi(crD_optional, rA, simm):
    return _b(11,0,5)|_b(crD_optional,6,8)|_b(rA,11,15)|_b(simm,16,31)

def inst_cmplw(crD_optional, rA, rB):
    return _b(31,0,5)|_b(crD_optional,6,8)|_b(rA,11,15)|_b(rB,16,20)|b(32,21,30)

def inst_cmplwi(crD_optional, rA, simm):
    return _b(10,0,5)|_b(crD_optional,6,8)|_b(rA,11,15)|_b(simm,16,31)

def inst_crand(crbD, crbA, crbB):
    return _b(19,0,5)|_b(crbD,6,10)|_b(crbA,11,15)|_b(crbB,16,20)|_b(257,21,30)

def inst_crandc(crbD, crbA, crbB):
    return _b(19,0,5)|_b(crbD,6,10)|_b(crbA,11,15)|_b(crbB,16,20)|_b(129,21,30)

def inst_creqv(crbD, crbA, crbB):
    return _b(19,0,5)|_b(crbD,6,10)|_b(crbA,11,15)|_b(crbB,16,20)|_b(289,21,30)

def inst_crnand(crbD, crbA, crbB):
    return _b(19,0,5)|_b(crbD,6,10)|_b(crbA,11,15)|_b(crbB,16,20)|_b(225,21,30)

def inst_crnor(crbD, crbA, crbB):
    return _b(19,0,5)|_b(crbD,6,10)|_b(crbA,11,15)|_b(crbB,16,20)|_b(33,21,30)

def inst_cror(crbD, crbA, crbB):
    return _b(19,0,5)|_b(crbD,6,10)|_b(crbA,11,15)|_b(crbB,16,20)|_b(449,21,30)

def inst_crorc(crbD, crbA, crbB):
    return _b(19,0,5)|_b(crbD,6,10)|_b(crbA,11,15)|_b(crbB,16,20)|_b(417,21,30)

def inst_crxor(crbD, crbA, crbB):
    return _b(19,0,5)|_b(crbD,6,10)|_b(crbA,11,15)|_b(crbB,16,20)|_b(193,21,30)

def inst_eqv(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(284,21,30)|_b(dot,31)

def inst_extsb(dot, rA, rS):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(954,21,30)|_b(dot,31)

def inst_extsh(dot, rA, rS):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(922,21,30)|_b(dot,31)

def inst_lbz(rD, d_bracket, rA0):
    return _b(34,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_lbzu(rD, d_bracket, rA):
    if rA == 0: raise AsmError('rA = 0')
    if rA == rD: raise AsmError('rA = rD')
    return _b(35,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(d_bracket,16,31)

def inst_lbzux(rD, rA, rB):
    if rA == 0: raise AsmError('rA = 0')
    if rA == rD: raise AsmError('rA = rD')
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(119,21,30)

def inst_lbzx(rD, rA0, rB):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(rB,16,20)|_b(87,21,30)

def inst_lha(rD, d_bracket, rA0):
    return _b(42,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_lhau(rD, d_bracket, rA):
    if rA == 0: raise AsmError('rA = 0')
    if rA == rD: raise AsmError('rA = rD')
    return _b(43,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(d_bracket,16,31)

def inst_lhaux(rD, rA, rB):
    if rA == 0: raise AsmError('rA = 0')
    if rA == rD: raise AsmError('rA = rD')
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(375,21,30)

def inst_lhax(rD, rA0, rB):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(rB,16,20)|_b(343,21,30)

def inst_lha(rD, d_bracket, rA0):
    return _b(40,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_lhzu(rD, d_bracket, rA):
    if rA == 0: raise AsmError('rA = 0')
    if rA == rD: raise AsmError('rA = rD')
    return _b(41,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(d_bracket,16,31)

def inst_lhzux(rD, rA, rB):
    if rA == 0: raise AsmError('rA = 0')
    if rA == rD: raise AsmError('rA = rD')
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(311,21,30)

def inst_lhzx(rD, rA0, rB):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(rB,16,20)|_b(279,21,30)

def inst_lmw(rD, d_bracket, rA0):
    return _b(46,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_lwz(rD, d_bracket, rA0):
    return _b(32,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_lwzu(rD, d_bracket, rA):
    if rA == 0: raise AsmError('rA = 0')
    if rA == rD: raise AsmError('rA = rD')
    return _b(33,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(d_bracket,16,31)

def inst_lwzux(rD, rA, rB):
    if rA == 0: raise AsmError('rA = 0')
    if rA == rD: raise AsmError('rA = rD')
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(55,21,30)

def inst_lwzx(rD, rA0, rB):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA0,11,15)|_b(rB,16,20)|_b(23,21,30)

def inst_mcrf(crD, crS):
    return _b(19,0,5)|_b(crD,6,8)|_b(crS,11,13)

def inst_mfcr(rD):
    return _b(31,0,5)|_b(rD,6,10)|_b(19,21,30)

def inst_mfspr(rD, spr):
    return _b(31,0,5)|_b(rD,6,10)|_b(spr&0x1f,11,15)|_b(spr>>5,16,20)|_b(339,21,30)

def inst_mtcrf(crm, rS):
    return _b(31,0,5)|_b(rS,6,10)|_b(crm,12,19)|_b(144,21,30)

def inst_mtspr(rS, spr):
    return _b(31,0,5)|_b(rS,6,10)|_b(spr&0x1f,11,15)|_b(spr>>5,16,20)|_b(467,21,30)

def inst_mulhw(dot, rD, rA, rB):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(75,22,30)|_b(dot,31)

def inst_mulhwu(dot, rD, rA, rB):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(11,22,30)|_b(dot,31)

def inst_nand(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(476,21,30)|_b(dot,31)

def inst_neg(dot, rD, rA):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(104,22,30)|_b(dot,31)

def inst_nor(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(124,21,30)|_b(dot,31)

def inst_or(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(444,21,30)|_b(dot,31)

def inst_orc(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(412,21,30)|_b(dot,31)

def inst_orc(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(412,21,30)|_b(dot,31)

def inst_ori(rA, rS, uimm):
    return _b(24,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(uimm,16,31)

def inst_oris(rA, rS, uimm):
    return _b(25,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(uimm,16,31)

def inst_rlwimi(dot, rA, rS, sh, mb, me):
    return _b(20,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(sh,16,20)|_b(mb,21,25)|_b(me,26,30)|_b(dot,31)

def inst_rlwinm(dot, rA, rS, sh, mb, me):
    return _b(21,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(sh,16,20)|_b(mb,21,25)|_b(me,26,30)|_b(dot,31)

def inst_rlwnm(dot, rA, rS, rB, mb, me):
    return _b(23,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(mb,21,25)|_b(me,26,30)|_b(dot,31)

def inst_slw(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(24,21,30)|_b(dot,31)

def inst_sraw(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(792,21,30)|_b(dot,31)

def inst_srawi(dot, rA, rS, sh):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(sh,16,20)|_b(824,21,30)|_b(dot,31)

def inst_srw(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(536,21,30)|_b(dot,31)

def inst_stb(rS, d_bracket, rA0):
    return _b(38,0,5)|_b(rS,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_stbu(rS, d_bracket, rA):
    if rA == 0: raise AsmError('rA = 0')
    return _b(29,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(d_bracket,16,31)

def inst_stbux(rS, rA, rB):
    if rA == 0: raise AsmError('rA = 0')
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(247,21,30)

def inst_stbx(rS, rA0, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA0,11,15)|_b(rB,16,20)|_b(215,21,30)

def inst_sth(rS, d_bracket, rA0):
    return _b(44,0,5)|_b(rS,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_sthu(rS, d_bracket, rA):
    if rA == 0: raise AsmError('rA = 0')
    return _b(45,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(d_bracket,16,31)

def inst_sthux(rS, rA, rB):
    if rA == 0: raise AsmError('rA = 0')
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(439,21,30)

def inst_sthx(rS, rA0, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA0,11,15)|_b(rB,16,20)|_b(407,21,30)

def inst_stmw(rS, d_bracket, rA0):
    return _b(47,0,5)|_b(rS,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_stw(rS, d_bracket, rA0):
    return _b(36,0,5)|_b(rS,6,10)|_b(rA0,11,15)|_b(d_bracket,16,31)

def inst_stwu(rS, d_bracket, rA):
    if rA == 0: raise AsmError('rA = 0')
    return _b(37,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(d_bracket,16,31)

def inst_stwux(rS, rA, rB):
    if rA == 0: raise AsmError('rA = 0')
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(183,21,30)

def inst_stwx(rS, rA0, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA0,11,15)|_b(rB,16,20)|_b(151,21,30)

def inst_subf(dot, rD, rA, rB):
    return _b(31,0,5)|_b(rD,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(40,22,30)|_b(dot,31)

def inst_xor(dot, rA, rS, rB):
    return _b(31,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(rB,16,20)|_b(316,21,30)|_b(dot,31)

def inst_xori(rA, rS, uimm):
    return _b(26,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(uimm,16,31)

def inst_xoris(rA, rS, uimm):
    return _b(27,0,5)|_b(rS,6,10)|_b(rA,11,15)|_b(uimm,16,31)

# "High-level" instructions

def inst_bctr(link):
    return inst_bcctr(link, 0b10100, 0)

def inst_blr(link):
    return inst_bclr(link, 0b10100, 0)

def inst_beq(link, crA_optional, dest):
    return inst_bc(link, 0b01100, 4*crA_optional+2, dest)

def inst_bge(link, crA_optional, dest):
    return inst_bc(link, 0b01100, 4*crA_optional, dest)

def inst_bgt(link, crA_optional, dest):
    return inst_bc(link, 0b00100, 4*crA_optional+1, dest)

def inst_ble(link, crA_optional, dest):
    return inst_bc(link, 0b01100, 4*crA_optional+1, dest)

def inst_blt(link, crA_optional, dest):
    return inst_bc(link, 0b00100, 4*crA_optional, dest)

def inst_bne(link, crA_optional, dest):
    return inst_bc(link, 0b00100, 4*crA_optional+2, dest)

def inst_crclr(crbD):
    return inst_crxor(crbD, crbD, crbD)

def inst_crset(crbD):
    return inst_creqv(crbD, crbD, crbD)

def inst_li(rD, simm):
    return inst_addi(rD, 0, simm)

def inst_lis(rD, simm):
    return inst_addis(rD, 0, simm)

def inst_mfctr(rD):
    return inst_mfspr(rD, 9)

def inst_mflr(rD):
    return inst_mfspr(rD, 8)

def inst_mfxer(rD):
    return inst_mfspr(rD, 1)

def inst_mtctr(rD):
    return inst_mtspr(rD, 9)

def inst_mtlr(rD):
    return inst_mtspr(rD, 8)

def inst_mtxer(rD):
    return inst_mtspr(rD, 1)

def inst_nop():
    return inst_ori(0, 0, 0)

def inst_subi(rD, rA, simm):
    return inst_addi(rD, rA, -simm)

# Command line needs to go dead last
if __name__ == '__main__': command_line()
