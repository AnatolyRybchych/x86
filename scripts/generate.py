#!/bin/python3

import json
import sys
import re

class Obj:
    pass

SZOVRD = 0x66

# 64-bit operand size is used
REX_W = 0b01001000

# This is an extension to the MODRM.reg field
REX_R = 0b01000100

#This is an extension to the SIB.index field
REX_X = 0b01000010

#This is an extension to the MODRM.rm field or the SIB.base field.
REX_B = 0b01000001

REX_WR = REX_W | REX_R
REX_WX = REX_W | REX_X
REX_WB = REX_W | REX_B
REX_RX = REX_R | REX_X
REX_RB = REX_R | REX_B
REX_XB = REX_X | REX_B
REX_WRX = REX_WR | REX_X
REX_WRB = REX_WR | REX_B
REX_WXB = REX_WX | REX_B
REX_RXB = REX_RX | REX_B
REX_WRXB = REX_WRX | REX_B

def preproccess(inst) -> Obj:
    new = Obj()
    new.orig = inst
    new.description = inst.get('Description, Notes')
    new.op1 = inst.get('Operand 1')
    new.op2 = inst.get('Operand 2')
    new.op3 = inst.get('Operand 3')
    new.op4 = inst.get('Operand 4')
    new.pref_0F = inst.get('Prefix 0F')
    new.proccessor = inst.get('Introduced with the Processor')
    primary_opcode = inst['Primary Opcode']
    new.secondary_opcode = inst.get('Secondary Opcode')
    new.ext_grp = inst.get('Instruction Extension Group')
    new.mnemonic = inst['Instruction Mnemonic'].strip().upper()
    new.oper_mode = inst.get('Mode of Operation')
    new.undef_flags = inst.get('Undefined Flags')
    new.modif_flags = inst.get('Modified Flags')
    new.tested_flags = inst.get('Tested Flags')
    new.defined_flags = inst.get('Defined Flags')
    new.doc_status = inst.get('Documentation Status')
    new.lock_fpush_fpop = inst.get('Lock Prefix/FPU Push/FPU Pop')
    new.ring_level = inst.get('Ring Level')
    new.flag_values = inst.get('Flags Values')

    primary_opcode, new.reg_in_op = re.match(r'^([0-9A-F]{2})\+?(r)?$', primary_opcode).groups()
    new.reg_in_op = new.reg_in_op == 'r'

    if primary_opcode in ['0F', 'F1']:
        raise Exception('Prefix')

    new.pref = inst.get('Prefix')

    reg_op = inst.get('Register/Opcode Field')
    new.reg_const = reg_op and re.match('^\d+$', reg_op) and int(reg_op)

    new.opcode = bytes.fromhex(primary_opcode)
    new.opcode += (new.secondary_opcode and bytes.fromhex(new.secondary_opcode) or b'')

    new.ops = [
        *(new.op1 and [new.op1] or []),
        *(new.op2 and [new.op2] or []),
        *(new.op3 and [new.op3] or []),
        *(new.op4 and [new.op4] or []),
    ]

    return new


insts = []
for inst in json.load(sys.stdin):
    try:
        insts.append(preproccess(inst))
    except:
        pass

def mod_rm(mod, reg, rm):
    res = Obj()
    res.mod = mod
    res.reg = reg
    res.rm = rm

    return res

def instruction(inst, **overload) -> list[str]:
    def get(name, default=None):
        return overload.get(name, getattr(inst, name, default))
    
    res_bytes = []

    mandatory_pref = get('mandatory_pref')
    vex = get('vex')
    if mandatory_pref and not vex:
        res_bytes += ['0x%02X' % b for b in mandatory_pref]
    
    pref_0F = get('pref_0F')
    if pref_0F and not vex:
        res_bytes += [f'0x{pref_0F}']

    res_bytes += ['0x%02X' % b if type(b) is int else b for b in get('prefix', [])]

    if vex:
        res_bytes += ['0x%02X' % b if type(b) is int else b for b in vex]

    opcode = ['0x%02X' % b for b in inst.opcode]

    if get('reg_in_op', False):
        opcode[-1] = f'U8({opcode[-1]}) + reg.id'

    res_bytes += opcode

    mod_rm = get('mod_rm', None)
    mod = mod_rm and mod_rm.mod
    if mod_rm:
        mod_rm = f'mod_rm({f"{bin(mod)}"}, {mod_rm.reg}, {mod_rm.rm})'
        res_bytes += [mod_rm]

    sib = get('sib', None)
    if sib:
        sib = f'sib({sib["scale"]}, {sib["index"]}, {sib["base"]})'
        res_bytes += [sib]

    disp = get('disp', [])
    if disp:
        res_bytes += disp

    imm = get('imm', None)
    if imm:
        res_bytes += imm

    lock = get('lock', False)

    args: str =  ', '.join(get('args', []))

    ret = f'Instruction<{len(res_bytes)}, {lock and mod != 0b11 and "true" or "false"}>'

    return [
        '',
        f'// {get("mnemonic")} {", ".join(get("ops"))}; {get("description")}',
        f'static constexpr {ret} {get("mnemonic")}({args})' + '{',[
            f'return {ret}' + '{' + ', '.join([ f'U8({b})' for b in res_bytes]) + '};',
        ], '}'
    ]

def arr(var, count, first = 0):
    return [f'{var}[{i}]' for i in range(first, first + count)]

generated = set()
def generate_instruction(inst) -> list[str]:
    signature = json.dumps([inst.mnemonic, inst.op1, inst.op2, inst.op3, inst.op4])
    if signature in generated:
        return []
        raise Exception(f'// duplicate {signature}')

    generated.add(signature)

    if inst.reg_in_op:
        for i, arg in enumerate(inst.ops):
            if re.match(r'^r\d', arg):
                inst.ops[i] = f'#{arg}'
                break

    def VEX(RXBWL: str, vvvv = None):
        if not inst.pref_0F:
            raise Exception("VEX prefix is not expected")

        map_select = '00001'
        if inst.secondary_opcode == '38':
            map_select = '00010'
        elif inst.secondary_opcode == '3A':
            map_select = '00011'

        pp = '00'
        if inst.pref == '66':
            pp = '01'
        elif inst.pref == 'F3':
            pp = '10'
        elif inst.pref == 'F2':
            pp = '11'

        r, nr = 'R' in RXBWL and (1, 0) or (0, 1)
        x, nx = 'X' in RXBWL and (1, 0) or (0, 1)
        b, nb = 'B' in RXBWL and (1, 0) or (0, 1)
        w, nw = 'W' in RXBWL and (1, 0) or (0, 1)
        l, nl = 'L' in RXBWL and (1, 0) or (0, 1)

        vvvv = vvvv or '0b1111'

        if [x, b, w, map_select] == [0, 0, 0, '00001']:
            return [f'0xC5', f'0b{nr}0000000 | (~{vvvv} & 0b1111)<<3 | 0b{l}{pp}']
        else:
            return [f'0xC5', int(f'{nr}{nx}{nb}{map_select}', 2), f'0b{w}0000{l}{pp} | ((~{vvvv} & 0b1111) << 3)']

    sib = {'scale': 'rm.scale', 'index': 'rm.index.id', 'base': 'rm.id'}
    ssesib = {'scale': 'xmmm.scale', 'index': 'xmmm.index.id', 'base': 'xmmm.id'}
    mmxsib = {'scale': 'mmm.scale', 'index': 'mmm.index.id', 'base': 'mmm.id'}

    generator = {
    '': lambda: instruction(inst, args=[]),
    'imm8': lambda: instruction(inst, args=['IMM8 imm'], imm=arr('imm', 1)),
    'imm16': lambda: instruction(inst, args=['IMM16 imm'], imm=arr('imm', 2)),
    'r/m8': lambda: [
        *instruction(inst, args=['RegRm8 rm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id')),
        *instruction(inst, args=['Reg8 rm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm8 rm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['EReg8 rm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id')),
    ],
    'r/m8,r8': lambda: [
        *instruction(inst, args=['RegRm8 rm', 'Reg8 reg'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, args=['Reg8 rm', 'Reg8 reg'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm8 rm', 'Reg8 reg'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['EReg8 rm', 'Reg8 reg'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args=['RegRm8 rm', 'EReg8 reg'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args=['Reg8 rm', 'EReg8 reg'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args=['ERegRm8 rm', 'EReg8 reg'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EReg8 rm', 'EReg8 reg'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
    ],
    'r/m8,imm8': lambda: [
        *instruction(inst, args = ['RegRm8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, args = ['Reg8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['ERegRm8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['EReg8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id'), imm=arr('imm', 1)),
    ],
    'rel8': lambda: instruction(inst, args=['REL8 rel'], imm=arr('rel', 2)),
    'rel16/32': lambda: [
        *instruction(inst, prefix=[SZOVRD], args=['REL16 rel'], imm=arr('rel', 2)),
        *instruction(inst, args=['REL32 rel'], imm=arr('rel', 4)),
        *instruction(inst, prefix=[REX_W], args=['REL64 rel'], imm=arr('rel', 8)),
    ],
    'r8,r/m8': lambda: [
        *instruction(inst, args=['Reg8 reg', 'RegRm8 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['Reg8 reg', 'ERegRm8 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args=['EReg8 reg', 'RegRm8 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EReg8 reg', 'ERegRm8 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
    ],
    'r/m8,1': lambda: [
        *instruction(inst, args=['RegRm8 rm'], mod_rm=mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm8 rm'], mod_rm=mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
    ],
    'r/m16/32': lambda: [
        *instruction(inst, prefix=[REX_W], args=['RegRm64 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_W], args=['Reg64 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Disp32 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args=['EReg64 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Disp32 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Indir, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Disp8, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Disp32, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Indir, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Disp8, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Disp32, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Indir, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Disp8, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Disp32, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Indir, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Disp8, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Disp32, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['RegRm32 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, args=['Reg32 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, args=['RegRm32Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, args=['RegRm32Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['RegRm32Disp32 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['EReg32 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Disp32 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['SIB<RegRm32Indir, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, args=['SIB<RegRm32Disp8, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['SIB<RegRm32Disp32, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Indir, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Disp8, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Disp32, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Indir, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Disp8, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Disp32, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Indir, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Disp8, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Disp32, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], args=['RegRm16 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args=['Reg16 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Disp16 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['EReg16 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Disp16 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 2)),
    ],
    'r/m16/32,1': lambda: [
        *instruction(inst, prefix=[REX_W], args=['RegRm64 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_W], args=['Reg64 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Disp32 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args=['EReg64 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Disp32 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Indir, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Disp8, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Disp32, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Indir, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Disp8, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Disp32, Reg64> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Indir, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Disp8, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Disp32, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Indir, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Disp8, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Disp32, EReg64> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['RegRm32 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, args=['Reg32 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, args=['RegRm32Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, args=['RegRm32Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['RegRm32Disp32 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['EReg32 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Disp32 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['SIB<RegRm32Indir, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, args=['SIB<RegRm32Disp8, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['SIB<RegRm32Disp32, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Indir, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Disp8, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Disp32, Reg32> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Indir, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Disp8, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Disp32, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Indir, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b00, inst.reg_const or 0, 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Disp8, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b01, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Disp32, EReg32> rm'], sib=sib, mod_rm = mod_rm(0b10, inst.reg_const or 0, 0b100), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], args=['RegRm16 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args=['Reg16 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Disp16 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['EReg16 rm'], mod_rm = mod_rm(0b11, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Indir rm'], mod_rm = mod_rm(0b00, inst.reg_const or 0, 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Disp8 rm'], mod_rm = mod_rm(0b01, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Disp16 rm'], mod_rm = mod_rm(0b10, inst.reg_const or 0, 'rm.id'), disp=arr('rm.disp', 2)),
    ],
    'r/m16/32,imm8': lambda: [
        *instruction(inst, prefix=[REX_W], args=['RegRm64 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args=['Reg64 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Indir rm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Disp8 rm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Disp32 rm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args=['EReg64 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Indir rm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Disp8 rm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Disp32 rm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Indir, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Disp8, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Disp32, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Indir, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Disp8, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Disp32, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Indir, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Disp8, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Disp32, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Indir, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Disp8, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Disp32, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['RegRm32 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, args=['Reg32 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, args=['RegRm32Indir rm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, args=['RegRm32Disp8 rm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['RegRm32Disp32 rm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args=['EReg32 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Indir rm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Disp8 rm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Disp32 rm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['SIB<RegRm32Indir, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 1)),
        *instruction(inst, args=['SIB<RegRm32Disp8, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['SIB<RegRm32Disp32, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Indir, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Disp8, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Disp32, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Indir, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Disp8, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Disp32, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Indir, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Disp8, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Disp32, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], args=['RegRm16 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['Reg16 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Indir rm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Disp8 rm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Disp16 rm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['EReg16 rm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Indir rm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Disp8 rm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Disp16 rm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 1), disp=arr('rm.disp', 2)),
    ],
    '#r16/32,imm16/32': lambda: [
        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'IMM64 imm'], imm=arr('imm', 8)),
        *instruction(inst, prefix=[REX_WB], args=['EReg64 reg', 'IMM64 imm'], imm=arr('imm', 8)),
        *instruction(inst, args=['Reg32 reg', 'IMM32 imm'], imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_B], args=['EReg32 reg', 'IMM32 imm'], imm=arr('imm', 4)),
        *instruction(inst, prefix=[SZOVRD], args=['Reg16 reg', 'IMM16 imm'], imm=arr('imm', 2)),
    ],
    'r/m16/32,imm16/32': lambda: [
        *instruction(inst, prefix=[REX_W], args=['RegRm64 rm', 'IMM32 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Indir rm', 'IMM32 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Disp8 rm', 'IMM32 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['RegRm64Disp32 rm', 'IMM32 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 4), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64 rm', 'IMM32 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Indir rm', 'IMM32 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Disp8 rm', 'IMM32 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['ERegRm64Disp32 rm', 'IMM32 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 4), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64, Reg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b11, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Indir, Reg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Disp8, Reg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['SIB<RegRm64Disp32, Reg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64, Reg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b11, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Indir, Reg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Disp8, Reg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['SIB<ERegRm64Disp32, Reg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64, EReg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b11, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Indir, EReg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Disp8, EReg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WX], args=['SIB<RegRm64Disp32, EReg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64, EReg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b11, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Indir, EReg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Disp8, EReg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WXB], args=['SIB<ERegRm64Disp32, EReg64> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['RegRm32 rm', 'IMM32 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 4)),
        *instruction(inst, args=['RegRm32Indir rm', 'IMM32 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 4)),
        *instruction(inst, args=['RegRm32Disp8 rm', 'IMM32 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['RegRm32Disp32 rm', 'IMM32 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 4), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32 rm', 'IMM32 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Indir rm', 'IMM32 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Disp8 rm', 'IMM32 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm32Disp32 rm', 'IMM32 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 4), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['SIB<RegRm32, Reg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b11, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, args=['SIB<RegRm32Indir, Reg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, args=['SIB<RegRm32Disp8, Reg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['SIB<RegRm32Disp32, Reg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32, Reg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b11, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Indir, Reg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Disp8, Reg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm32Disp32, Reg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32, EReg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b11, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Indir, EReg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Disp8, EReg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], args=['SIB<RegRm32Disp32, EReg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32, EReg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b11, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Indir, EReg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b00, inst.reg_const, 0b100), imm=arr('imm', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Disp8, EReg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b01, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm32Disp32, EReg32> rm', 'IMM32 imm'], sib=sib, mod_rm=mod_rm(0b10, inst.reg_const, 0b100), imm=arr('imm', 4), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], args=['RegRm16 rm', 'IMM16 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 2)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Indir rm', 'IMM16 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 2)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Disp8 rm', 'IMM16 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 2), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm16Disp16 rm', 'IMM16 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 2), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16 rm', 'IMM16 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), imm=arr('imm', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Indir rm', 'IMM16 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'rm.id'), imm=arr('imm', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Disp8 rm', 'IMM16 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'rm.id'), imm=arr('imm', 2), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm16Disp16 rm', 'IMM16 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'rm.id'), imm=arr('imm', 2), disp=arr('rm.disp', 2)),
    ],
    'r/m16/32,r16/32': lambda: [
        *instruction(inst, prefix=[REX_W], args = ['RegRm64 rm', 'Reg64 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 rm', 'Reg64 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args = ['RegRm64Indir rm', 'Reg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args = ['RegRm64Disp8 rm', 'Reg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args = ['RegRm64Disp32 rm', 'Reg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args = ['ERegRm64 rm', 'Reg64 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args = ['EReg64 rm', 'Reg64 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args = ['ERegRm64Indir rm', 'Reg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args = ['ERegRm64Disp8 rm', 'Reg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['ERegRm64Disp32 rm', 'Reg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WR], args = ['RegRm64 rm', 'EReg64 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args = ['Reg64 rm', 'EReg64 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args = ['RegRm64Indir rm', 'EReg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args = ['RegRm64Disp8 rm', 'EReg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['RegRm64Disp32 rm', 'EReg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRB], args = ['ERegRm64 rm', 'EReg64 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 rm', 'EReg64 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args = ['ERegRm64Indir rm', 'EReg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args = ['ERegRm64Disp8 rm', 'EReg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['ERegRm64Disp32 rm', 'EReg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[REX_W], sib=sib, args = ['SIB<RegRm64Indir, Reg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_W], sib=sib, args = ['SIB<RegRm64Disp8, Reg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], sib=sib, args = ['SIB<RegRm64Disp32, Reg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], sib=sib, args = ['SIB<ERegRm64Indir, Reg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WB], sib=sib, args = ['SIB<ERegRm64Disp8, Reg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], sib=sib, args = ['SIB<ERegRm64Disp32, Reg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WR], sib=sib, args = ['SIB<RegRm64Indir, Reg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WR], sib=sib, args = ['SIB<RegRm64Disp8, Reg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], sib=sib, args = ['SIB<RegRm64Disp32, Reg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRB], sib=sib, args = ['SIB<ERegRm64Indir, Reg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRB], sib=sib, args = ['SIB<ERegRm64Disp8, Reg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], sib=sib, args = ['SIB<ERegRm64Disp32, Reg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WX], sib=sib, args = ['SIB<RegRm64Indir, EReg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WX], sib=sib, args = ['SIB<RegRm64Disp8, EReg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WX], sib=sib, args = ['SIB<RegRm64Disp32, EReg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WXB], sib=sib, args = ['SIB<ERegRm64Indir, EReg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WXB], sib=sib, args = ['SIB<ERegRm64Disp8, EReg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WXB], sib=sib, args = ['SIB<ERegRm64Disp32, EReg64> rm', 'Reg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRX], sib=sib, args = ['SIB<RegRm64Indir, EReg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRX], sib=sib, args = ['SIB<RegRm64Disp8, EReg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRX], sib=sib, args = ['SIB<RegRm64Disp32, EReg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRXB], sib=sib, args = ['SIB<ERegRm64Indir, EReg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRXB], sib=sib, args = ['SIB<ERegRm64Disp8, EReg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRXB], sib=sib, args = ['SIB<ERegRm64Disp32, EReg64> rm', 'EReg64 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),

        *instruction(inst, args = ['Reg32 rm', 'Reg32 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, args = ['RegRm32Indir rm', 'Reg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, args = ['RegRm32Disp8 rm', 'Reg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, args = ['RegRm32Disp32 rm', 'Reg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args = ['EReg32 rm', 'Reg32 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args = ['ERegRm32Indir rm', 'Reg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args = ['ERegRm32Disp8 rm', 'Reg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args = ['ERegRm32Disp32 rm', 'Reg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args = ['Reg32 rm', 'EReg32 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args = ['RegRm32Indir rm', 'EReg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args = ['RegRm32Disp8 rm', 'EReg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args = ['RegRm32Disp32 rm', 'EReg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 rm', 'EReg32 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args = ['ERegRm32Indir rm', 'EReg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args = ['ERegRm32Disp8 rm', 'EReg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['ERegRm32Disp32 rm', 'EReg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        
        *instruction(inst, prefix=[], sib=sib, args = ['SIB<RegRm32Indir, Reg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[], sib=sib, args = ['SIB<RegRm32Disp8, Reg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[], sib=sib, args = ['SIB<RegRm32Disp32, Reg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], sib=sib, args = ['SIB<ERegRm32Indir, Reg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_B], sib=sib, args = ['SIB<ERegRm32Disp8, Reg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], sib=sib, args = ['SIB<ERegRm32Disp32, Reg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], sib=sib, args = ['SIB<RegRm32Indir, Reg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_R], sib=sib, args = ['SIB<RegRm32Disp8, Reg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], sib=sib, args = ['SIB<RegRm32Disp32, Reg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], sib=sib, args = ['SIB<ERegRm32Indir, Reg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], sib=sib, args = ['SIB<ERegRm32Disp8, Reg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], sib=sib, args = ['SIB<ERegRm32Disp32, Reg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], sib=sib, args = ['SIB<RegRm32Indir, EReg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_X], sib=sib, args = ['SIB<RegRm32Disp8, EReg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], sib=sib, args = ['SIB<RegRm32Disp32, EReg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], sib=sib, args = ['SIB<ERegRm32Indir, EReg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], sib=sib, args = ['SIB<ERegRm32Disp8, EReg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], sib=sib, args = ['SIB<ERegRm32Disp32, EReg32> rm', 'Reg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], sib=sib, args = ['SIB<RegRm32Indir, EReg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], sib=sib, args = ['SIB<RegRm32Disp8, EReg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], sib=sib, args = ['SIB<RegRm32Disp32, EReg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], sib=sib, args = ['SIB<ERegRm32Indir, EReg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], sib=sib, args = ['SIB<ERegRm32Disp8, EReg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], sib=sib, args = ['SIB<ERegRm32Disp32, EReg32> rm', 'EReg32 reg'], mod_rm = mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], args = ['RegRm16 rm', 'Reg16 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 rm', 'Reg16 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args = ['RegRm16Indir rm', 'Reg16 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args = ['RegRm16Disp8 rm', 'Reg16 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['RegRm16Disp16 rm', 'Reg16 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['ERegRm16 rm', 'Reg16 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['EReg16 rm', 'Reg16 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['ERegRm16Indir rm', 'Reg16 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['ERegRm16Disp8 rm', 'Reg16 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['ERegRm16Disp16 rm', 'Reg16 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['RegRm16 rm', 'EReg16 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['Reg16 rm', 'EReg16 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['RegRm16Indir rm', 'EReg16 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['RegRm16Disp8 rm', 'EReg16 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['RegRm16Disp16 rm', 'EReg16 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['ERegRm16 rm', 'EReg16 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 rm', 'EReg16 reg'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['ERegRm16Indir rm', 'EReg16 reg'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['ERegRm16Disp8 rm', 'EReg16 reg'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['ERegRm16Disp16 rm', 'EReg16 reg'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
    ],
    'r16/32,r/m16/32': lambda: [
        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'RegRm64 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'RegRm64Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'RegRm64Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'RegRm64Disp32 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['Reg64 reg', 'ERegRm64 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args=['Reg64 reg', 'ERegRm64Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args=['Reg64 reg', 'ERegRm64Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['Reg64 reg', 'ERegRm64Disp32 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WR], args=['EReg64 reg', 'RegRm64 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args=['EReg64 reg', 'RegRm64Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args=['EReg64 reg', 'RegRm64Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], args=['EReg64 reg', 'RegRm64Disp32 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRB], args=['EReg64 reg', 'ERegRm64 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args=['EReg64 reg', 'ERegRm64Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args=['EReg64 reg', 'ERegRm64Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], args=['EReg64 reg', 'ERegRm64Disp32 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'SIB<RegRm64, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'SIB<RegRm64Indir, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'SIB<RegRm64Disp8, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args=['Reg64 reg', 'SIB<RegRm64Disp32, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args=['Reg64 reg', 'SIB<ERegRm64, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WB], args=['Reg64 reg', 'SIB<ERegRm64Indir, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WB], args=['Reg64 reg', 'SIB<ERegRm64Disp8, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args=['Reg64 reg', 'SIB<ERegRm64Disp32, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WR], args=['EReg64 reg', 'SIB<RegRm64, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WR], args=['EReg64 reg', 'SIB<RegRm64Indir, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WR], args=['EReg64 reg', 'SIB<RegRm64Disp8, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], args=['EReg64 reg', 'SIB<RegRm64Disp32, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRB], args=['EReg64 reg', 'SIB<ERegRm64, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRB], args=['EReg64 reg', 'SIB<ERegRm64Indir, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRB], args=['EReg64 reg', 'SIB<ERegRm64Disp8, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], args=['EReg64 reg', 'SIB<ERegRm64Disp32, Reg64> rm'], sib=sib,  mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WX], args=['Reg64 reg', 'SIB<RegRm64, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WX], args=['Reg64 reg', 'SIB<RegRm64Indir, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WX], args=['Reg64 reg', 'SIB<RegRm64Disp8, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WX], args=['Reg64 reg', 'SIB<RegRm64Disp32, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WXB], args=['Reg64 reg', 'SIB<ERegRm64, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WXB], args=['Reg64 reg', 'SIB<ERegRm64Indir, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WXB], args=['Reg64 reg', 'SIB<ERegRm64Disp8, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WXB], args=['Reg64 reg', 'SIB<ERegRm64Disp32, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRX], args=['EReg64 reg', 'SIB<RegRm64, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRX], args=['EReg64 reg', 'SIB<RegRm64Indir, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRX], args=['EReg64 reg', 'SIB<RegRm64Disp8, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRX], args=['EReg64 reg', 'SIB<RegRm64Disp32, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRXB], args=['EReg64 reg', 'SIB<ERegRm64, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRXB], args=['EReg64 reg', 'SIB<ERegRm64Indir, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_WRXB], args=['EReg64 reg', 'SIB<ERegRm64Disp8, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRXB], args=['EReg64 reg', 'SIB<ERegRm64Disp32, EReg64> rm'], sib=sib,  mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['Reg32 reg', 'RegRm32 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, args=['Reg32 reg', 'RegRm32Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, args=['Reg32 reg', 'RegRm32Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['Reg32 reg', 'RegRm32Disp32 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'ERegRm32 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'ERegRm32Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'ERegRm32Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'ERegRm32Disp32 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'RegRm32 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'RegRm32Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'RegRm32Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'RegRm32Disp32 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'ERegRm32 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'ERegRm32Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'ERegRm32Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'ERegRm32Disp32 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['Reg32 reg', 'SIB<RegRm32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, args=['Reg32 reg', 'SIB<RegRm32Indir, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, args=['Reg32 reg', 'SIB<RegRm32Disp8, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['Reg32 reg', 'SIB<RegRm32Disp32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'SIB<ERegRm32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'SIB<ERegRm32Indir, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'SIB<ERegRm32Disp8, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'SIB<ERegRm32Disp32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'SIB<RegRm32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'SIB<RegRm32Indir, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'SIB<RegRm32Disp8, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'SIB<RegRm32Disp32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'SIB<ERegRm32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'SIB<ERegRm32Indir, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'SIB<ERegRm32Disp8, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'SIB<ERegRm32Disp32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], args=['Reg32 reg', 'SIB<RegRm32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_X], args=['Reg32 reg', 'SIB<RegRm32Indir, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_X], args=['Reg32 reg', 'SIB<RegRm32Disp8, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], args=['Reg32 reg', 'SIB<RegRm32Disp32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['Reg32 reg', 'SIB<ERegRm32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['Reg32 reg', 'SIB<ERegRm32Indir, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['Reg32 reg', 'SIB<ERegRm32Disp8, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['Reg32 reg', 'SIB<ERegRm32Disp32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args=['EReg32 reg', 'SIB<RegRm32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], args=['EReg32 reg', 'SIB<RegRm32Indir, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], args=['EReg32 reg', 'SIB<RegRm32Disp8, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args=['EReg32 reg', 'SIB<RegRm32Disp32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args=['EReg32 reg', 'SIB<ERegRm32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b11, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], args=['EReg32 reg', 'SIB<ERegRm32Indir, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], args=['EReg32 reg', 'SIB<ERegRm32Disp8, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args=['EReg32 reg', 'SIB<ERegRm32Disp32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], args=['Reg16 reg', 'RegRm16 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args=['Reg16 reg', 'RegRm16Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args=['Reg16 reg', 'RegRm16Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['Reg16 reg', 'RegRm16Disp16 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg16 reg', 'ERegRm16 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg16 reg', 'ERegRm16Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg16 reg', 'ERegRm16Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg16 reg', 'ERegRm16Disp16 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg16 reg', 'RegRm16 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg16 reg', 'RegRm16Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg16 reg', 'RegRm16Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg16 reg', 'RegRm16Disp16 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg16 reg', 'ERegRm16 rm'], mod_rm=mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg16 reg', 'ERegRm16Indir rm'], mod_rm=mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg16 reg', 'ERegRm16Disp8 rm'], mod_rm=mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg16 reg', 'ERegRm16Disp16 rm'], mod_rm=mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
    ],
    'r16/32,r/m8': lambda: [
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'Reg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'Reg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'EReg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'EReg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),

        *instruction(inst, prefix=[], args = ['Reg32 reg', 'RegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[], args = ['Reg32 reg', 'Reg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'Reg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'EReg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'EReg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),


        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'Reg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'Reg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'EReg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'EReg8 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
    ],
    'r16/32,r/m16': lambda: [
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'Reg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'Reg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'EReg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'EReg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),

        *instruction(inst, args = ['Reg32 reg', 'RegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, args = ['Reg32 reg', 'Reg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, args = ['Reg32 reg', 'RegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, args = ['Reg32 reg', 'RegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, args = ['Reg32 reg', 'RegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'Reg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'EReg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'EReg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),

        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'Reg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'Reg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'EReg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'EReg16 rm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm16Indir rm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm16Disp8 rm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm16Disp16 rm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), disp=arr('rm.disp', 2)),
    ],
    'r/m16/32,r16/32,imm8': lambda: [
        *instruction(inst, prefix=[REX_W], args = ['RegRm64 rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args = ['RegRm64Indir rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args = ['RegRm64Disp8 rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args = ['RegRm64Disp32 rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WR], args = ['RegRm64 rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['Reg64 rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['RegRm64Indir rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['RegRm64Disp8 rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['RegRm64Disp32 rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args = ['ERegRm64 rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['EReg64 rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['ERegRm64Indir rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['ERegRm64Disp8 rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['ERegRm64Disp32 rm', 'Reg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRB], args = ['ERegRm64 rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['ERegRm64Indir rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['ERegRm64Disp8 rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['ERegRm64Disp32 rm', 'EReg64 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[REX_W], args = ['SIB<RegRm64Indir, Reg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args = ['SIB<RegRm64Disp8, Reg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args = ['SIB<RegRm64Disp32, Reg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WR], args = ['SIB<RegRm64Indir, Reg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['SIB<RegRm64Disp8, Reg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['SIB<RegRm64Disp32, Reg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args = ['SIB<ERegRm64Indir, Reg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['SIB<ERegRm64Disp8, Reg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['SIB<ERegRm64Disp32, Reg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRB], args = ['SIB<ERegRm64Indir, Reg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['SIB<ERegRm64Disp8, Reg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['SIB<ERegRm64Disp32, Reg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WX], args = ['SIB<RegRm64Indir, EReg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WX], args = ['SIB<RegRm64Disp8, EReg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WX], args = ['SIB<RegRm64Disp32, EReg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRX], args = ['SIB<RegRm64Indir, EReg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRX], args = ['SIB<RegRm64Disp8, EReg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRX], args = ['SIB<RegRm64Disp32, EReg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WXB], args = ['SIB<ERegRm64Indir, EReg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WXB], args = ['SIB<ERegRm64Disp8, EReg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WXB], args = ['SIB<ERegRm64Disp32, EReg64> rm', 'Reg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRXB], args = ['SIB<ERegRm64Indir, EReg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRXB], args = ['SIB<ERegRm64Disp8, EReg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRXB], args = ['SIB<ERegRm64Disp32, EReg64> rm', 'EReg64 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, args = ['RegRm32 rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, args = ['Reg32 rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, args = ['RegRm32Indir rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, args = ['RegRm32Disp8 rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, args = ['RegRm32Disp32 rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args = ['RegRm32 rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_R], args = ['Reg32 rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_R], args = ['RegRm32Indir rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_R], args = ['RegRm32Disp8 rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args = ['RegRm32Disp32 rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args = ['ERegRm32 rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['EReg32 rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['ERegRm32Indir rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['ERegRm32Disp8 rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args = ['ERegRm32Disp32 rm', 'Reg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args = ['ERegRm32 rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['ERegRm32Indir rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['ERegRm32Disp8 rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['ERegRm32Disp32 rm', 'EReg32 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, args = ['SIB<RegRm32Indir, Reg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, args = ['SIB<RegRm32Disp8, Reg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, args = ['SIB<RegRm32Disp32, Reg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args = ['SIB<RegRm32Indir, Reg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_R], args = ['SIB<RegRm32Disp8, Reg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args = ['SIB<RegRm32Disp32, Reg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args = ['SIB<ERegRm32Indir, Reg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['SIB<ERegRm32Disp8, Reg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args = ['SIB<ERegRm32Disp32, Reg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args = ['SIB<ERegRm32Indir, Reg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['SIB<ERegRm32Disp8, Reg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['SIB<ERegRm32Disp32, Reg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], args = ['SIB<RegRm32Indir, EReg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_X], args = ['SIB<RegRm32Disp8, EReg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], args = ['SIB<RegRm32Disp32, EReg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args = ['SIB<RegRm32Indir, EReg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RX], args = ['SIB<RegRm32Disp8, EReg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args = ['SIB<RegRm32Disp32, EReg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args = ['SIB<ERegRm32Indir, EReg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_XB], args = ['SIB<ERegRm32Disp8, EReg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args = ['SIB<ERegRm32Disp32, EReg32> rm', 'Reg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args = ['SIB<ERegRm32Indir, EReg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RXB], args = ['SIB<ERegRm32Disp8, EReg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args = ['SIB<ERegRm32Disp32, EReg32> rm', 'EReg32 reg', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], args = ['RegRm16 rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['RegRm16Indir rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['RegRm16Disp8 rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['RegRm16Disp16 rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['ERegRm16 rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['EReg16 rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['ERegRm16Indir rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['ERegRm16Disp8 rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['ERegRm16Disp16 rm', 'Reg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['RegRm16 rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['Reg16 rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['RegRm16Indir rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['RegRm16Disp8 rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['RegRm16Disp16 rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['ERegRm16 rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['ERegRm16Indir rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['ERegRm16Disp8 rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['ERegRm16Disp16 rm', 'EReg16 reg', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 2)),
    ],
    'r16/32,r/m16/32,imm8': lambda: [
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm64 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm64Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm64Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'RegRm64Disp32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm64 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm64Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm64Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'ERegRm64Disp32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm64 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm64Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm64Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'RegRm64Disp32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm64 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm64Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm64Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'ERegRm64Disp32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'SIB<RegRm64Indir, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'SIB<RegRm64Disp8, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_W], args = ['Reg64 reg', 'SIB<RegRm64Disp32, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'SIB<ERegRm64Indir, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'SIB<ERegRm64Disp8, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WB], args = ['Reg64 reg', 'SIB<ERegRm64Disp32, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'SIB<RegRm64Indir, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'SIB<RegRm64Disp8, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WR], args = ['EReg64 reg', 'SIB<RegRm64Disp32, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'SIB<ERegRm64Indir, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'SIB<ERegRm64Disp8, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRB], args = ['EReg64 reg', 'SIB<ERegRm64Disp32, Reg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WX], args = ['Reg64 reg', 'SIB<RegRm64Indir, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WX], args = ['Reg64 reg', 'SIB<RegRm64Disp8, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WX], args = ['Reg64 reg', 'SIB<RegRm64Disp32, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WXB], args = ['Reg64 reg', 'SIB<ERegRm64Indir, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WXB], args = ['Reg64 reg', 'SIB<ERegRm64Disp8, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WXB], args = ['Reg64 reg', 'SIB<ERegRm64Disp32, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRX], args = ['EReg64 reg', 'SIB<RegRm64Indir, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRX], args = ['EReg64 reg', 'SIB<RegRm64Disp8, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRX], args = ['EReg64 reg', 'SIB<RegRm64Disp32, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_WRXB], args = ['EReg64 reg', 'SIB<ERegRm64Indir, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_WRXB], args = ['EReg64 reg', 'SIB<ERegRm64Disp8, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_WRXB], args = ['EReg64 reg', 'SIB<ERegRm64Disp32, EReg64> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, args = ['Reg32 reg', 'RegRm32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, args = ['Reg32 reg', 'RegRm32Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, args = ['Reg32 reg', 'RegRm32Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, args = ['Reg32 reg', 'RegRm32Disp32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm32Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm32Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'RegRm32Disp32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm32Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm32Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'ERegRm32Disp32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm32Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm32Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'ERegRm32Disp32 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, args = ['Reg32 reg', 'SIB<RegRm32Indir, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, args = ['Reg32 reg', 'SIB<RegRm32Disp8, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, args = ['Reg32 reg', 'SIB<RegRm32Disp32, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'SIB<RegRm32Indir, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'SIB<RegRm32Disp8, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args = ['EReg32 reg', 'SIB<RegRm32Disp32, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'SIB<ERegRm32Indir, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'SIB<ERegRm32Disp8, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args = ['Reg32 reg', 'SIB<ERegRm32Disp32, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'SIB<ERegRm32Indir, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'SIB<ERegRm32Disp8, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args = ['EReg32 reg', 'SIB<ERegRm32Disp32, Reg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], args = ['Reg32 reg', 'SIB<RegRm32Indir, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_X], args = ['Reg32 reg', 'SIB<RegRm32Disp8, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], args = ['Reg32 reg', 'SIB<RegRm32Disp32, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args = ['EReg32 reg', 'SIB<RegRm32Indir, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RX], args = ['EReg32 reg', 'SIB<RegRm32Disp8, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args = ['EReg32 reg', 'SIB<RegRm32Disp32, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args = ['Reg32 reg', 'SIB<ERegRm32Indir, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_XB], args = ['Reg32 reg', 'SIB<ERegRm32Disp8, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args = ['Reg32 reg', 'SIB<ERegRm32Disp32, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args = ['EReg32 reg', 'SIB<ERegRm32Indir, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b00, 'reg.id', 0b100), imm = arr('imm', 1)),
        *instruction(inst, prefix=[REX_RXB], args = ['EReg32 reg', 'SIB<ERegRm32Disp8, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b01, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args = ['EReg32 reg', 'SIB<ERegRm32Disp32, EReg32> rm', 'IMM8 imm'], sib=sib, mod_rm = mod_rm(0b10, 'reg.id', 0b100), imm = arr('imm', 1), disp=arr('rm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm16 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm16Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm16Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args = ['Reg16 reg', 'RegRm16Disp16 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm16 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm16Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm16Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args = ['EReg16 reg', 'RegRm16Disp16 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm16 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm16Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm16Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args = ['Reg16 reg', 'ERegRm16Disp16 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 2)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm16 rm', 'IMM8 imm'], mod_rm = mod_rm(0b11, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm16Indir rm', 'IMM8 imm'], mod_rm = mod_rm(0b00, 'reg.id', 'rm.id'), imm = arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm16Disp8 rm', 'IMM8 imm'], mod_rm = mod_rm(0b01, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args = ['EReg16 reg', 'ERegRm16Disp16 rm', 'IMM8 imm'], mod_rm = mod_rm(0b10, 'reg.id', 'rm.id'), imm = arr('imm', 1), disp=arr('rm.disp', 2)),
    ],
    'm32': lambda: [
        *instruction(inst, mod_rm=mod_rm(0b11, inst.reg_const, 'rm.id'), args=['RegRm32 rm']),
    ],
    'xmm,r/m32': lambda: [
        *instruction(inst, args=['XMM xmm', 'RegRm32 rm'], mod_rm=mod_rm(0b11, 'xmm.id', 'rm.id')),
        *instruction(inst, args=['XMM xmm', 'Reg32 rm'], mod_rm=mod_rm(0b11, 'xmm.id', 'rm.id')),
        *instruction(inst, args=['XMM xmm', 'RegRm32Indir rm'], mod_rm=mod_rm(0b00, 'xmm.id', 'rm.id')),
        *instruction(inst, args=['XMM xmm', 'RegRm32Disp8 rm'], mod_rm=mod_rm(0b01, 'xmm.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['XMM xmm', 'RegRm32Disp32 rm'], mod_rm=mod_rm(0b10, 'xmm.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm32 rm'], mod_rm=mod_rm(0b11, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'Reg32 rm'], mod_rm=mod_rm(0b11, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm32Indir rm'], mod_rm=mod_rm(0b00, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm32Disp8 rm'], mod_rm=mod_rm(0b01, 'xmm.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm32Disp32 rm'], mod_rm=mod_rm(0b10, 'xmm.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm32 rm'], mod_rm=mod_rm(0b11, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'EReg32 rm'], mod_rm=mod_rm(0b11, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm32Indir rm'], mod_rm=mod_rm(0b00, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm32Disp8 rm'], mod_rm=mod_rm(0b01, 'xmm.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm32Disp32 rm'], mod_rm=mod_rm(0b10, 'xmm.id', 'rm.id'), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm32 rm'], mod_rm=mod_rm(0b11, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'EReg32 rm'], mod_rm=mod_rm(0b11, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm32Indir rm'], mod_rm=mod_rm(0b00, 'xmm.id', 'rm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm32Disp8 rm'], mod_rm=mod_rm(0b01, 'xmm.id', 'rm.id'), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm32Disp32 rm'], mod_rm=mod_rm(0b10, 'xmm.id', 'rm.id'), disp=arr('rm.disp', 4)),

        *instruction(inst, args=['XMM xmm', 'SIB<RegRm32Indir, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, args=['XMM xmm', 'SIB<RegRm32Disp8, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, args=['XMM xmm', 'SIB<RegRm32Disp32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm32Indir, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm32Disp8, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm32Disp32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm32Indir, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm32Disp8, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm32Disp32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Indir, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Disp8, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Disp32, Reg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_X], args=['XMM xmm', 'SIB<RegRm32Indir, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_X], args=['XMM xmm', 'SIB<RegRm32Disp8, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_X], args=['XMM xmm', 'SIB<RegRm32Disp32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm32Indir, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm32Disp8, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm32Disp32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm32Indir, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm32Disp8, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm32Disp32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('rm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Indir, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Disp8, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('rm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Disp32, EReg32> rm'], sib=sib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('rm.disp', 4)),
    ],
    **{k: lambda: [
        *instruction(inst, args=['XMM xmm', 'XMMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, args=['XMM xmm', 'XMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, args=['XMM xmm', 'RegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, args=['XMM xmm', 'RegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, args=['XMM xmm', 'RegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'XMMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'XMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'EXMMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'EXMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'EXMMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'EXMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'XMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'XMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'RegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'RegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'RegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'XMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'XMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'EXMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'EXMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'EXMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'EXMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'YMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'YMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'RegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'RegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'RegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'YMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'YMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'EYMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'EYMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'EYMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'EYMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
    ] for k in ['xmm,xmm/m128', 'xmm,xmm/m64', 'xmm,xmm/m32']},
    **{k: lambda: [
        *instruction(inst, args=['XMMM xmmm', 'XMM xmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, args=['RegRm64Indir xmmm', 'XMM xmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, args=['RegRm64Disp8 xmmm', 'XMM xmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, args=['RegRm64Disp32 xmmm', 'XMM xmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['XMMM xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['RegRm64Indir xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['RegRm64Disp8 xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['RegRm64Disp32 xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['EXMMM xmmm', 'XMM xmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm64Indir xmmm', 'XMM xmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm64Disp8 xmmm', 'XMM xmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm64Disp32 xmmm', 'XMM xmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMMM xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['ERegRm64Indir xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['ERegRm64Disp8 xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['ERegRm64Disp32 xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['SIB<RegRm64Indir, Reg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_R], args=['SIB<RegRm64Disp8, Reg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['SIB<RegRm64Disp32, Reg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm64Indir, Reg64> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm64Disp8, Reg64> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm64Disp32, Reg64> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['SIB<ERegRm64Indir, Reg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], args=['SIB<ERegRm64Disp8, Reg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['SIB<ERegRm64Disp32, Reg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args=['SIB<RegRm64Indir, EReg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], args=['SIB<RegRm64Disp8, EReg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args=['SIB<RegRm64Disp32, EReg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Indir, EReg64> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Disp8, EReg64> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Disp32, EReg64> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args=['SIB<ERegRm64Indir, EReg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], args=['SIB<ERegRm64Disp8, EReg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args=['SIB<ERegRm64Disp32, EReg64> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['RegRm32Indir xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['RegRm32Disp8 xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['RegRm32Disp32 xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Indir xmmm', 'XMM xmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Disp8 xmmm', 'XMM xmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Disp32 xmmm', 'XMM xmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['ERegRm32Indir xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['ERegRm32Disp8 xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['ERegRm32Disp32 xmmm', 'EXMM xmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['SIB<RegRm32Indir, Reg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['SIB<RegRm32Disp8, Reg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['SIB<RegRm32Disp32, Reg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['SIB<ERegRm32Indir, Reg32> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['SIB<ERegRm32Disp8, Reg32> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['SIB<ERegRm32Disp32, Reg32> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['SIB<ERegRm32Indir, Reg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['SIB<ERegRm32Disp8, Reg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['SIB<ERegRm32Disp32, Reg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['SIB<RegRm32Indir, EReg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['SIB<RegRm32Disp8, EReg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['SIB<RegRm32Disp32, EReg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Indir, EReg32> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Disp8, EReg32> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Disp32, EReg32> xmmm', 'XMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['SIB<ERegRm32Indir, EReg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['SIB<ERegRm32Disp8, EReg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['SIB<ERegRm32Disp32, EReg32> xmmm', 'EXMM xmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMMM xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['RegRm64Indir xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['RegRm64Disp8 xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['RegRm64Disp32 xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['XMMM xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['RegRm64Indir xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['RegRm64Disp8 xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['RegRm64Disp32 xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['EXMMM xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['ERegRm64Indir xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['ERegRm64Disp8 xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['ERegRm64Disp32 xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMMM xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['ERegRm64Indir xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['ERegRm64Disp8 xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['ERegRm64Disp32 xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['SIB<RegRm64Indir, Reg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['SIB<RegRm64Disp8, Reg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['SIB<RegRm64Disp32, Reg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['SIB<ERegRm64Indir, Reg64> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['SIB<ERegRm64Disp8, Reg64> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['SIB<ERegRm64Disp32, Reg64> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['SIB<ERegRm64Indir, Reg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp8, Reg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp32, Reg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['SIB<RegRm64Indir, EReg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['SIB<RegRm64Disp8, EReg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['SIB<RegRm64Disp32, EReg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['SIB<ERegRm64Indir, EReg64> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp8, EReg64> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp32, EReg64> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['SIB<ERegRm64Indir, EReg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp8, EReg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp32, EReg64> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['RegRm32Indir xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['RegRm32Disp8 xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['RegRm32Disp32 xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['ERegRm32Indir xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['ERegRm32Disp8 xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['ERegRm32Disp32 xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['ERegRm32Indir xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['ERegRm32Disp8 xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['ERegRm32Disp32 xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['SIB<RegRm32Indir, Reg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['SIB<RegRm32Disp8, Reg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('R', 'xmm_extra.id'), args=['SIB<RegRm32Disp32, Reg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['SIB<ERegRm32Indir, Reg32> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['SIB<ERegRm32Disp8, Reg32> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('B', 'xmm_extra.id'), args=['SIB<ERegRm32Disp32, Reg32> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['SIB<ERegRm32Indir, Reg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp8, Reg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp32, Reg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RX', 'xmm_extra.id'), args=['SIB<RegRm32Indir, EReg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RX', 'xmm_extra.id'), args=['SIB<RegRm32Disp8, EReg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RX', 'xmm_extra.id'), args=['SIB<RegRm32Disp32, EReg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('XB', 'xmm_extra.id'), args=['SIB<ERegRm32Indir, EReg32> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('XB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp8, EReg32> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('XB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp32, EReg32> xmmm', 'XMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RXB', 'xmm_extra.id'), args=['SIB<ERegRm32Indir, EReg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RXB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp8, EReg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('RXB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp32, EReg32> xmmm', 'EXMM xmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMMM xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['RegRm64Indir xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['RegRm64Disp8 xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['RegRm64Disp32 xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['YMMM xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['RegRm64Indir xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['RegRm64Disp8 xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['RegRm64Disp32 xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['EYMMM xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['ERegRm64Indir xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['ERegRm64Disp8 xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['ERegRm64Disp32 xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMMM xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['ERegRm64Indir xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['ERegRm64Disp8 xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['ERegRm64Disp32 xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['SIB<RegRm64Indir, Reg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['SIB<RegRm64Disp8, Reg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['SIB<RegRm64Disp32, Reg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['SIB<ERegRm64Indir, Reg64> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp8, Reg64> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp32, Reg64> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['SIB<ERegRm64Indir, Reg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp8, Reg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp32, Reg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['SIB<RegRm64Indir, EReg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['SIB<RegRm64Disp8, EReg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['SIB<RegRm64Disp32, EReg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['SIB<ERegRm64Indir, EReg64> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp8, EReg64> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp32, EReg64> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['SIB<ERegRm64Indir, EReg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp8, EReg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['SIB<ERegRm64Disp32, EReg64> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['RegRm32Indir xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['RegRm32Disp8 xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['RegRm32Disp32 xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['ERegRm32Indir xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['ERegRm32Disp8 xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['ERegRm32Disp32 xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['ERegRm32Indir xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['ERegRm32Disp8 xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['ERegRm32Disp32 xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['SIB<RegRm32Indir, Reg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['SIB<RegRm32Disp8, Reg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LR', 'xmm_extra.id'), args=['SIB<RegRm32Disp32, Reg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['SIB<ERegRm32Indir, Reg32> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp8, Reg32> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp32, Reg32> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['SIB<ERegRm32Indir, Reg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp8, Reg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp32, Reg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRX', 'xmm_extra.id'), args=['SIB<RegRm32Indir, EReg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRX', 'xmm_extra.id'), args=['SIB<RegRm32Disp8, EReg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRX', 'xmm_extra.id'), args=['SIB<RegRm32Disp32, EReg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LXB', 'xmm_extra.id'), args=['SIB<ERegRm32Indir, EReg32> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LXB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp8, EReg32> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LXB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp32, EReg32> xmmm', 'YMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRXB', 'xmm_extra.id'), args=['SIB<ERegRm32Indir, EReg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRXB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp8, EReg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', prefix=[SZOVRD], vex=VEX('LRXB', 'xmm_extra.id'), args=['SIB<ERegRm32Disp32, EReg32> xmmm', 'EYMM xmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
    ] for k in ['xmm/m128,xmm', 'xmm/m64,xmm', 'xmm/m32,xmm']},
    'xmm,xmm': lambda: [
        *instruction(inst, args=['XMM xmm', 'XMMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, args=['XMM xmm', 'XMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'XMMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'XMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'EXMMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'EXMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'EXMMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'EXMM xmmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'XMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'XMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'XMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'XMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'EXMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'EXMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'EXMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'EXMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'YMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'YMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'YMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'YMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'EYMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'EYMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'EYMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'EYMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'xmm.id', 'xmmm.id')),
    ],
    **{k: lambda: [
        *instruction(inst, args=['XMM xmm', 'RegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, args=['XMM xmm', 'RegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, args=['XMM xmm', 'RegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'RegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'RegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['XMM xmm', 'RegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'RegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'ERegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'ERegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<RegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['XMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EXMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'RegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'RegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['YMM xmm', 'RegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'RegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'ERegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'xmm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'ERegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'xmm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<RegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['YMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EYMM xmm', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('xmmm.disp', 4)),
    
    ] for k in ['xmm,m64', 'xmm,m32', 'xmm,m16']},
    **{k: lambda: [
        *instruction(inst, args=['Reg32 reg', 'XMMM xmmm'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, args=['Reg32 reg', 'Reg32 xmmm'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, args=['Reg32 reg', 'RegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, args=['Reg32 reg', 'RegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, args=['Reg32 reg', 'RegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'XMMM xmmm'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'Reg32 xmmm'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'RegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'RegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'RegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'EXMMM xmmm'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'EReg32 xmmm'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'ERegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'ERegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'ERegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'EXMMM xmmm'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'EReg32 xmmm'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'ERegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'ERegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'ERegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'SIB<RegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'SIB<RegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EReg32 reg', 'SIB<RegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'SIB<ERegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'SIB<ERegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['Reg32 reg', 'SIB<ERegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'SIB<ERegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'SIB<ERegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EReg32 reg', 'SIB<ERegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args=['EReg32 reg', 'SIB<RegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], args=['EReg32 reg', 'SIB<RegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args=['EReg32 reg', 'SIB<RegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['Reg32 reg', 'SIB<ERegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['Reg32 reg', 'SIB<ERegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['Reg32 reg', 'SIB<ERegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args=['EReg32 reg', 'SIB<ERegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], args=['EReg32 reg', 'SIB<ERegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args=['EReg32 reg', 'SIB<ERegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg32 reg', 'RegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg32 reg', 'RegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg32 reg', 'RegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg32 reg', 'ERegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg32 reg', 'ERegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg32 reg', 'ERegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg32 reg', 'ERegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg32 reg', 'ERegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg32 reg', 'ERegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg32 reg', 'SIB<RegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg32 reg', 'SIB<RegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EReg32 reg', 'SIB<RegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg32 reg', 'SIB<ERegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg32 reg', 'SIB<ERegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['Reg32 reg', 'SIB<ERegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg32 reg', 'SIB<ERegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg32 reg', 'SIB<ERegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EReg32 reg', 'SIB<ERegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EReg32 reg', 'SIB<RegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EReg32 reg', 'SIB<RegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EReg32 reg', 'SIB<RegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['Reg32 reg', 'SIB<ERegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['Reg32 reg', 'SIB<ERegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['Reg32 reg', 'SIB<ERegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EReg32 reg', 'SIB<ERegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EReg32 reg', 'SIB<ERegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EReg32 reg', 'SIB<ERegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['Reg32 reg', 'XMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['Reg32 reg', 'Reg32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['Reg32 reg', 'RegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['Reg32 reg', 'RegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('', 'xmm_extra.id'), args=['Reg32 reg', 'RegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'XMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'Reg32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'EXMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'EReg32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'EXMMM xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'EReg32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm64Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm64Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm64Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Indir, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Indir, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm32Indir xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm32Disp8 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm32Disp32 xmmm', 'XMM xmm_extra = XMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('R', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('B', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Indir, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('XB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Indir, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('RXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'XMM xmm_extra = XMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['Reg32 reg', 'YMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['Reg32 reg', 'Reg32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['Reg32 reg', 'RegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['Reg32 reg', 'RegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('L', 'xmm_extra.id'), args=['Reg32 reg', 'RegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'YMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'Reg32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'EYMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'EReg32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'EYMMM xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'EReg32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b11, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm64Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm64Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm64Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Indir, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Disp8, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Disp32, Reg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Indir, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Disp8, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm64Disp32, EReg64> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'RegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'ERegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm32Indir xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b00, 'reg.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm32Disp8 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b01, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'ERegRm32Disp32 xmmm', 'YMM xmm_extra = YMM0'], mod_rm=mod_rm(0b10, 'reg.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LR', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Indir, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Disp8, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Disp32, Reg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRX', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<RegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LXB', 'xmm_extra.id'), args=['Reg32 reg', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Indir, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b00, 'reg.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Disp8, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b01, 'reg.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], mnemonic=f'V{inst.mnemonic}', vex=VEX('LRXB', 'xmm_extra.id'), args=['EReg32 reg', 'SIB<ERegRm32Disp32, EReg32> xmmm', 'YMM xmm_extra = YMM0'], sib=ssesib, mod_rm=mod_rm(0b10, 'reg.id', 0b100), disp=arr('xmmm.disp', 4)),
    ] for k in ['r32,xmm/m64', 'r32,xmm/m32']},
    **{k: lambda: [
        *instruction(inst, args=['MM mm', 'XMMM xmmm'], mod_rm=mod_rm(0b11, 'mm.id', 'xmmm.id')),
        *instruction(inst, args=['MM mm', 'RegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'mm.id', 'xmmm.id')),
        *instruction(inst, args=['MM mm', 'RegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'mm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, args=['MM mm', 'RegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'mm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_B], args=['MM mm', 'EXMMM xmmm'], mod_rm=mod_rm(0b11, 'mm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'ERegRm64Indir xmmm'], mod_rm=mod_rm(0b00, 'mm.id', 'xmmm.id')),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'ERegRm64Disp8 xmmm'], mod_rm=mod_rm(0b01, 'mm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'ERegRm64Disp32 xmmm'], mod_rm=mod_rm(0b10, 'mm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[REX_B], args=['MM mm', 'SIB<ERegRm64Indir, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'SIB<ERegRm64Disp8, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'SIB<ERegRm64Disp32, Reg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['MM mm', 'SIB<ERegRm64Indir, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['MM mm', 'SIB<ERegRm64Disp8, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['MM mm', 'SIB<ERegRm64Disp32, EReg64> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'ERegRm32Indir xmmm'], mod_rm=mod_rm(0b00, 'mm.id', 'xmmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'ERegRm32Disp8 xmmm'], mod_rm=mod_rm(0b01, 'mm.id', 'xmmm.id'), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'ERegRm32Disp32 xmmm'], mod_rm=mod_rm(0b10, 'mm.id', 'xmmm.id'), disp=arr('xmmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'SIB<ERegRm32Indir, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'SIB<ERegRm32Disp8, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'SIB<ERegRm32Disp32, Reg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['MM mm', 'SIB<ERegRm32Indir, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['MM mm', 'SIB<ERegRm32Disp8, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['MM mm', 'SIB<ERegRm32Disp32, EReg32> xmmm'], sib=ssesib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('xmmm.disp', 4)),
    ] for k in ['mm,xmm/m64', 'mm,xmm/m128']},
    'xmm,mm/m64': lambda: [
        *instruction(inst, args=['XMM xmm', 'MMM mmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'mmm.id')),
        *instruction(inst, args=['XMM xmm', 'MM mmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'mmm.id')),
        *instruction(inst, args=['XMM xmm', 'RegRm64Indir mmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'mmm.id')),
        *instruction(inst, args=['XMM xmm', 'RegRm64Disp8 mmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, args=['XMM xmm', 'RegRm64Disp32 mmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'MMM mmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'mmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'MM mmm'], mod_rm=mod_rm(0b11, 'xmm.id', 'mmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Indir mmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'mmm.id')),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Disp8 mmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'RegRm64Disp32 mmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Indir mmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'mmm.id')),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Disp8 mmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'ERegRm64Disp32 mmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Indir mmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'mmm.id')),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Disp8 mmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'ERegRm64Disp32 mmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Indir, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Disp8, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_R], args=['EXMM xmm', 'SIB<RegRm64Disp32, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Indir, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Disp8, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['XMM xmm', 'SIB<ERegRm64Disp32, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Indir, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Disp8, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_RB], args=['EXMM xmm', 'SIB<ERegRm64Disp32, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Indir, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Disp8, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_RX], args=['EXMM xmm', 'SIB<RegRm64Disp32, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Indir, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Disp8, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['XMM xmm', 'SIB<ERegRm64Disp32, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Indir, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Disp8, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_RXB], args=['EXMM xmm', 'SIB<ERegRm64Disp32, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Indir mmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'mmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Disp8 mmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'RegRm32Disp32 mmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Indir mmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'mmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Disp8 mmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'ERegRm32Disp32 mmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Indir mmm'], mod_rm=mod_rm(0b00, 'xmm.id', 'mmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Disp8 mmm'], mod_rm=mod_rm(0b01, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'ERegRm32Disp32 mmm'], mod_rm=mod_rm(0b10, 'xmm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Indir, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Disp8, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_R], args=['EXMM xmm', 'SIB<RegRm32Disp32, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Indir, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Disp8, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['XMM xmm', 'SIB<ERegRm32Disp32, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Indir, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Disp8, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RB], args=['EXMM xmm', 'SIB<ERegRm32Disp32, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Indir, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Disp8, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RX], args=['EXMM xmm', 'SIB<RegRm32Disp32, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Indir, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Disp8, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['XMM xmm', 'SIB<ERegRm32Disp32, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Indir, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'xmm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Disp8, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'xmm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_RXB], args=['EXMM xmm', 'SIB<ERegRm32Disp32, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'xmm.id', 0b100), disp=arr('mmm.disp', 4)),
    ],
    'xmm,imm8': lambda: [
        *instruction(inst, args=['XMMM xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1)),
        *instruction(inst, args=['XMM xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1)),
        *instruction(inst, args=['RegRm64Indir xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1)),
        *instruction(inst, args=['RegRm64Disp8 xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1), disp=arr('xmmm.disp', 1)),
        *instruction(inst, args=['RegRm64Disp32 xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1), disp=arr('xmmm.disp', 4)),
        *instruction(inst, args=['SIB<RegRm64Indir, Reg64> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1)),
        *instruction(inst, args=['SIB<RegRm64Disp8, Reg64> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1), disp=arr('xmmm.disp', 1)),
        *instruction(inst, args=['SIB<RegRm64Disp32, Reg64> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_B], args=['EXMMM xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args=['EXMM xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b11, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm64Indir xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm64Disp8 xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm64Disp32 xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Indir, EReg64> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Disp8, EReg64> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Disp32, EReg64> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm32Indir xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm32Disp8 xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['RegRm32Disp32 xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD], args=['SIB<RegRm32Indir, Reg32> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['SIB<RegRm32Disp8, Reg32> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD], args=['SIB<RegRm32Disp32, Reg32> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Indir xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Disp8 xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Disp32 xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'xmmm.id'), imm=arr('imm', 1), disp=arr('xmmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Indir, EReg32> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b00, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Disp8, EReg32> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b01, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1), disp=arr('xmmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Disp32, EReg32> xmmm', 'IMM8 imm'], mod_rm=mod_rm(0b10, inst.reg_const, 'xmmm.id'), sib=ssesib, imm=arr('imm', 1), disp=arr('xmmm.disp', 4)),
    ],
    'mm,mm/m64': lambda: [
        *instruction(inst, args=['MM mm', 'MMM mmm'], mod_rm=mod_rm(0b11, 'mm.id', 'mmm.id')),
        *instruction(inst, args=['MM mm', 'MM mmm'], mod_rm=mod_rm(0b11, 'mm.id', 'mmm.id')),
        *instruction(inst, args=['MM mm', 'RegRm64Indir mmm'], mod_rm=mod_rm(0b00, 'mm.id', 'mmm.id')),
        *instruction(inst, args=['MM mm', 'RegRm64Disp8 mmm'], mod_rm=mod_rm(0b01, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, args=['MM mm', 'RegRm64Disp32 mmm'], mod_rm=mod_rm(0b10, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[REX_B], args=['MM mm', 'ERegRm64Indir mmm'], mod_rm=mod_rm(0b00, 'mm.id', 'mmm.id')),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'ERegRm64Disp8 mmm'], mod_rm=mod_rm(0b01, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'ERegRm64Disp32 mmm'], mod_rm=mod_rm(0b10, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[REX_B], args=['MM mm', 'SIB<ERegRm64Indir, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'SIB<ERegRm64Disp8, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['MM mm', 'SIB<ERegRm64Disp32, Reg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['MM mm', 'SIB<ERegRm64Indir, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['MM mm', 'SIB<ERegRm64Disp8, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['MM mm', 'SIB<ERegRm64Disp32, EReg64> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'ERegRm32Indir mmm'], mod_rm=mod_rm(0b00, 'mm.id', 'mmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'ERegRm32Disp8 mmm'], mod_rm=mod_rm(0b01, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'ERegRm32Disp32 mmm'], mod_rm=mod_rm(0b10, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'SIB<ERegRm32Indir, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'SIB<ERegRm32Disp8, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['MM mm', 'SIB<ERegRm32Disp32, Reg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['MM mm', 'SIB<ERegRm32Indir, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['MM mm', 'SIB<ERegRm32Disp8, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['MM mm', 'SIB<ERegRm32Disp32, EReg32> mmm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('mmm.disp', 4)),
    ],
    'mm/m64,mm': lambda: [
        *instruction(inst, args=['MMM mmm', 'MM mm'], mod_rm=mod_rm(0b11, 'mm.id', 'mmm.id')),
        *instruction(inst, args=['RegRm64Indir mmm', 'MM mm'], mod_rm=mod_rm(0b00, 'mm.id', 'mmm.id')),
        *instruction(inst, args=['RegRm64Disp8 mmm', 'MM mm'], mod_rm=mod_rm(0b01, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, args=['RegRm64Disp32 mmm', 'MM mm'], mod_rm=mod_rm(0b10, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[REX_B], args=['ERegRm64Indir mmm', 'MM mm'], mod_rm=mod_rm(0b00, 'mm.id', 'mmm.id')),
        *instruction(inst, prefix=[REX_B], args=['ERegRm64Disp8 mmm', 'MM mm'], mod_rm=mod_rm(0b01, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['ERegRm64Disp32 mmm', 'MM mm'], mod_rm=mod_rm(0b10, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm64Indir, Reg64> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm64Disp8, Reg64> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_B], args=['SIB<ERegRm64Disp32, Reg64> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Indir, EReg64> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Disp8, EReg64> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[REX_XB], args=['SIB<ERegRm64Disp32, EReg64> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Indir mmm', 'MM mm'], mod_rm=mod_rm(0b00, 'mm.id', 'mmm.id')),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Disp8 mmm', 'MM mm'], mod_rm=mod_rm(0b01, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['ERegRm32Disp32 mmm', 'MM mm'], mod_rm=mod_rm(0b10, 'mm.id', 'mmm.id'), disp=arr('mmm.disp', 4)),

        *instruction(inst, prefix=[SZOVRD, REX_B], args=['SIB<ERegRm32Indir, Reg32> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['SIB<ERegRm32Disp8, Reg32> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_B], args=['SIB<ERegRm32Disp32, Reg32> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('mmm.disp', 4)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Indir, EReg32> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b00, 'mm.id', 0b100)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Disp8, EReg32> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b01, 'mm.id', 0b100), disp=arr('mmm.disp', 1)),
        *instruction(inst, prefix=[SZOVRD, REX_XB], args=['SIB<ERegRm32Disp32, EReg32> mmm', 'MM mm'], sib=mmxsib, mod_rm=mod_rm(0b10, 'mm.id', 0b100), disp=arr('mmm.disp', 4)),
    ],
    }

    inst_generator = generator.get(','.join(inst.ops))

    if inst_generator:
        return inst_generator()
    else:
        raise Exception(f'TODO {signature}')

def cat(text, ident = '', ident_inc = '    '):
    if type(text) == list:
        return ident_inc + (ident).join([cat(t, ident + ident_inc, ident_inc) for t in text])
    else:
        return text + '\n'

print("""#pragma once

#include <array>
#include <cstdint>
#include <type_traits>

#define U8(BYTE) static_cast<uint8_t>(BYTE)

namespace x86{
namespace{

typedef uint8_t RegId;

template <size_t INSTRUCTION_SIZE, bool LOCKABLE>
struct Instruction: std::array<uint8_t, INSTRUCTION_SIZE>{};

static constexpr uint8_t mod_rm(uint8_t mod, uint8_t reg, uint8_t rm){
    return (mod & 0b11) << 6 | (reg & 0b111) << 3 | (rm & 0b111);
}

static constexpr uint8_t sib(uint8_t scale, uint8_t index, uint8_t base){
    return (scale & 0b11) << 6 | (index & 0b111) << 3 | (base & 0b111);
}

}

enum class RegisterType{
    GP,
    MMX,
    SSE,
    AVX,
    AVX512,
};

enum class RegisterMod{
    NONE = -1,
    INDIRECT = 0b00,
    SHORT_DISPLACEMENT = 0b01,
    LONG_DISPLACEMENT = 0b10,
    DIRECT = 0b11,
};

struct Empty{};

template <RegisterMod REGISTER_MOD, size_t REGISTER_SIZE>
struct DispSize{static constexpr size_t VALUE = 0;};

template <> struct DispSize<RegisterMod::SHORT_DISPLACEMENT, 16>{static constexpr size_t VALUE = 1;};
template <> struct DispSize<RegisterMod::SHORT_DISPLACEMENT, 32>{static constexpr size_t VALUE = 1;};
template <> struct DispSize<RegisterMod::SHORT_DISPLACEMENT, 64>{static constexpr size_t VALUE = 1;};
template <> struct DispSize<RegisterMod::LONG_DISPLACEMENT, 16>{static constexpr size_t VALUE = 2;};
template <> struct DispSize<RegisterMod::LONG_DISPLACEMENT, 32>{static constexpr size_t VALUE = 4;};
template <> struct DispSize<RegisterMod::LONG_DISPLACEMENT, 64>{static constexpr size_t VALUE = 4;};

template <RegisterType REGISTER_TYPE, RegisterMod REGISTER_MOD, size_t REGISTER_SIZE, bool REGISTER_EXT = false, typename SIB = Empty>
struct Register;

template <RegisterMod REGISTER_MOD, size_t REGISTER_SIZE, bool REGISTER_EXT, typename SIB>
struct Register<RegisterType::GP, REGISTER_MOD, REGISTER_SIZE, REGISTER_EXT, SIB>{
    static constexpr RegisterType TYPE = RegisterType::GP;
    static constexpr RegisterMod MOD = REGISTER_MOD;
    static constexpr size_t SIZE = REGISTER_SIZE;
    static constexpr bool EXT = REGISTER_EXT;

    static constexpr bool INDIRECT = REGISTER_MOD == RegisterMod::INDIRECT
        || REGISTER_MOD == RegisterMod::SHORT_DISPLACEMENT
        || REGISTER_MOD == RegisterMod::LONG_DISPLACEMENT;

    static constexpr bool HAVE_SIB = not std::is_same<SIB, Empty>::value;

    static constexpr size_t DISPLACEMENT_SIZE = DispSize<REGISTER_MOD, REGISTER_SIZE>::VALUE;

    RegId id;
    std::array<uint8_t, DISPLACEMENT_SIZE> disp{};
    SIB index{};
    std::conditional<HAVE_SIB, uint8_t, Empty>::type scale{};

    template <typename Direct = Register<RegisterType::GP, RegisterMod::DIRECT, REGISTER_SIZE, REGISTER_EXT, SIB>>
    constexpr std::enable_if<REGISTER_MOD == RegisterMod::NONE, Direct>::type
    direct() const noexcept{
        return Direct{
            .id = id,
            .disp = disp,
            .index = index,
            .scale = scale,
        };
    }

    template <typename Direct = Register<RegisterType::GP, RegisterMod::INDIRECT, REGISTER_SIZE, REGISTER_EXT, SIB>>
    constexpr std::enable_if<REGISTER_MOD == RegisterMod::NONE, Direct>::type
    indirect() const noexcept{
        return Direct{
            .id = id,
            .disp = disp,
            .index = index,
            .scale = scale,
        };
    }

    template <uint8_t SCALE, typename SIB_Register = Register<RegisterType::GP, REGISTER_MOD, REGISTER_SIZE, REGISTER_EXT, Register<RegisterType::GP, RegisterMod::NONE, REGISTER_SIZE, REGISTER_EXT, Empty>>>
    constexpr std::enable_if<not HAVE_SIB and INDIRECT, SIB_Register>::type
    sib(Register<RegisterType::GP, RegisterMod::NONE, REGISTER_SIZE, REGISTER_EXT, Empty> index) const noexcept{
        static_assert(REGISTER_SIZE == 32 || REGISTER_SIZE == 64);
        static_assert(SCALE == 1 || SCALE == 2 || SCALE == 4 || SCALE == 8);

        return SIB_Register{
            .id = id,
            .disp = disp,
            .index = index,
            .scale = static_cast<uint8_t>((SCALE == 1) ? 0b00 : (SCALE == 2) ? 0b01 : (SCALE == 4) ? 0b10 : (SCALE == 8) ? 0b11 : 0),
        };
    }

    template <typename Displaced = Register<RegisterType::GP, RegisterMod::SHORT_DISPLACEMENT, REGISTER_SIZE, REGISTER_EXT, SIB>>
    constexpr std::enable_if<REGISTER_MOD == RegisterMod::NONE and Displaced::DISPLACEMENT_SIZE == 1, Displaced>::type
    disp8(int8_t disp) const noexcept{
        return Displaced{
            .id = id,
            .disp = {static_cast<uint8_t>(disp)},
            .index = index,
            .scale = scale,
        };
    }

    template <typename Displaced = Register<RegisterType::GP, RegisterMod::LONG_DISPLACEMENT, REGISTER_SIZE, REGISTER_EXT, SIB>>
    constexpr std::enable_if<REGISTER_MOD == RegisterMod::NONE and Displaced::DISPLACEMENT_SIZE == 2, Displaced>::type
    disp16(int16_t disp) const noexcept{
        return Displaced{
            .id = id,
            .disp = {
                static_cast<uint8_t>((disp >> 0) & 0xFF),
                static_cast<uint8_t>((disp >> 8) & 0xFF),
            },
            .index = index,
            .scale = scale,
        };
    }

    template <typename Displaced = Register<RegisterType::GP, RegisterMod::LONG_DISPLACEMENT, REGISTER_SIZE, REGISTER_EXT, SIB>>
    constexpr std::enable_if<REGISTER_MOD == RegisterMod::NONE and Displaced::DISPLACEMENT_SIZE == 4, Displaced>::type
    disp32(int32_t disp) const noexcept{
        return Displaced{
            .id = id,
            .disp = {
                static_cast<uint8_t>((disp >> 0) & 0xFF),
                static_cast<uint8_t>((disp >> 8) & 0xFF),
                static_cast<uint8_t>((disp >> 16) & 0xFF),
                static_cast<uint8_t>((disp >> 24) & 0xFF),
            },
            .index = index,
            .scale = scale,
        };
    }
};


template <>
struct Register<RegisterType::MMX, RegisterMod::NONE, 64>{
    RegId id;
};

template <>
struct Register<RegisterType::MMX, RegisterMod::DIRECT, 64>
    :public Register<RegisterType::MMX, RegisterMod::NONE, 64>{};


template <bool REGISTER_EXT>
struct Register<RegisterType::SSE, RegisterMod::NONE, 128, REGISTER_EXT>{
    RegId id;
};

template <bool REGISTER_EXT>
struct Register<RegisterType::SSE, RegisterMod::DIRECT, 128, REGISTER_EXT>
    :public Register<RegisterType::SSE, RegisterMod::NONE, 128, REGISTER_EXT>{};

template <bool REGISTER_EXT>
struct Register<RegisterType::AVX, RegisterMod::NONE, 256, REGISTER_EXT>{
    RegId id;
};

template <bool REGISTER_EXT>
struct Register<RegisterType::AVX, RegisterMod::DIRECT, 256, REGISTER_EXT>
    :public Register<RegisterType::AVX, RegisterMod::NONE, 256, REGISTER_EXT>{};

using Reg8 = Register<RegisterType::GP, RegisterMod::NONE, 8>;
using Reg16 = Register<RegisterType::GP, RegisterMod::NONE, 16>;
using Reg32 = Register<RegisterType::GP, RegisterMod::NONE, 32>;
using Reg64 = Register<RegisterType::GP, RegisterMod::NONE, 64>;
using EReg8 = Register<RegisterType::GP, RegisterMod::NONE, 8, true>;
using EReg16 = Register<RegisterType::GP, RegisterMod::NONE, 16, true>;
using EReg32 = Register<RegisterType::GP, RegisterMod::NONE, 32, true>;
using EReg64 = Register<RegisterType::GP, RegisterMod::NONE, 64, true>;

using RegRm8 = Register<RegisterType::GP, RegisterMod::DIRECT, 8>;
using RegRm16 = Register<RegisterType::GP, RegisterMod::DIRECT, 16>;
using RegRm32 = Register<RegisterType::GP, RegisterMod::DIRECT, 32>;
using RegRm64 = Register<RegisterType::GP, RegisterMod::DIRECT, 64>;
using ERegRm8 = Register<RegisterType::GP, RegisterMod::DIRECT, 8, true>;
using ERegRm16 = Register<RegisterType::GP, RegisterMod::DIRECT, 16, true>;
using ERegRm32 = Register<RegisterType::GP, RegisterMod::DIRECT, 32, true>;
using ERegRm64 = Register<RegisterType::GP, RegisterMod::DIRECT, 64, true>;

using RegRm16Indir = Register<RegisterType::GP, RegisterMod::INDIRECT, 16>;
using RegRm32Indir = Register<RegisterType::GP, RegisterMod::INDIRECT, 32>;
using RegRm64Indir = Register<RegisterType::GP, RegisterMod::INDIRECT, 64>;
using ERegRm16Indir = Register<RegisterType::GP, RegisterMod::INDIRECT, 16, true>;
using ERegRm32Indir = Register<RegisterType::GP, RegisterMod::INDIRECT, 32, true>;
using ERegRm64Indir = Register<RegisterType::GP, RegisterMod::INDIRECT, 64, true>;

using RegRm16Disp8 = Register<RegisterType::GP, RegisterMod::SHORT_DISPLACEMENT, 16>;
using RegRm32Disp8 = Register<RegisterType::GP, RegisterMod::SHORT_DISPLACEMENT, 32>;
using RegRm64Disp8 = Register<RegisterType::GP, RegisterMod::SHORT_DISPLACEMENT, 64>;
using ERegRm16Disp8 = Register<RegisterType::GP, RegisterMod::SHORT_DISPLACEMENT, 16, true>;
using ERegRm32Disp8 = Register<RegisterType::GP, RegisterMod::SHORT_DISPLACEMENT, 32, true>;
using ERegRm64Disp8 = Register<RegisterType::GP, RegisterMod::SHORT_DISPLACEMENT, 64, true>;

using RegRm16Disp16 = Register<RegisterType::GP, RegisterMod::LONG_DISPLACEMENT, 16>;
using RegRm32Disp32 = Register<RegisterType::GP, RegisterMod::LONG_DISPLACEMENT, 32>;
using RegRm64Disp32 = Register<RegisterType::GP, RegisterMod::LONG_DISPLACEMENT, 64>;
using ERegRm16Disp16 = Register<RegisterType::GP, RegisterMod::LONG_DISPLACEMENT, 16, true>;
using ERegRm32Disp32 = Register<RegisterType::GP, RegisterMod::LONG_DISPLACEMENT, 32, true>;
using ERegRm64Disp32 = Register<RegisterType::GP, RegisterMod::LONG_DISPLACEMENT, 64, true>;

using MM = Register<RegisterType::MMX, RegisterMod::NONE, 64>;
using XMM = Register<RegisterType::SSE, RegisterMod::NONE, 128>;
using EXMM = Register<RegisterType::SSE, RegisterMod::NONE, 128, true>;
using YMM = Register<RegisterType::AVX, RegisterMod::NONE, 256>;
using EYMM = Register<RegisterType::AVX, RegisterMod::NONE, 256, true>;

using MMM = Register<RegisterType::MMX, RegisterMod::DIRECT, 64>;
using XMMM = Register<RegisterType::SSE, RegisterMod::DIRECT, 128>;
using EXMMM = Register<RegisterType::SSE, RegisterMod::DIRECT, 128, true>;
using YMMM = Register<RegisterType::AVX, RegisterMod::DIRECT, 256>;
using EYMMM = Register<RegisterType::AVX, RegisterMod::DIRECT, 256, true>;

using IMM8 = std::array<uint8_t, 1>;
using IMM16 = std::array<uint8_t, 2>;
using IMM32 = std::array<uint8_t, 4>;
using IMM64 = std::array<uint8_t, 8>;

using REL8 = std::array<uint8_t, 1>;
using REL16 = std::array<uint8_t, 2>;
using REL32 = std::array<uint8_t, 4>;
using REL64 = std::array<uint8_t, 8>;

template<typename T1, typename T2>
using SIB = Register<T1::TYPE, T1::MOD, T1::SIZE, T1::EXT, T2>;

constexpr auto AL = Reg8{0};
constexpr auto CL = Reg8{1};
constexpr auto DL = Reg8{2};
constexpr auto BL = Reg8{3};
constexpr auto AH = Reg8{4};
constexpr auto CH = Reg8{5};
constexpr auto DH = Reg8{6};
constexpr auto BH = Reg8{7};
constexpr auto R8B  = EReg8{0};
constexpr auto R9B  = EReg8{1};
constexpr auto R10B = EReg8{2};
constexpr auto R11B = EReg8{3};
constexpr auto R12B = EReg8{4};
constexpr auto R13B = EReg8{5};
constexpr auto R14B = EReg8{6};
constexpr auto R15B = EReg8{7};

constexpr auto AX = Reg16{0};
constexpr auto CX = Reg16{1};
constexpr auto DX = Reg16{2};
constexpr auto BX = Reg16{3};
constexpr auto SP = Reg16{4};
constexpr auto BP = Reg16{5};
constexpr auto SI = Reg16{6};
constexpr auto DI = Reg16{7};
constexpr auto R8W  = EReg16{0};
constexpr auto R9W  = EReg16{1};
constexpr auto R10W = EReg16{2};
constexpr auto R11W = EReg16{3};
constexpr auto R12W = EReg16{4};
constexpr auto R13W = EReg16{5};
constexpr auto R14W = EReg16{6};
constexpr auto R15W = EReg16{7};

constexpr auto EAX = Reg32{0};
constexpr auto ECX = Reg32{1};
constexpr auto EDX = Reg32{2};
constexpr auto EBX = Reg32{3};
constexpr auto ESP = Reg32{4};
constexpr auto EBP = Reg32{5};
constexpr auto ESI = Reg32{6};
constexpr auto EDI = Reg32{7};
constexpr auto R8D  = EReg32{0};
constexpr auto R9D  = EReg32{1};
constexpr auto R10D = EReg32{2};
constexpr auto R11D = EReg32{3};
constexpr auto R12D = EReg32{4};
constexpr auto R13D = EReg32{5};
constexpr auto R14D = EReg32{6};
constexpr auto R15D = EReg32{7};

constexpr auto RAX = Reg64{0};
constexpr auto RCX = Reg64{1};
constexpr auto RDX = Reg64{2};
constexpr auto RBX = Reg64{3};
constexpr auto RSP = Reg64{4};
constexpr auto RBP = Reg64{5};
constexpr auto RSI = Reg64{6};
constexpr auto RDI = Reg64{7};
constexpr auto R8  = EReg64{0};
constexpr auto R9  = EReg64{1};
constexpr auto R10 = EReg64{2};
constexpr auto R11 = EReg64{3};
constexpr auto R12 = EReg64{4};
constexpr auto R13 = EReg64{5};
constexpr auto R14 = EReg64{6};
constexpr auto R15 = EReg64{7};

constexpr auto MM0 = MM{0};
constexpr auto MM1 = MM{1};
constexpr auto MM2 = MM{2};
constexpr auto MM3 = MM{3};
constexpr auto MM4 = MM{4};
constexpr auto MM5 = MM{5};
constexpr auto MM6 = MM{6};
constexpr auto MM7 = MM{7};

constexpr auto XMM0 = XMM{0};
constexpr auto XMM1 = XMM{1};
constexpr auto XMM2 = XMM{2};
constexpr auto XMM3 = XMM{3};
constexpr auto XMM4 = XMM{4};
constexpr auto XMM5 = XMM{5};
constexpr auto XMM6 = XMM{6};
constexpr auto XMM7 = XMM{7};
constexpr auto XMM8 = EXMM{0};
constexpr auto XMM9 = EXMM{1};
constexpr auto XMM10 = EXMM{2};
constexpr auto XMM11 = EXMM{3};
constexpr auto XMM12 = EXMM{4};
constexpr auto XMM13 = EXMM{5};
constexpr auto XMM14 = EXMM{6};
constexpr auto XMM15 = EXMM{7};

constexpr auto YMM0 = YMM{0};
constexpr auto YMM1 = YMM{1};
constexpr auto YMM2 = YMM{2};
constexpr auto YMM3 = YMM{3};
constexpr auto YMM4 = YMM{4};
constexpr auto YMM5 = YMM{5};
constexpr auto YMM6 = YMM{6};
constexpr auto YMM7 = YMM{7};
constexpr auto YMM8 = EYMM{0};
constexpr auto YMM9 = EYMM{1};
constexpr auto YMM10 = EYMM{2};
constexpr auto YMM11 = EYMM{3};
constexpr auto YMM12 = EYMM{4};
constexpr auto YMM13 = EYMM{5};
constexpr auto YMM14 = EYMM{6};
constexpr auto YMM15 = EYMM{7};

constexpr IMM8 imm8(uint8_t val){
    return IMM8{val};
}

constexpr IMM16 imm16(uint16_t val){
    return IMM16{
        static_cast<uint8_t>((val >> 0) & 0xFF),
        static_cast<uint8_t>((val >> 8) & 0xFF),
    };
}

constexpr IMM32 imm32(uint32_t val){
    return IMM32{
        static_cast<uint8_t>((val >> 0) & 0xFF),
        static_cast<uint8_t>((val >> 8) & 0xFF),
        static_cast<uint8_t>((val >> 16) & 0xFF),
        static_cast<uint8_t>((val >> 24) & 0xFF),
    };
}

constexpr IMM64 imm64(uint64_t val){
    return IMM64{
        static_cast<uint8_t>((val >> 0) & 0xFF),
        static_cast<uint8_t>((val >> 8) & 0xFF),
        static_cast<uint8_t>((val >> 16) & 0xFF),
        static_cast<uint8_t>((val >> 24) & 0xFF),
        static_cast<uint8_t>((val >> 32) & 0xFF),
        static_cast<uint8_t>((val >> 40) & 0xFF),
        static_cast<uint8_t>((val >> 48) & 0xFF),
        static_cast<uint8_t>((val >> 56) & 0xFF),
    };
}


""")

for inst in insts:
    try:
        print(cat(generate_instruction(inst)))
    except Exception as e:
        print(f'// ERROR: {e}')

print('}')