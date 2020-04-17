# Taken from
# https://github.com/deadsy/py_z80/blob/master/z80da.py

#-----------------------------------------------------------------------------
"""
Z80 Disassembler
"""
#-----------------------------------------------------------------------------

_r = ('b', 'c', 'd', 'e', 'h', 'l', '(hl)', 'a')
_rp = ('bc', 'de', 'hl', 'sp')
_rp2 = ('bc', 'de', 'hl', 'af')
_cc = ('nz', 'z', 'nc', 'c', 'po', 'pe', 'p', 'm')
_alu = ('add', 'adc', 'sub', 'sbc', 'and', 'xor', 'or', 'cp')
_alux = ('a,', 'a,', '', 'a,', '', '', '', '')
_rot = ('rlc', 'rrc', 'rl', 'rr', 'sla', 'sra', 'sll', 'srl')
_rota = ('rlca', 'rrca', 'rla', 'rra', 'daa', 'cpl', 'scf', 'ccf')
_im = ('0', '0', '1', '2', '0', '0', '1', '2')
_bli = (
    ('ldi', 'ldd', 'ldir', 'lddr'), ('cpi', 'cpd', 'cpir', 'cpdr'),
    ('ini', 'ind', 'inir', 'indr'), ('outi', 'outd', 'otir', 'otdr')
)

#-----------------------------------------------------------------------------

def _da_normal(mem, pc):
    """
    Normal decode with no prefixes
    """
    m0 = mem[pc]
    m1 = mem[pc + 1]
    m2 = mem[pc + 2]
    x = (m0 >> 6) & 3
    y = (m0 >> 3) & 7
    z = (m0 >> 0) & 7
    p = (m0 >> 4) & 3
    q = (m0 >> 3) & 1
    n =  m1
    nn = (m2 << 8) + m1
    d = m1
    if d & 0x80:
        d = (d & 0x7f) - 128
    d = (pc + d + 2) & 0xffff

    if x == 0:
        if z == 0:
            if y == 0:
                return ('nop', '', 1)
            elif y == 1:
                return ('ex', 'af,af\'', 1)
            elif y == 2:
                return ('djnz', '%04x' % d, 2)
            elif y == 3:
                return ('jr', '%04x' % d, 2)
            else:
                return ('jr', '%s,%04x' % (_cc[y - 4], d), 2)
        elif z == 1:
            if q == 0:
                return ('ld', '%s,%04x' % (_rp[p], nn), 3)
            elif q == 1:
                return ('add', 'hl,%s' % _rp[p], 1)
        elif z == 2:
            if q == 0:
                if p == 0:
                    return ('ld', '(bc),a', 1)
                elif p == 1:
                    return ('ld', '(de),a', 1)
                elif p == 2:
                    return ('ld', '(%04x),hl' % nn, 3)
                else:
                    return ('ld', '(%04x),a' % nn, 3)
            else:
                if p == 0:
                    return ('ld', 'a,(bc)', 1)
                elif p == 1:
                    return ('ld', 'a,(de)', 1)
                elif p == 2:
                    return ('ld', 'hl,(%04x)' % nn, 3)
                else:
                    return ('ld', 'a,(%04x)' % nn, 3)
        elif z == 3:
            if q == 0:
                return ('inc', _rp[p], 1)
            else:
                return ('dec', _rp[p], 1)
        elif z == 4:
            return ('inc', _r[y], 1)
        elif z == 5:
            return ('dec', _r[y], 1)
        elif z == 6:
            return ('ld', '%s,%02x' % (_r[y], n), 2)
        else:
            return (_rota[y], '', 1)
    elif x == 1:
        if (z == 6) and (y == 6):
            return ('halt', '', 1)
        else:
            return ('ld', '%s,%s' % (_r[y], _r[z]), 1)
    elif x == 2:
        return (_alu[y], '%s%s' % (_alux[y], _r[z]), 1)
    else:
        if z == 0:
            return ('ret', _cc[y], 1)
        elif z == 1:
            if q == 0:
                return ('pop', _rp2[p], 1)
            else:
                if p == 0:
                    return ('ret', '', 1)
                elif p == 1:
                    return ('exx', '', 1)
                elif p == 2:
                    return ('jp', 'hl', 1)
                else:
                    return ('ld', 'sp,hl', 1)
        elif z == 2:
            return ('jp', '%s,%04x' % (_cc[y], nn), 3)
        elif z == 3:
            if y == 0:
                return ('jp', '%04x' % nn, 3)
            elif y == 2:
                return ('out', '(%02x),a' % n, 2)
            elif y == 3:
                return ('in', 'a,(%02x)' % n, 2)
            elif y == 4:
                return ('ex', '(sp),hl', 1)
            elif y == 5:
                return ('ex', 'de,hl', 1)
            elif y == 6:
                return ('di', '', 1)
            else:
                return ('ei', '', 1)
        elif z == 4:
            return ('call', '%s,%04x' % (_cc[y], nn), 3)
        elif z == 5:
            if q == 0:
                return ('push', _rp2[p], 1)
            else:
                if p == 0:
                    return ('call', '%04x' % nn, 3)
        elif z == 6:
            return (_alu[y], '%s%02x' % (_alux[y], n), 2)
        else:
            return ('rst', '%02x' % (y << 3), 1)

#-----------------------------------------------------------------------------

def _da_index(mem, pc, ir):
    """
    Decode with index register substitutions
    """
    m0 = mem[pc]
    m1 = mem[pc + 1]
    m2 = mem[pc + 2]
    x = (m0 >> 6) & 3
    y = (m0 >> 3) & 7
    z = (m0 >> 0) & 7
    p = (m0 >> 4) & 3
    q = (m0 >> 3) & 1
    n0 = m1
    n1 = m2
    nn = (m2 << 8) + m1
    d = m1
    if d & 0x80:
        d = (d & 0x7f) - 128
    sign = ('', '+')[d >= 0]
    dj = (pc + d + 2) & 0xffff

    # if using (hl) then: (hl)->(ix+d), h and l are unaffected.
    alt0_r = list(_r)
    alt0_r[6] = '(%s%s%02x)' % (ir, sign, d)

    # if not using (hl) then: hl->ix, h->ixh, l->ixl
    alt1_r = list(_r)
    alt1_r[4] = '%sh' % ir
    alt1_r[5] = '%sl' % ir

    alt_rp = list(_rp)
    alt_rp[2] = ir
    alt_rp2 = list(_rp2)
    alt_rp2[2] = ir

    if x == 0:
        if z == 0:
            if y == 0:
                return ('nop', '', 2)
            elif y == 1:
                return ('ex', 'af,af\'', 2)
            elif y == 2:
                return ('djnz', '%04x' % dj, 3)
            elif y == 3:
                return ('jr', '%04x' % dj, 3)
            else:
                return ('jr', '%s,%04x' % (_cc[y - 4], dj), 3)
        elif z == 1:
            if q == 0:
                return ('ld', '%s,%04x' % (alt_rp[p], nn), 4)
            elif q == 1:
                return ('add', '%s,%s' % (ir, alt_rp[p]), 2)
        elif z == 2:
            if q == 0:
                if p == 0:
                    return ('ld', '(bc),a', 2)
                elif p == 1:
                    return ('ld', '(de),a', 2)
                elif p == 2:
                    return ('ld', '(%04x),%s' % (nn, ir), 4)
                else:
                    return ('ld', '(%04x),a' % nn, 4)
            else:
                if p == 0:
                    return ('ld', 'a,(bc)', 2)
                elif p == 1:
                    return ('ld', 'a,(de)', 2)
                elif p == 2:
                    return ('ld', '%s,(%04x)' % (ir, nn), 4)
                else:
                    return ('ld', 'a,(%04x)' % nn, 4)
        elif z == 3:
            if q == 0:
                return ('inc', alt_rp[p], 2)
            else:
                return ('dec', alt_rp[p], 2)
        elif z == 4:
            if y == 6:
                return ('inc', alt0_r[y], 3)
            else:
                return ('inc', alt1_r[y], 2)
        elif z == 5:
            if y == 6:
                return ('dec', alt0_r[y], 3)
            else:
                return ('dec', alt1_r[y], 2)
        elif z == 6:
            if y == 6:
                return ('ld', '%s,%02x' % (alt0_r[y], n1), 4)
            else:
                return ('ld', '%s,%02x' % (alt1_r[y], n0), 3)
        else:
            return (_rota[y], '', 2)
    elif x == 1:
        if (z == 6) and (y == 6):
            return ('halt', '', 2)
        else:
            if (y == 6) or (z == 6):
                return ('ld', '%s,%s' % (alt0_r[y], alt0_r[z]), 3)
            else:
                return ('ld', '%s,%s' % (alt1_r[y], alt1_r[z]), 2)
    elif x == 2:
        if z == 6:
            return (_alu[y], '%s%s' % (_alux[y], alt0_r[z]), 3)
        else:
            return (_alu[y], '%s%s' % (_alux[y], alt1_r[z]), 2)
    else:
        if z == 0:
            return ('ret', _cc[y], 2)
        elif z == 1:
            if q == 0:
                return ('pop', alt_rp2[p], 2)
            else:
                if p == 0:
                    return ('ret', '', 2)
                elif p == 1:
                    return ('exx', '', 2)
                elif p == 2:
                    return ('jp', ir, 2)
                else:
                    return ('ld', 'sp,%s' % ir, 2)
        elif z == 2:
            return ('jp', '%s,%04x' % (_cc[y], nn), 4)
        elif z == 3:
            if y == 0:
                return ('jp', '%04x' % nn, 4)
            elif y == 2:
                return ('out', '(%02x),a' % n0, 3)
            elif y == 3:
                return ('in', 'a,(%02x)' % n0, 3)
            elif y == 4:
                return ('ex', '(sp),%s' % ir, 2)
            elif y == 5:
                return ('ex', 'de,hl', 2)
            elif y == 6:
                return ('di', '', 2)
            else:
                return ('ei', '', 2)
        elif z == 4:
            return ('call', '%s,%04x' % (_cc[y], nn), 4)
        elif z == 5:
            if q == 0:
                return ('push', alt_rp2[p], 2)
            else:
                if p == 0:
                    return ('call', '%04x' % nn, 4)
        elif z == 6:
            return (_alu[y], '%s%02x' % (_alux[y], n0), 3)
        else:
            return ('rst', '%02x' % (y << 3), 2)

#-----------------------------------------------------------------------------

def _da_cb_prefix(mem, pc):
    """
    0xCB <opcode>
    """
    m0 = mem[pc]
    x = (m0 >> 6) & 3
    y = (m0 >> 3) & 7
    z = (m0 >> 0) & 7

    if x == 0:
        return (_rot[y], _r[z], 2)
    elif x == 1:
        return ('bit', '%d,%s' % (y, _r[z]), 2)
    elif x == 2:
        return ('res', '%d,%s' % (y, _r[z]), 2)
    else:
        return ('set', '%d,%s' % (y, _r[z]), 2)

#-----------------------------------------------------------------------------

def _da_ddcb_fdcb_prefix(mem, pc, ir):
    """
    0xDDCB <d> <opcode>
    0xFDCB <d> <opcode>
    """
    m0 = mem[pc]
    m1 = mem[pc + 1]
    x = (m1 >> 6) & 3
    y = (m1 >> 3) & 7
    z = (m1 >> 0) & 7
    d = m0
    if d & 0x80:
        d = (d & 0x7f) - 128
    sign = ('', '+')[d >= 0]

    if x == 0:
        if z == 6:
            return(_rot[y], '(%s%s%02x)' % (ir, sign, d), 4)
        else:
            return(_rot[y], '(%s%s%02x),%s' % (ir, sign, d, _r[z]), 4)
    elif x == 1:
        return ('bit', '%d,(%s%s%02x)' % (y, ir, sign, d), 4)
    elif x == 2:
        if z == 6:
            return ('res', '%d,(%s%s%02x)' % (y, ir, sign, d), 4)
        else:
            return ('res', '%d,(%s%s%02x),%s' % (y, ir, sign, d, _r[z]), 4)
    else:
        if z == 6:
            return ('set', '%d,(%s%s%02x)' % (y, ir, sign, d), 4)
        else:
            return ('set', '%d,(%s%s%02x),%s' % (y, ir, sign, d, _r[z]), 4)

#-----------------------------------------------------------------------------

def _da_ed_prefix(mem, pc):
    """
    0xED <opcode>
    0xED <opcode> <nn>
    """
    m0 = mem[pc]
    m1 = mem[pc + 1]
    m2 = mem[pc + 2]
    x = (m0 >> 6) & 3
    y = (m0 >> 3) & 7
    z = (m0 >> 0) & 7
    p = (m0 >> 4) & 3
    q = (m0 >> 3) & 1
    nn = (m2 << 8) + m1

    if x == 1:
        if z == 0:
            if y == 6:
                return ('in', '(c)', 2)
            else:
                return ('in', '%s,(c)' % _r[y], 2)
        elif z == 1:
            if y == 6:
                return ('out', '(c)', 2)
            else:
                return ('out', '(c),%s' % _r[y], 2)
        elif z == 2:
            if q == 0:
                return ('sbc', 'hl,%s' % _rp[p], 2)
            else:
                return ('adc', 'hl,%s' % _rp[p], 2)
        elif z == 3:
            if q == 0:
                return ('ld', '(%04x),%s' % (nn, _rp[p]), 4)
            else:
                return ('ld', '%s,(%04x)' % (_rp[p], nn), 4)
        elif z == 4:
            return ('neg', '', 2)
        elif z == 5:
            if y == 1:
                return ('reti', '', 2)
            else:
                return ('retn', '', 2)
        elif z == 6:
            return ('im', _im[y], 2)
        else:
            if y == 0:
                return ('ld', 'i,a', 2)
            elif y == 1:
                return ('ld', 'r,a', 2)
            elif y == 2:
                return ('ld', 'a,i', 2)
            elif y == 3:
                return ('ld', 'a,r', 2)
            elif y == 4:
                return ('rrd', '', 2)
            elif y == 5:
                return ('rld', '', 2)
            else:
                return ('nop', '', 2)
    elif x == 2:
        if (z <= 3) and (y >= 4):
            return (_bli[z][y - 4], '', 2)
    return ('nop', '', 2)

#-----------------------------------------------------------------------------

def _da_dd_fd_prefix(mem, pc, ir):
    """
    0xDD <x>
    0xFD <x>
    """
    m0 = mem[pc]
    if m0 in (0xdd, 0xed, 0xfd):
        return ('nop', '', 1)
    elif m0 == 0xcb:
        return _da_ddcb_fdcb_prefix(mem, pc + 1, ir)
    else:
        return _da_index(mem, pc, ir)

#-----------------------------------------------------------------------------

def disassemble(mem, pc):
    """
    Disassemble z80 opcodes starting at mem[pc].
    Return an (operation, operands, nbytes) tuple.
    """
    m0 = mem[pc]
    if m0 == 0xcb:
        return _da_cb_prefix(mem, pc + 1)
    elif m0 == 0xdd:
        return _da_dd_fd_prefix(mem, pc + 1, 'ix')
    elif m0 == 0xed:
        return _da_ed_prefix(mem, pc + 1)
    elif m0 == 0xfd:
        return _da_dd_fd_prefix(mem, pc + 1, 'iy')
    else:
        return _da_normal(mem, pc)