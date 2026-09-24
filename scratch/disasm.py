import capstone
import struct

with open(r'C:\Users\Familia\AppData\Roaming\BambuStudio\plugins\BambuSource.dll', 'rb') as f:
    data = f.read()

# PE parsing
e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
image_base = struct.unpack_from('<Q', data, e_lfanew + 24 + 24)[0]
section_table_offset = e_lfanew + 24 + opt_hdr_size

sections = []
for i in range(num_sections):
    sec = data[section_table_offset + i*40 : section_table_offset + (i+1)*40]
    name = sec[:8].rstrip(b'\x00').decode('latin1')
    vsize, va, rsize, rptr = struct.unpack_from('<IIII', sec, 8)
    sections.append({'name': name, 'va': va, 'vsize': vsize, 'rptr': rptr, 'rsize': rsize})

def va_to_fo(va):
    rva = va - image_base
    for s in sections:
        if s['va'] <= rva < s['va'] + s['vsize']:
            return s['rptr'] + (rva - s['va'])
    return None

def get_str(va):
    fo = va_to_fo(va)
    if fo is None or fo < 0 or fo >= len(data): return ''
    s = b''
    while fo < len(data) and data[fo] != 0 and len(s) < 80:
        s += bytes([data[fo]])
        fo += 1
    try:
        dec = s.decode('ascii')
        if len(dec) >= 3 and dec.isprintable(): return dec
    except:
        pass
    return ''

func_va = 0x18005a2f0
fo = va_to_fo(func_va)
code = data[fo : fo + 0x1000]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

count = 0
for insn in md.disasm(code, func_va):
    extra = ''
    if 'rip' in insn.op_str and insn.mnemonic in ['lea', 'mov']:
        parts = insn.op_str.split('rip + ')
        if len(parts) == 2:
            disp_hex = parts[1].split(']')[0]
            disp = int(disp_hex, 16)
            target = insn.address + insn.size + disp
            st = get_str(target)
            if st:
                extra = f'  ; "{st}"'
    print(f'0x{insn.address:x}: {insn.mnemonic:10s} {insn.op_str}{extra}')
    count += 1
    if count > 150:
        break
