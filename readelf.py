

from os import system
import struct
import sys





def readsymtab(f,elf_hdr,sh_hdrs  , elf_class=32 , end_char='<' , shidx_strtab = 29):
  
  fmt = None
  fmt32 = 'IIIBBH'
  fmt64 = 'IBBHQQ'
  fields = None
  fields32 = ['st_name_idx','st_value','st_size','st_info','st_other','st_shndx']
  fields64 = ['st_name_idx','st_info','st_other','st_shndx','st_value','st_size']
  
  if elf_class == 32:
    fmt = fmt32
    fields = fields32
  elif elf_class == 64:
    fmt = fmt64
    fields = fields64
  fmt = end_char + fmt
  strtab_hdr = sh_hdrs[shidx_strtab]
  
  f.seek(int('0x'+ ''.join(strtab_hdr['sh_offset']), 16))
  strtab_str = f.read(int('0x'+ ''.join(strtab_hdr['sh_size']), 16))
  symtabs = []
  for hdr in sh_hdrs:
    tab = []
    if 'sym' in hdr['sh_name']:
      f.seek(int('0x'+ ''.join(hdr['sh_offset']), 16))
      tabsize = int('0x'+ ''.join(hdr['sh_size']), 16)
      while tabsize != 0:
        entsize = struct.calcsize(fmt)
        syment = dict(zip(fields,struct.unpack(fmt,f.read(entsize))))
        tab.append(syment)
        syment['st_bind'] = syment['st_info'] >> 4
        syment['st_type'] = syment['st_info'] & 0xf
        syment['st_vis'] = syment['st_other'] & 0x3
        offset = syment['st_name_idx']
        
        syment['st_name'] = str(strtab_str[offset:offset+strtab_str[offset:].index(bytes(chr(0x00), 'utf-8'))])[2:-1]
        tabsize -= entsize
      symtabs.append([hdr['sh_name'],tab])
  return symtabs

