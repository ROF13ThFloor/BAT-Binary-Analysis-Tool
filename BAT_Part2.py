from inspect import FullArgSpec
from os import read, terminal_size
from posixpath import split
import sys
import copy

from graphviz.graphs import Graph
import attr_types
from colorama import Fore,Back,Style
from capstone import * 
from tabulate import tabulate
from graphviz import Digraph, dot
import readelf
from dfs import Graph

 



little_endian = False

def get_ei_class(attr):
    if (attr == '01'):
        return "32"
    else:
        return "64" 
  
def get_ei_data(attr):
    if (attr == '01'):
        return "2's comp , little endian"
    else:
        return "2's comp , big endian" 


def get_ei_version(attr):
    return "current version = 1"



def get_ei_osabi(attr):
    if (attr == "00"):
        return "system v"
    elif (attr == "01"):
        return "HP-UX"
    elif (attr == "02"):
        return "NetBSD"
    elif (attr == "03"):
        return "Linux"
    elif (attr == "04"):
        return "GNU Hurd"
    elif (attr == "06"):
        return "Solaris"
    elif (attr == "07"):
        return "AIX"
    elif (attr == "08"):
        return "IRIX"
    elif (attr == "09"):
        return "FreeBSD"
    elif (attr == "0A"):
        return "Tru64"
    elif (attr == "0B"):
        return "Novell Modesto"
    elif (attr == "0C"):
        return "OpenBSD"
    elif (attr == "0D"):
        return "OpenVMS"
    elif (attr == "0E"):
        return "NonStop Kernel"
    elif (attr == "0F"):
        return "AROS"
    elif (attr == "10"):
        return "Fenix OS"
    elif (attr == "11"):
        return "CloudABI"
    elif (attr == "12"):
        return "Stratus Technologies OpenVOS"


def get_ei_abiversion(attr):
    return attr

def get_ei_pad(attr):
    return ''.join(attr)

def get_e_type(attr):
    if (attr[0] == "00"):
        return "No file type"
    elif (attr[0] == "01"):
        return "relocatable object file"
    elif (attr[0] == "02"):
        return "executable binary"
    elif (attr[0] == "03"):
        return "Shared object file"
    elif (attr[0] == "04"):
        return "Core file"
    elif (attr[0] == "FE" and attr[1] == "00"):
        return "Operating system-specific"
    elif (attr[0] == "FE" and attr[1] == "FF"):
        return "Operating system-specific"
    elif (attr[0] == "FF" and attr[1] == "00"):
        return "Processor-specific"
    elif (attr[0] == "FF" and attr[1] == "FF"):
        return "Processor-specific"



def get_e_machine(attr):
    if (attr[0] == "10"):
        return "WDC 65C816"
    attr_to_int = int('0x'+''.join(attr[0]),16)
    return attr_types.e_machines[str(attr_to_int)]



def fix_little_endian(attr):

    tmp = copy.deepcopy(attr)
    return tmp[::-1]


def get_e_version(attr):
    if (little_endian):
        version = ''.join(fix_little_endian(attr))
        return hex(int(version , 16))
    else:
        version = ''.join(attr)
        return hex(int(version , 16))

def get_e_entry(attr):
    if (little_endian):
        entry = ''.join(fix_little_endian(attr))
        return hex(int(entry , 16))
    else:
        entry = ''.join(attr)
        return entry

def get_e_flags(attr):
    if (little_endian):
        flags = ''.join(fix_little_endian(attr))
        return hex(int(flags , 16))
    else:
        flags = ''.join(attr)
        return flags 

def get_e_ehsize(attr):
    return int_extract(attr)

def get_e_shstrndx(attr):
    return int_extract(attr)


def get_ptype(attr):
    tmp = fix_little_endian(attr)
    str_tmp = ''.join(tmp)
    
    type_value = str(int(str_tmp, 16))
    if (type_value in attr_types.p_types):
        return attr_types.p_types[type_value]
    else:
        return "unknown"    
def get_pflags(attr):
    tmp = fix_little_endian(attr)
    tmp_str = ''.join(tmp)
    return attr_types.p_flags[str(int(tmp_str , 16))]

def get_poffset(attr):
    tmp = fix_little_endian(attr)
    tmp_str = ''.join(tmp)
    return tmp_str

def get_pvaddr(attr):
    tmp = fix_little_endian(attr)
    tmp_str = ''.join(tmp)
    return tmp_str

def get_ppaddr(attr):
    tmp = fix_little_endian(attr)
    tmp_str = ''.join(tmp)
    return tmp_str

def get_pfilesz(attr):
    tmp = fix_little_endian(attr)
    tmp_str = ''.join(tmp)
    return tmp_str


def get_pmemsz(attr):
    tmp = fix_little_endian(attr)
    tmp_str = ''.join(tmp)
    return tmp_str


def get_palign(attr):
    tmp = fix_little_endian(attr)
    tmp_str = ''.join(tmp)

    return hex(int(tmp_str ,16))





def get_sh_name(attr , f , name_entry_offset):
    sh_name_ndx = attr 
    name = ''
    if (sh_name_ndx != 0 ):
        f.seek(name_entry_offset + sh_name_ndx)
        while(True):
            read = f.read(1)
            name += ['{:02x}'.format(c) for c in read][0]
            if name[-2]+name[-1] == '00':
                name = name[:-2]
                break
    return str(bytes.fromhex(name))[2:-1]


def get_sh_type(attr):
    tmp = fix_little_endian(attr)
    str_tmp = ''.join(tmp)
    
    type_value = str(int(str_tmp, 16))
    if (type_value in attr_types.s_types):
        return attr_types.s_types[type_value]
    else:
        return "unknown"   


def get_sh_flags(attr):
    tmp = fix_little_endian(attr)
    str_tmp = ''.join(tmp)
    
    type_value = str(int(str_tmp, 16))
    if (type_value in attr_types.s_flags):
        return attr_types.s_flags[type_value]
    else:
        return "unknown"   

def get_sh_addr(attr):
    tmp_addr = fix_little_endian(attr)
    return ''.join(tmp_addr)

def get_sh_offset(attr):
    tmp_addr = fix_little_endian(attr)
    return ''.join(tmp_addr)


def get_sh_size(attr):
    tmp_addr = fix_little_endian(attr)
    return ''.join(tmp_addr)

def get_sh_link(attr):
    return int_extract(attr)

def get_sh_info(attr):
    return int_extract(attr)

def get_sh_addralign(attr):
    return int_extract(attr)

def get_sh_entsize(attr):
    tmp_addr = fix_little_endian(attr)
    return ''.join(tmp_addr)

# for x 64 
def extract_header_file_output_x64(e_header_file_info ):
    file_header = dict()
    file_header["ei_Magic"] = ' '.join(e_header_file_info[:16])
    file_header["ei_class"] = get_ei_class(e_header_file_info[4])
    file_header["ei_data"]  = get_ei_data(e_header_file_info[5])
    file_header["ei_version"] = get_ei_version(e_header_file_info[6])
    file_header["ei_osabi"] = get_ei_osabi(e_header_file_info[7])
    file_header["ei_abiversion"] = get_ei_abiversion(e_header_file_info[8])
    file_header["ei_pad"] = get_ei_pad(e_header_file_info[9:16])
    file_header["e_type"] = get_e_type(e_header_file_info[16:18])
    file_header["e_machine"] = get_e_machine(e_header_file_info[18:20])
    file_header["e_version"] = get_e_version(e_header_file_info[20:24])
    file_header["e_entry"] = get_e_entry(e_header_file_info[24:32])
    file_header["e_flags"] = get_e_flags(e_header_file_info[48:52])
    file_header["e_ehsize"] = get_e_ehsize(e_header_file_info[52:54])
    file_header["e_shstrndx"] = get_e_shstrndx(e_header_file_info[62:64])
    return file_header
        
def extract_program_header_output_x64(e_program_header):
    program_header = dict()
    for index , pr_enries in enumerate(e_program_header):
        program_header[str(index)] = dict()
        program_header[str(index)]["p_type"] = get_ptype(pr_enries[0:4])
        program_header[str(index)]["p_flags"] = get_pflags(pr_enries[4:8])
        program_header[str(index)]["p_offset"] = get_poffset(pr_enries[8:16])
        program_header[str(index)]["p_vaddr"] = get_pvaddr(pr_enries[16:24])
        program_header[str(index)]["p_paddr"] = get_ppaddr(pr_enries[24:32])
        program_header[str(index)]["p_filesz"] = get_pfilesz(pr_enries[32:40])
        program_header[str(index)]["p_memsz"] = get_pmemsz(pr_enries[40:48])
        program_header[str(index)]["p_align"] = get_palign(pr_enries[48:56])
    return program_header    

def extract_section_header_output_x64(e_section_header  ,e_shstrndx , f ):
    section_header = dict()
    name_entry_offset  = int_extract(e_section_header[e_shstrndx][24:32])
    for index , s in enumerate(e_section_header):
        section_header[str(index)] = dict()
        tmp = int_extract(s[:4])
        section_header[str(index)]["sh_name"] = get_sh_name(tmp , f , name_entry_offset)
        section_header[str(index)]["sh_type"] = get_sh_type(s[4:8])
        section_header[str(index)]["sh_flags"] = get_sh_flags(s[8:16])
        section_header[str(index)]["sh_addr"] = get_sh_addr(s[16:24])
        section_header[str(index)]["sh_offset"] = get_sh_offset(s[24:32])
        section_header[str(index)]["sh_size"] = get_sh_size(s[32:40])
        section_header[str(index)]["sh_link"] = get_sh_link(s[40:44])
        section_header[str(index)]["sh_info"] = get_sh_info(s[44:48])
        section_header[str(index)]["sh_addralign"] = get_sh_addralign(s[48:56])
        section_header[str(index)]["sh_entsize"] = get_sh_entsize(s[56:64])

    return section_header

def std_outx64(file_header , program_headers , section_headers , h_structur_extracted):
    #start to print elf file header 
    print(Fore.LIGHTCYAN_EX + "ELF Header")
    print(Fore.RED  + "\t Magic:\0\0"  + "\t\t "  + file_header["ei_Magic"])
    print(Fore.GREEN + "\t Class:"  + "\t\t " + "ELF" +  file_header["ei_class"])
    print(Fore.GREEN + "\t Data:\0"  + "\t\t "  +  file_header["ei_data"])
    print(Fore.GREEN + "\t Version:"  + "\t\t "  +  file_header["ei_version"])
    print(Fore.GREEN + "\t Type : \0"  + "\t\t "  +  file_header["e_type"])
    print(Fore.GREEN + "\t OS/ABI: "  + "\t\t "  +  file_header["ei_osabi"])
    print(Fore.GREEN + "\t ABI Version: "  + "\t\t "  +  file_header["ei_abiversion"])
    print(Fore.GREEN + "\t Machine :"  + "\t\t "  +  file_header["e_machine"])
    print(Fore.GREEN + "\tVersion :"  + "\t\t "  +  file_header["e_version"])
    print(Fore.GREEN + "\t Entry point address:"  + "    "  +  file_header["e_entry"])

# structure
    print(Fore.GREEN + "\t Start of program headers:"  + "\t\t"  +  str(h_structur_extracted["e_phoff"])+ "\tBytes into file")
    print(Fore.GREEN + "\t Start of section headers:"  + "\t\t"  +  str(h_structur_extracted["e_shoff"])+ "\tBytes into file")
    print(Fore.GREEN + "\t Flags:"  + "\t\t"  +  str(file_header["e_flags"]))
    print(Fore.GREEN + "\t Size of this header:"  + "\t\t"  +  str(file_header["e_ehsize"])+ "\tBytes")
    print(Fore.GREEN + "\t Size of program headers:"  + "\t\t"  +  str(h_structur_extracted["e_phentsize"])+ "\tBytes")
    print(Fore.GREEN + "\t Number of program headers: "  + "\t\t"  +  str(h_structur_extracted["e_phnum"]))
    print(Fore.GREEN + "\t Size of section headers: "  + "\t\t"  +  str(h_structur_extracted["e_shentsize"]) + "\tBytes")
    print(Fore.GREEN + "\t Number of section headers:"  + "\t\t"  +  str(h_structur_extracted["e_shnum"]) )
    print(Fore.GREEN + "\t Number of section headers table index :"  + "\t\t"  +  str(file_header["e_shstrndx"]) )

# prog header
    print("\n\n")
    print( Fore.LIGHTCYAN_EX+ "Program header")

    print(Fore.GREEN+ "Elf file type is " , file_header['e_type'])
    print(Fore.GREEN + "entry point is  " , file_header['e_entry'])
    print(Fore.GREEN + "there are  " , str(h_structur_extracted['e_phnum']) + "\tprogram header")
    p_table = [[ 'Type', 'offset', 'VirtAddr', 'PhysAddr' , 'FileSiz' , 'MemSiz' , 'Flags' ,'Align'  ] ]
    for i in program_headers:
        row = []
        row.append(program_headers[i]["p_type"])
        row.append(program_headers[i]["p_offset"])
        row.append(program_headers[i]["p_vaddr"])
        row.append(program_headers[i]["p_paddr"])
        row.append(program_headers[i]["p_filesz"])
        row.append(program_headers[i]["p_memsz"])
        row.append(program_headers[i]["p_flags"])
        row.append(program_headers[i]["p_align"])
        p_table.append(row)

    print(tabulate(p_table))
    
    # section headers 
    print("\n\n")
    print( Fore.LIGHTCYAN_EX+ "Section header")
    print(Fore.GREEN + "there are  " , str(h_structur_extracted['e_shnum']) + "\tprogram header")


    s_table = [[ 'Number' , 'Name', 'Type', 'Address', 'Offset' , 'Size' , 'EntSize' , 'Flags' ,'Link'  , 'Info'  ,  'Align'] ]

    for i in section_headers:
        row = []
        row.append(i)
        row.append(section_headers[i]["sh_name"])
        row.append(section_headers[i]["sh_type"])
        row.append(section_headers[i]["sh_addr"])
        row.append(section_headers[i]["sh_offset"])
        row.append(section_headers[i]["sh_size"])
        row.append(section_headers[i]["sh_entsize"])
        row.append(section_headers[i]["sh_flags"])
        row.append(section_headers[i]["sh_link"])
        row.append(section_headers[i]["sh_info"])
        row.append(section_headers[i]["sh_addralign"])

        s_table.append(row)

    
    print(tabulate(s_table))

    print("\n\n")
    print("Key to Flags:W (write), A (alloc), X (execute), M (merge), S (strings), I (info),L (link order), O (extra OS processing required), G (group), T (TLS),")



def create_output_x64(e_header_file_info , h_structur_extracted , e_program_header , e_section_header , f):
    file_header = dict()
    file_header = extract_header_file_output_x64(e_header_file_info )
    program_headers = extract_program_header_output_x64(e_program_header)
    section_headers = extract_section_header_output_x64(e_section_header , file_header["e_shstrndx"] , f)
    # print(program_headers)
    # print(file_header)
    # print(section_headers)
    std_outx64(file_header , program_headers , section_headers , h_structur_extracted)

    end_char = ''
    # print(readsymtable(f , section_headers))
    if little_endian == True:
        end_char = '<'
    else :
        end_char  = '>'
    lists = []
    st_tabindx = 0
    relocated_list = []
    dyn_symindex = 0
    got_offset = 0

    for i in section_headers:
        lists.append(section_headers[i])
        if (section_headers[i]['sh_name'] == '.strtab'):
            st_tabindx = int(i)
        if (section_headers[i]['sh_name'] == '.dynsym'):
            dyn_symindex = int(i)
        if (section_headers[i]['sh_name'] == '.got'):
            got_offset = section_headers[i]['sh_addr']
        
    symbol_table = readelf.readsymtab(f , file_header, lists , elf_class=64 ,end_char=end_char , shidx_strtab=st_tabindx  )
    Dynamic_relocated_list = read_dynSections(f , section_headers ,  symbol_table , x86_or_x64, little_endian   )
    relocated_list = dict()
    for s in symbol_table:
        for symb in s[1]: 
            relocated_list[symb['st_value']] = symb
    
    nodes = []
    Graphs = []
    syscalls = dict()
    dynamic_count = 0

    for i in symbol_table:
        for sym in i[1]:
            if (sym['st_size'] != 0):
                if ('X' in section_headers[str(sym['st_shndx'])]['sh_flags']):
                    f.seek(sym['st_value'])
                    x = f.read(sym['st_size'])
                    CS_mode = 0
                    if little_endian == True:
                        CS_mode  = CS_MODE_LITTLE_ENDIAN
                    else :
                        CS_mode = CS_MODE_BIG_ENDIAN
                    md = Cs(CS_ARCH_X86, CS_MODE_32 + CS_mode)
                    disass_items = [*md.disasm_lite(x, sym['st_value'])]
                    for i, (address, size, mnemonic, op_str) in enumerate(disass_items):
                        # print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
                        if (mnemonic == 'call'):
                            # print('caller is : ' , sym['st_name'])
                            
                            caller =  sym['st_name']
                            if (op_str[:2] == '0x' and int(op_str,16) in relocated_list):
                                # print('callee is : ' , relocated_list[int(op_str, 16)]['st_name'])
                                if (relocated_list[int(op_str, 16)]['st_name'] != ''):
                                    callee = relocated_list[int(op_str, 16)]['st_name']
                                else : 
                                    is_there , name = search_inDynamics(op_str , Dynamic_relocated_list , little_endian , x86_or_x64 , f , got_offset)

                                    if (is_there):
                                        callee = name
                                    else:
                                        callee = 'UNKNOWN'
                            else:
                                if (op_str[:2] == '0x'):
                                    is_there , name = search_inDynamics(op_str , Dynamic_relocated_list , little_endian , x86_or_x64 , f , got_offset)
                                    if (is_there):
                                        callee = name 
                                
                                    else:
                                        callee = 'UNKNOWN' + str(op_str)
                                else :
                                    callee = 'UNKNOWN' + str(op_str)
                                
                            if (caller not in nodes):
                                nodes.append(caller)
                            if (callee not in nodes):
                                nodes.append(callee)
                            Graphs.append([caller , callee])
                            
                            if (callee == 'syscall'):
                                ins = ''
                                x = i 
                                
                                while(ins != 'edi'):
                                    x = x - 1
                                    ins = disass_items[x][-1].split(',')[0]
                                    syscalnum = disass_items[x][-1].split(',')[1]
                                syscalnum = syscalnum.split(' ')[-1]
                                syscalnum = int(syscalnum , 16)
                                if (syscalls != 0 ):
                                    if(sym['st_name'] in syscalls):
                                        syscalls[sym['st_name']].append(syscalnum)
                                    else:
                                        syscalls[sym['st_name']] = []
                                        syscalls[sym['st_name']].append(syscalnum)
                        if (mnemonic == 'syscall'):
                            syscal_num = int(disass_items[i-1][-1].split(',')[-1].split(' ')[-1] , 16)
                            if (syscalls != 0 ):
                                if (sym['st_name'] in syscalls):
                                    syscalls[sym['st_name']].append(syscal_num)
                                else:
                                    syscalls[sym['st_name']] = []
                                    syscalls[sym['st_name']].append(syscal_num)

    nodes  , Graphs = filter_Graph(nodes , Graphs )

    dot_file = Digraph(name="output" + "/" + file_path)
    Detect_FuncSysCallPattern(nodes , Graphs  , syscalls)
    print(syscalls)
    dot_file.format = 'png'
    # print(syscalls)
    for l in nodes:
        sysc = ''
        try:
            if (sys.argv[2] == '-s'):
                sysc = '   syscalls : '
                if (l in syscalls):
                    for i in syscalls[l]:
                        sysc += str(i) + "  "
        except:
                pass

        if (l == 'main'):
            dot_file.node(l , l + sysc  , attrs=sysc, shape='circle')
        else:
            dot_file.node(l , l + sysc , attrs=sysc)
    for ed in Graphs:
        
        dot_file.edge(ed[0], ed[1], label='call')
        dot_file.edge(ed[1], ed[0], label='ret')

    try:
        dot_file.render() 
    except Exception as e:
        pass
        pass





# for x86
def extract_header_file_output_x86(e_header_file_info ):
    file_header = dict()
    file_header["ei_Magic"] = ' '.join(e_header_file_info[:16])
    file_header["ei_class"] = get_ei_class(e_header_file_info[4])
    file_header["ei_data"]  = get_ei_data(e_header_file_info[5])
    file_header["ei_version"] = get_ei_version(e_header_file_info[6])
    file_header["ei_osabi"] = get_ei_osabi(e_header_file_info[7])
    file_header["ei_abiversion"] = get_ei_abiversion(e_header_file_info[8])
    file_header["ei_pad"] = get_ei_pad(e_header_file_info[9:16])
    file_header["e_type"] = get_e_type(e_header_file_info[16:18])
    file_header["e_machine"] = get_e_machine(e_header_file_info[18:20])
    file_header["e_version"] = get_e_version(e_header_file_info[20:24])
    file_header["e_entry"] = get_e_entry(e_header_file_info[24:28])
    file_header["e_flags"] = get_e_flags(e_header_file_info[36:40])
    file_header["e_ehsize"] = get_e_ehsize(e_header_file_info[40:42])
    file_header["e_shstrndx"] = get_e_shstrndx(e_header_file_info[50:52])
    return file_header

def extract_program_header_output_x86(e_program_header):
    program_header = dict()
    for index , pr_enries in enumerate(e_program_header):
        program_header[str(index)] = dict()
        program_header[str(index)]["p_type"] = get_ptype(pr_enries[0:4])
        program_header[str(index)]["p_flags"] = get_pflags(pr_enries[24:28])
        program_header[str(index)]["p_offset"] = get_poffset(pr_enries[4:8])
        program_header[str(index)]["p_vaddr"] = get_pvaddr(pr_enries[8:12])
        program_header[str(index)]["p_paddr"] = get_ppaddr(pr_enries[12:16])
        program_header[str(index)]["p_filesz"] = get_pfilesz(pr_enries[16:20])
        program_header[str(index)]["p_memsz"] = get_pmemsz(pr_enries[20:24])
        program_header[str(index)]["p_align"] = get_palign(pr_enries[28:32])
    return program_header   

def extract_section_header_output_x86(e_section_header , e_shstrndx , f):
    section_header = dict()
    name_entry_offset  = int_extract(e_section_header[e_shstrndx][16:20])
    for index , s in enumerate(e_section_header):
        section_header[str(index)] = dict()
        tmp = int_extract(s[:4])
        section_header[str(index)]["sh_name"] = get_sh_name(tmp , f , name_entry_offset)
        section_header[str(index)]["sh_type"] = get_sh_type(s[4:8])
        section_header[str(index)]["sh_flags"] = get_sh_flags(s[8:12])
        section_header[str(index)]["sh_addr"] = get_sh_addr(s[12:16])
        section_header[str(index)]["sh_offset"] = get_sh_offset(s[16:20])
        section_header[str(index)]["sh_size"] = get_sh_size(s[20:24])
        section_header[str(index)]["sh_link"] = get_sh_link(s[24:28])
        section_header[str(index)]["sh_info"] = get_sh_info(s[28:32])
        section_header[str(index)]["sh_addralign"] = get_sh_addralign(s[32:36])
        section_header[str(index)]["sh_entsize"] = get_sh_entsize(s[36:40])

    return section_header    


def std_outx86(file_header , program_headers , section_headers):
    print("1")



def get_dynsymname(offset , index , f):
    dyn_name_str = offset 
    name = ''
    if (index != 0 ):
        f.seek(offset + index)
        while(True):
            read = f.read(1)
            name += ['{:02x}'.format(c) for c in read][0]
            if name[-2]+name[-1] == '00':
                name = name[:-2]
                break
    return str(bytes.fromhex(name))[2:-1]

def read_dynSections(f , section_headers  ,symbol_table , mode  , little_endian ):
    
    read_size = 0
    And_Roperator = 0 
    Shift_Count = 0
    column_size = 0
    if (mode == 'x86'):
        read_size = 16
        Shift_Count = 8
        And_Roperator = 0xFFFFFF
        column_size = 4
    else :
        And_Roperator = 0xFFFFFFFF
        Shift_Count = 32
        read_size = 24
        column_size = 8
    dynstr_index , dyn_index , rel_dyn_index , rel_plt_index = 0 , 0 , 0 , 0 
    for s in section_headers:
        if (section_headers[s]['sh_name'] == '.dynsym'):
            dyn_index = s
        if (section_headers[s]['sh_name'] == '.dynstr'):
            dynstr_index = s
        if (mode == 'x86' ):
            if (section_headers[s]['sh_name'] == '.rel.plt'):
                rel_plt_index = s
            if (section_headers[s]['sh_name'] == '.rel.dyn'):
                rel_dyn_index = s
        if (mode == 'x64' ):
            if (section_headers[s]['sh_name'] == '.rela.plt'):
                rel_plt_index = s
            if (section_headers[s]['sh_name'] == '.rela.dyn'):
                rel_dyn_index = s
    # read dyn
    dyn_size =  int('0x'+ ''.join(section_headers[dyn_index]['sh_size']), 16)
    f.seek(int('0x'+ ''.join(section_headers[dyn_index]['sh_offset']), 16))
    dyn_symbolTable = []
    for symbol_data in [f.read(read_size) for _ in range(dyn_size // read_size)]:
        index = symbol_data[:4]
        index  = ["{:02x}".format(i) for i in index]
        
        index = int_extract(index)
        name = get_dynsymname(int('0x'+ ''.join(section_headers[dynstr_index]['sh_offset']), 16) ,  index , f )
        dyn_symbolTable.append([index , name ])
    #  read rel.plt 
    plt_table = []
    plt_row_size = 8 if mode == 'x86' else 24
    
    plt_size = int('0x'+ ''.join(section_headers[rel_plt_index]['sh_size']), 16)
    f.seek(int('0x'+ ''.join(section_headers[rel_plt_index]['sh_offset']), 16))
    for row in [f.read(plt_row_size) for s in range(plt_size // plt_row_size)]:
        row  = ["{:02x}".format(i) for i in row] 
        plt_offset =  ''.join(fix_little_endian(row[:column_size]))
        dyn_indx = (int_extract(row[column_size:]) >> Shift_Count) & And_Roperator
        plt_info = int_extract(row[column_size:])

        # plt_info = int_extract(row[4:]
        plt_table.append([ plt_offset , plt_info , dyn_indx])
    # read rel.dyn 
    # print(plt_table)

    reldyn_table = []
    reldyn_row_size = 8 if mode == 'x86' else 24
    reldyn_size = int('0x'+ ''.join(section_headers[rel_dyn_index]['sh_size']), 16)
    f.seek(int('0x'+ ''.join(section_headers[rel_dyn_index]['sh_offset']), 16))
    for row in [f.read(reldyn_row_size) for s in range(reldyn_size // reldyn_row_size)]:
        row  = ["{:02x}".format(i) for i in row] 
        reldyn_offset =  ''.join(fix_little_endian(row[:column_size]))
        reldyn_indx = (int_extract(row[column_size:]) >> Shift_Count) & And_Roperator
        reldyn_info = int_extract(row[column_size:])

        # plt_info = int_extract(row[4:]
        reldyn_table.append([ reldyn_offset , reldyn_info , reldyn_indx])

    # print(reldyn_table)
    # print('-----------')
    # print(dyn_symbolTable)
    # print(reldyn_table)    
    relocated_Dynamic_list = []
    
    for i in range(len(reldyn_table)):
        offset = reldyn_table[i][0]
        info = reldyn_table[i][1]
        name = dyn_symbolTable[reldyn_table[i][2]][1]
        relocated_Dynamic_list.append([offset , info , name])
    for i in range(len(plt_table)):
        offset = plt_table[i][0]
        info = plt_table[i][1]
        
        name = dyn_symbolTable[plt_table[i][2]][1]
        relocated_Dynamic_list.append([offset , info , name])

    
    return relocated_Dynamic_list


def is_in_dtable(d_list , Got_called_function): 

    for l in d_list:
        if (int('0x' + l[0] , 16) ==int(Got_called_function ,16) ):
            called_func = l[2]
            return  called_func

def search_inDynamics(op_str , d_list , little_endian , x86_or_x64  , f  , got_offset):

    if (op_str[:2] == '0x'):
        # print(op_str , '-----------------------')
        f.seek(int(op_str , 16))
        x = f.read(20)
        CS_mode = 0
        if little_endian == True:
            CS_mode  = CS_MODE_LITTLE_ENDIAN
        else :
            CS_mode = CS_MODE_BIG_ENDIAN
        if x86_or_x64 == 'x86':
            file_format = CS_MODE_32
        else : 
            file_format = CS_MODE_64
        md = Cs(CS_ARCH_X86, file_format + CS_mode)
        disass_items = [*md.disasm_lite(x, int(op_str , 16))]
        for i, (address, size, mnemonic, op_str) in enumerate(disass_items):

            if ('jmp' in mnemonic ):
                if x86_or_x64 == 'x86':
                    index = op_str.split('0x')[1].split(']')[0]
                    
                    Got_called_function = hex(int('0x' + index , 16) + int( '0x' + got_offset , 16))
                    func_called = is_in_dtable(d_list , Got_called_function)
                    if (func_called != ''):
                        return True , func_called
                    else :
                        return False , func_called
                    # pass
                else: 
                    # print(op_str)
                    index  = op_str.split('0x')[1].split(']')[0]
                    got_offset = disass_items[i+1][0]
                    
                    Got_called_function = hex(int('0x' + index , 16) + got_offset)
                    func_called = is_in_dtable(d_list , Got_called_function)
                    if (func_called != ''):
                        return True , func_called
                    else :
                        return False , func_called

        else :
            return False , ''

def  filter_Graph(nodes , Graphs ):
    for n in nodes:
        if (n == 'main'):
            continue 
        is_called  = False 
        for e , e2  in enumerate(Graphs):
            if (e2[1] == n):
                is_called = True
        if (is_called  == False ):
            # print(n , 'should remove')
            nodes.remove(n)
            # print(nodes)
            for l in Graphs:
                if (l[0] == n):
                    Graphs.remove(l)
                    nodes.remove(l[1])
        if ('UNK' in n):
            nodes.remove(n)
            for l in Graphs:
                if (l[0] == n):
                    Graphs.remove(l)
                    nodes.remove(l[1])
                if (l[1] == n):
                    Graphs.remove(l)
                    nodes.remove(l[0])
                
                    
                    
            


    return nodes , Graphs

def  Detect_FuncSysCallPattern(nodes , Graphs  , syscalls):
    
    
    f= open('FuncCallPattern.txt' , 'r')
    pattern_count = int(f.readline())
    call_patterns = []
    for i in range(pattern_count):
        content = f.readline()
        content = content.split(' ')
        call_patterns.append(content[:-1])
    print( Fore.YELLOW + "*"*100 )

    g = Graph()
    for n1 , n2 in Graphs:
        g.addEdge(n1,n2)
    Traversed_DFS =  g.DFS('main')
    Traversed_list = g.Traversed_DFS.split('*')
    
    success = False 
    for p in call_patterns:
        
        index = 0
        success = False 
        for t in Traversed_list:
            # print(t , p[index])
            if (success == True):
                print(Fore.RED  + "Warning : " + '-->'.join(p) + "    Has been detected" )
                break
            # print(p[index] , t)
            if ('->' in t):
                if (p[index] in t.split('->')[-1]):
                    index += 1
                    if (index == len(p)):
                        success = True
            if (success != True):
                if (t == p[index]):
                    index+=1
                    if (index == len(p)):
                        success = True

    f= open('SyscallPattern.txt' , 'r')
    pattern_count = int(f.readline())
    syscall_patterns = []
    for i in range(pattern_count):
        content = f.readline()
        content = content.split(' ')
        syscall_patterns.append(content[:-1])

    # print(syscalls)




    print( Fore.RED + "*"*100 )
    for p in syscall_patterns:
        
        index = 0
        success = False 
        for t in Traversed_list:
            # print(t , p[index])
            # print(p[index],t )
            if (success == True):
                print(Fore.BLUE  + "Warning : " + '-->'.join(p) + "    Has been detected" )
                break

            if (success != True):
                if (t in syscalls):
                    if (int(p[index]) in syscalls[t]):
                        index+=1
                        if (index == len(p)):
                            success = True








def create_output_x86(e_header_file_info , h_structur_extracted , e_program_header , e_section_header , f):
    file_header = dict()
    file_header = extract_header_file_output_x86(e_header_file_info )
    program_headers = extract_program_header_output_x86(e_program_header)
    section_headers = extract_section_header_output_x86(e_section_header , file_header["e_shstrndx"] , f)
    std_outx64(file_header , program_headers , section_headers , h_structur_extracted)

    end_char = ''
    # print(readsymtable(f , section_headers))
    if little_endian == True:
        end_char = '<'
    else :
        end_char  = '>'
    lists = []
    st_tabindx = 0
    dyn_symindex = 0
    got_offset = 0
    relocated_list = []
    for i in section_headers:
        lists.append(section_headers[i])
        if (section_headers[i]['sh_name'] == '.strtab'):
            st_tabindx = int(i)
        if (section_headers[i]['sh_name'] == '.dynsym'):
            dyn_symindex = int(i)
        if (section_headers[i]['sh_name'] == '.got'):
            got_offset = section_headers[i]['sh_addr']

    symbol_table = readelf.readsymtab(f , file_header, lists , elf_class=32 ,end_char=end_char , shidx_strtab=st_tabindx  )

    
    Dynamic_relocated_list = read_dynSections(f , section_headers ,  symbol_table , x86_or_x64, little_endian   )
    
    relocated_list = dict()
    for s in symbol_table:
        for symb in s[1]:
            
            relocated_list[symb['st_value']] = symb
    nodes = []
    Graphs = []
    syscalls = {}
    dynamic_count = 0
    for i in symbol_table:
        for sym in i[1]:
            if (sym['st_size'] != 0):
                if ('X' in section_headers[str(sym['st_shndx'])]['sh_flags']):
                    f.seek(sym['st_value'])
                    x = f.read(sym['st_size'])
                    CS_mode = 0
                    if little_endian == True:
                        CS_mode  = CS_MODE_LITTLE_ENDIAN
                    else :
                        CS_mode = CS_MODE_BIG_ENDIAN
                    md = Cs(CS_ARCH_X86, CS_MODE_32 + CS_mode)
                    disass_items = [*md.disasm_lite(x, sym['st_value'])]
                    for i, (address, size, mnemonic, op_str) in enumerate(disass_items):
                        # print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
                        if (mnemonic == 'call'):
                            # print('caller is : ' , sym['st_name'])
                            
                            caller =  sym['st_name']
                            if (op_str[:2] == '0x' and int(op_str,16) in relocated_list):
                                # print('callee is : ' , relocated_list[int(op_str, 16)]['st_name'])
                                if (relocated_list[int(op_str, 16)]['st_name'] != ''):
                                    callee = relocated_list[int(op_str, 16)]['st_name']
                                else : 
                                    is_there , name = search_inDynamics(op_str , Dynamic_relocated_list , little_endian , x86_or_x64 , f , got_offset)

                                    if (is_there):
                                        callee = sym['st_name']  + "->" +  name 
                                    else:
                                        callee = 'UNKNOWN'
                                        dynamic_count +=1
                            else:
                                if (op_str[:2] == '0x'):
                                    is_there , name = search_inDynamics(op_str , Dynamic_relocated_list , little_endian , x86_or_x64 , f , got_offset)
                                    if (is_there):
                                        callee = name + ''
                                    else:
                                        callee = 'UNKNOWN\t' + str(op_str)
                                else :
                                    callee = 'UNKNOWN\t' + str(op_str)
                                
                            if (caller not in nodes):
                                nodes.append(caller)
                            if (callee not in nodes):
                                nodes.append(callee)
                            Graphs.append([caller , callee])
                            if (callee == 'syscall'):
                                syscalnum = disass_items[i-1][-1]
                                # if ('0x' in syscalnum):
                                syscalnum = int(syscalnum , 16)
                                if (sym['st_name'] in syscalls):
                                    syscalls[sym['st_name']].append(syscalnum)
                                else:
                                    syscalls[sym['st_name']] = []
                                    syscalls[sym['st_name']].append(syscalnum)
                        # deetct int 0x80
                        if ('int' in mnemonic and '0x80' in op_str):
                            syscall_num =int(disass_items[i-1][3].split(',')[1].split(' ')[1] , 16)
                            print()
                            
                            if (syscall_num != ''):
                                if (sym['st_name'] in syscalls):
                                    syscalls[sym['st_name']].append(int(syscall_num))
                                else:
                                    syscalls[sym['st_name']] = []
                                    syscalls[sym['st_name']].append(int(syscall_num))
    # print(Graphs)
    nodes  , Graphs = filter_Graph(nodes , Graphs )
    # print(Graphs)
    dot_file = Digraph(name="output" + "/"+file_path)
    Detect_FuncSysCallPattern(nodes , Graphs  , syscalls)
    
    dot_file.format = 'png'
    # print(syscalls)
    for l in nodes:
        sysc = ''
        try:
            if (sys.argv[2] == '-s'):
                sysc = '   syscalls : '
                if (l in syscalls):
                    for i in syscalls[l]:
                        sysc += str(i) + "  "
        except:
                pass
        if (l == 'main'):
            dot_file.node(l , l + sysc  , attrs=sysc, shape='circle')
        else:
            dot_file.node(l , l + sysc , attrs=sysc)
    for ed in Graphs:
        
        dot_file.edge(ed[0], ed[1], label='call')
        dot_file.edge(ed[1], ed[0], label='ret')

    try:
        dot_file.render() 
    except Exception as e:
        pass
    
    






# extract based on endian_or_no
def int_extract(size_in_bin):
    
    if (little_endian == False):
        return int('0x'+''.join(size_in_bin),16)
    else:
        tmp = copy.deepcopy(size_in_bin)
        tmp.reverse()        
        return int('0x'+''.join(tmp),16)



# in this function we extract structure of headers such as , program header start , size and section header start , size 
def extract_elf_structure_x64(e_file_info):
    h_extracted = dict()
    h_extracted["e_phoff"] = int_extract(e_file_info[32:40])
    h_extracted["e_shoff"] = int_extract(e_file_info[40:48])
    h_extracted["e_phentsize"] = int_extract(e_file_info[54:56])
    h_extracted["e_phnum"] = int_extract(e_file_info[56:58])
    h_extracted["e_shentsize"] = int_extract(e_file_info[58:60])
    h_extracted["e_shnum"] = int_extract(e_file_info[60:62])
    return h_extracted

def extract_elf_structure_x86(e_file_info):
    h_extracted = dict()
    h_extracted["e_phoff"] = int_extract(e_file_info[28:32])
    h_extracted["e_shoff"] = int_extract(e_file_info[32:36])
    h_extracted["e_phentsize"] = int_extract(e_file_info[42:44])
    h_extracted["e_phnum"] = int_extract(e_file_info[44:46])
    h_extracted["e_shentsize"] = int_extract(e_file_info[46:48])
    h_extracted["e_shnum"] = int_extract(e_file_info[48:50])
    return h_extracted

file_path = sys.argv[1]
f = open(file_path , 'rb')
e_ident = f.read(16)
e_ident=["{:02x}".format(i) for i in e_ident]


# set endianness
# print(e_ident)
if (e_ident[5] == '01'):
    little_endian = True
else:
    little_endian = False



#check x86 or x64
x86_or_x64 = ""
if (e_ident[4]== '01'):
    x86_or_x64 = "x86"
else:
    x86_or_x64 = "x64"



#start to extract data based on x86_or_x64
if (x86_or_x64 == "x86"):
    print("x86 ----------------------------------------------- ")

    tmp = f.read(36)
    e_header_file_info = e_ident + ["{:02x}".format(i) for i in tmp]

    h_structur_extracted = extract_elf_structure_x86(e_header_file_info)
    f.seek(h_structur_extracted["e_phoff"])
    e_program_header = []
    e_section_header = []
    for i in range(h_structur_extracted["e_phnum"]):
        e_program_header.append(["{:02x}".format(pr) for pr in f.read(h_structur_extracted["e_phentsize"])])
    # extract section header 
    f.seek(h_structur_extracted["e_shoff"])
    for i in range(h_structur_extracted["e_shnum"]):
        e_section_header.append(["{:02x}".format(se) for se in f.read(h_structur_extracted["e_shentsize"])])

    create_output_x86(e_header_file_info , h_structur_extracted , e_program_header , e_section_header , f)    
else:
    print("x64-----------------------------------------------------")
    tmp = f.read(48)
    e_header_file_info = e_ident + ["{:02x}".format(i) for i in tmp]
    h_structur_extracted = extract_elf_structure_x64(e_header_file_info)
    # jump to the first of program header 
    f.seek(h_structur_extracted["e_phoff"])
    e_program_header = []
    e_section_header = []
    for i in range(h_structur_extracted["e_phnum"]):
        e_program_header.append(["{:02x}".format(pr) for pr in f.read(h_structur_extracted["e_phentsize"])])
    # extract section header 
    f.seek(h_structur_extracted["e_shoff"])
    for i in range(h_structur_extracted["e_shnum"]):
        e_section_header.append(["{:02x}".format(se) for se in f.read(h_structur_extracted["e_shentsize"])])
    create_output_x64(e_header_file_info , h_structur_extracted , e_program_header , e_section_header , f)

    