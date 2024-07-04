# coding=utf-8
# 解析 elf 文件需要导入的依赖库
# 安装 pyelftools 库成功 , 安装 elftools 库会报错
from elftools.elf.elffile import ELFFile
# 导入 Capstone 反汇编框架 , 用于解析 ELF 文件
from capstone import *


def get_str_offset(row_bytes,str1):
    str_bytes = bytes("\0"+str1+"\0",encoding="ASCII")
    offset = row_bytes.find(str_bytes)
    if offset != -1:
        offset += 1
    return offset

def find_string_xref(elf_path,pstr):
    # 打开 elf 文件
    file = open(elf_path, 'rb')
    # 创建 ELFFile 对象 , 该对象是核心对象
    elf_file = ELFFile(file)


    for section in elf_file.iter_sections():
        if section.name == ".rodata":
            rodata_header = section.header
        else:
            if section.name == ".text":
                text_header = section.header

        
    pstr_offset = 0
    
    if rodata_header != None:
        file.seek(rodata_header.sh_addr)
        rodata_bytes = file.read(rodata_header.sh_size)
        rodata_offet = get_str_offset(rodata_bytes,pstr)
        if rodata_offet != -1:
            pstr_offset = rodata_header.sh_addr + rodata_offet
    else:
        print("can't find rodata section")
        
    if pstr_offset == 0:
        print("can't find string")
        return 0
    print("success find string addr:",hex(pstr_offset))
    string_xref = []
    text_addr = text_header.sh_addr
    file.seek(text_header.sh_offset)
    text_bytes = file.read(text_header.sh_size)
    capstone = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    print("start find string xref")
    disasm = capstone.disasm_lite(text_bytes, text_addr)

    off = -1
    flag = False
    for line in disasm:
        address,size,mnemonic,op_str = line
        if mnemonic == "adrp":
            flag = True
            pre_address,pre_size,pre_mnemonic,pre_op_str = line
            continue
        if flag:
            if mnemonic == "add":
                op1 = pre_op_str.split(",")[-1]
                op2 = op_str.split(",")[-1]
                if op1[1] == "#" and op2[1]=="#":
                    off = int(op1[2:],16) + int(op2[2:],16)-pstr_offset
                    if off>=0 and off<=len(pstr):
                        string_xref.append(hex(pre_address))
            flag = False
        
        

        

    # 关闭文件
    file.close()
    print("find {} xref.".format(len(string_xref)))
    for xref in string_xref:
        print("xref addr:",xref)


if __name__ == '__main__':
    #find_string_xref的第一个参数为需要解析的elf文件路径,
    # 第二个参数为要查找交叉引用的字符串,字符串需要完整无误地输入
    find_string_xref("./libtest.so","test")