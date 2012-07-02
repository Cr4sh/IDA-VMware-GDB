
#
# ******************************************************************************
#
#  Helper script for Windows kernel debugging with IDA Pro on VMware + GDB stub.
#
#    By Oleksiuk Dmytro (aka Cr4sh)
#    http://twitter.com/d_olex
#    http://blog.cr4.sh
#    mailto:cr4sh0@gmail.com
#
#  Features:
#
#    - Enumerating loaded kernel modules and segments creation for them.
#    - Loading debug symbols for kernel modules.
# 
#  Based on original vmware_modules.py from Hex Blog article 
#  (http://www.hexblog.com/?p=94).
#
#  Changes:
#     
#    * Changed nt!PsLoadedModuleList finding algo, 'cause using FS segment base
#      for this -- is bad idea (FS not always points to the _KPCR).
#    * Added complete support of Windows x64.
#    * Fixed bugs in .PDB loading for mdules with the 'non-canonical' image path.
#
#  Tested on IDA 6.1 with IDAPython v1.5.2 on Windows XP, Vista, 7 (x32 and x64)
#  as debug targets.
#
# ******************************************************************************
#

#
# Path to the folder, that contains files from the \SystemRoot\system32
# of your debug target.
#
SYSTEM32_COPY_PATH = "E:\\VMware Virtual Machines\\Windows 7 RTM x86\\System32"

#
# Lave this list empty, if you want to load debug symbols for all modules.
# Otherwise -- specify list of the module file names.
#
PDB_MODULES = [ "ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe", "win32k.sys" ]

def is_64bit():

    #
    # Seems that idainfo.is_32bit() and idainfo.is_64bit() always
    # returns False (WTF?!) on my machines, so, I implemented a little hack
    # with the IDT location check on x86_64 canonical address.
    #

    idtr_str = Eval('SendGDBMonitor("r idtr")')
    idt = long(idtr_str[10 : 10 + 10], 16)
    
    return ((idt & 0xffffff00) == 0xfffff800)

# def end

if is_64bit():

    print "[+] 64-bit target"

    Ptr = Qword    

    # type argument for SegCreate()
    segment_type = 2

    LIST_ENTRY_Blink = 8

    UNICODE_STRING_Buffer = 8

    LDR_DATA_TABLE_ENTRY_BaseAddress = 0x30
    LDR_DATA_TABLE_ENTRY_EntryPoint  = 0x38
    LDR_DATA_TABLE_ENTRY_SizeOfImage = 0x40
    LDR_DATA_TABLE_ENTRY_FullDllName = 0x48
    LDR_DATA_TABLE_ENTRY_BaseDllName = 0x58

    IMAGE_NT_HEADERS_OptionalHeader = 0x18
    IMAGE_OPTIONAL_HEADER_SizeOfImage = 0x38

else:

    print "[+] 32-bit target"

    Ptr = Dword    

    # type argument for SegCreate()
    segment_type = 1

    LIST_ENTRY_Blink = 4

    UNICODE_STRING_Buffer = 4

    LDR_DATA_TABLE_ENTRY_BaseAddress = 0x18
    LDR_DATA_TABLE_ENTRY_EntryPoint  = 0x1c
    LDR_DATA_TABLE_ENTRY_SizeOfImage = 0x20
    LDR_DATA_TABLE_ENTRY_FullDllName = 0x24
    LDR_DATA_TABLE_ENTRY_BaseDllName = 0x2c

    IMAGE_NT_HEADERS_OptionalHeader = 0x18
    IMAGE_OPTIONAL_HEADER_SizeOfImage = 0x38


def find_sign(addr, sign):

    IMAGE_DOS_HEADER_e_lfanew = 0x3c

    # get image size from NT headers
    e_lfanew = Dword(addr + IMAGE_DOS_HEADER_e_lfanew)
    SizeOfImage = Dword(addr + e_lfanew + \
        IMAGE_NT_HEADERS_OptionalHeader + \
        IMAGE_OPTIONAL_HEADER_SizeOfImage)    

    l = 0
    while l < SizeOfImage:

        matched = True
        
        for i in range(0, len(sign)):

            b = Byte(addr + l + i)
            if sign[i] is not None and sign[i] != b:

                matched = False
                break

        if matched:

            return addr + l

        l += 1

    raise Exception("find_sign(): Unable to locate signature")

# def end

def get_interrupt_vector_64(number):

    #
    # get IDT base, GDB returns is as the following string:
    # idtr base=0xfffff80003400080 limit=0xfff
    #
    idtr_str = Eval('SendGDBMonitor("r idtr")')

    # extract and convert IDT base
    idt = long(idtr_str[10 : 10 + 18], 16)

    # go to the specified IDT descriptor
    idt += number * 16

    # build interrupt vector address
    descriptor_0 = Qword(idt)
    descriptor_1 = Qword(idt + 8)
    descriptor = ((descriptor_0 >> 32) & 0xffff0000) + (descriptor_0 & 0xffff) + (descriptor_1 << 32)

    return descriptor

# def end

def get_interrupt_vector_32(number):

    #
    # get IDT base, GDB returns is as the following string:
    # idtr base=0x80b95400 limit=0x7ff
    #
    idtr_str = Eval('SendGDBMonitor("r idtr")')

    # extract and convert IDT base
    idt = long(idtr_str[10 : 10 + 10], 16)

    # go to the specified IDT descriptor
    idt += number * 8

    # build interrupt vector address
    descriptor_0 = Qword(idt)
    descriptor = ((descriptor_0 >> 32) & 0xffff0000) + (descriptor_0 & 0xffff)

    return descriptor

# def end

def find_PsLoadedModuleList_64(addr):

    #
    # Find nt!PsLoadedModuleList on Windows x64 by 
    # following signature from the nt!IoFillDumpHeader():
    #
    sign = [ 
        0xC7, 0x43, 0x30, 0x64, 0x86, 0x00, 0x00,  # mov     dword ptr [rbx+30h], 8664h
        0x89, 0x93, 0x98, 0x0F, 0x00, 0x00,        # mov     [rbx+0F98h], edx
        0x48, 0x8B, 0x05, None, None, None, None,  # mov     rax, cs:MmPfnDatabase
        0x48, 0x89, 0x43, 0x18,                    # mov     [rbx+18h], rax
        0x48, 0x8D, 0x05, None, None, None, None   # lea     rax, PsLoadedModuleList        
    ]

    sign_offset = 24

    s = find_sign(addr, sign)

    return s + sign_offset + Dword(s + sign_offset + 3) + 7

# def end

def find_PsLoadedModuleList_32(addr):

    #
    # Find nt!PsLoadedModuleList on Windows x32 by 
    # following signature from the nt!IoFillDumpHeader():
    #
    sign = [ 
        0xA1, None, None, None, None,            # mov     eax, ds:_MmPfnDatabase
        0x89, None, 0x14,                        # mov     [esi+14h], eax
        0xC7, None, 0x18, None, None, None, None # mov     dword ptr [esi+18h], offset _PsLoadedModuleList        
    ]

    sign_offset = 11

    s = find_sign(addr, sign)

    return Dword(s + sign_offset)

# def end

def get_unistr(addr):
    
    length = Word(addr)
    start = Ptr(addr + UNICODE_STRING_Buffer)
    
    if length > 1000:

        raise Exception("get_unistr(): String too long")

    res = u''
    while length > 0:

        c = Word(start)
        
        if c == 0:

            break

        res += unichr(c)
        start += 2
        length -= 1
    
    return res

# def end

def walk_modulelist(list, callback):

    # get the first module
    cur_mod = Ptr(list)

    # loop until we come back to the beginning
    while cur_mod != list and cur_mod != BADADDR:

        BaseAddress = Ptr(cur_mod + LDR_DATA_TABLE_ENTRY_BaseAddress)
        EntryPoint  = Ptr(cur_mod + LDR_DATA_TABLE_ENTRY_EntryPoint)
        SizeOfImage = Ptr(cur_mod + LDR_DATA_TABLE_ENTRY_SizeOfImage)
        FullDllName = get_unistr(cur_mod + LDR_DATA_TABLE_ENTRY_FullDllName).encode('utf-8')
        BaseDllName = get_unistr(cur_mod + LDR_DATA_TABLE_ENTRY_BaseDllName).encode('utf-8')
        
        # get next module (FLink)
        next_mod = Ptr(cur_mod)

        print " * %s %s" % (str(hex(BaseAddress)), FullDllName)

        if callback is not None:

            callback(BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint)
        
        # check that BLink points to the previous structure
        if Ptr(next_mod + LIST_ENTRY_Blink) != cur_mod:

            raise Exception("walk_modulelist(): List error")
        
        cur_mod = next_mod

# def end

def get_module_base(addr):

    if is_64bit():

        page_mask = 0xFFFFFFFFFFFFF000

    else:

        page_mask = 0xFFFFF000

    # align address by PAGE_SIZE
    addr &= page_mask

    # find module base by address inside it
    l = 0
    while l < 5 * 1024 * 1024:

        # check for the MZ signature
        w = Word(addr - l) 
        if w == 0x5a4d:
        
            return addr - l
        
        l += 0x1000

    raise Exception("get_module_base(): Unable to locate DOS signature")

# def end

def add_segment_callback(BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint):
    
    # do we already have a segment for this module?
    if SegStart(BaseAddress) != BaseAddress or \
       SegEnd(BaseAddress) != BaseAddress + SizeOfImage:

        try:

            # if not, create one
            SegCreate(BaseAddress, BaseAddress + SizeOfImage, 0, segment_type, saRelByte, scPriv)
            SegRename(BaseAddress, BaseDllName)

        except:

            pass

# def end

def load_pdb_callback(BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint):

    if len(PDB_MODULES) > 0 and BaseDllName.lower() not in PDB_MODULES:

        # skip this module
        return

    # fix the path, that starts with the windows folder name
    if FullDllName.lower().startswith("\\windows\\system32"):    

        FullDllName = "\\SystemRoot\\system32" + FullDllName[17:]

    # fix the path, that contains file name only
    if FullDllName.find("\\") == -1:    

        FullDllName = "\\SystemRoot\\system32\\DRIVERS\\" + FullDllName

    # load modules from the System32 only
    if FullDllName.lower().startswith("\\systemroot\\system32"):

        # translate into local filename
        filename = SYSTEM32_COPY_PATH + FullDllName[20:]

        if is_64bit():

            val = 0xFFFFFFFFFFFFFFFE

        else:

            val = 0xFFFFFFFE

        penode = idaapi.netnode()
        penode.create("$ PE header")
        
        # save old values
        save_base = penode.altval(val)
        save_name = idaapi.get_input_file_path()
        
        # set parameters for PDB plugin
        penode.altset(val, BaseAddress)
        idaapi.set_root_filename(filename)
        
        # load symbols
        print "Trying to load symbols for %s from %s" % (BaseDllName, filename)
        RunPlugin("pdb", 3) # use 1 to get a confirmation prompt
        pdbnode = idaapi.netnode("$ pdb")
        ok = pdbnode.altval(0)
        if not ok:

            print "Could not load symbols for %s" % BaseDllName
        
        # restore previous values
        penode.altset(val, save_base)
        idaapi.set_root_filename(save_name)

    else:
    
        print "%s is not in System32 directory" % BaseDllName

# def end

if is_64bit():

    get_interrupt_vector = get_interrupt_vector_64
    find_PsLoadedModuleList = find_PsLoadedModuleList_64

else:

    get_interrupt_vector = get_interrupt_vector_32
    find_PsLoadedModuleList = find_PsLoadedModuleList_32

addr = get_interrupt_vector(0)
kernel_base = get_module_base(addr)

print "Kernel base is %s" % str(hex(kernel_base))

PsLoadedModuleList = find_PsLoadedModuleList(kernel_base)

print "nt!PsLoadedModuleList is at %s" % str(hex(PsLoadedModuleList))

walk_modulelist(PsLoadedModuleList, add_segment_callback)
walk_modulelist(PsLoadedModuleList, load_pdb_callback)

#
# EoF
#
