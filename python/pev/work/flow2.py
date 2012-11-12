import os
import sys
import ctypes
import pe
from pe import PE
import collections
import distorm3

encountered = list()
externTable = {}

def hasAddr(addr):
    for r in encountered:
        if addr in r:
            return True
    return False

def getExterns(f):

    # get VA of Import Directory
    dirTableRva = f.directories_ptr[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].contents.VirtualAddress

    if dirTableRva == 0:
        print 'import directory not found'
        sys.exit(1)

    # OK, lets fill the first directory table entry
    nextEntryRva = dirTableRva
    while True:
        id = f.fill(pe._IMAGE_IMPORT_DESCRIPTOR, nextEntryRva)
        if f.isNull(id):
            break

        # let's do all the functions for this DLL
        lookupTableRva = id.OriginalFirstThunk
        addressTableRva = id.FirstThunk

        # loop through the tables
        nextIltRva = lookupTableRva
        nextIatRva = addressTableRva

        while True:
            iltEntry = f.fill(pe._IMPORT_LOOKUP_TABLE32, nextIltRva)
            
            # if the iltEntry is null, we're at the end of the array
            if f.isNull(iltEntry):
                break

            # if not importing by ordinal, then we're importing by name
            # get the hint/name table
            if iltEntry.OrdinalFlag == 0:
                hintNameTable = f.fill(pe._IMAGE_IMPORT_BY_NAME, iltEntry.HintNameRva)
                
                externTable[nextIatRva + f.imagebase] = hintNameTable.Name
            else:
                externTable[nextIatRva + f.imagebase] = 'Ordinal: '+ iltEntry.OrdinalNumber

            # either way, go to next entry
            nextIltRva += ctypes.sizeof(iltEntry)
            nextIatRva += ctypes.sizeof(iltEntry)

        nextEntryRva += ctypes.sizeof(id)

def doWork(workQ):

    # get the next rva to do work on
    workRva = workQ.pop()
    print 'doing work {:x}\n'.format(workRva)

    f.seek(f.rva2ofs(workRva))
    code = f.read()

    # distorm it and get the next flowcontrol instruction
    offset = workRva
    iterable = distorm3.DecomposeGenerator(offset, code, dt, \
        distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)
    inst = iterable.next()

    # check if we've been here before, if so stop doing here
    if hasAddr(inst.address):
        #print 'Found a loop!', hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
        print 'Found a loop!', hex(inst.address), inst, inst.flowControl
        return
    encountered.append(range(workRva, inst.address+1))

    # loop until we hit a break condition ( a return )
    while True:
        #
        # handle various instructions differently
        #
        # the types of instructions we have are:
        # 
        # Indicates the instruction is not a flow-control instruction.
        # "FC_NONE",
        # Indicates the instruction is one of: CALL, CALL FAR.
        # "FC_CALL",
        # Indicates the instruction is one of: RET, IRET, RETF.
        # "FC_RET",
        # Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
        # "FC_SYS",
        # Indicates the instruction is one of: JMP, JMP FAR.
        # "FC_UNC_BRANCH",
        # Indicates the instruction is one of:
        # JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
        # "FC_CND_BRANCH",
        # Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
        # "FC_INT",
        # Indicates the instruction is one of: CMOVxx.
        # "FC_CMOV"

        # if we hit a ret return for now
        if inst.flowControl == 'FC_RET':
            print hex(inst.address), inst, inst.flowControl
            return

        # if a conditional branch, don't take it
        elif inst.flowControl == 'FC_CND_BRANCH':
            # print what we've got
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type

            # don't goto the conditional branch's operand, add it to the workQ
            # if it's an immediate or absolute memory address operand
            type = inst.operands[0].type
            if type == 'AbsoluteMemoryAddress':
                rva = inst.operands[0].value - f.imagebase
                print 'adding workQ ABS: {:x}'.format(inst.operands[0].value)
                workQ.append(rva)
            elif type == 'Immediate':
                print 'adding workQ IMM: {:x}'.format(inst.operands[0].value)
                workQ.append(inst.operands[0].value)
            else:
                print 'unhandled', type

            # fall through this branch
            f.seek(f.rva2ofs(inst.address+inst.size))
            offset = inst.address + inst.size

        # if a call to an absolute memory address don't follow it for now
        elif inst.flowControl == 'FC_CALL':
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
            type = inst.operands[0].type
            if type == 'AbsoluteMemoryAddress':
                addr = inst.operands[0].value
                if addr in externTable:
                    print 'extern call', externTable[addr]
                else:
                    print 'absolute call {:x}'.format(addr)
                    rva = inst.operands[0].value - f.imagebase
                    f.seek(f.rva2ofs(rva))
                    offset = rva
            elif type == 'Immediate':
                print 'FC_CALL', inst.operands[0].type, inst.operands[0].value
                workQ.append(inst.operands[0].value)
            else:
                print 'unhandled', type
            f.seek(f.rva2ofs(inst.address+inst.size))
            offset = inst.address + inst.size
        elif inst.flowControl == 'FC_UNC_BRANCH':
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
            type = inst.operands[0].type
            if type == 'AbsoluteMemoryAddress':
                addr = inst.operands[0].value
                if addr in externTable:
                    print 'extern jmp', externTable[addr]
                    return
                else:
                    print 'absolute jmp {:x}'.format(addr)
                    rva = inst.operands[0].value - f.imagebase
                    f.seek(f.rva2ofs(rva))
                    offset = rva
            elif type == 'Immediate':
                print 'FC_UNC_BRANCH', inst.operands[0].type, inst.operands[0].value
                f.seek(f.rva2ofs(inst.operands[0].value))
                offset = inst.operands[0].value
            else:
                print 'unhandled', type
        elif inst.flowControl == 'FC_INT':
            print 'unhandled', hex(inst.address), inst, inst.flowControl
            f.seek(f.rva2ofs(inst.address+inst.size))
            offset = inst.address + inst.size
        elif inst.flowControl == 'FC_SYS':
            print 'unhandled', hex(inst.address), inst, inst.flowControl
            f.seek(f.rva2ofs(inst.address+inst.size))
            offset = inst.address + inst.size
        elif inst.flowControl == 'FC_CMOV':
            print 'unhandled', hex(inst.address), inst, inst.flowControl
            f.seek(f.rva2ofs(inst.address+inst.size))
            offset = inst.address + inst.size
        else:
            # print what we've got
            print hex(inst.address), inst, inst.flowControl
            sys.exit(1)
            workRva = inst.operands[0].value
            f.seek(f.rva2ofs(workRva))
            offset = workRva

        # read the next instruction and add it to the encountered list
        code = f.read()
        iterable = distorm3.DecomposeGenerator(offset, code, dt, \
            distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)

        inst = iterable.next()
        # if we've encountered a loop exit
        if hasAddr(inst.address):
            #print 'Found a loop!', hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
            print 'Found a loop!', hex(inst.address), inst, inst.flowControl
            return
        encountered.append(range(workRva, inst.address+1))

if __name__ == '__main__':
    f = PE(open('print.exe', 'rb'))
    print 'ImageBase', f.imagebase
    print 'entrypoint ofs', hex(f.rva2ofs(f.entrypoint))
    getExterns(f)

    # some datastructure of interest
    workQ = collections.deque()

    # distorm3 
    dt = distorm3.Decode32Bits

    # inst1
    f.seek(f.rva2ofs(f.entrypoint))
    code = f.read()

    workQ.append(f.entrypoint)

    while workQ:
        doWork(workQ)

