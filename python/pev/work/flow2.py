import os
import sys
import ctypes
import pe
from pe import PE
import collections
import distorm3

# the encountered list contains tuples of (range, [addr])
# where the range is the sequence and the addr is where
# control flow went next. if control flow was a call or cnd jmp
# then add fall through and taking the operand.
encountered = list()
externTable = {}

def hasAddr(addr):
    for r in encountered:
        if addr in r[0]:
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

# this is the address of the beginning of the sequence containing
# the reference to initterm. If this is infact a thunk, backtrack some
# more
def doInitTermTable(addr):
    print 'initerm {:x}'.format(addr)
    
    possibleThunkCall = []

    for r in encountered:
        for i in r[0]:
            print '{:x}'.format(i),
        print
        if r[0][-1]==addr:
            possibleThunkCall += r
        if r[0][0]==addr and r[0][-1]==addr:
            print '''it's a thunk!'''
            isThunk = True

    #if isThunk:
    #    for r in possibleThunkCall:
    #        print '{:x}'.format(r)

    # f.seek(f.rva2ofs(addr))
    # code = f.read()

    # # distorm it and get the next flowcontrol instruction
    # offset = workRva
    # # when disassembling now return everything but stop on the first flowcontrol
    # # which should be the reference to initterm or the reference to the initerm thunk
    # iterable = distorm3.DecomposeGenerator(offset, code, dt
    #     distorm3.DF_STOP_ON_FLOW_CONTROL)
    # inst = iterable.next()

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
        print 'Found a loop!', hex(inst.address), inst, inst.flowControl
        return

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
            # add this sequence to the encountered list 
            encountered.append((range(workRva, inst.address+1), []))
            print 'encountered ret {:x} {:x}'.format(workRva, inst.address)
            return




        # if a conditional branch, don't take it
        elif inst.flowControl == 'FC_CND_BRANCH':
            # print what we've got
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type

            # don't goto the conditional branch's operand, add it to the workQ
            # if it's an immediate or absolute memory address operand
            type = inst.operands[0].type
            branchList = []
            if type == 'AbsoluteMemoryAddress':
                rva = inst.operands[0].value - f.imagebase
                print 'adding workQ ABS: {:x}'.format(rva)
                workQ.append(rva)
                branchList.append(rva)
            elif type == 'Immediate':
                rva = inst.operands[0].value
                print 'adding workQ IMM: {:x}'.format(rva)
                workQ.append(inst.operands[0].value)
                branchList.append(rva)
            else:
                print 'unhandled', type

            # fall through this branch
            fallThrough = inst.address + inst.size
            branchList.append(fallThrough)

            # add this sequence+branchList to the encountered list
            encountered.append((range(workRva, inst.address+1), branchList))
            print 'encountered CND {:x} {:x}'.format(workRva, inst.address)

            # fall through this conditional branch, press on
            f.seek(f.rva2ofs(fallThrough))
            offset = fallThrough




        # if a call to an absolute memory address don't follow it for now
        elif inst.flowControl == 'FC_CALL':
            # print what we've got
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type

            # don't goto the call's operand, add it to the workQ
            # if it's an immediate or absolute memory address operand
            type = inst.operands[0].type
            branchList = []
            if type == 'AbsoluteMemoryAddress':
                addr = inst.operands[0].value
                if addr in externTable:
                    print 'extern call', externTable[addr]
                    if externTable[addr] == '_initterm':
                        doInitTermTable(workRva)
                else:
                    print 'absolute call {:x}'.format(addr)

                    # add this sequence+branchList to the encountered list
                    rva = inst.operands[0].value - f.imagebase
                    branchList.append(rva)
            elif type == 'Immediate':
                rva = inst.operands[0].value
                print 'FC_CALL', inst.operands[0].type, rva

                # add this sequence+branchList to the encountered list
                branchList.append(rva)

                workQ.append(rva)
            else:
                print 'unhandled', type
            fallThrough = inst.address+inst.size
            branchList.append(fallThrough)

            # add this sequence+branchList to the encountered list
            encountered.append((range(workRva, inst.address+1), branchList))
            print 'encountered CALL {:x} {:x}'.format(workRva, inst.address)

            # fall through this call, press on
            f.seek(f.rva2ofs(fallThrough))
            offset = fallThrough




        elif inst.flowControl == 'FC_UNC_BRANCH':
            # print what we've got
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type

            # this is an unconditional jump, so we always take the operand.
            # Problem is we aren't doing computed calls, so if we encounter
            # anything other than an AbsoluteMemoryAddress or Immediate we punt
            type = inst.operands[0].type
            if type == 'AbsoluteMemoryAddress':
                addr = inst.operands[0].value
                if addr in externTable:
                    print 'extern jmp', externTable[addr]
                    if externTable[addr] == '_initterm':
                        doInitTermTable(workRva)
                    return
                else:
                    print 'absolute jmp {:x}'.format(addr)

                    # add this sequence+branch to the encountered list
                    rva = inst.operands[0].value - f.imagebase
                    encountered.append((range(workRva, inst.address+1), [rva]))
                    print 'encountered UNC {:x} {:x}'.format(workRva, inst.address)

                    # this is an unconditional branch, take it
                    f.seek(f.rva2ofs(rva))
                    offset = rva
            elif type == 'Immediate':
                print 'FC_UNC_BRANCH', inst.operands[0].type, inst.operands[0].value

                # add this sequence+branchList to the encountered list
                rva = inst.operands[0].value
                encountered.append((range(workRva, inst.address+1), [rva]))
                print 'encountered UNC {:x} {:x}'.format(workRva, inst.address)

                # this is an unconditional branch, take it
                f.seek(f.rva2ofs(rva))
                offset = rva
            else:
                print 'unhandled', type



        # these are unhandled flowControl types
        elif inst.flowControl in ['FC_INT', 'FC_SYS', 'FC_CMOV']:
            print 'unhandled', hex(inst.address), inst, inst.flowControl

            # unhandled, just fall through and add nothing to the work stack
            fallThrough = inst.address + inst.size

            # add this sequence to the encountered list 
            encountered.append((range(workRva, inst.address+1), [fallThrough]))
            print 'encountered UNK {:x} {:x}'.format(workRva, inst.address)

            f.seek(f.rva2ofs(fallThrough))
            offset = fallThrough
        # we should never be here
        else:
            # print what we've got
            print hex(inst.address), inst, inst.flowControl
            sys.exit(1)

        # read the next instruction
        code = f.read()
        iterable = distorm3.DecomposeGenerator(offset, code, dt, \
            distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)
        inst = iterable.next()

        # if we've encountered a loop exit
        if hasAddr(inst.address):
            print 'Found a loop!', hex(inst.address), inst, inst.flowControl
            return
        workRva = inst.address

if __name__ == '__main__':
    f = PE(open('print.exe', 'rb'))
    print 'ImageBase', f.imagebase
    print 'entrypoint ofs', hex(f.rva2ofs(f.entrypoint))
    getExterns(f)

    # some datastructure of interest
    workQ = collections.deque()

    # distorm3 
    dt = distorm3.Decode32Bits

    # add the entrypoint to the workQ
    workQ.append(f.entrypoint)

    while workQ:
        doWork(workQ)

