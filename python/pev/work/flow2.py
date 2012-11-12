import os
import sys
import ctypes
import pe
from pe import PE
import collections
import distorm3

encountered = list()
def hasAddr(addr):
    for r in encountered:
        if addr in r:
            return True
    return False

def getExterns(f):
    externTable = {}

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
                
                externTable[nextIatRva] = hintNameTable.Name
            else:
                externTable[nextIatRva] = 'Ordinal: '+ iltEntry.OrdinalNumber

            # either way, go to next entry
            nextIltRva += ctypes.sizeof(iltEntry)
            nextIatRva += ctypes.sizeof(iltEntry)

        nextEntryRva += ctypes.sizeof(id)

    return externTable


if __name__ == '__main__':
    f = PE(open('print.exe', 'rb'))
    print 'ImageBase', f.imagebase
    print 'entrypoint ofs', hex(f.rva2ofs(f.entrypoint))

    # some datastructure of interest
    externTable = getExterns(f)
    workQ = collections.deque()

    # distorm3 
    dt = distorm3.Decode32Bits

    # inst1
    f.seek(f.rva2ofs(f.entrypoint))
    code = f.read()

    offset = f.entrypoint

    iterable = distorm3.DecomposeGenerator(offset, code, dt, \
        distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)

    inst = iterable.next()
    
    # add what we've encountered
    encountered.append(range(f.entrypoint, inst.address+1))
    print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type

    # while workQ:
    #     doWork()

    while True:
        #
        # handle various instructions differently
        #

        # if we hit a ret return for now
        if inst.flowControl == 'FC_RET':
            print hex(inst.address), inst, inst.flowControl
            sys.exit()

        # if a conditional branch, don't take it
        elif inst.flowControl == 'FC_CND_BRANCH':
            # print what we've got
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type

            # don't goto the conditional branch's operand, add it to the workQ
            print 'workQ: {:x}'.format(inst.operands[0].value)
            workQ.append(inst.operands[0].value)

            # fall through this branch
            f.seek(f.rva2ofs(inst.address+inst.size))
            offset = inst.address + inst.size
        # if a call to an absolute memory address don't follow it for now
        elif inst.operands[0].type == 'AbsoluteMemoryAddress':
            print 'absolute call', inst.operands[0].type
            f.seek(f.rva2ofs(inst.address+inst.size))
            offset = inst.address + inst.size
        else:
            # print what we've got
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
            branchAddr = inst.operands[0].value
            f.seek(f.rva2ofs(branchAddr))
            offset = branchAddr

        # read the next instruction and add it to the encountered list
        code = f.read()
        iterable = distorm3.DecomposeGenerator(offset, code, dt, \
            distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)

        inst = iterable.next()
        # if we've encountered a loop exit
        if hasAddr(inst.address):
            print 'Found a loop!', hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
            sys.exit()
        encountered.append(range(branchAddr, inst.address+1))
