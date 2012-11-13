import os
import sys
import ctypes
import re
import pe
from pe import PE
import collections
import distorm3

# the encountered list contains tuples of (range, [addr])
# where the range is the sequence and the addr is where
# control flow went next. if control flow was a call or cnd jmp
# then add operand and fallthrough. Take fallthrough, add operand
# to the workQ
encountered = list()
externTable = {}
initTermTable = 0
initTermSeq = 0
getMainArgsAddr = 0

# # returns true if hs contains needle
# def containsList(hs, needle):
#     for i in xrange(len(hs)-len(needle)+1):
#         for j in xrange(len(needle)):
#             if hs[i+j] != small[j]:
#                 break
#         else:
#             return True
#     return False
    

def hasAddr(addr):
    for r in encountered:
        if addr in r[0]:
            return True
    return False

def getSequence(addr):
    for r in encountered:
        if addr in r[0]:
            return r
    return None

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

# returns a list of RVAs of functions in this function pointer table
def findFunctionPointers(f, lowAddr, highAddr):
    if lowAddr > highAddr:
        print 'ffp problem'
        sys.exit(3)

    addr = lowAddr
    funcList = []
    while addr <= highAddr:
        funcPtr = f.fill(ctypes.c_uint32, addr)
        if funcPtr.value != 0:
            funcList.append(funcPtr.value - f.imagebase)
        addr += 4
    return funcList

# this is the address of the beginning of the sequence containing
# the reference to initterm. If this is infact a thunk, backtrack some
# more
# once a call to the thunk is found, return the arguments to _initterm
def findInitTerm(f, addr):
    global initTermSeq

    # first, we need to find the sequence which contains the call
    # to the _initterm thunk
    print 'initerm {:x}'.format(addr)
    
    possibleThunkCall = []
    isThunk = False

    for r in encountered:
        # if the last instruction of this sequence was the init
        # address keep track of it
        if r[0][-1]==addr:
            possibleThunkCall.append(r)
        if r[0][0]==addr and r[0][-1]==addr:
            isThunk = True

    # if this is a thunk, find the addr which branches to it
    if isThunk:
        # for now only handling ONE call
        for r in encountered:
            if addr in r[1]:
                print 'call to {:x} from {:x}'.format(addr, r[0][0])
                return findInitTerm(f, r[0][0])
        #for r in possibleThunkCall:
        #    print 'thunk'
        #    print 'seq',
        #    for e in r[0]:
        #        print '{:x}'.format(e),
        #    print
        #    print 'branch',
        #    for e in r[1]:
        #        print '{:x}'.format(e),

    # if we're here then addr is the beginning of the sequence which
    # contains the call to the _initterm thunk. Now, lets get the arguments
    # to _initterm (the last two things pushed onto the stack)
    else:
        print 'call to _initterm from {:x}'.format(addr)
        initTermSeq = addr

        f.seek(f.rva2ofs(addr))
        code = f.read()

        offset = addr
        iterable = distorm3.DecomposeGenerator(offset, code, distorm3.Decode32Bits, distorm3.DF_STOP_ON_FLOW_CONTROL)

        pushArgs = []
        for inst in iterable:
            if inst.mnemonic == 'PUSH':
                operand = inst.operands[0]
                if operand.type == 'Immediate':
                    print operand.type
                    print '{:x}'.format(inst.operands[0].value - f.imagebase)
                    pushArgs.append(inst.operands[0].value - f.imagebase)
                else:
                    # if this negative one is encountered we bail
                    pushArgs.append(-1)
            print inst

        # get the last two args, put them in the correct order
        args = pushArgs[-2:]
        args.reverse()

        if -1 in args:
            print 'Problem! diInitTermTable'
            sys.exit(2)

        print args
        return args

def getMainArgs(f, addr):
    f.seek(f.rva2ofs(addr))
    code = f.read()

    offset = addr
    iterable = distorm3.DecomposeGenerator(offset, code, distorm3.Decode32Bits, distorm3.DF_STOP_ON_FLOW_CONTROL)

    pushArgs = []
    for inst in iterable:
        if inst.mnemonic == 'PUSH':
            operand = inst.operands[0]
            print operand, operand.type
            if operand.type == 'Immediate':
                print operand.type
                print '{:x}'.format(inst.operands[0].value - f.imagebase)
                pushArgs.append(inst.operands[0].value - f.imagebase)
            else:
                pushArgs.append(-1)
        print inst

    args = pushArgs[-3:]

    if -1 in args:
        print 'Problem! getMainArgs'
        sys.exit(11)
    return args

# start looking for the _main call starting at initTermAddr,
# we know when we hit the main call by identifying argc,argv,envp
# being pushed to the stack
def findMainCall(f, initTermAddr, args):
    workQ = collections.deque()
    print 'findMainCall init addr {:x}'.format(initTermAddr) 
    workQ.append(initTermAddr)

    # while we have work, look for the call to main
    while workQ:
        addr = workQ.pop()

        seq = getSequence(addr)

        # goto the new work addr and disassemble until we hit a flow control
        f.seek(f.rva2ofs(addr))
        code = f.read()
        offset = addr
        iterable = distorm3.DecomposeGenerator(offset, code, distorm3.Decode32Bits, distorm3.DF_STOP_ON_FLOW_CONTROL)

        pushArgs = []
        for inst in iterable:
            if inst.mnemonic == 'PUSH':
                operand = inst.operands[0]
                print operand, operand.type
                if operand.type == 'AbsoluteMemoryAddress':
                    print operand.type
                    print '{:x}'.format(inst.operands[0].value - f.imagebase)
                    pushArgs.append(inst.operands[0].value - f.imagebase)
                else:
                    pushArgs.append(-1)
            print inst

        pushList = pushArgs[-3:]

        print 'pushList', pushList
        # if we found Main, return the conditional branch for this sequence
        if pushList == args:
            print 'found Main! {:x}'.format(seq[1][0])
            return seq[1][0]
        # otherwise add all branches to the workQ
        elif seq is not None:
            print 'extending',
            for i in seq[1]: print '{:x}'.format(i),
            print

            workQ.extend(seq[1])
    return None

# takes an address and finds its exit
# by look for a rets
# we assume this addr has already been explored,
# otherwise this won't work
def findFuncExit(f, funcAddr):
    workQ = collections.deque()
    print 'findFuncExit for addr {:x}'.format(funcAddr) 
    workQ.append(funcAddr)

    explored = []
    retList = []
    while workQ:
        addr = workQ.pop()

        if addr in explored:
            continue

        seq = getSequence(addr)
        if seq is not None:
            # if seq[1] is empty then there are no branches
            # for this sequence, could be a ret or an unhandled
            # instruction, check for ret
            if not seq[1]:
                f.seek(f.rva2ofs(addr))
                code = f.read()

                # distorm it and get the next flowcontrol instruction
                offset = addr
                iterable = distorm3.DecomposeGenerator(offset, code, distorm3.Decode32Bits, \
                    distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)
                inst = iterable.next()

                if inst.flowControl == 'FC_RET':
                    retList.append(inst.address)
            else:
                print 'extending2',
                explored.append(addr)
                for i in seq[1]: print '{:x}'.format(i),
                print
                workQ.extend(seq[1])
    return retList

def doWork(workQ):
    global initTermTable
    global getMainArgsAddr

    # get the next rva to do work on
    workRva = workQ.pop()
    print 'doing work {:x}\n'.format(workRva)

    f.seek(f.rva2ofs(workRva))
    code = f.read()

    # distorm it and get the next flowcontrol instruction
    offset = workRva
    iterable = distorm3.DecomposeGenerator(offset, code, distorm3.Decode32Bits, \
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
                        initTermTable = workRva
                        print 'initTermTable {:x}'.format(initTermTable)

                    m = re.search('^__.*get.*mainargs$', externTable[addr])
                    if m is not None:
                       getMainArgsAddr = workRva 
                       print '__getmainargs {:x}'.format(getMainArgsAddr)
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
                        initTermTable = workRva
                        print 'initTermTable {:x}'.format(initTermTable)

                    m = re.search('^__.*get.*mainargs$', externTable[addr])
                    if m is not None:
                       getMainArgsAddr = workRva 
                       print '__getmainargs {:x}'.format(getMainArgsAddr)

                    # add this sequence+branch to the encountered list
                    rva = addr - f.imagebase
                    encountered.append((range(workRva, inst.address+1), [rva]))
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
        else:
            # WE SHOULD NEVER BE HERE
            # print what we've got
            print hex(inst.address), inst, inst.flowControl
            sys.exit(1)

        # read the next instruction
        code = f.read()
        iterable = distorm3.DecomposeGenerator(offset, code, distorm3.Decode32Bits, \
            distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)
        inst = iterable.next()

        # if we've encountered a loop exit
        if hasAddr(inst.address):
            print 'Found a loop!', hex(inst.address), inst, inst.flowControl
            return
        workRva = offset

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print 'usage: flow2.py path-to-exe'
        sys.exit(13)

    f = PE(open(sys.argv[1], 'rb'))
    print 'ImageBase', f.imagebase
    print 'entrypoint ofs', hex(f.rva2ofs(f.entrypoint))
    getExterns(f)


    # add the entrypoint to the workQ
    workQ = collections.deque()
    workQ.append(f.entrypoint)

    # explore the program
    while workQ:
        doWork(workQ)
    print '* Initial Exploration Done'

    # try and get the function pointers from the 
    # _initterm function pointer table
    if not initTermTable:
        print '''couldn't find _initterm'''
        sys.exit(4)

    print '* Found _initterm' 
    args = findInitTerm(f, initTermTable)

    if args:
        print '* Found _initterm args' 
        funcList = findFunctionPointers(f, *args)
    else:
        print '''couldn't find _initterm args'''
        sys.exit(5)

    if not funcList:
        print 'no functions found in _initterm table'
        sys.exit(6)

    print '* Exploring _initerm func pointers'
    workQ.extend(funcList)
    # explore what was in the _initterm func ptr table
    while workQ:
        doWork(workQ)
    print '* Exploring _initerm func pointers done'

    if not getMainArgsAddr:
        print '''couldn't find getmainargs'''
        sys.exit(7)

    print '* Found call to _getmainargs' 
    args = getMainArgs(f, getMainArgsAddr)

    if args:
        print '* Found _getmainargs args:',
        for i in args: print '{:x}'.format(i),
        print
    else:
        print '''couldn't find getmainargs args'''
        sys.exit(8)

    print '* Finding main call'
    mainAddr = findMainCall(f, initTermSeq, args)
    if mainAddr is None:
        print '''couldn't find main'''
        sys.exit(12)
    print '* Found main call'
    print '* Finding main exit'
    exit = findFuncExit(f, mainAddr)
    print '* Found main exit',
    for i in exit: print '{:x}'.format(i),
    print

    print >> sys.stderr, 'entry: {:x}'.format(mainAddr)
    print >> sys.stderr, 'exit:  {:x}'.format(exit[0])
    print >> sys.stderr
    print >> sys.stderr, 'argc:  {:x}'.format(args[2])
    print >> sys.stderr, 'argv:  {:x}'.format(args[1])
    print >> sys.stderr, 'envp:  {:x}'.format(args[0])
    sys.exit(0)
