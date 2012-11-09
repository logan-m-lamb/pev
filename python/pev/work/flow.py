import os
import sys
from pe import PE
import distorm3

encountered = list()
def hasAddr(addr):
    for r in encountered:
        if addr in r:
            return True
    return False

if __name__ == '__main__':
    pe = PE(open('print.exe', 'rb'))
    print 'ImageBase', pe.imagebase
    print 'entrypoint ofs', hex(pe.rva2ofs(pe.entrypoint))

    # distorm3 
    dt = distorm3.Decode32Bits

    # inst1
    pe.seek(pe.rva2ofs(pe.entrypoint))
    code = pe.read()

    offset = pe.entrypoint
    iterable = distorm3.DecomposeGenerator(offset, code, dt, \
        distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)

    inst = iterable.next()
    
    # add what we've encountered
    encountered.append(range(pe.entrypoint, inst.address+1))
    print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type

    while True:
        # if a conditional branch, don't take it
#        if inst.flowControl == 'FC_CND_BRANCH':
#            pe.seek(pe.rva2ofs(inst.address+inst.size))
#            offset = inst.address + inst.size
#        else:
#            pe.seek(pe.rva2ofs(inst.operands[0].value))
#            offset = inst.operands[0].value
        branchAddr = inst.operands[0].value
        pe.seek(pe.rva2ofs(branchAddr))
        offset = branchAddr

        code = pe.read()
        iterable = distorm3.DecomposeGenerator(offset, code, dt, \
            distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)

        inst = iterable.next()
        if hasAddr(inst.address):
            print 'Found a loop!', hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
            sys.exit()

        encountered.append(range(branchAddr, inst.address+1))

        if inst.flowControl == 'FC_RET':
            print hex(inst.address), inst, inst.flowControl
            sys.exit()
        else:
            print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
