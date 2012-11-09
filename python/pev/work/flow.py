import os
from pe import PE
import distorm3

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
print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type

# inst2
pe.seek(pe.rva2ofs(inst.operands[0].value))
code = pe.read()

offset = inst.operands[0].value
iterable = distorm3.DecomposeGenerator(offset, code, dt, \
    distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)

#inst = iterable.next()
for inst in iterable:
	print hex(inst.address), inst, inst.flowControl, inst.operands[0], inst.operands[0].type
