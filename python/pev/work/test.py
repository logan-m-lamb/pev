import os
from pe import PE
import distorm3

# distorm3 things
offset = 0
dt = distorm3.Decode32Bits

f = open('print.exe', 'rb')
o = PE(f)

# distorm3 
f.seek(o.rva2ofs(o.entrypoint))
code = f.read()

iterable = distorm3.DecomposeGenerator(offset, code, dt, \
    distorm3.DF_RETURN_FC_ONLY | distorm3.DF_STOP_ON_FLOW_CONTROL)

print iterable.next()
