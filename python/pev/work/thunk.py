import os
import sys
import pe
import distorm3
import ctypes

if __name__ == '__main__':
    f = pe.PE(open('print.exe', 'rb'))
    
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
            print 'done'
            sys.exit(0)

        # OK, print name string
        print f.readStringRva(id.Name)

        # let's do all the functions for this DLL

        nextEntryRva += ctypes.sizeof(id)
