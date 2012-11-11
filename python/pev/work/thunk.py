import os
import sys
import pe
import distorm3
import ctypes

if __name__ == '__main__':
    f = pe.PE(open('/tmp/pewter.exe', 'rb'))
    
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
            break

        # OK, print name string
        print ' DLL Name:', f.readStringRva(id.Name)
        print ' rva:  Hint/Ord Member-Name Bound-To'

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
                
                # check if it is bound by seeing if the IAT differs from the ILT
                iatEntry = f.fill(pe._IMPORT_LOOKUP_TABLE32, nextIatRva)

                if iltEntry == iatEntry:
                    # unbound
                    print '{:8>x}{:>6} {:<60}'.format(nextIatRva, hintNameTable.Hint, hintNameTable.Name)
                else:
                    # bound
                    print '{:8>x}{:>6} {:<60} {:08x}'.format(nextIatRva, hintNameTable.Hint, hintNameTable.Name, iatEntry.Address)

            else:
                if iltEntry == iatEntry:
                    # unbound
                    print '{:8>x}{:>6} {:<60}'.format(nextIatRva, iltEntry.OrdinalNumber, '')
                else:
                    # bound
                    print '{:8>x}{:>6} {:<60} {:08x}'.format(nextIatRva, iltEntry.OrdinalNumber, '', iatEntry.Address)

            # either way, go to next entry
            nextIltRva += ctypes.sizeof(iltEntry)
            nextIatRva += ctypes.sizeof(iatEntry)
            

        nextEntryRva += ctypes.sizeof(id)
        print
