from ctypes import *
from os.path import split, join
import os

#==============================================================================
# Load libPe
#==============================================================================

_pe_path = split(__file__)[0]
potential_libs = ['pe.dll', 'libpe.dll', 'libpe.so', 'libpe.dylib']
lib_was_found = False
for i in potential_libs:
    try:
        _pe_file = join(_pe_path, i)
        _pe = cdll.LoadLibrary(_pe_file)
        lib_was_found = True
    except OSError:
        pass

if lib_was_found == False:
    raise ImportError("Error loading the pe dynamic library (or cannot load library into process).")

try:
    # really need to set argument types here

    # basic functions
    is_pe = _pe.is_pe
    pe_deinit = _pe.pe_deinit
    rva2ofs = _pe.rva2ofs
    ofs2rva = _pe.ofs2rva
    pe_get_size = _pe.pe_get_size

    # header functions
    pe_init = _pe.pe_init
    pe_get_sections = _pe.pe_get_sections
    pe_get_section = _pe.pe_get_section
    pe_get_directories = _pe.pe_get_directories
    pe_get_optional = _pe.pe_get_optional
    pe_get_coff = _pe.pe_get_coff
    pe_get_dos = _pe.pe_get_dos

    pe_get_resource_directory = _pe.pe_get_resource_directory
    pe_get_resource_entries = _pe.pe_get_resource_entries

    pe_rva2section = _pe.pe_rva2section
except AttributeError:
    raise ImportError("Error loading pe")

#==============================================================================
# libPe Interface
#==============================================================================
PE32 = 0x10b
PE64 = 0x20b
MZ   = 0x5a4d

# typedef uint32_t DWORD;
# typedef int32_t LONG;
# typedef uint8_t BYTE;
# typedef uint16_t WORD;
# typedef uint64_t QWORD;

MAX_SECTIONS = 96

# section name size
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_ORDINAL_FLAG32    = 0x80000000
IMAGE_ORDINAL_FLAG64    = 0x8000000000000000

# resources types
RT_CURSOR       = 1    # cursor image
RT_BITMAP       = 2    # bitmap (.bmp)
RT_ICON         = 3    # icon
RT_MENU         = 4    # menu
RT_DIALOG       = 5    # dialog window
RT_STRING       = 6    # unicode string
RT_FONTDIR      = 7    # font directory
RT_FONT         = 8    # font
RT_ACCELERATOR  = 9    # hot keys
RT_RCDATA       = 10   # data
RT_MESSAGETABLE = 11   # string table
RT_GROUP_CURSOR = 12   # cursor group
RT_GROUP_ICON   = 14   # icon group
RT_VERSION      = 16   # version information
RT_DLGINCLUDE   = 17   # names of header files for dialogs (*.h) used by compiler
RT_PLUGPLAY     = 19   # data determined by application
RT_VXD          = 20   # vxd info
RT_ANICURSOR    = 21   # animated cursor
RT_ANIICON      = 22   # animated icon
RT_HTML         = 23   # html page
RT_MANIFEST     = 24   # manifest of Windows XP build
RT_DLGINIT      = 240  # strings used for initiating some controls in dialogs
RT_TOOLBAR      = 241  # configuration of toolbars

# directory Entries
IMAGE_DIRECTORY_ENTRY_EXPORT         = 0   # Export Directory
IMAGE_DIRECTORY_ENTRY_IMPORT         = 1   # Import Directory
IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2   # Resource Directory
IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3   # Exception Directory
IMAGE_DIRECTORY_ENTRY_SECURITY       = 4   # Security Directory
IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5   # Base Relocation Table
IMAGE_DIRECTORY_ENTRY_DEBUG          = 6   # Debug Directory
# IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7   # Architecture Specific Data
IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8   # RVA of GP
IMAGE_DIRECTORY_ENTRY_TLS            = 9   # TLS Directory
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10   # Load Configuration Directory
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11   # Bound Import Directory in headers
IMAGE_DIRECTORY_ENTRY_IAT            = 12   # Import Address Table
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13   # Delay Load Import Descriptors
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14   # COM Runtime descriptor

class _RESOURCE_ENTRY (Structure):
    _pack_ = 1
    _fields_ = [
        ('name', c_char * 20),
        ('code', c_uint)
    ]

class _MACHINE_ENTRY (Structure):
    _pack_ = 1
    _fields_ = [
        ('name', c_char * 40),
        ('code', c_uint16)
    ]

class _IMAGE_DOS_HEADER (Structure):
    _pack_ = 1
    _fields_ = [
        ('e_magic', c_uint16),
        ('e_cblp', c_uint16),
        ('e_cp', c_uint16),
        ('e_crlc', c_uint16),
        ('e_cparhdr', c_uint16),
        ('e_minalloc', c_uint16),
        ('e_maxalloc', c_uint16),
        ('e_ss', c_uint16),
        ('e_sp', c_uint16),
        ('e_csum', c_uint16),
        ('e_ip', c_uint16),
        ('e_cs', c_uint16),
        ('e_lfarlc', c_uint16),
        ('e_ovno', c_uint16),
        ('e_res', c_uint16 * 4),
        ('e_oemid', c_uint16),
        ('e_oeminfo', c_uint16),
        ('e_res2', c_uint16 * 10),
        ('e_lfanew', c_int32)
    ]

class _IMAGE_FILE_HEADER (Structure):
    _pack_ = 1
    _fields_ = [
        ('Machine', c_uint16),
        ('NumberOfSections', c_uint16),
        ('TimeDateStamp', c_uint32),
        ('PointerToSymbolTable', c_uint32),
        ('NumberOfSymbols', c_uint32),
        ('SizeOfOptionalHeader', c_uint16),
        ('Characteristics', c_uint16)
    ]
_IMAGE_COFF_HEADER = _IMAGE_FILE_HEADER

class _IMAGE_OPTIONAL_HEADER_32 (Structure):
    _pack_ = 1
    _fields_ = [
        ('Magic', c_uint16),
        ('MajorLinkerVersion', c_uint8),
        ('MinorLinkerVersion', c_uint8),
        ('SizeOfCode', c_uint32),
        ('SizeOfInitializedData', c_uint32),
        ('SizeOfUninitializedData', c_uint32),
        ('AddressOfEntryPoint', c_uint32),
        ('BaseOfCode', c_uint32),
        ('BaseOfData', c_uint32), # only PE32
        ('ImageBase', c_uint32),
        ('SectionAlignment', c_uint32),
        ('FileAlignment', c_uint32),
        ('MajorOperatingSystemVersion', c_uint16),
        ('MinorOperatingSystemVersion', c_uint16),
        ('MajorImageVersion', c_uint16),
        ('MinorImageVersion', c_uint16),
        ('MajorSubsystemVersion', c_uint16),
        ('MinorSubsystemVersion', c_uint16),
        ('Reserved1', c_uint32),
        ('SizeOfImage', c_uint32),
        ('SizeOfHeaders', c_uint32),
        ('CheckSum', c_uint32),
        ('Subsystem', c_uint16),
        ('DllCharacteristics', c_uint16),
        ('SizeOfStackReserve', c_uint32),
        ('SizeOfStackCommit', c_uint32),
        ('SizeOfHeapReserve', c_uint32),
        ('SizeOfHeapCommit', c_uint32),
        ('LoaderFlags', c_uint32),
        ('NumberOfRvaAndSizes', c_uint32)
        # IMAGE_DATA_DIRECTORY DataDirectory[]
    ]

class _IMAGE_OPTIONAL_HEADER_64 (Structure):
    _pack_ = 1
    _fields_ = [
        ('Magic', c_uint16),
        ('MajorLinkerVersion', c_uint8),
        ('MinorLinkerVersion', c_uint8),
        ('SizeOfCode', c_uint32),
        ('SizeOfInitializedData', c_uint32),
        ('SizeOfUninitializedData', c_uint32),
        ('AddressOfEntryPoint', c_uint32),
        ('BaseOfCode', c_uint32),
        ('ImageBase', c_uint64),
        ('SectionAlignment', c_uint32),
        ('FileAlignment', c_uint32),
        ('MajorOperatingSystemVersion', c_uint16),
        ('MinorOperatingSystemVersion', c_uint16),
        ('MajorImageVersion', c_uint16),
        ('MinorImageVersion', c_uint16),
        ('MajorSubsystemVersion', c_uint16),
        ('MinorSubsystemVersion', c_uint16),
        ('Reserved1', c_uint32),
        ('SizeOfImage', c_uint32),
        ('SizeOfHeaders', c_uint32),
        ('CheckSum', c_uint32),
        ('Subsystem', c_uint16),
        ('DllCharacteristics', c_uint16),
        ('SizeOfStackReserve', c_uint64),
        ('SizeOfStackCommit', c_uint64),
        ('SizeOfHeapReserve', c_uint64),
        ('SizeOfHeapCommit', c_uint64),
        ('LoaderFlags', c_uint32), # must be zero
        ('NumberOfRvaAndSizes', c_uint32)
        # IMAGE_DATA_DIRECTORY DataDirectory[]
    ]

class _IMAGE_OPTIONAL_HEADER (Structure):
    _pack_ = 1
    _fields_ = [
        ('_32', POINTER(_IMAGE_OPTIONAL_HEADER_32)),
        ('_64', POINTER(_IMAGE_OPTIONAL_HEADER_64)),
    ]

class _IMAGE_DATA_DIRECTORY (Structure):
    _pack_ = 1
    _fields_ = [
        ('VirtualAddress', c_uint32),
        ('Size', c_uint32)
    ]    


class _IMAGE_SECTION_HEADER (Structure):
    class _Misc (Union):
        _pack_ = 1
        _fields_ = [
            ('PhysicalAddress', c_uint32), # same value as next field
            ('VirtualSize', c_uint32)
        ]
    _pack_ = 1
    _fields_ = [
        ('Name', c_uint8 * IMAGE_SIZEOF_SHORT_NAME),
        ('Misc', _Misc),
        ('DWORD VirtualAddress', c_uint32),
        ('DWORD SizeOfRawData', c_uint32),
        ('DWORD PointerToRawData', c_uint32),
        ('DWORD PointerToRelocations', c_uint32), # always zero in executables
        ('DWORD PointerToLinenumbers', c_uint32), #deprecated
        ('WORD NumberOfRelocations', c_uint16),
        ('WORD NumberOfLinenumber', c_uint16), #deprecated
        ('DWORD Characteristics', c_uint32)
    ]

class _IMAGE_RESOURCE_DIRECTORY (Structure):
    _pack_ = 1
    _fields_ = [
        ('Characteristics', c_uint32),
        ('TimeDateStamp', c_uint32),
        ('MajorVersion', c_uint16),
        ('MinorVersion', c_uint16),
        ('NumberOfNamedEntries', c_uint16),
        ('NumberOfIdEntries', c_uint16),
    ]


class _IMAGE_RESOURCE_DIRECTORY_ENTRY (Structure):
    class _u1 (Union):
        class _s1 (Structure):
            _pack_ = 1
            _fields_ = [
                ('NameOffset', c_uint32, 31),
                ('NameIsString', c_uint32, 1),
            ]
        _pack_ = 1
        _fields_ = [
            ('s1', _s1),
            ('Name', c_uint32),
            ('Id', c_uint16)
        ]
    class _u2 (Union):
        class _s2 (Structure):
            _pack_ = 1
            _fields_ = [
                ('OffsetToData', c_uint32, 31),
                ('DataIsDirectory', c_uint32, 1),
            ]
        _pack_ = 1
        _fields_ = [
            ('OffsetToData', c_uint32),
            ('s2', _s2)
        ]
    _pack_ = 1
    _fields_ = [
        ('u1', _u1),
        ('u2', _u2)
    ]

class _IMAGE_RESOURCE_DATA_ENTRY (Structure):
    _pack_ = 1
    _fields_ = [
        ('OffsetToData', c_uint32),
        ('Size', c_uint32),
        ('CodePage', c_uint32),
        ('Reserved', c_uint32),
    ]

class _VS_FIXEDFILEINFO (Structure):
    _pack_ = 1
    _fields_ = [
        ('dwSignature', c_uint32),
        ('dwStrucVersion', c_uint32),
        ('dwFileVersionMS', c_uint32),
        ('dwFileVersionLS', c_uint32),
        ('dwProductVersionMS', c_uint32),
        ('dwProductVersionLS', c_uint32),
        ('dwFileFlagsMask', c_uint32),
        ('dwFileFlags', c_uint32),
        ('dwFileOS', c_uint32),
        ('dwFileType', c_uint32),
        ('dwFileSubtype', c_uint32),
        ('dwFileDateMS', c_uint32),
        ('dwFileDateLS', c_uint32),
    ]

class _IMAGE_TLS_DIRECTORY32 (Structure):
    _pack_ = 1
    _fields_ = [
        ('StartAddressOfRawData', c_uint32),
        ('EndAddressOfRawData', c_uint32),                          
        ('AddressOfIndex', c_uint32),
        ('AddressOfCallBacks', c_uint32), # PIMAGE_TLS_CALLBACK
        ('SizeOfZeroFill', c_uint32),
        ('Characteristics', c_uint32) # reserved for future use
    ]

class _IMAGE_TLS_DIRECTORY64 (Structure):
    _pack_ = 1
    _fields_ = [
        ('StartAddressOfRawData', c_uint64),
        ('EndAddressOfRawData', c_uint64),                          
        ('AddressOfIndex', c_uint64),
        ('AddressOfCallBacks', c_uint64), # PIMAGE_TLS_CALLBACK
        ('SizeOfZeroFill', c_uint32),
        ('Characteristics', c_uint32) # reserved for future use
    ]

class _IMAGE_EXPORT_DIRECTORY (Structure):
    _pack_ = 1
    _fields_ = [
        ('Characteristics', c_uint32),
        ('TimeDateStamp', c_uint32),
        ('MajorVersion', c_uint16),
        ('MinorVersion', c_uint16),
        ('Name', c_uint32),
        ('Base', c_uint32),
        ('NumberOfFunctions', c_uint32),
        ('NumberOfNames', c_uint32),
        ('AddressOfFunctions', c_uint32),
        ('AddressOfNames', c_uint32),
        ('AddressOfNameOrdinals', c_uint32),
    ]

class _IMAGE_IMPORT_DESCRIPTOR (Structure):
    class _u1 (Union):
        _pack_ = 1
        _fields_ = [
            ('Characteristics', c_uint32), # 0 for terminating null import descriptor
            ('OriginalFirstThunk', c_uint32), # RVA to original unbound IAT
        ]
    _pack_ = 1
    _fields_ = [
        ('u1', _u1),
        ('TimeDateStamp', c_uint32),
        ('ForwarderChain', c_uint32), # 1 if no forwarders
        ('Name', c_uint32),
        # RVA to IAT (if bound this IAT has actual addresses)
        ('FirstThunk', c_uint32),
    ]

# import name entry
class _IMAGE_IMPORT_BY_NAME (Structure):
    _pack_ = 1
    _fields_ = [
        ('Hint', c_uint16),
        ('Name', c_uint8)
    ]

class _IMAGE_THUNK_DATA64 (Structure):
    class _u1 (Structure):
        _pack_ = 1
        _fields_ = [
            ('ForwarderString', c_uint64),
            ('Function', c_uint64),
            ('Ordinal', c_uint64),
            ('AddressOfData', c_uint64),
        ]
    _pack_ = 1
    _fields_ = [
        ('u1', _u1)
    ]

class _IMAGE_THUNK_DATA32 (Structure):
    class _u1 (Structure):
        _pack_ = 1
        _fields_ = [
            ('ForwarderString', c_uint32),
            ('Function', c_uint32),
            ('Ordinal', c_uint32),
            ('AddressOfData', c_uint32),
        ]
    _pack_ = 1
    _fields_ = [
        ('u1', _u1)
    ]

class FILE (Structure):
    pass
FILE_ptr = POINTER(FILE)
class _PE_FILE (Structure):

    _pack_ = 1
    _fields_ = [
        ('handle', FILE_ptr),
        ('isdll', c_bool),
        ('e_lfanew', c_uint16),
        ('architecture', c_uint16),
        ('entrypoint', c_uint64),
        ('imagebase', c_uint64),
        ('size', c_uint64),
        ('num_sections', c_uint16),
        ('num_directories', c_uint16),
        ('num_rsrc_entries', c_uint16),
        ('addr_sections', c_uint16),
        ('addr_directories', c_uint16),
        ('addr_dos', c_uint16),
        ('addr_optional', c_uint16),
        ('addr_coff', c_uint16),
        ('addr_rsrc_sec', c_uint16),
        ('addr_rsrc_dir', c_uint16),
        # pointers (will be freed if needed)
        ('optional_ptr', POINTER(_IMAGE_OPTIONAL_HEADER)),
        ('sections_ptr', POINTER(POINTER(_IMAGE_SECTION_HEADER))),
        ('directories_ptr', POINTER(POINTER(_IMAGE_DATA_DIRECTORY))),
        # IMAGE_TLS_DIRECTORY32 *tls_ptr
        ('rsrc_ptr', POINTER(_IMAGE_RESOURCE_DIRECTORY)),
        ('rsrc_entries_ptr', POINTER(POINTER(_IMAGE_RESOURCE_DIRECTORY_ENTRY)))
    ]

class PE:
    # f is an opened peFile
    def __init__(self, f):
        self.f = f
        self.f.seek(0, os.SEEK_SET)
        pythonapi.PyFile_AsFile.argtypes = [ py_object ]
        pythonapi.PyFile_AsFile.restype = FILE_ptr

        self.peFile = _PE_FILE()
        self.peFile_ptr = byref(self.peFile)

        # initialize things
        ret = pe_init(self.peFile_ptr, pythonapi.PyFile_AsFile(f))
        ret = is_pe(self.peFile_ptr)
        self.size = pe_get_size(self.peFile_ptr)
        pe_get_sections(self.peFile_ptr)
        pe_get_directories(self.peFile_ptr)
        pe_get_optional(self.peFile_ptr)
        pe_get_resource_entries(self.peFile_ptr)

    # delegate to the peFile
    def __getattr__(self, attr):
        return getattr(self.peFile, attr)

    def rva2ofs(self, addr):
        return rva2ofs(self.peFile_ptr, addr)

    def ofs2rva(self, addr):
        return ofs2rva(self.peFile_ptr, addr)

if __name__ == "__main__":
	f = open('print.exe', 'rb')
	pythonapi.PyFile_AsFile.argtypes = [ py_object ]
	pythonapi.PyFile_AsFile.restype = FILE_ptr

	peFile = _PE_FILE()
	peFile_ptr = byref(peFile)
	ret = pe_init(peFile_ptr, pythonapi.PyFile_AsFile(f))

	# some sanity checking
	print 'pe_init', ret
	ret = is_pe(peFile_ptr)
	print 'is_pe', ret
	ret = pe_get_optional(peFile_ptr)
	print 'pe_get_optional', ret
	ret = is_pe(peFile_ptr)
	print 'is_pe', ret
	print 'e_lfanew', peFile.e_lfanew
	print 'architecture', peFile.architecture
	print 'entrypoint', peFile.entrypoint


	# checking imports!
	pe_get_directories(peFile_ptr)
	print peFile.directories_ptr.contents
	print peFile.directories_ptr.contents.contents.VirtualAddress
