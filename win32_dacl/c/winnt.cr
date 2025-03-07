lib LibC
  SECURITY_MAX_SID_SIZE = 68

  enum WELL_KNOWN_SID_TYPE
    WinWorldSid = 1
  end

  alias SECURITY_DESCRIPTOR = Void # body unused

  OWNER_SECURITY_INFORMATION = 0x00000001_u32
  GROUP_SECURITY_INFORMATION = 0x00000002_u32
  DACL_SECURITY_INFORMATION  = 0x00000004_u32

  struct ACL
    aclRevision : BYTE
    sbz1 : BYTE
    aclSize : WORD
    aceCount : WORD
    sbz2 : WORD
  end

  struct TOKEN_OWNER
    owner : SID*
  end

  enum TOKEN_INFORMATION_CLASS
    TokenOwner = 4
  end

  @[Flags]
  enum ACCESS_MASK : DWORD
    GENERIC_READ  = 0x80000000
    GENERIC_WRITE = 0x40000000

    DELETE       = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC    = 0x00040000
    WRITE_OWNER  = 0x00080000
    SYNCHRONIZE  = 0x00100000

    FILE_READ_DATA            = 0x0001 # file & pipe
    FILE_LIST_DIRECTORY       = 0x0001 # directory
    FILE_WRITE_DATA           = 0x0002 # file & pipe
    FILE_ADD_FILE             = 0x0002 # directory
    FILE_APPEND_DATA          = 0x0004 # file
    FILE_ADD_SUBDIRECTORY     = 0x0004 # directory
    FILE_CREATE_PIPE_INSTANCE = 0x0004 # named pipe
    FILE_READ_EA              = 0x0008 # file & directory
    FILE_WRITE_EA             = 0x0010 # file & directory
    FILE_EXECUTE              = 0x0020 # file
    FILE_TRAVERSE             = 0x0020 # directory
    FILE_DELETE_CHILD         = 0x0040 # directory
    FILE_READ_ATTRIBUTES      = 0x0080 # all
    FILE_WRITE_ATTRIBUTES     = 0x0100 # all

    FILE_GENERIC_READ    = 0x120089 # STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE
    FILE_GENERIC_WRITE   = 0x120116 # STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE
    FILE_GENERIC_EXECUTE = 0x1200A0 # STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE

    # Required to query the values of a registry key.
    KEY_QUERY_VALUE = 0x0001

    # Required to create, delete, or set a registry value.
    KEY_SET_VALUE = 0x0002

    # Required to create a subkey of a registry key.
    KEY_CREATE_SUB_KEY = 0x0004

    # Required to enumerate the subkeys of a registry key.
    KEY_ENUMERATE_SUB_KEYS = 0x0008

    # Required to request change notifications for a registry key or for subkeys of a registry key.
    KEY_NOTIFY = 0x0010

    # Reserved for system use.
    KEY_CREATE_LINK = 0x0020

    # Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows.
    # This flag must be combined using the OR operator with the other flags in this table that either query or access registry values.
    # Windows 2000: This flag is not supported.
    KEY_WOW64_32KEY = 0x0200

    # Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows.
    # This flag must be combined using the OR operator with the other flags in this table that either query or access registry values.
    # Windows 2000: This flag is not supported.
    KEY_WOW64_64KEY = 0x0100

    KEY_WOW64_RES = 0x0300

    # Combines the `STANDARD_RIGHTS_READ`, `QUERY_VALUE`, `ENUMERATE_SUB_KEYS`, and `NOTIFY` values.
    # (STANDARD_RIGHTS_READ | QUERY_VALUE | ENUMERATE_SUB_KEYS | NOTIFY) & ~SYNCHRONIZE
    KEY_READ = 0x20019

    # Combines the `STANDARD_RIGHTS_REQUIRED`, `QUERY_VALUE`, `SET_VALUE`, `CREATE_SUB_KEY`, `ENUMERATE_SUB_KEYS`, `NOTIFY`, and `CREATE_LINK` access rights.
    # (STANDARD_RIGHTS_ALL | KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK) & ~SYNCHRONIZE
    KEY_ALL_ACCESS = 0xf003f

    # Equivalent to `READ`.
    # KEY_READ & ~SYNCHRONIZE
    KEY_EXECUTE = 0x20019

    # Combines the STANDARD_RIGHTS_WRITE, `KEY_SET_VALUE`, and `KEY_CREATE_SUB_KEY` access rights.
    # (STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY) & ~SYNCHRONIZE
    KEY_WRITE = 0x20006
  end
end
