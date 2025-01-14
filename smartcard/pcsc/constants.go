package pcsc

const (
	// Scope
	CARD_SCOPE_SYSTEM = 0x0002
	// Limits
	_MAX_ATR_SIZE = 33
	// States (Internal)
	SCARD_UNKNOWN    = 0x0001
	SCARD_ABSENT     = 0x0002
	SCARD_PRESENT    = 0x0004
	SCARD_SWALLOWED  = 0x0008
	SCARD_POWERED    = 0x0010
	SCARD_NEGOTIABLE = 0x0020
	SCARD_SPECIFIC   = 0x0040
	// States (GetStatusChange)
	SCARD_STATE_UNAWARE     = 0x0000
	SCARD_STATE_IGNORE      = 0x0001
	SCARD_STATE_CHANGED     = 0x0002
	SCARD_STATE_UNKNOWN     = 0x0004
	SCARD_STATE_UNAVAILABLE = 0x0008
	SCARD_STATE_EMPTY       = 0x0010
	SCARD_STATE_PRESENT     = 0x0020
	SCARD_STATE_ATRMATCH    = 0x0040
	SCARD_STATE_EXCLUSIVE   = 0x0080
	SCARD_STATE_INUSE       = 0x0100
	SCARD_STATE_MUTE        = 0x0200
	SCARD_STATE_UNPOWERED   = 0x0400
	// Protocols
	SCARD_PROTOCOL_UNDEFINED = 0x0000
	SCARD_PROTOCOL_T0        = 0x0001
	SCARD_PROTOCOL_T1        = 0x0002
	SCARD_PROTOCOL_RAW       = 0x0004
	SCARD_PROTOCOL_T15       = 0x0008
	SCARD_PROTOCOL_ANY       = (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
	// Sharing
	SCARD_SHARE_EXCLUSIVE = 0x0001
	SCARD_SHARE_SHARED    = 0x0002
	SCARD_SHARE_DIRECT    = 0x0003
	// Disconnect
	SCARD_LEAVE_CARD   = 0x0000
	SCARD_RESET_CARD   = 0x0001
	SCARD_UNPOWER_CARD = 0x0002
	SCARD_EJECT_CARD   = 0x0003
	// Errors
	SCARD_S_SUCCESS                 = 0x00000000
	SCARD_F_INTERNAL_ERROR          = 0x80100001
	SCARD_E_CANCELLED               = 0x80100002
	SCARD_E_INVALID_HANDLE          = 0x80100003
	SCARD_E_INVALID_PARAMETER       = 0x80100004
	SCARD_E_INVALID_TARGET          = 0x80100005
	SCARD_E_NO_MEMORY               = 0x80100006
	SCARD_F_WAITED_TOO_LONG         = 0x80100007
	SCARD_E_INSUFFICIENT_BUFFER     = 0x80100008
	SCARD_E_UNKNOWN_READER          = 0x80100009
	SCARD_E_TIMEOUT                 = 0x8010000A
	SCARD_E_SHARING_VIOLATION       = 0x8010000B
	SCARD_E_NO_SMARTCARD            = 0x8010000C
	SCARD_E_UNKNOWN_CARD            = 0x8010000D
	SCARD_E_CANT_DISPOSE            = 0x8010000E
	SCARD_E_PROTO_MISMATCH          = 0x8010000F
	SCARD_E_NOT_READY               = 0x80100010
	SCARD_E_INVALID_VALUE           = 0x80100011
	SCARD_E_SYSTEM_CANCELLED        = 0x80100012
	SCARD_F_COMM_ERROR              = 0x80100013
	SCARD_F_UNKNOWN_ERROR           = 0x80100014
	SCARD_E_INVALID_ATR             = 0x80100015
	SCARD_E_NOT_TRANSACTED          = 0x80100016
	SCARD_E_READER_UNAVAILABLE      = 0x80100017
	SCARD_P_SHUTDOWN                = 0x80100018
	SCARD_E_PCI_TOO_SMALL           = 0x80100019
	SCARD_E_READER_UNSUPPORTED      = 0x8010001A
	SCARD_E_DUPLICATE_READER        = 0x8010001B
	SCARD_E_CARD_UNSUPPORTED        = 0x8010001C
	SCARD_E_NO_SERVICE              = 0x8010001D
	SCARD_E_SERVICE_STOPPED         = 0x8010001E
	SCARD_E_UNEXPECTED              = 0x8010001F
	SCARD_E_ICC_INSTALLATION        = 0x80100020
	SCARD_E_ICC_CREATEORDER         = 0x80100021
	SCARD_E_UNSUPPORTED_FEATURE     = 0x80100022
	SCARD_E_DIR_NOT_FOUND           = 0x80100023
	SCARD_E_FILE_NOT_FOUND          = 0x80100024
	SCARD_E_NO_DIR                  = 0x80100025
	SCARD_E_NO_FILE                 = 0x80100026
	SCARD_E_NO_ACCESS               = 0x80100027
	SCARD_E_WRITE_TOO_MANY          = 0x80100028
	SCARD_E_BAD_SEEK                = 0x80100029
	SCARD_E_INVALID_CHV             = 0x8010002A
	SCARD_E_UNKNOWN_RES_MNG         = 0x8010002B
	SCARD_E_NO_SUCH_CERTIFICATE     = 0x8010002C
	SCARD_E_CERTIFICATE_UNAVAILABLE = 0x8010002D
	SCARD_E_NO_READERS_AVAILABLE    = 0x8010002E
	SCARD_E_COMM_DATA_LOST          = 0x8010002F
	SCARD_E_NO_KEY_CONTAINER        = 0x80100030
	SCARD_E_SERVER_TOO_BUSY         = 0x80100031
	SCARD_W_UNSUPPORTED_CARD        = 0x80100065
	SCARD_W_UNRESPONSIVE_CARD       = 0x80100066
	SCARD_W_UNPOWERED_CARD          = 0x80100067
	SCARD_W_RESET_CARD              = 0x80100068
	SCARD_W_REMOVED_CARD            = 0x80100069
	SCARD_W_SECURITY_VIOLATION      = 0x8010006A
	SCARD_W_WRONG_CHV               = 0x8010006B
	SCARD_W_CHV_BLOCKED             = 0x8010006C
	SCARD_W_EOF                     = 0x8010006D
	SCARD_W_CANCELLED_BY_USER       = 0x8010006E
	SCARD_W_CARD_NOT_AUTHENTICATED  = 0x8010006F
	// Others
	SCARD_INFINITE = 0xFFFFFFFF
	// Attributes
	SCARD_CLASS_ICC_STATE = 9
	SCARD_ATTR_ATR_STRING = (SCARD_CLASS_ICC_STATE<<16 | 0x0303)
)
