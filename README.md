# READ ME
This document summarizes the functions of the NFCTagWriter app, organized by tag type support.

---

## Part 1: NTAG4242 (NTAG 424 DNA) Functions

The NTAG 424 DNA tag support is implemented using the `NTAG424DNAScanner` class, which utilizes the NfcDnaKit library for communication with ISO 7816-compliant tags.

### 1. Set Password
- **Function**: `beginSettingPassword(password:)`
- **Purpose**: Set or change the AES-128 encryption password on the tag
- **Features**:
  - Supports setting password on new tags (using default key)
  - Supports changing existing password (requires current password authentication)
  - Automatically verifies password after setting
  - Verifies that default key no longer works after password is set
  - Uses AES-128 encryption (16-byte key)
- **Process**:
  1. Authenticate with default key (for new tags) or current password
  2. Change key 0 to new password
  3. Verify new password by authenticating with it
  4. Confirm default key is disabled

### 2. Read Data
- **Function**: `beginReadingData(password:)`
- **Purpose**: Read NDEF data from the tag's NDEF file
- **Features**:
  - Optional password authentication (if tag is protected)
  - Reads up to 256 bytes from NDEF file (file number 0x02)
  - Parses NDEF message using NLEN format (NFC Forum Type 4 Tag compliant)
  - Extracts text or URI from NDEF records
  - Supports both URI and text record types
- **Data Format**: NLEN structure `[NLEN(2 bytes)] [NDEF Data]`

### 3. Write Data
- **Function**: `beginWritingData(data:password:)`
- **Purpose**: Write NDEF data to the tag's NDEF file
- **Features**:
  - Requires password authentication if tag is protected
  - Creates NDEF message from text/URL string
  - Writes in chunks of 128 bytes (datasheet maximum for tearing protection)
  - Uses NLEN format for NFC Forum Type 4 Tag compliance
  - Verifies write operation by reading back data
- **Data Format**: Automatically creates NDEF URI or text records

### 4. Configure File Access
- **Function**: `beginConfiguringFileAccess(password:)`
- **Purpose**: Configure NDEF file access permissions for security
- **Features**:
  - Sets read access to ALL (0xE) - allows all readers (critical for iOS background detection)
  - Sets write access to KEY_0 (0x0) - requires authentication to write
  - Sets change access to KEY_0 (0x0) - requires authentication to change settings
  - Uses PLAIN communication mode for third-party tool compatibility
  - Disables SDM (Secure Unique NFC) for compatibility
  - Verifies configuration after applying changes
- **Security**: Prevents unauthorized writes while allowing reads

### 5. Configure CC File
- **Function**: `beginConfiguringCCFile(password:)`
- **Purpose**: Configure Capability Container (CC) file for iOS background detection
- **Features**:
  - Writes CC file content (32 bytes) with proper Type 4 Tag specification
  - Sets read access to ALL (0xE) - critical for iOS background detection
  - Sets write access to KEY_0 (0x0) - requires authentication
  - Uses PLAIN communication mode
  - Enables iOS to detect tag in background mode
- **File Structure**: Includes CCLEN, Mapping Version, MLe/MLc, and file control TLVs

### 6. UID Detection
- **Function**: Automatic during tag detection
- **Purpose**: Extract and display tag UID (Unique Identifier)
- **Features**:
  - Extracts UID from tag identifier
  - Displays in hex format (colon-separated)
  - Available for both ISO 7816 and MIFARE tag detections

### Technical Details
- **Library**: Uses NfcDnaKit for ISO 7816 tag communication
- **Encryption**: AES-128 (16-byte keys)
- **Tag Detection**: Supports both ISO 7816 and MIFARE detection modes
- **File System**: Type 4 Tag file structure (CC file, NDEF file)
- **Compatibility**: Works with third-party tools (NXP TagWriter, TagInfo, etc.)

---

## Part 2: NTAG21X (NTAG213/215/216) Functions

The NTAG21X tag support is implemented using the `NFCScanner` class, which handles MIFARE Ultralight protocol communication.

### 1. Read Tag Information
- **Function**: `beginReadingTagInfo()`
- **Purpose**: Read comprehensive tag information and capabilities
- **Features**:
  - Reads serial number (UID) from pages 0-2
  - Reads Capability Container (CC) from page 3
  - Determines tag type (NTAG213/215/216) from NDEF memory size
  - Calculates actual total memory size (different from NDEF size)
  - Reads password protection pages (AUTH0, ACCESS, PWD, PACK)
  - Displays password protection status (enabled/disabled, active/configured)
  - Shows memory information (total bytes, pages, NDEF size)
- **Information Displayed**:
  - Serial number (hex format)
  - Tag type
  - Total memory size and pages
  - NDEF memory size
  - CC version and access
  - Password protection pages locations
  - Password protection status and configuration

### 2. Read Data
- **Function**: `beginReading(password:)`
- **Purpose**: Read NDEF data from the tag
- **Features**:
  - Automatically checks if authentication is needed based on ACCESS byte
  - Supports write-only protection mode (read without password)
  - Supports read/write protection mode (requires password)
  - Parses NDEF TLV structure (Tag-Length-Value format)
  - Extracts text or URI from NDEF records
  - Handles both short and long length formats
  - Reads dynamically based on CC size information
- **Authentication**: Only authenticates if ACCESS bit 7 is set (read protection enabled)

### 3. Write Data
- **Function**: `beginWriting(password:textToWrite:)`
- **Purpose**: Write NDEF data to the tag
- **Features**:
  - Always requires password authentication if password is set
  - Creates NDEF URI or text records from input string
  - Writes data in TLV format (0x03 tag, length, payload, 0xFE terminator)
  - Writes page-by-page (4 bytes per page) starting from page 4
  - Handles large messages by writing multiple pages
  - Uses native MIFARE write commands (0xA2)
- **Data Format**: TLV structure `[0x03] [Length] [NDEF Data] [0xFE]`

### 4. Set Password
- **Function**: `beginSettingPassword(password:writeOnlyProtection:)`
- **Purpose**: Set password protection on the tag
- **Features**:
  - Supports two protection modes:
    - **Write Protected Only**: Read access without password, write requires password
    - **Read & Write Protected**: Both read and write require password
  - Writes 4-byte password to PWD page
  - Sets AUTH0 page (specifies which page requires authentication, typically 0x04)
  - Configures ACCESS byte:
    - Bit 7 = 0: Write-only protection (read allowed without password)
    - Bit 7 = 1: Read/write protection (both require password)
  - Preserves existing PACK and RFUI values
  - Validates tag type and memory pages before setting
- **Process**:
  1. Verify tag type and password protection page locations
  2. Write password to PWD page
  3. Set AUTH0 to 0x04 (page 4 and above require authentication)
  4. Read current ACCESS page
  5. Set ACCESS byte based on protection mode
  6. Tag must be removed and re-presented for protection to take effect

### 5. Authentication
- **Function**: `authenticateTag(miFareTag:session:)`
- **Purpose**: Authenticate with password for protected operations
- **Features**:
  - Uses PWD_AUTH command (0x1B) followed by 4-byte password
  - Receives 2-byte PACK (Password Acknowledge) on success
  - Handles authentication errors (NAK responses)
  - Required for write operations if password is set
  - Required for read operations if read protection is enabled
- **Command Format**: `[0x1B] [PWD(4 bytes)]`

### Technical Details
- **Protocol**: MIFARE Ultralight (ISO 14443-A)
- **Tag Types Supported**:
  - **NTAG213**: 180 bytes total (45 pages), NDEF: 144 bytes
  - **NTAG215**: 504 bytes total (126 pages), NDEF: 496 bytes
  - **NTAG216**: 888 bytes total (222 pages), NDEF: 872 bytes
- **Password Protection Pages**:
  - **NTAG213**: AUTH0=0x29, ACCESS=0x2A, PWD=0x2B, PACK=0x2C
  - **NTAG215**: AUTH0=0x83, ACCESS=0x84, PWD=0x85, PACK=0x86
  - **NTAG216**: AUTH0=0xE3, ACCESS=0xE4, PWD=0xE5, PACK=0xE6
- **Password Format**: 4 bytes (ASCII string, truncated/padded)
- **NDEF Format**: TLV structure with 0x03 tag for NDEF message

---

## Common Features

### Error Handling
- Comprehensive error messages for all operations
- Connection loss detection and recovery guidance
- Authentication failure handling with helpful messages
- Tag type validation before operations

### User Interface
- Real-time status updates during operations
- Alert messages for operation results
- Tag information display with detailed formatting
- Password protection mode selection (write-only vs read/write)

### Compatibility
- **NTAG4242**: Compatible with NXP TagWriter, TagInfo, and other Type 4 Tag tools
- **NTAG21X**: Standard MIFARE Ultralight protocol, compatible with most NFC readers

---

## Notes

- **NTAG4242** uses AES-128 encryption and requires 16-byte passwords
- **NTAG21X** uses 4-byte passwords and simpler authentication
- Both tag types support NDEF data format but use different storage structures
- Password protection must be configured before it takes effect (tag removal required for NTAG21X)
- iOS background detection requires proper CC file and NDEF file access configuration for NTAG4242
