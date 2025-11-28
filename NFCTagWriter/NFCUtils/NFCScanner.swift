//
//  NFCScanner.swift
//  NFCScanner
//
//  Created by andy@Firewalla.com on 11/26/25.
//
import CoreNFC

// Tag Information Structure
struct NFCTagInfo {
    var serialNumber: String = ""
    var memorySize: String = ""
    var tagType: String = ""
    var ndefMessageSize: String = ""
    var isPasswordProtected: Bool = false
    var details: String = ""
}

// NTAG21X Password Protection Pages Structure
struct NTAG21XPasswordPages {
    static let PWD_AUTH: UInt8 = 0x1B
    let tagType: String
    let auth0Page: UInt8
    let accessPage: UInt8
    let pwdPage: UInt8
    let packPage: UInt8
    let totalMemoryBytes: Int  // Actual total tag memory size
    let totalMemoryPages: Int  // Actual total tag pages
    
    // Convert NDEF memory size to actual total tag memory size
    // NDEF size is what's reported in CC, but actual tag has more memory
    static func totalMemorySize(for ndefBytes: Int) -> Int {
        switch ndefBytes {
        case 144, 180:  // NTAG213 NDEF sizes
            return 180  // Actual total: 180 bytes (45 pages)
        case 496, 504:  // NTAG215 NDEF sizes
            return 504  // Actual total: 504 bytes (126 pages)
        case 872, 888:  // NTAG216 NDEF sizes
            return 888  // Actual total: 888 bytes (222 pages)
        default:
            return ndefBytes  // Fallback: assume NDEF size = total size
        }
    }
    
    // Factory method to get pages based on NDEF memory size (from CC)
    static func pages(for ndefBytes: Int) -> NTAG21XPasswordPages? {
        let totalBytes = totalMemorySize(for: ndefBytes)
        let totalPages = totalBytes / 4
        
        switch ndefBytes {
        case 144, 180:  // NTAG213 NDEF memory size
            // NTAG213 (45 pages total)
            return NTAG21XPasswordPages(
                tagType: "NTAG213",
                auth0Page: 0x29,  // Page 41
                accessPage: 0x2A, // Page 42
                pwdPage: 0x2B,    // Page 43
                packPage: 0x2C,   // Page 44
                totalMemoryBytes: totalBytes,
                totalMemoryPages: totalPages
            )
        case 496, 504:  // NTAG215 NDEF memory size
            // NTAG215 (126 pages total)
            return NTAG21XPasswordPages(
                tagType: "NTAG215",
                auth0Page: 0x83,  // Page 131
                accessPage: 0x84, // Page 132
                pwdPage: 0x85,     // Page 133
                packPage: 0x86,    // Page 134
                totalMemoryBytes: totalBytes,
                totalMemoryPages: totalPages
            )
        case 872, 888:  // NTAG216 NDEF memory size
            // NTAG216 (222 pages total)
            return NTAG21XPasswordPages(
                tagType: "NTAG216",
                auth0Page: 0xE3,  // Page 227
                accessPage: 0xE4, // Page 228
                pwdPage: 0xE5,     // Page 229
                packPage: 0xE6,    // Page 230
                totalMemoryBytes: totalBytes,
                totalMemoryPages: totalPages
            )
        default:
            return nil
        }
    }
}

// Action types for NFC operations
enum NFCActionType {
    case read
    case write
    case setPassword
    case readTagInfo
}

// 1. Define the Delegate and Session Management
class NFCScanner: NSObject, NFCTagReaderSessionDelegate {
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("tagReaderSessionDidBecomeActive \(session.isReady)")
    }
    
    var session: NFCTagReaderSession?
    
    // Store strong reference to tag to keep it alive during operations
    private var currentTag: NFCMiFareTag?
    
    // Current action being performed
    private var currentAction: NFCActionType = .read
    
    // Callbacks for different operations
    var onWriteCompleted: ((String?, Error?) -> Void)?
    var onReadCompleted: ((String, String?, Error?) -> Void)?
    var onSetPasswordCompleted: ((String?, Error?) -> Void)?
    var onTagInfoCompleted: ((NFCTagInfo?, Error?) -> Void)?
    
    // Data for operations
    var textToWrite: String = ""
    var textRead: String = ""
    var textPassword: String = ""
    // Define a 4-byte password (e.g., "ABCD" converted to hex bytes)
    var passwordData: Data { Data(textPassword.prefix(4).utf8) }
    
    func beginWriting() {
        currentAction = .write
        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NFC tag to write."
        session?.begin()
    }
    
    func beginReading() {
        currentAction = .read
        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NFC tag to read."
        session?.begin()
    }
    
    func beginSettingPassword() {
        currentAction = .setPassword
        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NFC tag to set password."
        session?.begin()
    }
    
    func beginReadingTagInfo() {
        currentAction = .readTagInfo
        session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NFC tag to read information."
        session?.begin()
    }
    
    // --- NFCTagReaderSessionDelegate Methods ---
    
    // 2. Handle Tag Detection
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let firstTag = tags.first else {
            session.invalidate(errorMessage: "No tag found.")
            return
        }
        
        // Must connect to the tag before sending commands
        session.connect(to: firstTag) { [self] (error: Error?) in
            if let error = error {
                session.invalidate(errorMessage: "Connection error: \(error.localizedDescription)")
                return
            }
            
            // 3. Cast the detected tag to the MIFARE type
            if case let .miFare(miFareTag) = firstTag {
                // Store strong reference to keep tag alive
                self.currentTag = miFareTag
                // Route to appropriate handler based on action type
                self.handleTagAction(miFareTag: miFareTag, session: session)
            } else {
                session.invalidate(errorMessage: "Tag is not a compatible MIFARE type.")
            }
        }
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // Handle session invalidation (e.g., error or success)
        print("Session invalidated: \(error.localizedDescription)")
    }
    
    // Route tag action to appropriate handler based on action type
    private func handleTagAction(miFareTag: NFCMiFareTag, session: NFCTagReaderSession) {
        switch currentAction {
        case .readTagInfo:
            // Read tag info operation (no authentication needed for basic info)
            readTagInfo(miFareTag: miFareTag, session: session)
            
        case .setPassword:
            // Set password operation (no authentication needed)
            setPassword(miFareTag: miFareTag, session: session)
            
        case .read, .write:
            // Read or write operations require authentication
            authenticateTag(miFareTag: miFareTag, session: session)
        }
    }
    
    // 4. The `sendMiFareCommand` function
    func authenticateTag(miFareTag: NFCMiFareTag, session: NFCTagReaderSession) {
        
        // Construct the PWD_AUTH command: 0x1B followed by the 4-byte password
        let authenticationCommand: Data = Data([NTAG21XPasswordPages.PWD_AUTH]) + passwordData
        
        // Debug: Print password bytes being used for authentication
        print("=== Authentication Debug ===")
        print("Password data (hex): \(passwordData.map { String(format: "%02x", $0) }.joined(separator: " "))")
        print("Password data (ASCII): \(String(data: passwordData, encoding: .utf8) ?? "invalid")")
        print("Password length: \(passwordData.count) bytes")
        print("Auth command (hex): \(authenticationCommand.map { String(format: "%02x", $0) }.joined(separator: " "))")
        print("Attempting to authenticate tag...")
        
        self.performAuthentication(miFareTag: miFareTag, session: session, command: authenticationCommand)
    }
    
    private func performAuthentication(miFareTag: NFCMiFareTag, session: NFCTagReaderSession, command: Data) {
        
        print("Sending authentication command...")
        // Send the proprietary command packet
        // Use strong reference to keep tag and session alive during the operation
        miFareTag.sendMiFareCommand(commandPacket: command) { [weak self] (response: Data, error: Error?) in
            
            guard let self = self else { return }
            
            if let error = error {
                self.currentTag = nil // Release tag reference on error
                session.invalidate(errorMessage: "Authentication Failed: \(error.localizedDescription)")
                self.handleAuthenticationError(error: error)
                return
            }
            
            // Authentication successful. The response should contain the PACK value (2 bytes)
            // If the response is not empty and the authentication was accepted, the tag is now unlocked.
            // 1. Check for Core NFC transmission errors
            if let error = error {
                // ❌ FAILED: RF link error or tag dropped connection
                // Note: Some tags drop connection immediately on wrong password.
                print("Transmission error: \(error.localizedDescription)")
                self.currentTag = nil // Release tag reference on error
                session.invalidate(errorMessage: "Authentication Failed: \(error.localizedDescription)")
                self.handleAuthenticationError(error: error)
                return
            }
            
            // 2. Analyze response Data to determine protocol success
            // For Ultralight PWD_AUTH, success means receiving exactly 2 bytes (the PACK).
            // Failure often results in receiving 1 byte (NAK) or 0 bytes.
            
            print("Raw response data: \(response as NSData), Length: \(response.count)")
            
            if response.count == 2 {
                // ✅ SUCCESS
                // We received the 2-byte PACK (Password Acknowledge).
                // Ideally, you should also verify these 2 bytes match what you expect
                // if your system relies on specific PACK values.
                print("Raw authentication successful! PACK received: \(response as NSData)")
                // Proceed with protected operations based on action type
                self.performAuthenticatedOperation(miFareTag: miFareTag, session: session)
                return
            } else if response.count == 1 {
                // ❌ FAILED (Likely NAK)
                // Let's check if it's a standard MIFARE NAK
                let nakByte = response[0]
                print("Authentication failed. Tag returned NAK: 0x\(String(format:"%02X", nakByte))")
                
                // NAK 0x00 often means:
                // 1. Password protection is not enabled on the tag
                // 2. Wrong password format
                // 3. Password was not written correctly
                
                var errorMsg = "Authentication failed. Tag returned NAK: 0x\(String(format:"%02X", nakByte))"
                if nakByte == 0x00 {
                    errorMsg += "\n\nPossible causes:"
                    errorMsg += "\n1. Password protection may not be enabled (AUTH0/ACCESS not configured)"
                    errorMsg += "\n2. Password format mismatch (check if password was written correctly)"
                    errorMsg += "\n3. Tag may require password protection to be enabled before authentication"
                }
                
                print(errorMsg)
                self.currentTag = nil // Release tag reference on error
                session.invalidate(errorMessage: errorMsg)
                let authError = NSError(domain: "NFCScanner", code: -15, userInfo: [NSLocalizedDescriptionKey: errorMsg])
                self.handleAuthenticationError(error: authError)
                return
            } else {
                // ❌ FAILED (Unknown response format)
                print("Authentication failed. Unexpected response length: \(response.count)")
                self.currentTag = nil // Release tag reference on error
                session.invalidate(errorMessage: "Authentication failed. Unexpected response length: \(response.count)")
                self.handleAuthenticationError(error: error)
                return
            }
            
            // Route to appropriate operation based on action type
            self.performAuthenticatedOperation(miFareTag: miFareTag, session: session)
        }
    }
    
    // Handle authenticated operations after successful authentication
    private func performAuthenticatedOperation(miFareTag: NFCMiFareTag, session: NFCTagReaderSession) {
        switch currentAction {
        case .write:
            performWriteOperation(miFareTag: miFareTag, session: session)
        case .read:
            performReadOperation(miFareTag: miFareTag, session: session)
        default:
            // Should not reach here for authenticated operations
            session.invalidate(errorMessage: "Invalid action type for authenticated operation")
            self.currentTag = nil
        }
    }
    
    // Handle authentication errors
    private func handleAuthenticationError(error: Error?) {
        let authError = error ?? NSError(domain: "NFCScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Authentication failed"])
        switch currentAction {
        case .read:
            onReadCompleted?("", nil, authError)
        case .write:
            onWriteCompleted?(nil, authError)
        default:
            break
        }
    }
    
    // Perform write operation after authentication
    private func performWriteOperation(miFareTag: NFCMiFareTag, session: NFCTagReaderSession) {
        guard let onWriteCompleted = onWriteCompleted else {
            session.invalidate(errorMessage: "No write callback set")
            self.currentTag = nil
            return
        }
        
        print("Attempting to write using native writeNDEF API...")
        let text = self.textToWrite.isEmpty ? "https://firewalla.com" : self.textToWrite
        self.writeStringData(miFareTag: miFareTag, session: session, string: text) { [weak self] result in
            guard let self = self else { return }
            var writeMsg = "Write Successful."
            switch result {
            case .success:
                session.alertMessage = "Success! NDEF Written."
                self.currentTag = nil
                session.invalidate()
                print("Success! NDEF Written via raw commands.")
                onWriteCompleted(writeMsg, nil)
            case .failure(let err):
                writeMsg = "Write failed: \(err.localizedDescription)"
                self.currentTag = nil
                session.invalidate(errorMessage: writeMsg)
                print(writeMsg)
                onWriteCompleted(writeMsg, err)
            }
            print("writeNDEF done with \(writeMsg)")
        }
    }
    
    // Perform read operation after authentication
    private func performReadOperation(miFareTag: NFCMiFareTag, session: NFCTagReaderSession) {
        guard let onReadCompleted = onReadCompleted else {
            session.invalidate(errorMessage: "No read callback set")
            self.currentTag = nil
            return
        }
        
        // READ & PARSE
        readAndParseNDEF2(tag: miFareTag) { [weak self] result in
            guard let self = self else { return }
            var readMsg = "Read Successful."
            switch result {
            case .success(let message):
                // Success! You have the NFCNDEFMessage object back.
                // Parse the first record's payload to extract text
                if let firstRecord = message.records.first {
                    let text = self.parseNDEFTextPayload(firstRecord.payload)
                    if !text.isEmpty {
                        readMsg = "Read: \(text)"
                        self.textRead = text
                        print(readMsg)
                    } else {
                        readMsg = "Read NDEF successfully! Decode failed."
                        self.textRead = "N/A"
                        print(readMsg)
                    }
                } else {
                    readMsg = "Read NDEF successfully! No records found."
                    self.textRead = "N/A"
                    print(readMsg)
                }
                self.currentTag = nil // Release tag reference
                session.invalidate()
                onReadCompleted(self.textRead, readMsg, nil)
            case .failure(let err):
                readMsg = "Read failed: \(err.localizedDescription)"
                self.currentTag = nil // Release tag reference
                session.invalidate(errorMessage: readMsg)
                print(readMsg)
                onReadCompleted(self.textRead, readMsg, err)
            }
        }
    }
    
    // Read tag information and capabilities
    func readTagInfo(miFareTag: NFCMiFareTag, session: NFCTagReaderSession) {
        var tagInfo = NFCTagInfo()
        
        // Read pages 0-3 to get serial number and capability container
        // Page 0-2: Serial number (UID) - 7 bytes
        // Page 3: Capability Container (CC)
        let readCommand = Data([0x30, 0x00]) // Read from page 0 (returns 4 pages)
        
        miFareTag.sendMiFareCommand(commandPacket: readCommand) { [weak self] (response: Data, error: Error?) in
            guard let self = self else { return }
            
            if let error = error {
                self.currentTag = nil
                session.invalidate(errorMessage: "Failed to read tag info: \(error.localizedDescription)")
                self.onTagInfoCompleted?(nil, error)
                return
            }
            
            guard response.count >= 16 else {
                self.currentTag = nil
                session.invalidate(errorMessage: "Invalid tag response")
                self.onTagInfoCompleted?(nil, NSError(domain: "NFCScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid tag response"]))
                return
            }
            
            // Extract serial number from pages 0-2 (first 7 bytes)
            let serialBytes = response.prefix(7)
            tagInfo.serialNumber = serialBytes.map { String(format: "%02X", $0) }.joined(separator: ":")
            
            // Extract Capability Container from page 3 (bytes 12-15)
            let ccPage = response.subdata(in: 12..<16)
            
            // CC structure: [Magic (0xE1), Version, SIZE(MLEN), Access]
            if ccPage[0] == 0xE1 {
                let mlen = Int(ccPage[2])
                let ndefBytes = mlen * 8  // This is NDEF memory size, not total tag memory
                
                // Get password protection pages based on NDEF memory size to determine correct tag type
                guard let passwordPages = NTAG21XPasswordPages.pages(for: ndefBytes) else {
                    // Tag doesn't support password protection - determine type from NDEF memory size
                    let tagType: String
                    switch ndefBytes {
                    case 144, 180:  // NTAG213 NDEF sizes
                        tagType = "NTAG213"
                    case 496, 504:  // NTAG215 NDEF sizes
                        tagType = "NTAG215"
                    case 872, 888:  // NTAG216 NDEF sizes
                        tagType = "NTAG216"
                    default:
                        tagType = "NTAG (Unknown variant)"
                    }
                    tagInfo.tagType = tagType
                    
                    // Calculate actual total memory (same as NDEF for unknown types)
                    let totalBytes = NTAG21XPasswordPages.totalMemorySize(for: ndefBytes)
                    let totalPages = totalBytes / 4
                    
                    // Build details string
                    var details: [String] = []
                    details.append("Serial: \(tagInfo.serialNumber)")
                    details.append("Type: \(tagInfo.tagType)")
                    details.append("Total Memory: \(totalBytes) bytes (\(totalPages) pages)")
                    details.append("NDEF Size: \(ndefBytes) bytes")
                    
                    if ccPage.count >= 4 {
                        details.append("CC Version: \(String(format: "0x%02X", ccPage[1]))")
                        details.append("CC Access: \(String(format: "0x%02X", ccPage[3]))")
                    }
                    
                    details.append("Password Protected: No (Tag does not support password protection)")
                    tagInfo.details = details.joined(separator: "\n")
                    self.currentTag = nil
                    session.invalidate()
                    self.onTagInfoCompleted?(tagInfo, nil)
                    return
                }
                
                // Use the correct tag type from passwordPages struct
                tagInfo.tagType = passwordPages.tagType
                
                // Build details string with actual total memory size
                var details: [String] = []
                details.append("Serial: \(tagInfo.serialNumber)")
                details.append("Type: \(tagInfo.tagType)")
                details.append("Total Memory: \(passwordPages.totalMemoryBytes) bytes (\(passwordPages.totalMemoryPages) pages)")
                details.append("NDEF Size: \(ndefBytes) bytes")
                
                if ccPage.count >= 4 {
                    details.append("CC Version: \(String(format: "0x%02X", ccPage[1]))")
                    details.append("CC Access: \(String(format: "0x%02X", ccPage[3]))")
                }
                
                // Add password protection page information
                details.append("")
                details.append("Password Protection Pages:")
                details.append("  AUTH0: Page 0x\(String(format: "%02X", passwordPages.auth0Page)) (Page \(passwordPages.auth0Page))")
                details.append("  ACCESS: Page 0x\(String(format: "%02X", passwordPages.accessPage)) (Page \(passwordPages.accessPage))")
                
                details.append("  PACK:  Page 0x\(String(format: "%02X", passwordPages.packPage)) (Page \(passwordPages.packPage))")
                
                print("📋 \(passwordPages.tagType) detected - reading password pages 0x\(String(format: "%02X", passwordPages.auth0Page))-0x\(String(format: "%02X", passwordPages.packPage))")
                
                // Read password protection pages (read from AUTH0 page to get all 4 pages)
                let readAuth0Command = Data([0x30, passwordPages.auth0Page])
                miFareTag.sendMiFareCommand(commandPacket: readAuth0Command) { [weak self, passwordPages] (auth0Response: Data, auth0Error: Error?) in
                    guard let self = self else { return }
                    
                    var auth0: UInt8 = 0xFF
                    var accessByte: UInt8 = 0x00
                    
                    if let error = auth0Error {
                        print("⚠️ Error reading AUTH0/ACCESS pages: \(error.localizedDescription)")
                        details.append("")
                        details.append("Password Protection Status:")
                        details.append("  Status: Unknown (Error reading password pages: \(error.localizedDescription))")
                        tagInfo.details = details.joined(separator: "\n")
                        self.currentTag = nil
                        session.invalidate()
                        self.onTagInfoCompleted?(tagInfo, nil)
                        return
                    } else if auth0Response.count >= 16 {
                        // Response structure: Reading from AUTH0 page returns 4 pages (16 bytes)
                        // Bytes 0-3: AUTH0 page [AUTH0, ...]
                        // Bytes 4-7: ACCESS page [..., ACCESS, ...]
                        // Bytes 8-11: PWD page [PWD]
                        // Bytes 12-15: PACK page [PACK]
                        
                        // AUTH0 is always the first byte of the first page
                        auth0 = auth0Response[0]
                        
                        // ACCESS is the third byte (index 2) of the ACCESS page
                        // ACCESS page is always 1 page offset from AUTH0 page = 4 bytes, ACCESS is byte 2 of ACCESS page = byte 6
                        if auth0Response.count > 6 {
                            accessByte = auth0Response[6]
                        } else {
                            print("⚠️ Response truncated, ACCESS byte not available")
                            accessByte = 0x00
                        }
                        
                        print("📋 Tag Info Debug:")
                        print("   AUTH0: 0x\(String(format: "%02X", auth0))")
                        print("   ACCESS: 0x\(String(format: "%02X", accessByte))")
                        print("   Response length: \(auth0Response.count) bytes")
                        print("   Full response: \(auth0Response.map { String(format: "%02X", $0) }.joined(separator: " "))")
                        
                        // Password protection status:
                        // - AUTH0 != 0xFF means password protection is configured
                        // - ACCESS bit 7 (0x80) means password protection is actively enforced
                        // If AUTH0 is set but ACCESS is not, protection is configured but not enforced
                        let hasAuth0Configured = (auth0 != 0xFF)
                        let hasAccessEnabled = ((accessByte & 0x80) != 0)
                        
                        // Password protection is considered enabled if AUTH0 is configured
                        // (even if ACCESS isn't set, the configuration exists)
                        tagInfo.isPasswordProtected = hasAuth0Configured
                        
                        print("   AUTH0 configured: \(hasAuth0Configured)")
                        print("   ACCESS enabled: \(hasAccessEnabled)")
                        print("   Password Protected: \(tagInfo.isPasswordProtected)")
                        
                        // Add password protection status
                        details.append("")
                        details.append("Password Protection Status:")
                        if tagInfo.isPasswordProtected {
                            if hasAccessEnabled {
                                details.append("  Status: Yes (Active)")
                            } else {
                                details.append("  Status: Yes (Configured but not enforced)")
                            }
                        } else {
                            details.append("  Status: No")
                        }
                        
                        // Add AUTH0 and ACCESS values
                        details.append("  AUTH0 value: 0x\(String(format: "%02X", auth0))")
                        details.append("  ACCESS value: 0x\(String(format: "%02X", accessByte))")
                        
                        // Show what ACCESS value means
                        if (accessByte & 0x80) == 0 {
                            details.append("  Note: ACCESS bit 7 not set - password not enforced")
                        }
                    } else {
                        print("⚠️ Invalid AUTH0/ACCESS response length: \(auth0Response.count) bytes (expected 16)")
                        details.append("")
                        details.append("Password Protection Status:")
                        details.append("  Status: Unknown (Could not read password pages)")
                    }
                    
                    tagInfo.details = details.joined(separator: "\n")
                    self.currentTag = nil
                    session.invalidate()
                    self.onTagInfoCompleted?(tagInfo, nil)
                }
            } else {
                tagInfo.tagType = "Unknown (Not NDEF formatted)"
                tagInfo.details = "Serial: \(tagInfo.serialNumber)\nTag is not NDEF formatted"
                self.currentTag = nil
                session.invalidate()
                self.onTagInfoCompleted?(tagInfo, nil)
            }
        }
    }
    
    // Parse NDEF text payload by removing language prefix
    // NDEF text record format: [Status Byte (UTF-16 flag + lang length)] [Language Code] [Text Content]
    private func parseNDEFTextPayload(_ payload: Data) -> String {
        guard payload.count > 0 else { return "" }
        
        // First byte is the status byte
        let statusByte = payload[0]
        
        // Bit 7 indicates UTF-16 (1) or UTF-8 (0)
        let isUTF16 = (statusByte & 0x80) != 0
        
        // Bits 6-0 indicate the language code length
        let langCodeLength = Int(statusByte & 0x3F)
        
        // Check if we have enough bytes for the language code
        guard payload.count > langCodeLength else { return "" }
        
        // Extract language code (for debugging, but we don't need it)
        // let langCode = String(data: payload.subdata(in: 1..<(1 + langCodeLength)), encoding: .utf8) ?? ""
        
        // Extract the text content (everything after the language code)
        let textStartIndex = 1 + langCodeLength
        guard payload.count > textStartIndex else { return "" }
        
        let textData = payload.subdata(in: textStartIndex..<payload.count)
        
        // Decode based on UTF-16 flag
        if isUTF16 {
            return String(data: textData, encoding: .utf16) ?? ""
        } else {
            return String(data: textData, encoding: .utf8) ?? ""
        }
    }
    
    // Set password on NTAG tag and enable password protection
    func setPassword(miFareTag: NFCMiFareTag, session: NFCTagReaderSession) {
        print("=== Setting Password on NFC Tag ===")
        print("Password bytes (hex): \(passwordData.map { String(format: "%02x", $0) }.joined(separator: " "))")
        print("Password bytes (ASCII): \(String(data: passwordData, encoding: .utf8) ?? "invalid")")
        print("⚠️  IMPORTANT: Keep the tag near your device throughout the entire operation!")
        
        // Ensure we have a strong reference to the tag
        // Store strong reference to keep tag alive during operations
        self.currentTag = miFareTag
        
        // First, check the tag type by reading the Capability Container
        print("\nChecking tag type and capabilities...")
        let readCCCommand = Data([0x30, 0x00]) // Read page 0 (returns pages 0-3)
        
        miFareTag.sendMiFareCommand(commandPacket: readCCCommand) { [weak self] (response: Data, error: Error?) in
            guard let self = self else { return }
            
            if let error = error {
                let errorMsg = "Failed to read tag capabilities: \(error.localizedDescription)"
                print("❌ \(errorMsg)")
                self.currentTag = nil
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, error)
                return
            }
            
            guard response.count >= 16 else {
                let errorMsg = "Invalid tag response when reading capabilities"
                print("❌ \(errorMsg)")
                self.currentTag = nil
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NFCScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            // Extract Capability Container from page 3 (bytes 12-15)
            let ccPage = response.subdata(in: 12..<16)
            
            // Check if it's a valid NDEF tag
            guard ccPage[0] == 0xE1 else {
                let errorMsg = "Tag is not NDEF formatted"
                print("❌ \(errorMsg)")
                self.currentTag = nil
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NFCScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            // Calculate NDEF memory size (from CC)
            let mlen = Int(ccPage[2])
            let ndefBytes = mlen * 8  // This is NDEF memory size, not total tag memory
            
            print("NDEF memory size: \(ndefBytes) bytes (from CC)")
            
            // Get password protection pages based on NDEF memory size
            guard let passwordPages = NTAG21XPasswordPages.pages(for: ndefBytes) else {
                let errorMsg = "Tag type not supported for password protection. NDEF memory: \(ndefBytes) bytes"
                print("❌ \(errorMsg)")
                self.currentTag = nil
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NFCScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            print("✅ \(passwordPages.tagType) detected - Total memory: \(passwordPages.totalMemoryBytes) bytes (\(passwordPages.totalMemoryPages) pages)")
            print("   Using pages 0x\(String(format: "%02X", passwordPages.auth0Page)) (AUTH0), 0x\(String(format: "%02X", passwordPages.pwdPage)) (PWD), 0x\(String(format: "%02X", passwordPages.accessPage)) (ACCESS), 0x\(String(format: "%02X", passwordPages.packPage)) (PACK)")
            
            // Verify pages are within tag's actual memory range (not NDEF range)
            if UInt(passwordPages.totalMemoryPages) <= UInt(passwordPages.auth0Page) || UInt(passwordPages.totalMemoryPages) <= UInt(passwordPages.pwdPage) || UInt(passwordPages.totalMemoryPages) <= UInt(passwordPages.accessPage) {
                let errorMsg = "Tag does not have enough pages for password protection. Required pages: 0x\(String(format: "%02X", passwordPages.auth0Page)), 0x\(String(format: "%02X", passwordPages.pwdPage)), 0x\(String(format: "%02X", passwordPages.accessPage)), Available: \(passwordPages.totalMemoryPages) pages"
                print("❌ \(errorMsg)")
                self.currentTag = nil
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NFCScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            print("✅ Tag supports password protection")
            
            // Step 1: Write password to PWD page
            print("\nStep 1: Writing password to page 0x\(String(format: "%02X", passwordPages.pwdPage)) (PWD)...")
            let writePasswordCommand = Data([0xA2, passwordPages.pwdPage]) + self.passwordData
            
            // Use strong reference to tag (not weak) to keep it alive during the operation
            // Capture both self, miFareTag, and passwordPages in the first closure
            miFareTag.sendMiFareCommand(commandPacket: writePasswordCommand) { [weak self, passwordPages] (response: Data, error: Error?) in
                guard let self = self else { return }
                
                // Re-check tag reference - it should still be alive
                guard let tag = self.currentTag, tag === miFareTag else {
                    let errorMsg = "Tag reference lost. Please keep the tag near your device and try again."
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onSetPasswordCompleted?(nil, NSError(domain: "NFCScanner", code: 100, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                if let error = error {
                    let nsError = error as NSError
                    var errorMsg = "Failed to write password: \(error.localizedDescription)"
                    
                    // Provide helpful guidance for connection lost errors
                    if nsError.code == 100 || error.localizedDescription.contains("connection lost") {
                        errorMsg += "\n\nTip: Keep the tag steady and close to your device. Try again."
                    }
                    
                    print("❌ \(errorMsg)")
                    self.currentTag = nil
                    session.invalidate(errorMessage: errorMsg)
                    self.onSetPasswordCompleted?(nil, error)
                    return
                }
                
                print("✅ Password written to page 0x\(String(format: "%02X", passwordPages.pwdPage))")
                
                // Step 2: Set AUTH0 - specifies which page requires authentication
                // AUTH0 = 0x04 means page 4 and above require authentication
                print("\nStep 2: Setting AUTH0 to 0x04 on page 0x\(String(format: "%02X", passwordPages.auth0Page)) (page 4 requires authentication)...")
                let auth0PageData = Data([0xA2, passwordPages.auth0Page, 0x04, 0x00, 0x00, 0x00]) // AUTH0=0x04, rest zeros
                // Use the original tag reference directly, and capture it strongly in the closure
                // This ensures the tag stays alive
                miFareTag.sendMiFareCommand(commandPacket: auth0PageData) { [weak self, unowned tag = miFareTag, passwordPages] (response: Data, error: Error?) in
                    guard let self = self else { return }
                    
                    // Verify tag is still the same reference
                    guard self.currentTag === tag else {
                        let errorMsg = "Tag reference changed. Please keep the tag near your device and try again."
                        print("❌ \(errorMsg)")
                        session.invalidate(errorMessage: errorMsg)
                        self.onSetPasswordCompleted?(nil, NSError(domain: "NFCScanner", code: 100, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                        return
                    }
                    
                    if let error = error {
                        let nsError = error as NSError
                        var errorMsg = "Failed to set AUTH0: \(error.localizedDescription)"
                        
                        if nsError.code == 100 || error.localizedDescription.contains("connection lost") {
                            errorMsg += "\n\nTip: Keep the tag steady and close to your device. Try again."
                            errorMsg += "\nThe password was written but AUTH0 was not set. You may need to try again."
                        }
                        
                        print("❌ \(errorMsg)")
                        self.currentTag = nil
                        session.invalidate(errorMessage: errorMsg)
                        self.onSetPasswordCompleted?(nil, error)
                        return
                    }
                    
                    print("✅ AUTH0 set to 0x04 on page 0x\(String(format: "%02X", passwordPages.auth0Page))")
                    
                    // Step 3: Set ACCESS - enables password protection
                    // ACCESS = 0x80 enables password protection, PACK = 0x0000 (no PACK required)
                    print("\nStep 3: Setting ACCESS to enable password protection on page 0x\(String(format: "%02X", passwordPages.accessPage))...")
                    let accessPageData = Data([0xA2, passwordPages.accessPage, 0x00, 0x00, 0x80, 0x00]) // PACK=0x0000, ACCESS=0x80
                    
                    // Use the original tag reference directly
                    miFareTag.sendMiFareCommand(commandPacket: accessPageData) { [weak self, unowned tag = miFareTag] (response: Data, error: Error?) in
                        guard let self = self else { return }
                        
                        // Verify tag is still the same reference
                        guard self.currentTag === tag else {
                            let errorMsg = "Tag reference changed. Please keep the tag near your device and try again."
                            print("❌ \(errorMsg)")
                            session.invalidate(errorMessage: errorMsg)
                            self.onSetPasswordCompleted?(nil, NSError(domain: "NFCScanner", code: 100, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                            return
                        }
                        
                        if let error = error {
                            let nsError = error as NSError
                            var errorMsg = "Failed to set ACCESS: \(error.localizedDescription)"
                            
                            if nsError.code == 100 || error.localizedDescription.contains("connection lost") {
                                errorMsg += "\n\nTip: Keep the tag steady and close to your device. Try again."
                                errorMsg += "\nPassword and AUTH0 were set, but ACCESS was not. You may need to try again."
                            }
                            
                            print("❌ \(errorMsg)")
                            self.currentTag = nil
                            session.invalidate(errorMessage: errorMsg)
                            self.onSetPasswordCompleted?(nil, error)
                            return
                        }
                        
                        print("✅ ACCESS set to enable password protection")
                        
                        // Complete the operation without verification to avoid connection loss
                        let successMsg = "Password set successfully! Tag is now password-protected."
                        session.alertMessage = successMsg
                        self.currentTag = nil
                        session.invalidate()
                        print("✅ \(successMsg)")
                        self.onSetPasswordCompleted?(successMsg, nil)
                    }
                }
            }
        }
    }
    
    // --- NFCTagReaderSessionDelegate Methods END ---
    func readAndParseNDEF2(tag: NFCMiFareTag, completion: @escaping (Result<NFCNDEFMessage, Error>) -> Void) {
        
        // We will store the data here
        var accumulatedData = Data()
        
        // We will determine these dynamically after reading Page 3
        var maxUserPage: Int = 0
        
        // Internal loop function
        func readBlock(page: UInt8, targetLength: Int?) {
            
            // 1. SAFETY GUARD: Stop if we are about to read beyond the tag's limit
            // We only enforce this after we have calculated maxUserPage (when page > 3)
            if maxUserPage > 0 && page > UInt8(maxUserPage) {
                // We reached the end but didn't find a complete NDEF message.
                // This prevents the "Tag connection lost" error.
                completion(.failure(NFCReaderError(.readerErrorInvalidParameter)))
                return
            }
            
            let cmd = Data([0x30, page]) // Command 0x30 = READ (Returns 4 pages / 16 bytes)
            
            tag.sendMiFareCommand(commandPacket: cmd) { response, error in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                
                var currentChunk = response
                
                // --- STEP A: PARSE CAPABILITY CONTAINER (Only on first read of Page 3) ---
                if page == 3 {
                    // Page 3 structure: [Magic, Version, SIZE(MLEN), Access]
                    // MLEN byte tells us the size. Size = MLEN * 8 bytes.
                    let mlen = Int(currentChunk[2])
                    let totalBytes = mlen * 8
                    let totalPages = totalBytes / 4
                    
                    // Calculate the last readable user page.
                    // User memory starts at Page 4.
                    maxUserPage = 3 + totalPages
                    
                    // Remove the first 4 bytes (Page 3) because they are config, not NDEF data
                    currentChunk = currentChunk.subdata(in: 4..<currentChunk.count)
                }
                
                accumulatedData.append(currentChunk)
                
                // --- STEP B: CHECK FOR NDEF HEADER ---
                // We look for the "0x03" (NDEF Message TLV)
                
                var payloadLen = 0
                var contentStartIndex = 0
                var headerFound = false
                
                // Scan accumulated data to find the TLV
                if accumulatedData.count >= 2 {
                    // If the first byte is 0x03 (NDEF)
                    if accumulatedData.first == 0x03 {
                        
                        // Check Short Length (1 byte)
                        if accumulatedData.count >= 2 && accumulatedData[1] != 0xFF {
                            payloadLen = Int(accumulatedData[1])
                            contentStartIndex = 2
                            headerFound = true
                        }
                        // Check Long Length (3 bytes: FF LL LL)
                        else if accumulatedData.count >= 4 && accumulatedData[1] == 0xFF {
                            let lenHigh = Int(accumulatedData[2])
                            let lenLow = Int(accumulatedData[3])
                            payloadLen = (lenHigh << 8) + lenLow
                            contentStartIndex = 4
                            headerFound = true
                        }
                    }
                }
                
                // --- STEP C: DECIDE NEXT STEP ---
                
                let totalNeeded = contentStartIndex + payloadLen
                
                if headerFound && accumulatedData.count >= totalNeeded {
                    // 1. WE HAVE THE FULL MESSAGE
                    let rawNdef = accumulatedData.subdata(in: contentStartIndex..<totalNeeded)
                    if let message = NFCNDEFMessage(data: rawNdef) {
                        completion(.success(message))
                    } else {
                        completion(.failure(NFCReaderError(.readerErrorInvalidParameter)))
                    }
                    
                } else {
                    // 2. NEED MORE DATA -> READ NEXT CHUNK
                    // The READ command returns 4 pages. We advance our pointer by 4 pages.
                    // Note: If we started at Page 3, next read is Page 7.
                    // If we started at Page 4 (old logic), next is 8.
                    // Since we start at 3 now to get CC, we increment by 4.
                    
                    let nextPage = page + 4
                    
                    // Quick check to ensure next request is valid
                    if maxUserPage > 0 && nextPage > UInt8(maxUserPage) {
                        // If the next block is out of bounds, we stop.
                        completion(.failure(NFCReaderError(.readerErrorInvalidParameter)))
                        return
                    }
                    
                    readBlock(page: nextPage, targetLength: totalNeeded)
                }
            }
        }
        
        // START reading at Page 3 (to get the CC size byte)
        readBlock(page: 0x03, targetLength: nil)
    }
    
    func writeStringData(miFareTag: NFCMiFareTag, session: NFCTagReaderSession, string: String, completion: @escaping (Result<Void, Error>) -> Void) {
        // --- Next Step: Perform a Write Operation ---
        // IMPORTANT: Keep the phone near the tag throughout the write operation
        // Call write immediately after authentication to minimize delay
        
        guard let payload = NFCNDEFPayload.wellKnownTypeTextPayload(string: string,
                                                                    locale: Locale(identifier: "en")) else {
            completion(.failure(NSError(domain: "NFCScanner", code: -6, userInfo: [NSLocalizedDescriptionKey: "Failed to create NDEF payload from string: \(string)"])))
            return
        }
        let message = NFCNDEFMessage(records: [payload])
        // 2. Serialize it using the extension above
        let serializedMessage = message.asData()
        
        // Get raw bytes of the NDEF message
        // Note: .length gives size, but we need the actual bytes.
        // We have to rely on the payload data, but iOS doesn't give a simple .data property for the whole NDEF blob easily.
        // We construct the TLV wrapper manually around the payload.
        
        // Quick-and-dirty TLV construction for the whole message:
        // 0x03 (NDEF Message Type) + Length + Payload + 0xFE (Terminator)
        
        // Ideally, serialize the whole message.
        // Since CoreNFC doesn't expose a "serialize()" for NFCNDEFMessage easily,
        // you might need to build the byte array from records manually or use a helper.
        // For this example, let's assume you have the `ndefBytes` representing the full NDEF message.
        
        // --- SIMPLIFIED TLV WRAPPER ---
        // NDEF Record Format (simplified for a single short URI record):
        // D1 (MB, ME, SR, TNF=1) | 01 (Type Len) | [Payload Len] | 55 (Type=URI) | [Payload]
        // WRAPPING IN TLV (Tag-Length-Value)
        var tlvData = Data()
        tlvData.append(0x03) // T: NDEF Message
        // If you can't manually serialize, create a dummy byte array for this example:
        // Let's assume `serializedMessage` is your valid NDEF byte array.
        if serializedMessage.count < 255 {
            tlvData.append(UInt8(serializedMessage.count)) // L: Short format
        } else {
            tlvData.append(0xFF)
            tlvData.append(UInt8(serializedMessage.count >> 8))
            tlvData.append(UInt8(serializedMessage.count & 0xFF))
        }
        
        tlvData.append(serializedMessage) // V: The NDEF data
        tlvData.append(0xFE) // Terminator
        // 3. WRITE RAW DATA
        // Start at Page 4 (Standard for NTAG213/215/216)
        writeRawData(tag: miFareTag, session: session, data: tlvData, startPage: 0x04, completion: completion)
    }
    
    func writeRawData(tag: NFCMiFareTag, session: NFCTagReaderSession, data: Data, startPage: UInt8, completion: @escaping (Result<Void, Error>) -> Void) {
        var currentPage = startPage
        var buffer = data
        let totalPages = (data.count + 3) / 4 // Calculate total pages for progress
        
        print("=== Starting Raw Write Operation ===")
        print("Total pages to write: \(totalPages)")
        print("Starting at page: \(startPage)")
        print("Total data size: \(data.count) bytes")
        print("⚠️  If this fails with 'Tag connection lost', it confirms CoreNFC limitation after PWD_AUTH")
        
        // Recursive function to write 4 bytes at a time
        func writeNextPage() {
            // If we have no more data, we are done
            guard !buffer.isEmpty else {
                print("writeRawData all data written to NFC")
                completion(.success(()))
                return
            }
            
            // Update progress message (only update every few pages to avoid overhead)
            let pagesWritten = Int(currentPage - startPage)
            // Take the first 4 bytes (pad with 0x00 if less than 4 remain)
            let prefix = buffer.prefix(4)
            var pageData = Data(prefix)
            while pageData.count < 4 { pageData.append(0x00) }
            
            // Remove the bytes we just processed
            buffer = buffer.dropFirst(4)
            
            // Command 0xA2 (WRITE) + Page Address + 4 Bytes of Data
            // CoreNFC's sendMiFareCommand handles the command framing,
            // we just provide the instruction and payload.
            // Command: 0xA2
            // Packet: [0xA2, PageAddr, D0, D1, D2, D3]
            
            let writeCommand = Data([0xA2, currentPage]) + pageData
            
            print("📝 Attempting to write page \(currentPage)/\(Int(startPage) + totalPages - 1)")
            print("   Command: \(writeCommand.map { String(format: "%02x", $0) }.joined(separator: " "))")
            print("   Data: \(pageData.map { String(format: "%02x", $0) }.joined(separator: " "))")
            
            // Use strong reference to keep tag alive during write operations
            // Continue on the same queue context (NFC callbacks are already on the correct queue)
            tag.sendMiFareCommand(commandPacket: writeCommand) { result, error in
                if let error = error {
                    let errorDescription = error.localizedDescription
                    let nsError = error as NSError
                    print("❌ Write failed at page \(currentPage)")
                    print("   Error: \(errorDescription)")
                    print("   Domain: \(nsError.domain), Code: \(nsError.code)")
                    if let userInfo = nsError.userInfo as? [String: Any] {
                        print("   UserInfo: \(userInfo)")
                    }
                    print("   This is page \(Int(currentPage) - Int(startPage) + 1) of \(totalPages)")
                    if currentPage == startPage {
                        print("   ⚠️  Failed on FIRST page - confirms CoreNFC cannot maintain connection after PWD_AUTH")
                    }
                    completion(.failure(error))
                    return
                }
                
                // Verify we got a response (should be empty for write commands)
                print("Write command successful for page \(currentPage), response: \(result.map { String(format: "%02x", $0) }.joined(separator: " "))")
                
                // Success! Move to next page
                currentPage += 1
                print("Success! Wrote page \(currentPage - 1), moving to page \(currentPage)")
                
                // Continue immediately on the same queue - no delay needed
                // The NFC framework handles timing internally
                writeNextPage()
            }
        }
        
        // Start the loop
        writeNextPage()
    }
    
    func readAndParseNDEF(tag: NFCMiFareTag, session: NFCTagReaderSession, startPage: UInt8 = 0x04,
                          completion: @escaping (Result<NFCNDEFMessage, Error>) -> Void) {
        
        
        // Internal function to read 16 bytes (4 pages) starting at a specific page
        func readBlock(page: UInt8, targetLength: Int?, currentData: Data) {
            // Command 0x30 is "READ"
            let cmd = Data([0x30, page])
            
            tag.sendMiFareCommand(commandPacket: cmd) { response, error in
                if let error = error {
                    completion(.failure(error))
                    return
                }
                
                var newData = currentData
                newData.append(response)
                
                // --- PARSING LOGIC ---
                
                // If we haven't determined the NDEF length yet, try to find it now
                var contentPayloadStartIndex = 0
                var payloadLength = 0
                var headerFound = false
                
                // We expect the data to start with 0x03 (NDEF Message TLV)
                if newData.first == 0x03 {
                    // Check Short Format (Length is 1 byte)
                    if newData.count >= 2 && newData[1] != 0xFF {
                        payloadLength = Int(newData[1])
                        contentPayloadStartIndex = 2
                        headerFound = true
                    }
                    // Check Long Format (Length is 3 bytes: FF LL LL)
                    else if newData.count >= 4 && newData[1] == 0xFF {
                        let lenBytes = newData[2...3] // Very simplified Big Endian
                        // In a real app, convert bytes to Int properly
                        payloadLength = (Int(newData[2]) << 8) + Int(newData[3])
                        contentPayloadStartIndex = 4
                        headerFound = true
                    }
                }
                
                // If we still don't have enough data to even read the header, read next block
                if !headerFound && newData.count < 6 {
                    // Continue immediately on the same queue context
                    readBlock(page: page + 4, targetLength: nil, currentData: newData)
                    return
                }
                
                // Now we know the target length. Do we have enough data?
                // Total needed = Header Size + Payload Length
                let totalNeeded = contentPayloadStartIndex + payloadLength
                
                if newData.count >= totalNeeded {
                    // WE HAVE ALL DATA!
                    // Extract just the NDEF bytes (remove TLV header and trailing data)
                    let rawNdefBytes = newData.subdata(in: contentPayloadStartIndex..<totalNeeded)
                    
                    // Decode into NFCNDEFMessage
                    if let ndefMessage = NFCNDEFMessage(data: rawNdefBytes) {
                        completion(.success(ndefMessage))
                    } else {
                        completion(.failure(NSError(domain: "NFCScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to decode into NFCNDEFMessage"])))
                    }
                } else {
                    // We need more data. Read the next 4 pages (16 bytes).
                    // Note: The READ command jumps 4 pages at a time in the response,
                    // but we increment the request pointer by 4 pages to get the next chunk.
                    // Continue immediately on the same queue context
                    readBlock(page: page + 4, targetLength: totalNeeded, currentData: newData)
                }
            }
        }
        
        // Start reading at Page 4
        readBlock(page: startPage, targetLength: nil, currentData: Data())
    }
}


extension NFCNDEFMessage {
    /// Serializes the full NDEF message into raw bytes (excluding TLV wrapper)
    func asData() -> Data {
        var data = Data()
        
        for (index, record) in records.enumerated() {
            let isFirst = (index == 0)
            let isLast = (index == records.count - 1)
            
            data.append(record.serialize(isFirst: isFirst, isLast: isLast))
        }
        
        return data
    }
}

extension NFCNDEFPayload {
    /// Serialize a single record based on its position in the message
    func serialize(isFirst: Bool, isLast: Bool) -> Data {
        var buffer = Data()
        
        // --- 1. Construct the Header Byte (Flags + TNF) ---
        // Bit 7: MB (Message Begin)
        // Bit 6: ME (Message End)
        // Bit 5: CF (Chunk Flag) - usually 0 for standard records
        // Bit 4: SR (Short Record) - 1 if payload <= 255 bytes
        // Bit 3: IL (ID Length) - 1 if identifier exists
        // Bit 0-2: TNF (Type Name Format)
        
        var header: UInt8 = typeNameFormat.rawValue
        
        if isFirst { header |= 0x80 } // Set MB
        if isLast { header |= 0x40 }  // Set ME
        
        // Check if payload is short (<= 255 bytes)
        let isShort = payload.count <= 255
        if isShort { header |= 0x10 } // Set SR
        
        // Check if we have an ID
        let hasId = !identifier.isEmpty
        if hasId { header |= 0x08 }   // Set IL
        
        buffer.append(header)
        
        // --- 2. Type Length ---
        buffer.append(UInt8(type.count))
        
        // --- 3. Payload Length ---
        if isShort {
            buffer.append(UInt8(payload.count))
        } else {
            // If long, use 4 bytes (Big Endian)
            let length = UInt32(payload.count)
            buffer.append(UInt8((length >> 24) & 0xFF))
            buffer.append(UInt8((length >> 16) & 0xFF))
            buffer.append(UInt8((length >> 8) & 0xFF))
            buffer.append(UInt8(length & 0xFF))
        }
        
        // --- 4. ID Length (Optional) ---
        if hasId {
            buffer.append(UInt8(identifier.count))
        }
        
        // --- 5. Type ---
        buffer.append(type)
        
        // --- 6. ID (Optional) ---
        if hasId {
            buffer.append(identifier)
        }
        
        // --- 7. Payload ---
        buffer.append(payload)
        
        return buffer
    }
}
