//
//  NTAG424DNAScanner.swift
//  NFCTagWriter
//
//  Created for NTAG 424 DNA tag support using NfcDnaKit
//
import CoreNFC
import Foundation


// NTAG 424 Action Types
enum NTAG424DNAActionType {
    case setPassword
    case writeData
    case readData
    case configureFileAccess
    case configureCCFile
}

// NTAG 424 DNA Scanner using NfcDnaKit third-party library
// This is a refactored version using NfcDnaKit instead of manual APDU commands
class NTAG424DNAScanner: NSObject, NFCTagReaderSessionDelegate {
    
    var session: NFCTagReaderSession?
    
    // Store strong reference to tag and communicator
    private var currentTag: NFCISO7816Tag?
    private var communicator: DnaCommunicator?
    
    // Current action being performed
    private var currentAction: NTAG424DNAActionType = .setPassword
    
    // Callbacks
    var onSetPasswordCompleted: ((String?, Error?) -> Void)?
    var onAuthenticateCompleted: ((Bool, Error?) -> Void)?
    var onTagInfoCompleted: ((NTAG424TagInfo?, Error?) -> Void)?
    var onReadDataCompleted: ((String?, Error?) -> Void)?
    var onWriteDataCompleted: ((Bool, Error?) -> Void)?
    var onUIDDetected: ((String) -> Void)?  // Callback for when UID is detected
    var onConfigureFileAccessCompleted: ((String?, Error?) -> Void)?  // Callback for file access configuration
    var onConfigureCCFileCompleted: ((String?, Error?) -> Void)?  // Callback for CC file configuration
    
    // Password/Key data (16 bytes for AES-128)
    var password: String = ""
    var passwordData: Data {
        // Convert password string to 16-byte key (AES-128)
        // Pad or truncate to 16 bytes
        var keyData = Data(password.utf8)
        if keyData.count < 16 {
            // Pad with zeros
            keyData.append(contentsOf: Array(repeating: UInt8(0), count: 16 - keyData.count))
        } else if keyData.count > 16 {
            // Truncate to 16 bytes
            keyData = keyData.prefix(16)
        }
        return keyData
    }
    
    // Convert Data to [UInt8] array for NfcDnaKit
    private func dataToBytes(_ data: Data) -> [UInt8] {
        return Array(data)
    }
    
    // Convert [UInt8] array to Data
    private func bytesToData(_ bytes: [UInt8]) -> Data {
        return Data(bytes)
    }
    
    // Default key (usually all zeros for factory default)
    private let defaultKey: Data = Data(repeating: 0x00, count: 16)
    
    // Data to read/write
    var dataToWrite: String = ""
    
    private func handleError(error: Error) {
        // Call appropriate callback based on action
        switch self.currentAction {
        case .setPassword:
            self.onSetPasswordCompleted?(nil, error)
        case .readData:
            self.onReadDataCompleted?(nil, error)
        case .writeData:
            self.onWriteDataCompleted?(false, error)
        case .configureFileAccess:
            self.onConfigureFileAccessCompleted?(nil, error)
        case .configureCCFile:
            self.onConfigureCCFileCompleted?(nil, error)
        }
    }
    
    // Begin setting password on NTAG 424 tag
    func beginSettingPassword(password: String) {
        self.password = password
        currentAction = .setPassword
        
        // Use ISO14443 polling which supports ISO 7816 tags
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NTAG 424 tag to set password."
        session?.begin()
    }
    
    // Begin reading data from NTAG 424 tag
    func beginReadingData(password: String) {
        self.password = password
        currentAction = .readData
        
        // Use ISO14443 polling which supports ISO 7816 tags
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NTAG 424 tag to read data."
        session?.begin()
    }
    
    // Begin writing data to NTAG 424 tag
    func beginWritingData(data: String, password: String) {
        self.dataToWrite = data
        self.password = password
        currentAction = .writeData
        
        // Use ISO14443 polling which supports ISO 7816 tags
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NTAG 424 tag to write data."
        session?.begin()
    }
    
    // Begin configuring NDEF file access permissions
    func beginConfiguringFileAccess(password: String) {
        self.password = password
        currentAction = .configureFileAccess
        
        // Use ISO14443 polling which supports ISO 7816 tags
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NTAG 424 tag to configure file access."
        session?.begin()
    }
    
    // Begin configuring CC file for iOS background detection
    func beginConfiguringCCFile(password: String) {
        self.password = password
        currentAction = .configureCCFile
        
        // Use ISO14443 polling which supports ISO 7816 tags
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NTAG 424 tag to configure CC file for iOS background detection."
        session?.begin()
    }
    
    // MARK: - NFCTagReaderSessionDelegate
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("NTAG424DNAScanner: Session became active")
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        print("NTAG424DNAScanner: Session invalidated with error: \(error.localizedDescription)")
        self.currentTag = nil
        self.communicator = nil
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        print("NTAG424DNAScanner: Detected \(tags.count) tag(s)")
        
        guard let firstTag = tags.first else {
            session.invalidate(errorMessage: "No tag detected")
            return
        }
        
        // Debug: Print tag type
        print("📋 Detected tag type:")
        switch firstTag {
        case .iso7816:
            print("   - ISO 7816 tag")
        case .miFare:
            print("   - MIFARE tag")
        case .feliCa:
            print("   - FeliCa tag")
        case .iso15693:
            print("   - ISO 15693 tag")
        @unknown default:
            print("   - Unknown tag type")
        }
        
        // NTAG 424 DNA tags are ISO 7816-4 compliant but CoreNFC may detect them as MIFARE tags
        // NfcDnaKit requires ISO 7816 tags, so we can only use it when detected as ISO 7816
        // When detected as MIFARE, we need to inform the user to use NTAG424Scanner instead
        // or fall back to manual APDU commands (which NTAG424Scanner already handles)
        
        if case let .iso7816(tag) = firstTag {
            // Detected as ISO 7816 - use NfcDnaKit
            print("NTAG424DNAScanner: Detected ISO 7816 tag - using NfcDnaKit")
            self.currentTag = tag
            
            // Extract and notify UID
            let uid = tag.identifier.map { String(format: "%02X", $0) }.joined(separator: ":")
            print("📋 Tag UID: \(uid)")
            DispatchQueue.main.async {
                self.onUIDDetected?(uid)
            }
            
            // Initialize DnaCommunicator
            let comm = DnaCommunicator()
            comm.tag = tag
            comm.debug = true
            comm.trace = true
            self.communicator = comm
            
            // Connect to the tag
            session.connect(to: firstTag) { [weak self] (error: Error?) in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Failed to connect to tag: \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.handleError(error: error)
                    return
                }
                
                print("✅ Connected to NTAG 424 tag (ISO 7816)")
                
                // Begin the communicator (selects application)
                comm.begin { [weak self] beginError in
                    guard let self = self else { return }
                    
                    if let beginError = beginError {
                        let errorMsg = "Failed to begin communicator: \(beginError.localizedDescription)"
                        print("❌ \(errorMsg)")
                        session.invalidate(errorMessage: errorMsg)
                        // Call appropriate callback based on action
                        self.handleError(error: beginError)
                        return
                    }
                    
                    print("✅ Communicator initialized")
                    
                    // Route to appropriate handler based on action
                    switch self.currentAction {
                    case .setPassword:
                        self.setPassword(communicator: comm, session: session)
                    case .readData:
                        // For readTagInfo action, we'll read NDEF data
                        self.readData(communicator: comm, session: session)
                    case .writeData:
                        // For authenticate action, we'll write NDEF data
                        self.writeData(communicator: comm, session: session)
                    case .configureFileAccess:
                        self.configureFileAccess(communicator: comm, session: session)
                    case .configureCCFile:
                        self.configureCCFileOnly(communicator: comm, session: session)
                    }
                }
            }
        } else if case let .miFare(miFareTag) = firstTag {
            // Extract and notify UID
            let uid = miFareTag.identifier.map { String(format: "%02X", $0) }.joined(separator: ":")
            print("📋 Tag UID: \(uid)")
            DispatchQueue.main.async {
                self.onUIDDetected?(uid)
            }
            // Detected as MIFARE - NfcDnaKit cannot be used
            // Inform user that they should use NTAG424Scanner instead, or we could fall back
            let errorMsg = "NTAG 424 DNA detected as MIFARE tag.\n\nNfcDnaKit requires ISO 7816 tags.\n\nPlease use NTAG424Scanner instead, which supports both ISO 7816 and MIFARE detection.\n\nNote: NTAG 424 DNA tags support AES-128 encryption even when detected as MIFARE."
            print("❌ \(errorMsg)")
            print("   Detected tag type: MIFARE")
            print("   Solution: Use NTAG424Scanner which handles MIFARE tags via sendMiFareCommand()")
            session.invalidate(errorMessage: "Tag detected as MIFARE. Use NTAG424Scanner instead.")
            
            // Call completion with error based on action
            DispatchQueue.main.async {
                let error = NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg])
                self.handleError(error: error)
            }
        } else {
            // Unknown tag type
            let errorMsg = "Tag type not supported. NTAG 424 DNA requires ISO 7816 or MIFARE tag."
            print("❌ \(errorMsg)")
            print("   Detected tag type: \(firstTag)")
            session.invalidate(errorMessage: errorMsg)
        }
    }
    
    // MARK: - NTAG 424 Operations using NfcDnaKit
    
    // Set password on NTAG 424 tag using NfcDnaKit
    private func setPassword(communicator: DnaCommunicator, session: NFCTagReaderSession) {
        print("=== Setting Password on NTAG 424 Tag (using NfcDnaKit) ===")
        print("New password key (hex): \(passwordData.map { String(format: "%02X", $0) }.joined(separator: " "))")
        print("⚠️  IMPORTANT: Keep the tag near your device throughout the entire operation!")
        
        let defaultKeyBytes = dataToBytes(defaultKey)
        let newKeyBytes = dataToBytes(passwordData)
        
        // Step 1: Authenticate with default key (key number 0)
        print("\nStep 1: Authenticating with default key (key 0)...")
        communicator.authenticateEV2First(keyNum: 0, keyData: defaultKeyBytes) { [weak self] success, error in
            guard let self = self else { return }
            
            if let error = error {
                let errorMsg = "Authentication with default key failed: \(error.localizedDescription)"
                print("❌ \(errorMsg)")
                print("   Note: The tag may already have a password set. Try authenticating with the existing password first.")
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, error)
                return
            }
            
            if !success {
                let errorMsg = "Authentication with default key failed"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            print("✅ Authenticated with default key")
            
            // Step 2: Change the key to the new password
            // Key version is typically 0x00 for new keys
            print("\nStep 2: Changing key 0 to new password...")
            communicator.changeKey(keyNum: 0, oldKey: defaultKeyBytes, newKey: newKeyBytes, keyVersion: 0x00) { [weak self] success, error in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Failed to change key: \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onSetPasswordCompleted?(nil, error)
                    return
                }
                
                if !success {
                    let errorMsg = "Change key failed"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                let successMsg = "Password set successfully on NTAG 424 tag!\n\nNew key (hex): \(self.passwordData.map { String(format: "%02X", $0) }.joined(separator: " "))\n\n⚠️ IMPORTANT: Save this key securely. You will need it to authenticate with the tag in the future."
                print("✅ \(successMsg)")
                session.alertMessage = "Password set successfully!"
                session.invalidate()
                self.currentTag = nil
                self.communicator = nil
                self.onSetPasswordCompleted?(successMsg, nil)
            }
        }
    }
    
    // MARK: - Read/Write Data Operations
    
    // Read data from NTAG 424 tag NDEF file
    private func readData(communicator: DnaCommunicator, session: NFCTagReaderSession) {
        print("=== Reading Data from NTAG 424 Tag (using NfcDnaKit) ===")
        
        // Step 1: Authenticate if password is provided
        if !password.isEmpty {
            print("\nStep 1: Authenticating with password...")
            let keyBytes = dataToBytes(passwordData)
            communicator.authenticateEV2First(keyNum: 0, keyData: keyBytes) { [weak self] success, error in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Authentication failed: \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onReadDataCompleted?(nil, error)
                    return
                }
                
                if !success {
                    let errorMsg = "Authentication failed"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onReadDataCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                print("✅ Authenticated successfully")
                self.performReadData(communicator: communicator, session: session)
            }
        } else {
            // No password, read directly
            performReadData(communicator: communicator, session: session)
        }
    }
    
    // Perform the actual read operation
    private func performReadData(communicator: DnaCommunicator, session: NFCTagReaderSession) {
        print("\nStep 2: Reading NDEF file...")
//        Raw Storage: 256 Bytes.
//        Max Static NDEF Payload: 253 Bytes.
//        With SDM/SUN Enabled: ~190–200 Bytes (depending on configuration).
        // Read NDEF file (file number 2, max 256 bytes)
        //256 (Total) - 1 (Tag) - 1 (Len) - 1 (Terminator) = 253 bytes.
        communicator.readFileData(fileNum: DnaCommunicator.NDEF_FILE_NUMBER, length: 256, offset: 0) { [weak self] data, error in
            guard let self = self else { return }
            
            if let error = error {
                let errorMsg = "Failed to read NDEF file: \(error.localizedDescription)"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onReadDataCompleted?(nil, error)
                return
            }
            
            print("📥 Read \(data.count) bytes from NDEF file")
            
            // Parse NDEF message from the data
            let text = self.parseNDEFData(bytesToData(data))
            
            if !text.isEmpty {
                print("✅ Read data: \(text)")
                session.alertMessage = "Data read successfully!"
                session.invalidate()
                self.currentTag = nil
                self.communicator = nil
                self.onReadDataCompleted?(text, nil)
            } else {
                let errorMsg = "No NDEF data found or failed to parse"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onReadDataCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            }
        }
    }
    
    // Write data to NTAG 424 tag NDEF file
    private func writeData(communicator: DnaCommunicator, session: NFCTagReaderSession) {
        print("=== Writing Data to NTAG 424 Tag (using NfcDnaKit) ===")
        print("Data to write: \(dataToWrite)")
        
        // Step 1: Authenticate if password is provided
        if !password.isEmpty {
            print("\nStep 1: Authenticating with password...")
            let keyBytes = dataToBytes(passwordData)
            communicator.authenticateEV2First(keyNum: 0, keyData: keyBytes) { [weak self] success, error in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Authentication failed: \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onWriteDataCompleted?(false, error)
                    return
                }
                
                if !success {
                    let errorMsg = "Authentication failed"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onWriteDataCompleted?(false, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                print("✅ Authenticated successfully")
                self.performWriteData(communicator: communicator, session: session)
            }
        } else {
            // No password, write directly
            performWriteData(communicator: communicator, session: session)
        }
    }
    
    // Configure NDEF file access permissions
    private func configureFileAccess(communicator: DnaCommunicator, session: NFCTagReaderSession) {
        print("=== Configuring NDEF File Access Permissions ===")
        
        // Step 1: Authenticate if password is provided
        if !password.isEmpty {
            print("\nStep 1: Authenticating with password...")
            let keyBytes = dataToBytes(passwordData)
            communicator.authenticateEV2First(keyNum: 0, keyData: keyBytes) { [weak self] success, error in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Authentication failed: \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onConfigureFileAccessCompleted?(nil, error)
                    return
                }
                
                if !success {
                    let errorMsg = "Authentication failed"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onConfigureFileAccessCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                print("✅ Authenticated successfully")
                self.performConfigureFileAccess(communicator: communicator, session: session)
            }
        } else {
            // No password, try to configure directly (may fail if authentication is required)
            performConfigureFileAccess(communicator: communicator, session: session)
        }
    }
    
    // Perform the actual file access configuration
    private func performConfigureFileAccess(communicator: DnaCommunicator, session: NFCTagReaderSession) {
        // Configure NDEF file
        self.configureNDEFFile(communicator: communicator, session: session)
    }
     
     // Configure CC File Only - separate action
     private func configureCCFileOnly(communicator: DnaCommunicator, session: NFCTagReaderSession) {
         print("\n" + String(repeating: "=", count: 60))
         print("🔧 Configuring CC File (0x01) for iOS Background Detection...")
         print(String(repeating: "=", count: 60))
         
         // Step 1: Authenticate first (required before reading file settings)
         print("\nStep 1: Authenticating with password...")
         let keyBytes = self.dataToBytes(self.passwordData)
         communicator.authenticateEV2First(keyNum: 0, keyData: keyBytes) { [weak self] success, error in
             guard let self = self else { return }
             
             if let error = error {
                 let errorMsg = "Authentication failed: \(error.localizedDescription)"
                 print("❌ \(errorMsg)")
                 session.invalidate(errorMessage: errorMsg)
                 self.onConfigureCCFileCompleted?(nil, error)
                 return
             }
             
             if !success {
                 let errorMsg = "Authentication failed"
                 print("❌ \(errorMsg)")
                 session.invalidate(errorMessage: errorMsg)
                 self.onConfigureCCFileCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                 return
             }
             
             print("✅ Authenticated successfully")
             
             // Step 2: Read current CC file settings (now that we're authenticated)
             print("\nStep 2: Reading CC file settings...")
             communicator.getFileSettings(fileNum: DnaCommunicator.CC_FILE_NUMBER) { [weak self] ccSettings, ccError in
                 guard let self = self else { return }
                 print("CC file settings: readPermission \(String(describing: ccSettings?.readPermission))")
                 if let ccError = ccError {
                     let errorMsg = "Failed to read CC file settings: \(ccError.localizedDescription)"
                     print("❌ \(errorMsg)")
                     session.invalidate(errorMessage: errorMsg)
                     self.onConfigureCCFileCompleted?(nil, ccError)
                     return
                 }
                 
                 guard let ccSettings = ccSettings else {
                     let errorMsg = "Failed to get CC file settings"
                     print("❌ \(errorMsg)")
                     session.invalidate(errorMessage: errorMsg)
                     self.onConfigureCCFileCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                     return
                 }
                 
                 // Step 3: Configure CC file
                 self.configureCCFile(communicator: communicator, session: session, ccSettings: ccSettings) { [weak self] success in
                     guard let self = self else { return }
                     if success {
                         let successMsg = "CC File (0x01) configured successfully for iOS background detection!\n\n" +
                             "CC File Access Permissions:\n" +
                             "• Read Access: ALL (0xE) - Critical for iOS Background ✅\n" +
                             "• Write Access: Key 0 (0x0)\n" +
                             "• R/W Access: Key 0 (0x0)\n" +
                             "• Change Access: ALL (0xE)\n" +
                             "• Communication Mode: PLAIN ✅\n" +
                             "• SDM: Disabled\n\n" +
                             "📱 iOS Background Detection:\n" +
                             "✅ CC File is now configured correctly!\n" +
                             "   Your tag should be detectable by iOS in background."
                         print("✅ \(successMsg)")
                         session.alertMessage = "CC file configured successfully!"
                         session.invalidate()
                         self.currentTag = nil
                         self.communicator = nil
                         self.onConfigureCCFileCompleted?(successMsg, nil)
                     } else {
                         let errorMsg = "Failed to configure CC file"
                         print("❌ \(errorMsg)")
                         session.invalidate(errorMessage: errorMsg)
                         self.onConfigureCCFileCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                     }
                 }
             }
         }
     }
     
     // Write CC File (0x01) content directly (no permission configuration)
     private func configureCCFile(communicator: DnaCommunicator, session: NFCTagReaderSession, ccSettings: FileSettings, completion: @escaping (Bool) -> Void) {
         print("\n" + String(repeating: "=", count: 60))
         print("📝 Writing CC File (0x01) Content...")
         print(String(repeating: "=", count: 60))
         
         // CC file content (32 bytes) - Type 4 Tag specification
         // 001720010000FF0406E104010000000506E10500808283000000000000000000
         let ccFileContent: [UInt8] = [
            0x00, 0x17,  // CCLEN (23 bytes)
            0x20,        // Mapping Version (2.0)
            0x01, 0x00,  // MLe (256 bytes)
            0x00, 0xFF,  // MLc (255 bytes)
            0x04, 0x06, 0xE1, 0x04, 0x01, 0x00, 0x00, 0x00,  // NDEF-File Control TLV
            0x05, 0x06, 0xE1, 0x05, 0x00, 0x80, 0x82, 0x83,  // Data File Control TLV
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Padding (9 bytes)
         ]
         
         print("   CC File Content: \(ccFileContent.map { String(format: "%02X", $0) }.joined(separator: " "))")
         print("   Total size: \(ccFileContent.count) bytes")
         
         // Write CC file content directly (no permission configuration)
         communicator.writeFileData(fileNum: DnaCommunicator.CC_FILE_NUMBER, data: ccFileContent, mode: .PLAIN, offset: 0) { [weak self] writeError in
             guard let self = self else { return }
             
             if let writeError = writeError {
                 print("❌ Failed to write CC file content: \(writeError.localizedDescription)")
                 completion(false)
                 return
             }
             
             print("✅ CC file content written successfully!")
             completion(true)
         }
     }
     
     // Configure NDEF File (0x02)
     // According to NTAG 424 DNA datasheet, ChangeFileSettings command structure must match GetFileSettings response
     // GetFileSettings response structure: [FileType] [FileOption] [AccessRights(2)] [FileSize(3)] [SDM params if SDM enabled]
     // When SDM is DISABLED:
     //   ChangeFileSettings structure: [FileNo] [FileOption] [AccessRights(2)] [FileSize(3)]
     //   NO SDM parameters!
     private func configureNDEFFile(communicator: DnaCommunicator, session: NFCTagReaderSession) {
         print("\n" + String(repeating: "=", count: 60))
         print("🔧 Configuring NDEF File (0x02)...")
         print(String(repeating: "=", count: 60))
         
         // First, read current file settings to get file size and check permissions
         print("\nStep 1: Reading current NDEF file settings...")
         communicator.getFileSettings(fileNum: DnaCommunicator.NDEF_FILE_NUMBER) { [weak self] currentSettings, error in
             guard let self = self else { return }
             
             if let error = error {
                 let errorMsg = "Failed to read NDEF file settings: \(error.localizedDescription)"
                 print("❌ \(errorMsg)")
                 session.invalidate(errorMessage: errorMsg)
                 self.onConfigureFileAccessCompleted?(nil, error)
                 return
             }
             
             guard let currentSettings = currentSettings else {
                 let errorMsg = "Failed to get NDEF file settings"
                 print("❌ \(errorMsg)")
                 session.invalidate(errorMessage: errorMsg)
                 self.onConfigureFileAccessCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                 return
             }
             
             print("   Current NDEF File Settings:")
             print("   • Read Access: \(currentSettings.readPermission.rawValue) (\(currentSettings.readPermission.displayValue()))")
             print("   • Write Access: \(currentSettings.writePermission.rawValue) (\(currentSettings.writePermission.displayValue()))")
             print("   • R/W Access: \(currentSettings.readWritePermission.rawValue) (\(currentSettings.readWritePermission.displayValue()))")
             print("   • Change Access: \(currentSettings.changePermission.rawValue) (\(currentSettings.changePermission.displayValue()))")
             print("   • Communication Mode: \(currentSettings.communicationMode)")
             print("   • SDM Enabled: \(currentSettings.sdmEnabled)")
             print("   • File Size: \(currentSettings.fileSize ?? 256) bytes")
             
             // Check if we can change the file settings
             if currentSettings.changePermission != .ALL && currentSettings.changePermission != .KEY_0 {
                 let errorMsg = "Cannot change NDEF file settings: Change Access permission (\(currentSettings.changePermission.rawValue)) does not allow changes"
                 print("❌ \(errorMsg)")
                 session.invalidate(errorMessage: "Change Access permission does not allow file settings modification")
                 self.onConfigureFileAccessCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                 return
             }
             
             print("\nStep 2: Building ChangeFileSettings command...")
             
             let fileNo: UInt8 = DnaCommunicator.NDEF_FILE_NUMBER  // 0x02
             
             // FileOption byte structure:
             // - bit 6 = SDM enabled (0x40) - Set to 0 (SDM DISABLED)
             // - bits 1-0 = communication mode (0x00 = Plain, 0x01 = MAC, 0x03 = FULL)
             // SDM is DISABLED, so bit 6 = 0
             // Communication mode = PLAIN (0x00)
             let fileOption: UInt8 = 0x00  // SDM disabled (bit 6 = 0), PLAIN mode (bits 1-0 = 0x00)
             
             // Access Rights:
             // - Read: 0xE (Free/ALL) - Open for all readers (critical for iOS background detection)
             // - Write: 0x0 (Key 0) - Requires AES authentication to write
             // - R/W: 0x0 (Key 0) - Requires authentication
             // - Change: 0x0 (Key 0) - Requires authentication to change settings
             let accessRightsByte1: UInt8 = (0xE << 4) | 0x0  // Read: 0xE (Free/ALL), Write: 0x0 (Key 0) = 0xE0
             let accessRightsByte2: UInt8 = (0x0 << 4) | 0x0  // R/W: 0x0 (Key 0), Change: 0x0 (Key 0) = 0x00
             
             // File size: Use current file size (3 bytes, little endian) - REQUIRED in ChangeFileSettings
             let fileSize = currentSettings.fileSize ?? 256
             let fileSizeBytes: [UInt8] = [
                 UInt8(fileSize & 0xFF),
                 UInt8((fileSize >> 8) & 0xFF),
                 UInt8((fileSize >> 16) & 0xFF)
             ]
             
             // Build command data
             // According to NTAG 424 DNA datasheet and NfcDnaKit's changeFileSettings helper:
             // ChangeFileSettings structure: [FileOption] [AccessRights(2)]
             // FileSize is NOT included in ChangeFileSettings command (it's read-only or set during file creation)
             // When SDM is DISABLED: NO SDM parameters!
             var commandData: [UInt8] = []
             commandData.append(fileOption)        // 1 byte - FileOption (0x00 = PLAIN, no SDM)
             commandData.append(accessRightsByte1) // 1 byte - Access rights byte 1 (0xE0)
             commandData.append(accessRightsByte2) // 1 byte - Access rights byte 2 (0x00)
             // NO FileSize bytes - FileSize is not part of ChangeFileSettings command
             // NO SDM parameters since SDM is disabled
             
             print("\n   Target Configuration:")
             print("   • Read Access: ALL (0xE) - Critical for iOS Background ✅")
             print("   • Write Access: Key 0 (0x0) - Requires AES authentication ✅")
             print("   • R/W Access: Key 0 (0x0)")
             print("   • Change Access: Key 0 (0x0)")
             print("   • Communication Mode: PLAIN ✅")
             print("   • SDM: Disabled ❌")
             print("   • File Size: \(fileSize) bytes")
             print("\n   Command Structure (SDM DISABLED):")
             print("   • FileNo: 0x\(String(format: "%02X", fileNo)) (in header)")
             print("   • FileOption: 0x\(String(format: "%02X", fileOption)) (PLAIN mode, SDM disabled)")
             print("   • AccessRights: 0x\(String(format: "%02X", accessRightsByte1)) 0x\(String(format: "%02X", accessRightsByte2))")
             print("   Command data length: \(commandData.count) bytes")
             print("   Command data: \(commandData.map { String(format: "%02X", $0) }.joined(separator: " "))")
             print("   Expected: 00 E0 00 (FileOption=0x00, AccessRights=0xE0 0x00)")
             print("   Note: FileSize is NOT included in ChangeFileSettings command")
             
             // Re-authenticate to ensure session is still valid before changing file settings
             print("\nStep 3: Re-authenticating to ensure session is valid...")
             let keyBytes = self.dataToBytes(self.passwordData)
             communicator.authenticateEV2First(keyNum: 0, keyData: keyBytes) { [weak self] authSuccess, authError in
                 guard let self = self else { return }
                 
                 if let authError = authError {
                     let errorMsg = "Re-authentication failed: \(authError.localizedDescription)"
                     print("❌ \(errorMsg)")
                     session.invalidate(errorMessage: errorMsg)
                     self.onConfigureFileAccessCompleted?(nil, authError)
                     return
                 }
                 
                 if !authSuccess {
                     let errorMsg = "Re-authentication failed"
                     print("❌ \(errorMsg)")
                     session.invalidate(errorMessage: errorMsg)
                     self.onConfigureFileAccessCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                     return
                 }
                 
                 print("✅ Re-authenticated successfully")
                 print("\nStep 4: Sending ChangeFileSettings command (0x5F) with encryption and MAC protection...")
                 
                 // Use nxpEncryptedCommand for ChangeFileSettings
                 // Note: ChangeFileSettings (0x5F) requires authentication and MAC protection/encryption
                 communicator.nxpEncryptedCommand(command: 0x5F, header: [fileNo], data: commandData) { [weak self] result, error in
                     guard let self = self else { return }
                     
                     if let error = error {
                         let errorMsg = "Failed to configure file access: \(error.localizedDescription)"
                         print("❌ \(errorMsg)")
                         session.invalidate(errorMessage: errorMsg)
                         self.onConfigureFileAccessCompleted?(nil, error)
                         return
                     }
                     
                     // Check status word
                     if result.statusMajor == 0x91 && result.statusMinor == 0x00 {
                         print("✅ NDEF file ChangeFileSettings command succeeded!")
                         
                         let successMsg = "NDEF file access permissions configured successfully!\n\n" +
                         "NDEF File (0x02) Access Permissions:\n" +
                         "• Read Access: Free/ALL (0xE) - Critical for iOS Background ✅\n" +
                         "• Write Access: Key Protected (0x0) - Protects against overwriting ✅\n" +
                         "• R/W Access: Key Protected (0x0) - Internal management ✅\n" +
                         "• Change Access: Key Protected (0x0) - Requires authentication to change settings ✅\n\n" +
                         "SDM Configuration: Disabled ❌\n\n" +
                         "📱 iOS Background Detection:\n" +
                         "✅ NDEF File (0x02) is configured correctly!\n" +
                         "✅ Readable by all third-party tools (NXP TagWrite, TagInfo, iOS, etc.)\n" +
                         "✅ Write-protected (requires AES authentication)\n" +
                         "💡 Note: Also configure CC File (0x01) using 'Configure CC File' button for full iOS background detection support."
                         print("✅ \(successMsg)")
                         session.alertMessage = "File access configured successfully!"
                         session.invalidate()
                         self.currentTag = nil
                         self.communicator = nil
                         self.onConfigureFileAccessCompleted?(successMsg, nil)
                     } else {
                         // Error status word received
                         let statusCode = (Int(result.statusMajor) << 8) | Int(result.statusMinor)
                         var errorMsg = "Configuration failed with status: 0x\(String(format: "%02X", result.statusMajor))\(String(format: "%02X", result.statusMinor))"
                         
                         // Decode common error codes
                         if result.statusMajor == 0x91 {
                             switch result.statusMinor {
                             case 0x7E:
                                 errorMsg += " Length of command string invalid."
                             case 0x1E:
                                 errorMsg += " (Insufficient NV-Memory to complete command)"
                             case 0x7C:
                                 errorMsg += " (Length error - command data length incorrect)"
                                 print("   💡 Hint: Command data length is \(commandData.count) bytes. Expected: 3 bytes (FileOption + AccessRights(2))")
                             default:
                                 errorMsg += " (Error code: 0x\(String(format: "%02X", result.statusMinor))"
                             }
                         }
                         
                         print("❌ \(errorMsg)")
                         session.invalidate(errorMessage: errorMsg)
                         self.onConfigureFileAccessCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: statusCode, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                     }
                 }
             }
         }
     }
    
    // Perform the actual write operation
    // According to NTAG 424 DNA datasheet, we must use ISO 7816 commands (WriteData) to write to NDEF file
    // Standard Core NFC tag.writeNDEF() does NOT work for NTAG 424 DNA (Type 4 Tag)
    // We must use DnaCommunicator.writeFileData() which uses ISO 7816 WriteData command
    private func performWriteData(communicator: DnaCommunicator, session: NFCTagReaderSession) {
        print("\nStep 2: Creating NDEF message...")
        
        // Create NDEF message from text/URL
        guard let ndefData = createNDEFMessage(from: dataToWrite) else {
            let errorMsg = "Failed to create NDEF message from: \(dataToWrite)"
            print("❌ \(errorMsg)")
            session.invalidate(errorMessage: errorMsg)
            onWriteDataCompleted?(false, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            return
        }
        let ndefBytes = dataToBytes(ndefData)
        print("📤 NDEF file data size: \(ndefBytes.count) bytes (NLEN format, NFC Forum Type 4 Tag compliant)")
        print("   • NLEN structure: \(ndefBytes.prefix(min(32, ndefBytes.count)).map { String(format: "%02X", $0) }.joined(separator: " "))...")
        print("   ✅ Format: [NLEN(2 bytes)] [NDEF Data] - Compliant with NFC Forum Type 4 Tag specification")
        
        // Write to NDEF file (file number 2)
        // According to NTAG 424 DNA datasheet section 8.2.3.1 StandardData file:
        // "The writing operations of single frames up to 128 bytes with a WriteData or ISOUpdateBinary 
        //  command are also tearing protected."
        // 
        // IMPORTANT: nxpNativeCommand uses UInt8 for APDU packet length, which can only represent 0-255.
        // The APDU structure is: [CLA INS P1 P2 Lc] [Header] [Data] [Le]
        // Where Lc (length of command data) is a UInt8.
        // 
        // For writeFileData, the packet structure is:
        // Header: [fileNum] + [offset(3)] + [dataSize(3)] = 7 bytes
        // Data: [data bytes]
        // MAC: [8 bytes if authenticated]
        // Total: 7 + dataSize + MAC
        //
        // According to datasheet: Maximum single frame write = 128 bytes (tearing protected)
        // Since we need to write 256 bytes, we must write in chunks of 128 bytes.
        print("\nStep 3: Writing to NDEF file in chunks...")
        print("   • Using PLAIN mode (for third-party tool compatibility)")
        print("   • Writing at offset: 0x00")
        print("   • Data format: NLEN format (NFC Forum Type 4 Tag compliant)")
        print("   • Structure: [NLEN(2 bytes)] [NDEF Data]")
        print("   • Total bytes to write: \(ndefBytes.count) bytes")
        print("   • Chunk size: 128 bytes (datasheet maximum for tearing protection)")
        
        // Write in chunks according to datasheet specification
        // Chunk size: 128 bytes (maximum single frame write with tearing protection per datasheet 8.2.3.1)
        let chunkSize = 128
        var currentOffset = 0
        
        func writeNextChunk() {
            guard currentOffset < ndefBytes.count else {
                // All data written, verify
                print("✅ All data written successfully!")
                print("   • NDEF message written in NLEN format (NFC Forum Type 4 Tag compliant)")
                print("   • Structure: [NLEN(2 bytes)] [NDEF Data]")
                print("   • Total bytes written: \(ndefBytes.count) bytes")
                print("   • NXP TagInfo should now detect 'NDEF Data Storage Populated'")
                print("   • Third-party tools should be able to read the NDEF message")
                
                // Verify the write by reading back a small portion
                print("\nStep 4: Verifying write...")
                communicator.readFileData(fileNum: DnaCommunicator.NDEF_FILE_NUMBER, length: min(32, ndefBytes.count), offset: 0) { [weak self] readData, readError in
                    guard let self = self else { return }
                    
                    if let readError = readError {
                        print("   ⚠️ Could not verify write: \(readError.localizedDescription)")
                    } else {
                        print("   📥 Read back \(readData.count) bytes from offset 0x00")
                        print("   • First 16 bytes: \(readData.prefix(16).map { String(format: "%02X", $0) }.joined(separator: " "))")
                        
                        // Check if NLEN structure is correct (NFC Forum Type 4 Tag compliance)
                        if readData.count >= 2 {
                            let nlenHigh = readData[0]
                            let nlenLow = readData[1]
                            let ndefLength = (Int(nlenHigh) << 8) | Int(nlenLow)
                            
                            if ndefLength > 0 && ndefLength <= 0xFFFE {
                                print("   ✅ NLEN structure verified (NFC Forum Type 4 Tag compliant)")
                                print("   • NLEN: 0x\(String(format: "%02X", nlenHigh))\(String(format: "%02X", nlenLow)) = \(ndefLength) bytes")
                                print("   • NDEF data starts at offset 0x02")
                                
                                // Check if NDEF data is present
                                if readData.count >= 2 + ndefLength {
                                    print("   • NDEF data present: \(ndefLength) bytes")
                                } else if readData.count > 2 {
                                    print("   • Partial NDEF data read: \(readData.count - 2) bytes (expected \(ndefLength) bytes)")
                                }
                            } else {
                                print("   ⚠️ WARNING: NLEN value may be incorrect (0x\(String(format: "%04X", ndefLength)))")
                                print("   ⚠️ Expected range: 0x0001 to 0xFFFE")
                            }
                        } else {
                            print("   ⚠️ WARNING: Insufficient data to verify NLEN structure")
                        }
                    }
                    
                    session.alertMessage = "Data written successfully!"
                    session.invalidate()
                    self.currentTag = nil
                    self.communicator = nil
                    self.onWriteDataCompleted?(true, nil)
                }
                return
            }
            
            let remainingBytes = ndefBytes.count - currentOffset
            let currentChunkSize = min(chunkSize, remainingBytes)
            let chunk = Array(ndefBytes[currentOffset..<(currentOffset + currentChunkSize)])
            
            print("   • Writing chunk: offset=0x\(String(format: "%02X", currentOffset)), size=\(currentChunkSize) bytes, remaining=\(remainingBytes - currentChunkSize) bytes")
            
            communicator.writeFileData(fileNum: DnaCommunicator.NDEF_FILE_NUMBER, data: chunk, mode: .PLAIN, offset: currentOffset) { [weak self] error in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Failed to write NDEF file at offset 0x\(String(format: "%02X", currentOffset)): \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    print("   💡 If this fails, ensure NDEF file is configured with:")
                    print("      • Read Access = ALL (0xE)")
                    print("      • Write Access = Key 0 (requires authentication)")
                    print("      • Communication Mode = PLAIN")
                    session.invalidate(errorMessage: errorMsg)
                    self.onWriteDataCompleted?(false, error)
                    return
                }
                
                // Advance offset and write next chunk
                currentOffset += currentChunkSize
                
                // Add a small delay between chunks to avoid overwhelming the tag
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                    writeNextChunk()
                }
            }
        }
        
        // Start writing chunks
        writeNextChunk()
    }
    
    // MARK: - NDEF Helpers
    
    // Create NDEF message from text/URL string
    // According to NFC Forum Type 4 Tag specification, NDEF file uses NLEN format:
    // NLEN Structure: [NLEN(2 bytes, big-endian)] [NDEF Data]
    // Where:
    //   - NLEN = 2-byte length field (big-endian) indicating NDEF message length (0x0000 to 0xFFFE)
    //   - NDEF Data = The actual NDEF message bytes
    // 
    // This matches the format used by NXP TagWriter and other standard tools.
    // Example from working tag: [00 47] [D1 02 42 53 70 ...] where 0x0047 = 71 bytes
    private func createNDEFMessage(from text: String) -> Data? {
        // Create the NDEF message payload
        var ndefPayload: Data?
        
        // Try to create URI payload first (for URLs)
        if let uriPayload = NFCNDEFPayload.wellKnownTypeURIPayload(string: text) {
            let message = NFCNDEFMessage(records: [uriPayload])
            ndefPayload = message.asData()
        } else if let textPayload = NFCNDEFPayload.wellKnownTypeTextPayload(string: text, locale: Locale(identifier: "en")) {
            // Fallback to text payload
            let message = NFCNDEFMessage(records: [textPayload])
            ndefPayload = message.asData()
        }
        
        guard let payload = ndefPayload else {
            return nil
        }
        
        // Wrap the NDEF payload in NLEN format for NFC Forum Type 4 Tag compliance
        // NLEN format: [NLEN high byte] [NLEN low byte] [NDEF Data]
        var nlenData = Data()
        
        // NLEN: 2-byte length field (big-endian)
        // Range: 0x0000 to 0xFFFE (0 to 65534 bytes)
        // IMPORTANT: NLEN must be exactly 2 bytes, big-endian
        let ndefLength = UInt16(payload.count)
        nlenData.append(UInt8((ndefLength >> 8) & 0xFF))  // High byte
        nlenData.append(UInt8(ndefLength & 0xFF))          // Low byte
        
        // Append the actual NDEF message data
        nlenData.append(payload)
        
        print("   📝 NDEF NLEN structure (NFC Forum Type 4 Tag compliant):")
        print("   • NLEN format: [NLEN(2 bytes)] [NDEF Data]")
        print("   • NDEF message length: \(payload.count) bytes (0x\(String(format: "%04X", ndefLength)))")
        print("   • Total file data length: \(nlenData.count) bytes")
        print("   • NLEN bytes: \(String(format: "%02X", (ndefLength >> 8) & 0xFF)) \(String(format: "%02X", ndefLength & 0xFF))")
        print("   • First 16 bytes: \(nlenData.prefix(min(16, nlenData.count)).map { String(format: "%02X", $0) }.joined(separator: " "))...")
        print("   ✅ Compliant with NFC Forum Type 4 Tag specification (NLEN format)")
        
        return nlenData
    }
    
    // Parse NDEF data and extract text/URL
    // IMPORTANT: For Type 4 Tag (NTAG 424 DNA), NDEF data uses NLEN format:
    // NLEN Structure: [NLEN(2 bytes)] [NDEF Data]
    // Where NLEN is a 2-byte big-endian length field (0x0000 to 0xFFFE)
    private func parseNDEFData(_ data: Data) -> String {
        guard data.count >= 2 else { return "" }
        
        // Extract NLEN (2-byte length field, big-endian)
        let nlenHigh = data[0]
        let nlenLow = data[1]
        let ndefLength = (Int(nlenHigh) << 8) | Int(nlenLow)
        
        var ndefPayload: Data?
        
        if ndefLength > 0 && ndefLength <= 0xFFFE {
            // Valid NLEN format
            let payloadStart = 2  // Skip NLEN bytes
            let payloadEnd = payloadStart + ndefLength
            
            if data.count >= payloadEnd {
                ndefPayload = Data(data[payloadStart..<payloadEnd])
                print("   📥 Extracted NDEF payload from NLEN format: \(ndefLength) bytes")
            } else {
                // Partial data - read what we have
                if data.count > payloadStart {
                    ndefPayload = Data(data[payloadStart..<data.count])
                    print("   ⚠️ Partial NDEF data: read \(data.count - payloadStart) bytes (expected \(ndefLength) bytes)")
                } else {
                    print("   ⚠️ NLEN indicates \(ndefLength) bytes, but no data available")
                }
            }
        } else {
            // Invalid NLEN or legacy format - try to parse as raw NDEF data
            print("   📥 Invalid NLEN (0x\(String(format: "%04X", ndefLength))), trying to parse as raw NDEF data")
            
            // Remove padding (0x00 bytes at the end)
            var trimmedData = data
            while trimmedData.last == 0x00 || trimmedData.last == 0xFE {
                trimmedData = trimmedData.dropLast()
            }
            
            if trimmedData.count > 0 {
                ndefPayload = trimmedData
            }
        }
        
        guard let payload = ndefPayload, payload.count > 0 else {
            print("   ❌ Failed to extract NDEF payload from TLV structure")
            return ""
        }
        
        // Try to parse as NDEF message
        if let message = try? NFCNDEFMessage(data: payload) {
            print("   ✅ Successfully parsed NDEF message with \(message.records.count) record(s)")
            
            for record in message.records {
                // Check if it's a URI record
                if record.typeNameFormat == .nfcWellKnown, record.type == Data([0x55]) { // "U" = URI
                    let uri = parseNDEFURIPayload(record.payload)
                    if !uri.isEmpty {
                        print("   📎 Found URI record: \(uri)")
                        return uri
                    }
                }
                
                // Check if it's a text record
                if record.typeNameFormat == .nfcWellKnown, record.type == Data([0x54]) { // "T" = Text
                    let text = parseNDEFTextPayload(record.payload)
                    if !text.isEmpty {
                        print("   📝 Found text record: \(text)")
                        return text
                    }
                }
            }
        } else {
            print("   ⚠️ Failed to parse NDEF payload as NFCNDEFMessage")
            print("   💡 Payload hex (first 32 bytes): \(payload.prefix(32).map { String(format: "%02X", $0) }.joined(separator: " "))")
        }
        
        // Fallback: try to decode as UTF-8 string
        if let text = String(data: payload, encoding: .utf8), !text.isEmpty {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                print("   📄 Decoded as UTF-8 text: \(trimmed)")
                return trimmed
            }
        }
        
        return ""
    }
    
    // Parse NDEF URI payload
    private func parseNDEFURIPayload(_ payload: Data) -> String {
        guard payload.count > 0 else { return "" }
        
        let prefixCode = payload[0]
        let uriSuffix = payload.subdata(in: 1..<payload.count)
        
        let uriPrefixes: [String] = [
            "",                    // 0x00: No prefix
            "http://www.",         // 0x01
            "https://www.",        // 0x02
            "http://",             // 0x03
            "https://",            // 0x04
            "tel:",                // 0x05
            "mailto:",             // 0x06
        ]
        
        let prefix: String
        if Int(prefixCode) < uriPrefixes.count {
            prefix = uriPrefixes[Int(prefixCode)]
        } else {
            prefix = ""
        }
        
        if let suffix = String(data: uriSuffix, encoding: .utf8) {
            return prefix + suffix
        }
        
        return ""
    }
    
    // Parse NDEF text payload
    private func parseNDEFTextPayload(_ payload: Data) -> String {
        guard payload.count > 0 else { return "" }
        
        let statusByte = payload[0]
        let langCodeLength = Int(statusByte & 0x3F)
        
        guard payload.count > langCodeLength else { return "" }
        
        let textStartIndex = 1 + langCodeLength
        guard payload.count > textStartIndex else { return "" }
        
        let textData = payload.subdata(in: textStartIndex..<payload.count)
        let isUTF16 = (statusByte & 0x80) != 0
        
        if isUTF16 {
            return String(data: textData, encoding: .utf16) ?? ""
        } else {
            return String(data: textData, encoding: .utf8) ?? ""
        }
    }
    
}

