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
        print("\nStep 2: Diagnosing iOS Background Detection Requirements...")
        print(String(repeating: "=", count: 60))
        
        // CRITICAL: CC file (file 0x01) must be readable without authentication for iOS background detection
        // iOS reads the CC file first to determine if the tag is NDEF-formatted
        print("\n📋 Checking CC File (0x01) - CRITICAL for iOS Background Detection...")
        communicator.getFileSettings(fileNum: DnaCommunicator.CC_FILE_NUMBER) { [weak self] ccSettings, ccError in
            guard let self = self else { return }
            
            var ccFileReadable = false
            var ccFileMode = "Unknown"
            
            if let ccError = ccError {
                print("   ❌ ERROR: Could not read CC file settings: \(ccError.localizedDescription)")
                print("   ⚠️ This will PREVENT iOS background NFC detection!")
            } else if let ccSettings = ccSettings {
                ccFileReadable = (ccSettings.readPermission == .ALL)
                ccFileMode = ccSettings.communicationMode == .PLAIN ? "PLAIN" : "\(ccSettings.communicationMode)"
                
                print("   CC File Read Access: \(ccSettings.readPermission.rawValue) (\(ccSettings.readPermission.displayValue()))")
                print("   CC File Communication Mode: \(ccFileMode)")
                
                if !ccFileReadable {
                    print("   ❌ CRITICAL: CC file Read Access is NOT Free/ALL!")
                    print("   ❌ This WILL PREVENT iOS background NFC detection!")
                    print("   💡 SOLUTION: CC file must have Read Access = ALL (0xE) for iOS background detection")
                } else if ccSettings.communicationMode != .PLAIN {
                    print("   ⚠️ WARNING: CC file Communication Mode is NOT PLAIN!")
                    print("   ⚠️ This may prevent iOS background NFC detection!")
                } else {
                    print("   ✅ CC file Read Access is correct (Free/ALL)")
                    print("   ✅ CC file Communication Mode is PLAIN")
                }
            }
            
            print("\n📋 Checking NDEF File (0x02)...")
            
            // Now read NDEF file settings and check if it has data
            communicator.getFileSettings(fileNum: DnaCommunicator.NDEF_FILE_NUMBER) { [weak self] settings, error in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Failed to read current file settings: \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onConfigureFileAccessCompleted?(nil, error)
                    return
                }
                
                guard let currentSettings = settings else {
                    let errorMsg = "Failed to get file settings"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onConfigureFileAccessCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                let ndefReadable = (currentSettings.readPermission == .ALL)
                let ndefMode = currentSettings.communicationMode == .PLAIN ? "PLAIN" : "\(currentSettings.communicationMode)"
                
                print("   NDEF File Read Access: \(currentSettings.readPermission.rawValue) (\(currentSettings.readPermission.displayValue()))")
                print("   NDEF File Communication Mode: \(ndefMode)")
                print("   NDEF File Size: \(currentSettings.fileSize ?? 256) bytes")
                print("   SDM Enabled: \(currentSettings.sdmEnabled)")
                
                if !ndefReadable {
                    print("   ❌ CRITICAL: NDEF file Read Access is NOT Free/ALL!")
                    print("   ❌ This WILL PREVENT iOS background NFC detection!")
                } else if currentSettings.communicationMode != .PLAIN {
                    print("   ⚠️ WARNING: NDEF file Communication Mode is NOT PLAIN!")
                    print("   ⚠️ This may prevent iOS background NFC detection!")
                } else {
                    print("   ✅ NDEF file Read Access is correct (Free/ALL)")
                    print("   ✅ NDEF file Communication Mode is PLAIN")
                }
                
                // Check if NDEF file has data
                print("\n📋 Checking if NDEF file contains data...")
                communicator.readFileData(fileNum: DnaCommunicator.NDEF_FILE_NUMBER, length: 256, offset: 0) { [weak self] ndefData, readError in
                    guard let self = self else { return }
                    
                    var hasNdefData = false
                    if let readError = readError {
                        print("   ⚠️ Could not read NDEF file data: \(readError.localizedDescription)")
                    } else {
                        // Check if data contains valid NDEF (not all zeros or empty)
                        let nonZeroBytes = ndefData.filter { $0 != 0x00 && $0 != 0xFE }
                        hasNdefData = nonZeroBytes.count > 3 // At least some NDEF structure
                        
                        if hasNdefData {
                            print("   ✅ NDEF file contains data (\(ndefData.count) bytes)")
                        } else {
                            print("   ⚠️ WARNING: NDEF file appears to be empty or contains only padding!")
                            print("   ⚠️ iOS may not detect the tag in background if NDEF file is empty!")
                            print("   💡 SOLUTION: Write valid NDEF data to the NDEF file")
                        }
                    }
                    
                    // Summary
                    let separator = String(repeating: "=", count: 60)
                    print("\n" + separator)
                    print("📱 iOS Background Detection Diagnosis Summary:")
                    print(separator)
                    
                    var allRequirementsMet = true
                    
                    if !ccFileReadable {
                        print("❌ CC File (0x01) Read Access: NOT Free/ALL - BLOCKS iOS Background Detection")
                        allRequirementsMet = false
                    } else {
                        print("✅ CC File (0x01) Read Access: Free/ALL")
                    }
                    
                    if !ndefReadable {
                        print("❌ NDEF File (0x02) Read Access: NOT Free/ALL - BLOCKS iOS Background Detection")
                        allRequirementsMet = false
                    } else {
                        print("✅ NDEF File (0x02) Read Access: Free/ALL")
                    }
                    
                    if ccFileMode != "PLAIN" {
                        print("⚠️ CC File (0x01) Communication Mode: \(ccFileMode) (should be PLAIN)")
                        allRequirementsMet = false
                    } else {
                        print("✅ CC File (0x01) Communication Mode: PLAIN")
                    }
                    
                    if ndefMode != "PLAIN" {
                        print("⚠️ NDEF File (0x02) Communication Mode: \(ndefMode) (should be PLAIN)")
                        allRequirementsMet = false
                    } else {
                        print("✅ NDEF File (0x02) Communication Mode: PLAIN")
                    }
                    
                    if !hasNdefData {
                        print("⚠️ NDEF File (0x02) Data: Empty or invalid - May prevent iOS detection")
                        // Not blocking, but recommended
                    } else {
                        print("✅ NDEF File (0x02) Data: Contains valid NDEF data")
                    }
                    
                     if !allRequirementsMet {
                         print("\n❌ iOS Background Detection Requirements NOT MET!")
                         print("💡 Will attempt to fix:")
                         if !ccFileReadable || ccFileMode != "PLAIN" {
                             print("   1. Configure CC File (0x01) Read Access = ALL (0xE), Mode = PLAIN")
                         }
                         if !ndefReadable || ndefMode != "PLAIN" {
                             print("   2. Configure NDEF File (0x02) Read Access = ALL (0xE), Mode = PLAIN")
                         }
                         print("\n   Starting configuration...")
                     } else {
                         print("\n✅ All iOS Background Detection Requirements MET!")
                         print("   Your tag should be detectable by iOS in background.")
                     }
                     
                     print("\n" + separator)
                     
                     // Check if NDEF file needs configuration
                     let needsNDEFFileConfig = !ndefReadable || ndefMode != "PLAIN"
                     
                     // Warn about CC file if needed, but don't configure it automatically
                     if !ccFileReadable || ccFileMode != "PLAIN" {
                         print("\n⚠️ WARNING: CC File (0x01) is not configured for iOS background detection!")
                         print("   💡 Use the 'Configure CC File' button to fix this separately.")
                         print("   Continuing with NDEF file configuration...")
                     }
                     
                     if needsNDEFFileConfig {
                         // Configure NDEF file
                         self.configureNDEFFile(communicator: communicator, session: session, currentSettings: currentSettings)
                     } else {
                         // NDEF file is already correctly configured
                         let successMsg = "NDEF file is already correctly configured for iOS background detection!\n\n" +
                             "NDEF File (0x02): ✅ Read Access = ALL (0xE), Mode = PLAIN\n\n" +
                             "⚠️ Note: If CC File (0x01) Read Access is not ALL (0xE), use 'Configure CC File' button to fix it."
                         print("✅ \(successMsg)")
                         session.alertMessage = "NDEF file already correctly configured!"
                         session.invalidate()
                         self.currentTag = nil
                         self.communicator = nil
                         self.onConfigureFileAccessCompleted?(successMsg, nil)
                     }
                 }
             }
         }
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
     
     private func handleCCFileConfigResult(_ result: NxpCommandResult, error: Error?, commandData: [UInt8], completion: @escaping (Bool) -> Void) {
         if let error = error {
             print("❌ Failed to configure CC file: \(error.localizedDescription)")
             completion(false)
             return
         }
         
         if result.statusMajor == 0x91 && result.statusMinor == 0x00 {
             print("✅ CC File (0x01) configured successfully!")
             print("   • Read Access: ALL (0xE) ✅")
             print("   • Communication Mode: PLAIN ✅")
             completion(true)
         } else {
             // Error status word received
             let errorMsg = "CC file configuration failed: 0x\(String(format: "%02X", result.statusMajor))\(String(format: "%02X", result.statusMinor))"
             print("❌ \(errorMsg)")
             completion(false)
         }
     }
     
     // NOTE: header+data: MAC, data:encrypted for ChangeFileSettings
     // Configure CC File (0x01) for iOS background detection (internal helper)
     private func configureCCFile(communicator: DnaCommunicator, session: NFCTagReaderSession, ccSettings: FileSettings, completion: @escaping (Bool) -> Void) {
         print("\n" + String(repeating: "=", count: 60))
         print("🔧 Configuring CC File (0x01) for iOS Background Detection...")
         print(String(repeating: "=", count: 60))
         
         print("   Current CC File Read Access: \(ccSettings.readPermission.rawValue) (\(ccSettings.readPermission.displayValue()))")
         print("   Current CC File Communication Mode: \(ccSettings.communicationMode)")
         print("   Current CC File Size: \(ccSettings.fileSize ?? 32) bytes")
         print("   Current Change Access: \(ccSettings.changePermission.rawValue) (\(ccSettings.changePermission.displayValue()))")
         
         // CC file configuration for iOS background detection:
         // - Read Access: ALL (0xE) - CRITICAL
         // - Write Access: Can be protected (0x0 = Key 0)
         // - R/W Access: Can be protected
         // - Change Access: Should allow changes (ALL or KEY_0)
         // - Communication Mode: PLAIN (0x00) - CRITICAL
         // - SDM: Typically disabled for CC file
         //
         // IMPORTANT: CC file ChangeFileSettings command structure is different from NDEF file!
         // CC file structure: [FileNo] [FileOption] [AccessRights(2 bytes)]
         // NO FileSize bytes for CC file!
         let fileNo: UInt8 = DnaCommunicator.CC_FILE_NUMBER  // 0x01
         let fileOption: UInt8 = 0x00  // SDM disabled (bit 6 = 0), PLAIN mode (bits 1-0 = 0x00)
         // Access Rights: Read=0xE (Free), Write=0x0 (Key 0), R/W=0x0 (Key 0), Change=0xE (Free)
         let accessRightsByte1: UInt8 = (0xE << 4) | 0x0  // Read: 0xE (Free/ALL), Write: 0x0 (Key 0) = 0xE0
         let accessRightsByte2: UInt8 = (0x0 << 4) | 0xE  // R/W: 0x0 (Key 0), Change: 0xE (Free/ALL) = 0x0E
         
         // Build command data for CC file
         // According to NTAG 424 DNA datasheet, ChangeFileSettings command structure must match GetFileSettings response
         // GetFileSettings response structure (from FileSettings parsing):
         //   [FileType] [FileOption] [AccessRights(2)] [FileSize(3)] [SDM params if SDM enabled]
         // For CC file:
         //   - FileType is NOT included (it's read-only, comes from GetFileSettings response)
         //   - FileSize is NOT included for CC file (it's fixed at 32 bytes)
         //   - SDM params are NOT included (CC file has SDM disabled)
         // So for CC file ChangeFileSettings: [FileOption] [AccessRights(2)] = 3 bytes
         // FileNo goes in header (matching getFileSettings pattern: header=[fileNum])
         var commandData: [UInt8] = []
         commandData.append(fileOption)        // 1 byte - File option (0x00 = PLAIN, no SDM)
         commandData.append(accessRightsByte1) // 1 byte - Access rights byte 1 (0xE0)
         commandData.append(accessRightsByte2) // 1 byte - Access rights byte 2 (0x0E)
         // Total: 3 bytes (FileOption + AccessRights)
         // FileNo: In header (1 byte)
         // Total payload: 4 bytes (1 in header + 3 in data)
         // NO FileType byte (read-only, not part of ChangeFileSettings)
         // NO FileSize bytes for CC file!
         // NO SDM parameters for CC file!
         
         print("\n   Target Configuration:")
         print("   • Read Access: ALL (0xE) - Critical for iOS Background ✅")
         print("   • Write Access: Key 0 (0x0)")
         print("   • R/W Access: Key 0 (0x0)")
         print("   • Change Access: ALL (0xE)")
         print("   • Communication Mode: PLAIN ✅")
         print("   • SDM: Disabled")
         print("   Command structure: header=[\(String(format: "%02X", fileNo))], data=\(commandData.count) bytes")
         print("   Header: \(String(format: "%02X", fileNo)) (FileNo)")
         print("   Data: \(commandData.map { String(format: "%02X", $0) }.joined(separator: " "))")
         print("   Expected: Header=01, Data=00 E0 0E (FileOption=0x00, AccessRights=0xE0 0x0E)")
         print("   Pattern: FileNo in header, FileOption+AccessRights in data (matching getFileSettings pattern)")
         print("   Note: Data is sent in PLAIN (not encrypted) - nxpMacCommand adds MAC for integrity")
         
         // Re-authenticate before changing CC file settings
         // Use Key 0 for authentication
         print("\n   Re-authenticating with Key 0...")
         let keyBytes = self.dataToBytes(self.passwordData)
         communicator.authenticateEV2First(keyNum: 0, keyData: keyBytes) { [weak self] authSuccess, authError in
             guard let self = self else { return }
             
             if let authError = authError {
                 print("❌ Re-authentication failed: \(authError.localizedDescription)")
                 completion(false)
                 return
             }
             
             if !authSuccess {
                 print("❌ Re-authentication failed")
                 completion(false)
                 return
             }
             
             print("   ✅ Authenticated successfully")
             print("   Sending ChangeFileSettings command (0x5F) for CC file...")
             print("   Command structure: header=[\(String(format: "%02X", fileNo))], data=\(commandData.count) bytes")
             print("   Header: \(String(format: "%02X", fileNo))")
             print("   Data (plain): \(commandData.map { String(format: "%02X", $0) }.joined(separator: " "))")
             print("   Note: ChangeFileSettings is a security command - requires MAC protection when authenticated")
             print("   Note: Data is sent in PLAIN - nxpMacCommand adds MAC automatically for integrity")
             print("   Note: FileNo in header, FileOption+AccessRights in data (NO FileSize, NO SDM params)")
             // IMPORTANT: ChangeFileSettings is a security command that modifies file settings
             // It requires MAC protection when authenticated, regardless of the file's communication mode
             // The file's communication mode (PLAIN/MAC/FULL) only applies to read/write operations, not to ChangeFileSettings
             // 
             // nxpEncryptedCommand sends data in PLAIN and adds MAC for integrity, data encrypted
             communicator.nxpEncryptedCommand(command: 0x5F, header: [fileNo], data: commandData) { [weak self] result, error in
                 guard let self = self else { return }
                 self.handleCCFileConfigResult(result, error: error, commandData: commandData, completion: completion)
             }
         }
     }
     
     // Configure NDEF File (0x02)
    private func configureNDEFFile(communicator: DnaCommunicator, session: NFCTagReaderSession, currentSettings: FileSettings) {
        print("\n" + String(repeating: "=", count: 60))
        print("🔧 Configuring NDEF File (0x02)...")
        print(String(repeating: "=", count: 60))
        
        print("   Current R/W Access: \(currentSettings.readWritePermission.rawValue), Change Access: \(currentSettings.changePermission.rawValue)")
        if currentSettings.sdmEnabled {
            print("   Current SDM Options: UID=\(currentSettings.sdmOptionUid), ReadCounter=\(currentSettings.sdmOptionReadCounter)")
            print("   Current SDM Meta Read: \(currentSettings.sdmMetaReadPermission.rawValue), File Read: \(currentSettings.sdmFileReadPermission.rawValue)")
        }
        
        // Check if we can change the file settings
        if currentSettings.changePermission != .ALL && currentSettings.changePermission != .KEY_0 {
            let errorMsg = "Cannot change NDEF file settings: Change Access permission (\(currentSettings.changePermission.rawValue)) does not allow changes"
            print("❌ \(errorMsg)")
            session.invalidate(errorMessage: "Change Access permission does not allow file settings modification")
            self.onConfigureFileAccessCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            return
        }
        
        print("   File Number: 0x02 (NDEF File)")
        print("   Target Configuration:")
        print("   • Read Access: 0xE (Free/Plain - Critical for iOS Background) ✅")
        print("   • Write Access: 0x0 (Key Protected - Protects against overwriting)")
        print("   • R/W Access: 0x3 (Key Protected - Internal management)")
        print("   • Change Access: 0xE (Free - user changed this)")
        print("   • SDM: Enabled with UID mirroring and Read Counter")
        print("   • Communication Mode: PLAIN ✅")
        
        // ChangeFileSettings command: 0x5F
        // According to NTAG 424 DNA datasheet structure (matching GetFileSettings response):
        // [FileNo] [FileOption] [AccessRights(2)] [FileSize(3)] [SDM params if SDM enabled]
        // When SDM is enabled and Meta Read Permission = ALL:
        //   [SDMOptions] [SDMAccessRights(2)] [UIDOffset(3)] [ReadCounterOffset(3)] [MACInputOffset(3)] [MACOffset(3)]
        
        let fileNo: UInt8 = DnaCommunicator.NDEF_FILE_NUMBER  // 0x02
        
        // FileOption byte: bit 6 = SDM enabled (0x40), bits 1-0 = communication mode (0x00 = Plain)
        // Preserve current communication mode if possible
        let currentCommMode = currentSettings.communicationMode
        var fileOption: UInt8 = 0x40  // SDM enabled (bit 6)
        // Set communication mode bits (bits 1-0)
        switch currentCommMode {
        case .PLAIN:
            fileOption |= 0x00  // 0b00 = Plain
        case .MAC:
            fileOption |= 0x01  // 0b01 = MAC
        case .FULL:
            fileOption |= 0x03  // 0b11 = Full
        default:
            fileOption |= 0x00  // Default to Plain
        }
        
        let accessRightsByte1: UInt8 = (0xE << 4) | 0x0  // Read: 0xE (Free), Write: 0x0 (Key 0)
        let accessRightsByte2: UInt8 = (0x3 << 4) | 0xE  // R/W: 0x3 (Key 3), Change: 0xE (Free - user changed this)
        
        // File size: Use current file size (3 bytes, little endian) - REQUIRED in ChangeFileSettings
        let fileSize = currentSettings.fileSize ?? 256
        let fileSizeBytes: [UInt8] = [
            UInt8(fileSize & 0xFF),
            UInt8((fileSize >> 8) & 0xFF),
            UInt8((fileSize >> 16) & 0xFF)
        ]
        
        // SDM Options: bit 7 = UID mirroring, bit 6 = Read Counter
        let sdmOptions: UInt8 = 0xC0  // 0b11000000 = UID (bit 7) + Read Counter (bit 6)
        
        // SDM Access Rights
        // SDMAccessRights1: Meta Read (high nibble) | File Read (low nibble)
        let sdmAccessRights1: UInt8 = (0xE << 4) | 0xE  // Meta Read: 0xE (ALL), File Read: 0xE (ALL)
        // SDMAccessRights2: bits 7-4 = reserved (0x0), bits 3-0 = Read Counter Retrieval Permission
        let sdmAccessRights2: UInt8 = 0x0E  // Read Counter Retrieval: 0xE (ALL) in low nibble
        
        // SDM Offsets (3 bytes each, little endian)
        // When Meta Read Permission == ALL and UID option enabled:
        let uidOffsetBytes: [UInt8] = [0x00, 0x00, 0x00]  // UID Offset: 0x00
        // When Meta Read Permission == ALL and Read Counter option enabled:
        let readCounterOffsetBytes: [UInt8] = [0x07, 0x00, 0x00]  // Read Counter Offset: 0x07
        // When File Read Permission != NONE (0xE != 0xF):
        let macInputOffsetBytes: [UInt8] = [0x49, 0x00, 0x00]  // MAC Input Offset: 0x49
        let macOffsetBytes: [UInt8] = [0x7C, 0x00, 0x00]  // MAC Offset: 0x7C
        
        // Build command data - MUST match GetFileSettings structure exactly
        // According to NTAG 424 DNA datasheet, when SDM is enabled with Meta Read Permission = ALL:
        // Structure: [FileNo] [FileOption] [AccessRights(2)] [FileSize(3)] 
        //            [SDMOptions] [SDMAccessRights(2)] 
        //            [UIDOffset(3)] [ReadCounterOffset(3)] [MACInputOffset(3)] [MACOffset(3)]
        var commandData: [UInt8] = []
        commandData.append(fileOption)        // 1 byte
        commandData.append(accessRightsByte1) // 1 byte
        commandData.append(accessRightsByte2) // 1 byte
        commandData.append(contentsOf: fileSizeBytes) // 3 bytes - REQUIRED
        // SDM parameters (only if SDM enabled)
        commandData.append(sdmOptions)        // 1 byte
        commandData.append(sdmAccessRights1)  // 1 byte
        commandData.append(sdmAccessRights2)  // 1 byte
        // Offsets (when Meta Read Permission == ALL and options enabled)
        // Since we're setting Meta Read Permission to ALL (0xE) and both UID and Read Counter options are enabled
        commandData.append(contentsOf: uidOffsetBytes)      // 3 bytes (UID option enabled)
        commandData.append(contentsOf: readCounterOffsetBytes) // 3 bytes (Read Counter option enabled)
        // Offsets (when File Read Permission != NONE)
        // Since we're setting File Read Permission to ALL (0xE), which is != NONE (0xF)
        commandData.append(contentsOf: macInputOffsetBytes)  // 3 bytes
        commandData.append(contentsOf: macOffsetBytes)       // 3 bytes
        
        print("   Command data length: \(commandData.count) bytes")
        print("   Command data: \(commandData.map { String(format: "%02X", $0) }.joined(separator: " "))")
        
        // Re-authenticate to ensure session is still valid before changing file settings
        // The getFileSettings call may have affected the authentication session
        print("\nStep 5: Re-authenticating to ensure session is valid...")
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
            print("\nStep 6: Sending ChangeFileSettings command (0x5F) with MAC protection...")
            
            // Use nxpMacCommand since we need to be authenticated
            // Note: ChangeFileSettings (0x5F) requires authentication and MAC protection
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
                    let successMsg = "NDEF file access permissions and SDM configured successfully!\n\n" +
                    "NDEF File (0x02) Access Permissions:\n" +
                    "• Read Access: Free/Plain (0xE) - Critical for iOS Background ✅\n" +
                    "• Write Access: Key Protected (0x0) - Protects against overwriting\n" +
                    "• R/W Access: Key Protected (0x3) - Internal management\n" +
                    "• Change Access: Free (0xE) - User modified\n\n" +
                    "SDM Configuration:\n" +
                    "• SDM: Enabled\n" +
                    "• UID Mirroring: Enabled (Offset: 0x00)\n" +
                    "• Read Counter: Enabled (Offset: 0x07)\n" +
                    "• SDM Meta Read: Free (0xE)\n" +
                    "• SDM File Read: Free (0xE)\n" +
                     "• SDM Read Counter Retrieval: Free (0xE)\n" +
                     "• MAC Input Offset: 0x49\n" +
                     "• MAC Offset: 0x7C\n\n" +
                     "📱 iOS Background Detection:\n" +
                     "✅ NDEF File (0x02) is configured correctly!\n" +
                     "💡 Note: Also configure CC File (0x01) using 'Configure CC File' button for full iOS background detection support."
                    print("✅ \(successMsg)")
                    session.alertMessage = "File access and SDM configured successfully!"
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
                            errorMsg += " (Security status not satisfied - authentication may have expired or access rights don't allow this operation)"
                            print("   💡 Hint: The authentication session may have expired. Try re-authenticating before changing file settings.")
                            print("   💡 Hint: Ensure the current Change Access permission allows modifications (should be Free/ALL or Key 0)")
                        case 0x1E:
                            errorMsg += " (Insufficient NV-Memory to complete command)"
                        case 0x7C:
                            errorMsg += " (Length error - command data length incorrect)"
                        default:
                            errorMsg += " (Error code: 0x\(String(format: "%02X", result.statusMinor)))"
                        }
                    }
                    
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onConfigureFileAccessCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: statusCode, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                }
            }
        }
    }
    
    // Perform the actual write operation
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
        print("📤 NDEF message size: \(ndefBytes.count) bytes")
        
        // Write to NDEF file (file number 2)
        print("\nStep 3: Writing to NDEF file...")
        communicator.writeFileData(fileNum: DnaCommunicator.NDEF_FILE_NUMBER, data: ndefBytes, offset: 0) { [weak self] error in
            guard let self = self else { return }
            
            if let error = error {
                let errorMsg = "Failed to write NDEF file: \(error.localizedDescription)"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onWriteDataCompleted?(false, error)
                return
            }
            
            print("✅ Data written successfully!")
            session.alertMessage = "Data written successfully!"
            session.invalidate()
            self.currentTag = nil
            self.communicator = nil
            self.onWriteDataCompleted?(true, nil)
        }
    }
    
    // MARK: - NDEF Helpers
    
    // Create NDEF message from text/URL string
    private func createNDEFMessage(from text: String) -> Data? {
        // Try to create URI payload first (for URLs)
        if let uriPayload = NFCNDEFPayload.wellKnownTypeURIPayload(string: text) {
            let message = NFCNDEFMessage(records: [uriPayload])
            return message.asData()
        }
        
        // Fallback to text payload
        if let textPayload = NFCNDEFPayload.wellKnownTypeTextPayload(string: text, locale: Locale(identifier: "en")) {
            let message = NFCNDEFMessage(records: [textPayload])
            return message.asData()
        }
        
        return nil
    }
    
    // Parse NDEF data and extract text/URL
    private func parseNDEFData(_ data: Data) -> String {
        guard data.count > 0 else { return "" }
        
        // Remove padding (0x00 bytes at the end)
        var trimmedData = data
        while trimmedData.last == 0x00 {
            trimmedData = trimmedData.dropLast()
        }
        
        guard trimmedData.count > 0 else { return "" }
        
        // Try to parse as NDEF message
        if let message = try? NFCNDEFMessage(data: trimmedData) {
            for record in message.records {
                // Check if it's a URI record
                if record.typeNameFormat == .nfcWellKnown, record.type == Data([0x55]) { // "U" = URI
                    let uri = parseNDEFURIPayload(record.payload)
                    if !uri.isEmpty {
                        return uri
                    }
                }
                
                // Check if it's a text record
                if record.typeNameFormat == .nfcWellKnown, record.type == Data([0x54]) { // "T" = Text
                    let text = parseNDEFTextPayload(record.payload)
                    if !text.isEmpty {
                        return text
                    }
                }
            }
        }
        
        // Fallback: try to decode as UTF-8 string
        if let text = String(data: trimmedData, encoding: .utf8), !text.isEmpty {
            return text.trimmingCharacters(in: .whitespacesAndNewlines)
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

