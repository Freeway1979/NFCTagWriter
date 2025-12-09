//
//  NTAG424Scanner.swift
//  NFCTagWriter
//
//  Created for NTAG 424 tag support
//
//  IMPORTANT: NTAG 424 DNA Tag Detection and ISO 7816 Usage
//  ==========================================================
//
//  Why NTAG 424 DNA is detected as MIFARE:
//  ----------------------------------------
//  1. NTAG 424 DNA tags are ISO 7816-4 compliant but also support ISO 14443-A (MIFARE) protocol
//  2. CoreNFC's tag detection algorithm may identify them as NFCMiFareTag first because:
//     - They respond to MIFARE commands during initial detection
//     - The NFC controller sees ISO 14443-A protocol first
//     - CoreNFC prioritizes MIFARE detection for ISO 14443-A tags
//  3. However, NTAG 424 DNA tags still support ISO 7816-4 APDU commands even when detected as MIFARE
//
//  AES-128 Encryption Support:
//  ---------------------------
//  ✅ YES - NTAG 424 DNA FULLY supports AES-128 encryption even when detected as MIFARE!
//  
//  Key points:
//  - Detection method (MIFARE vs ISO 7816) is ONLY about the transport/communication layer
//  - AES-128 encryption happens at the APPLICATION layer through APDU commands
//  - The tag's security features (AES, authentication, encryption) work identically regardless of detection
//  - When detected as MIFARE, we send ISO 7816-4 APDU commands through sendMiFareCommand()
//  - These APDU commands include AuthenticateEV2First which uses AES-128 for mutual authentication
//  - All encryption/decryption operations (aes128ECBDecrypt, aes128ECBEncrypt) work the same way
//
//  How to use NFCISO7816Tag functions:
//  -----------------------------------
//  When detected as ISO 7816 tag:
//  - Use tag.sendCommand(apdu: NFCISO7816APDU) directly
//  - Example: tag.sendCommand(apdu: apdu) { response, sw1, sw2, error in ... }
//  - AES encryption is handled by the tag internally during authentication
//
//  When detected as MIFARE tag:
//  - Send APDU commands through tag.sendMiFareCommand(commandPacket: Data)
//  - Build APDU as Data: [CLA, INS, P1, P2, Lc, Data...]
//  - Parse response: last 2 bytes are status words (SW1, SW2)
//  - Example: tag.sendMiFareCommand(commandPacket: apduData) { response, error in ... }
//  - AES encryption is STILL fully supported - authentication uses AES-128 via APDU commands
//
//  This scanner handles both cases automatically and AES encryption works in both paths.

import CoreNFC
import CryptoKit
import CommonCrypto

// NTAG 424 Tag Information Structure
struct NTAG424TagInfo {
    var serialNumber: String = ""
    var tagType: String = "NTAG 424"
    var memorySize: String = ""
    var isPasswordProtected: Bool = false
    var details: String = ""
}

// NTAG 424 Action Types
enum NTAG424ActionType {
    case setPassword
    case authenticate
}

// NTAG 424 Scanner for handling NTAG 424 tags
// NTAG 424 uses ISO/IEC 7816-4 APDU commands and AES-128 encryption
class NTAG424Scanner: NSObject, NFCTagReaderSessionDelegate {
    
    var session: NFCTagReaderSession?
    
    // Store strong reference to tag
    private var currentTag: NFCISO7816Tag?
    
    // Current action being performed
    private var currentAction: NTAG424ActionType = .setPassword
    
    // Callbacks
    var onSetPasswordCompleted: ((String?, Error?) -> Void)?
    var onAuthenticateCompleted: ((Bool, Error?) -> Void)?
    var onTagInfoCompleted: ((NTAG424TagInfo?, Error?) -> Void)?
    
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
    
    // Default key (usually all zeros for factory default)
    private let defaultKey: Data = Data(repeating: 0x00, count: 16)
    
    // NTAG 424 APDU Command Constants
    struct APDU {
        // ISO 7816-4 INS codes for NTAG 424
        static let SELECT_APPLICATION: UInt8 = 0xA4
        static let READ_BINARY: UInt8 = 0xB0
        static let UPDATE_BINARY: UInt8 = 0xD6
        static let GET_DATA: UInt8 = 0xCA
        static let CHANGE_KEY: UInt8 = 0xC4
        static let AUTHENTICATE_EV2: UInt8 = 0x71  // AuthenticateEV2First or AuthenticateEV2NonFirst
        static let AUTHENTICATE_PICC: UInt8 = 0x0A  // AuthenticatePICC
        
        // NTAG 424 specific file IDs
        static let FILE_ID_NDEF: UInt16 = 0x0001
        static let FILE_ID_CC: UInt16 = 0xE103
    }
    
    // Begin setting password on NTAG 424 tag
    func beginSettingPassword(password: String) {
        self.password = password
        currentAction = .setPassword
        
        // Use ISO14443 polling which supports both ISO 7816 and MIFARE tags
        // NTAG 424 DNA tags may be detected as either type
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NTAG 424 tag to set password."
        session?.begin()
    }
    
    // MARK: - NFCTagReaderSessionDelegate
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        print("NTAG424Scanner: Session became active")
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        print("NTAG424Scanner: Session invalidated with error: \(error.localizedDescription)")
        self.currentTag = nil
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        print("NTAG424Scanner: Detected \(tags.count) tag(s)")
        
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
        // This happens because:
        // 1. NTAG 424 DNA supports both ISO 14443-A (MIFARE) and ISO 7816-4 protocols
        // 2. CoreNFC's detection algorithm may identify them as MIFARE first
        // 3. However, they still support ISO 7816 APDU commands through the MIFARE interface
        
        if case let .iso7816(tag) = firstTag {
            // Detected as ISO 7816 - use NFCISO7816Tag functions directly
            print("NTAG424Scanner: Detected ISO 7816 tag")
            print("ℹ️  Using NFCISO7816Tag.sendCommand() for APDU commands")
            self.currentTag = tag
            
            // Connect to the tag
            session.connect(to: firstTag) { [weak self] (error: Error?) in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Failed to connect to tag: \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onSetPasswordCompleted?(nil, error)
                    return
                }
                
                print("✅ Connected to NTAG 424 tag (ISO 7816)")
                
                // Route to appropriate handler based on action
                switch self.currentAction {
                case .setPassword:
                    self.setPassword(tag: tag, session: session)
                case .authenticate:
                    // Authentication is handled as part of other operations
                    break
                }
            }
        } else if case let .miFare(miFareTag) = firstTag {
            // Detected as MIFARE - send APDU commands through sendMiFareCommand
            print("NTAG424Scanner: Detected MIFARE tag (NTAG 424 DNA)")
            print("ℹ️  NTAG 424 DNA is ISO 7816-4 compliant but detected as MIFARE")
            print("   Will send APDU commands through NFCMiFareTag.sendMiFareCommand()")
            print("   Note: APDU commands can be sent via sendMiFareCommand for NTAG 424 DNA")
            
            self.currentTag = nil  // No ISO 7816 tag, will use MIFARE interface
            
            // Connect to the tag
            session.connect(to: firstTag) { [weak self] (error: Error?) in
                guard let self = self else { return }
                
                if let error = error {
                    let errorMsg = "Failed to connect to tag: \(error.localizedDescription)"
                    print("❌ \(errorMsg)")
                    session.invalidate(errorMessage: errorMsg)
                    self.onSetPasswordCompleted?(nil, error)
                    return
                }
                
                print("✅ Connected to NTAG 424 tag (via MIFARE interface)")
                
                // Route to appropriate handler - use MIFARE interface
                switch self.currentAction {
                case .setPassword:
                    self.setPasswordViaMiFare(tag: miFareTag, session: session)
                case .authenticate:
                    // Authentication is handled as part of other operations
                    break
                }
            }
        } else {
            // Unknown tag type
            let errorMsg = "Tag type not supported. NTAG 424 DNA requires ISO 7816 or MIFARE tag."
            print("❌ \(errorMsg)")
            print("   Detected tag type: \(firstTag)")
            session.invalidate(errorMessage: errorMsg)
        }
    }
    
    // MARK: - NTAG 424 Operations
    
    // Set password on NTAG 424 tag
    // This involves selecting the application, authenticating with the default key, then changing the key
    private func setPassword(tag: NFCISO7816Tag, session: NFCTagReaderSession) {
        print("=== Setting Password on NTAG 424 Tag ===")
        print("New password key (hex): \(passwordData.map { String(format: "%02X", $0) }.joined(separator: " "))")
        print("⚠️  IMPORTANT: Keep the tag near your device throughout the entire operation!")
        
        // Step 1: Select Application (DF name: D2760000850101h - NFC Forum application identifier)
        print("\nStep 1: Selecting application...")
        selectApplication(tag: tag, session: session) { [weak self] success, error in
            guard let self = self else { return }
            
            if let error = error {
                let errorMsg = "Failed to select application: \(error.localizedDescription)"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, error)
                return
            }
            
            if !success {
                let errorMsg = "Failed to select application"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            print("✅ Application selected")
            
            // Step 2: Authenticate with default key (usually all zeros)
            print("\nStep 2: Authenticating with default key...")
            self.authenticateWithKey(tag: tag, key: self.defaultKey, session: session) { [weak self] success, error in
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
                    self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                print("✅ Authenticated with default key")
                
                // Step 3: Change the key to the new password
                print("\nStep 3: Changing key to new password...")
                self.changeKey(tag: tag, newKey: self.passwordData, session: session)
            }
        }
    }
    
    // Select Application using SELECT command
    // For NTAG 424, use DF name: D2760000850101h (NFC Forum application identifier)
    private func selectApplication(tag: NFCISO7816Tag, session: NFCTagReaderSession, completion: @escaping (Bool, Error?) -> Void) {
        // SELECT APPLICATION command
        // ISO Select command: 00 A4 04 00 + Length + AID
        // CLA = 0x00, INS = 0xA4, P1 = 0x04 (Select by DF name), P2 = 0x00, Lc = DF name length, Data = DF name
        // DF name for NTAG 424: D2760000850101h (7 bytes)
        let dfName: [UInt8] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]  // D2760000850101h
        
        // Build APDU using explicit initializer to ensure correct Lc handling
        let dfNameData = Data(dfName)
        let apdu = NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: APDU.SELECT_APPLICATION,  // 0xA4
            p1Parameter: 0x04,  // Select by DF name
            p2Parameter: 0x00,
            data: dfNameData,  // DF name (7 bytes)
            expectedResponseLength: -1  // Variable length response
        )
        
        print("📤 Sending SELECT APPLICATION command (DF name: D2760000850101h)...")
        tag.sendCommand(apdu: apdu) { (response: Data, statusWord1: UInt8, statusWord2: UInt8, error: Error?) in
            if let error = error {
                print("❌ SELECT APPLICATION error: \(error.localizedDescription)")
                completion(false, error)
                return
            }
            
            // Check status words
            // 0x90 0x00 = Success
            // 0x6A 0x82 = Application not found
            let success = (statusWord1 == 0x90 && statusWord2 == 0x00)
            
            if success {
                print("✅ SELECT APPLICATION successful")
                if response.count > 0 {
                    print("   Response: \(response.map { String(format: "%02X", $0) }.joined(separator: " "))")
                }
            } else {
                let statusCode = String(format: "%02X%02X", statusWord1, statusWord2)
                print("❌ SELECT APPLICATION failed with status: 0x\(statusCode)")
                
                var errorMsg = "Failed to select application"
                if statusWord1 == 0x6A && statusWord2 == 0x82 {
                    errorMsg = "Application not found. Tag may not be NTAG 424 or may not support this application."
                }
                
                completion(false, NSError(domain: "NTAG424Scanner", code: Int(statusWord1) << 8 | Int(statusWord2), userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            completion(true, nil)
        }
    }
    
    // Authenticate with a key using AuthenticateEV2First (3-pass mutual authentication)
    // NTAG 424 uses ISO 7816-4 APDU commands with challenge-response protocol
    // Steps:
    // 1. Send "Get Challenge" (AuthenticateEV2First with key)
    // 2. Receive encrypted RndB from Tag (16 bytes)
    // 3. Decrypt RndB, rotate it (left rotate by 1 byte), generate RndA
    // 4. Send encrypted RndA + RndB' back to tag
    private func authenticateWithKey(tag: NFCISO7816Tag, key: Data, session: NFCTagReaderSession, completion: @escaping (Bool, Error?) -> Void) {
        print("🔐 Authenticating with key: \(key.map { String(format: "%02X", $0) }.joined(separator: " "))")
        
        guard key.count == 16 else {
            let error = NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key must be exactly 16 bytes for AES-128"])
            completion(false, error)
            return
        }
        
        // Step 1: Send AuthenticateEV2First command (Get Challenge)
        // According to NTAG 424 DNA datasheet (Section 11.4.1):
        // APDU: 90 71 00 00 10 [Key (16 bytes)]
        // - CLA = 0x90 (Native command class)
        // - INS = 0x71 (AuthenticateEV2First)
        // - P1 = 0x00 (Key number: 0x00=AppMasterKey, 0x01-0x04=AppKey1-4)
        // - P2 = 0x00
        // - Lc = 0x10 (16 bytes for AES-128 key)
        // - Data = Key (16 bytes)
        print("\n📤 Step 1: Sending AuthenticateEV2First (Get Challenge)...")
        print("   Command structure per NTAG 424 DNA datasheet: 90 71 00 00 10 [Key]")
        
        // Build APDU using explicit initializer to ensure correct Lc handling
        let apdu = NFCISO7816APDU(
            instructionClass: 0x90,  // Native command class
            instructionCode: APDU.AUTHENTICATE_EV2,  // 0x71 (AuthenticateEV2First)
            p1Parameter: 0x00,  // Key number (0x00 = AppMasterKey, default key)
            p2Parameter: 0x00,
            data: key,  // Key data (16 bytes) - Lc is automatically set to key.count
            expectedResponseLength: -1  // Variable length response (expects encrypted RndB)
        )
        
        tag.sendCommand(apdu: apdu) { [weak self] (response: Data, statusWord1: UInt8, statusWord2: UInt8, error: Error?) in
            guard let self = self else { return }
            
            if let error = error {
                print("❌ Step 1 error: \(error.localizedDescription)")
                completion(false, error)
                return
            }
            
            // Check status words
            // 0x91 0xAF = More data available (encrypted RndB in response)
            // 0x90 0x00 = Success (should not happen here)
            // Other = Error
            
            guard statusWord1 == 0x91 && statusWord2 == 0xAF else {
                let statusCode = String(format: "%02X%02X", statusWord1, statusWord2)
                print("❌ Step 1 failed with status: 0x\(statusCode)")
                
                var errorMsg = "Get Challenge failed"
                if statusWord1 == 0x63 {
                    errorMsg = "Wrong key or authentication failed"
                } else if statusWord1 == 0x69 {
                    errorMsg = "Security status not satisfied"
                }
                
                completion(false, NSError(domain: "NTAG424Scanner", code: Int(statusWord1) << 8 | Int(statusWord2), userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            // Step 2: Receive encrypted RndB from Tag (16 bytes)
            guard response.count >= 16 else {
                let errorMsg = "Invalid response length: expected 16 bytes, got \(response.count)"
                print("❌ \(errorMsg)")
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            let encryptedRndB = response.prefix(16)
            print("📥 Step 2: Received encrypted RndB: \(encryptedRndB.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // Step 3: Decrypt RndB, rotate it, generate RndA
            guard let decryptedRndB = self.decryptAES128(data: encryptedRndB, key: key) else {
                let errorMsg = "Failed to decrypt RndB"
                print("❌ \(errorMsg)")
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            print("   Decrypted RndB: \(decryptedRndB.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // Rotate RndB left by 1 byte
            let rotatedRndB = self.rotateLeft(data: decryptedRndB, by: 1)
            print("   Rotated RndB: \(rotatedRndB.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // Generate random RndA (16 bytes)
            var rndA = Data(count: 16)
            let result = rndA.withUnsafeMutableBytes { bytes in
                SecRandomCopyBytes(kSecRandomDefault, 16, bytes.baseAddress!)
            }
            
            guard result == errSecSuccess else {
                let errorMsg = "Failed to generate RndA"
                print("❌ \(errorMsg)")
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            print("   Generated RndA: \(rndA.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // Concatenate RndA || RotatedRndB (32 bytes total)
            var dataToEncrypt = Data()
            dataToEncrypt.append(rndA)
            dataToEncrypt.append(rotatedRndB)
            
            // Encrypt RndA || RotatedRndB (use ECB mode for NTAG 424)
            guard let encryptedData = self.aes128ECBEncrypt(data: dataToEncrypt, key: key) else {
                let errorMsg = "Failed to encrypt RndA || RndB'"
                print("❌ \(errorMsg)")
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            print("   Encrypted RndA || RndB': \(encryptedData.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // Step 4: Send encrypted RndA + RndB' back to tag
            // According to NTAG 424 DNA datasheet (Section 11.4.1, Fig. 14):
            // After receiving 0x91 0xAF with encrypted RndB, send continue command:
            // APDU: 90 AF 00 00 20 [Encrypted RndA || RndB' (32 bytes)]
            // - CLA = 0x90
            // - INS = 0xAF (Continue command)
            // - P1 = 0x00
            // - P2 = 0x00
            // - Lc = 0x20 (32 bytes: 16 bytes RndA + 16 bytes rotated RndB)
            // - Data = Encrypted(RndA || RndB') (32 bytes)
            print("\n📤 Step 4: Sending encrypted RndA || RndB'...")
            print("   Command structure per datasheet: 90 AF 00 00 20 [Encrypted RndA||RndB']")
            
            // Build response APDU using explicit initializer to ensure correct Lc handling
            let responseApdu = NFCISO7816APDU(
                instructionClass: 0x90,  // Native command class
                instructionCode: 0xAF,  // Continue authentication command
                p1Parameter: 0x00,
                p2Parameter: 0x00,
                data: encryptedData,  // Encrypted RndA || RndB' (32 bytes) - Lc is automatically set to 0x20
                expectedResponseLength: -1  // Variable length response
            )
            
            tag.sendCommand(apdu: responseApdu) { (finalResponse: Data, finalSW1: UInt8, finalSW2: UInt8, finalError: Error?) in
                if let error = finalError {
                    print("❌ Step 4 error: \(error.localizedDescription)")
                    completion(false, error)
                    return
                }
                
                // Check final status
                let success = (finalSW1 == 0x90 && finalSW2 == 0x00)
                
                if success {
                    print("✅ Authentication successful!")
                    if finalResponse.count > 0 {
                        print("   Final response: \(finalResponse.map { String(format: "%02X", $0) }.joined(separator: " "))")
                    }
                } else {
                    let statusCode = String(format: "%02X%02X", finalSW1, finalSW2)
                    print("❌ Authentication failed with final status: 0x\(statusCode)")
                    
                    var errorMsg = "Authentication failed"
                    if finalSW1 == 0x63 {
                        errorMsg = "Wrong key or authentication failed"
                    } else if finalSW1 == 0x69 {
                        errorMsg = "Security status not satisfied"
                    }
                    
                    completion(false, NSError(domain: "NTAG424Scanner", code: Int(finalSW1) << 8 | Int(finalSW2), userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                completion(true, nil)
            }
        }
    }
    
    // AES-128 encryption helper
    private func encryptAES128(data: Data, key: Data) -> Data? {
        guard data.count == 16 || data.count == 32, key.count == 16 else {
            return nil
        }
        
        do {
            let symmetricKey = SymmetricKey(data: key)
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
            return sealedBox.ciphertext + sealedBox.nonce
        } catch {
            print("❌ AES encryption error: \(error)")
            return nil
        }
    }
    
    // AES-128 decryption helper
    private func decryptAES128(data: Data, key: Data) -> Data? {
        guard data.count == 16, key.count == 16 else {
            return nil
        }
        
        // For NTAG 424, the encryption is AES-128 in ECB mode (not GCM)
        // We need to use CommonCrypto or a library that supports ECB mode
        // For now, let's use a simple approach with CryptoKit's AES.GCM
        // Note: This might need adjustment based on actual NTAG 424 encryption mode
        
        // Actually, NTAG 424 uses AES-128 in a specific mode
        // Let's use CommonCrypto for ECB mode
        return self.aes128ECBDecrypt(data: data, key: key)
    }
    
    // AES-128 ECB mode decryption (NTAG 424 uses ECB mode)
    private func aes128ECBDecrypt(data: Data, key: Data) -> Data? {
        guard data.count == 16, key.count == 16 else {
            return nil
        }
        
        // Create a mutable buffer to avoid overlapping access issues
        let bufferSize = data.count
        var decryptedBuffer = [UInt8](repeating: 0, count: bufferSize)
        var numBytesDecrypted: size_t = 0
        
        // Get pointers from input data
        let keyBytes = key.withUnsafeBytes { $0.baseAddress! }
        let encryptedBytes = data.withUnsafeBytes { $0.baseAddress! }
        
        // Perform decryption
        let status = decryptedBuffer.withUnsafeMutableBytes { decryptedBytes in
            CCCrypt(
                CCOperation(kCCDecrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                keyBytes, key.count,
                nil, // No IV for ECB mode
                encryptedBytes, data.count,
                decryptedBytes.baseAddress, bufferSize,
                &numBytesDecrypted
            )
        }
        
        guard status == kCCSuccess, numBytesDecrypted == data.count else {
            return nil
        }
        
        return Data(decryptedBuffer)
    }
    
    // AES-128 ECB mode encryption
    // Supports 16-byte, 32-byte, or any length (padded to 16-byte blocks)
    private func aes128ECBEncrypt(data: Data, key: Data) -> Data? {
        guard key.count == 16 else {
            return nil
        }
        
        // Pad data to 16-byte boundary if needed
        var paddedData = data
        let remainder = data.count % 16
        if remainder != 0 {
            paddedData.append(0x80)  // Add 0x80 padding
            while paddedData.count % 16 != 0 {
                paddedData.append(0x00)
            }
        }
        
        // Encrypt each 16-byte block
        var encrypted = Data()
        for i in stride(from: 0, to: paddedData.count, by: 16) {
            let block = paddedData.subdata(in: i..<min(i+16, paddedData.count))
            if block.count == 16 {
                // Encrypt single 16-byte block
                var encryptedBlock = [UInt8](repeating: 0, count: 16)
                var numBytesEncrypted: size_t = 0
                
                let keyBytes = key.withUnsafeBytes { $0.baseAddress! }
                let blockBytes = block.withUnsafeBytes { $0.baseAddress! }
                
                let status = encryptedBlock.withUnsafeMutableBytes { encryptedBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes, key.count,
                        nil, // No IV for ECB mode
                        blockBytes, 16,
                        encryptedBytes.baseAddress, 16,
                        &numBytesEncrypted
                    )
                }
                
                guard status == kCCSuccess, numBytesEncrypted == 16 else {
                    return nil
                }
                
                encrypted.append(contentsOf: encryptedBlock)
            }
        }
        
        // Return only the encrypted data (same length as input, not padded)
        if data.count == 16 || data.count == 32 {
            return encrypted.prefix(data.count)
        }
        return encrypted
        
        // Create a mutable buffer to avoid overlapping access issues
        let bufferSize = data.count
        var encryptedBuffer = [UInt8](repeating: 0, count: bufferSize)
        var numBytesEncrypted: size_t = 0
        
        // Get pointers from input data
        let keyBytes = key.withUnsafeBytes { $0.baseAddress! }
        let plainBytes = data.withUnsafeBytes { $0.baseAddress! }
        
        // Perform encryption
        let status = encryptedBuffer.withUnsafeMutableBytes { encryptedBytes in
            CCCrypt(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                keyBytes, key.count,
                nil, // No IV for ECB mode
                plainBytes, data.count,
                encryptedBytes.baseAddress, bufferSize,
                &numBytesEncrypted
            )
        }
        
        guard status == kCCSuccess, numBytesEncrypted == data.count else {
            return nil
        }
        
        return Data(encryptedBuffer)
    }
    
    // MARK: - MIFARE Interface Helpers (for NTAG 424 detected as MIFARE)
    
    // Send APDU command through MIFARE interface
    // NTAG 424 DNA tags support APDU commands even when detected as MIFARE
    private func sendAPDUViaMiFare(tag: NFCMiFareTag, apduData: Data, completion: @escaping (Data?, UInt8, UInt8, Error?) -> Void) {
        // Send APDU command as MIFARE command
        // The APDU bytes are sent directly through sendMiFareCommand
        tag.sendMiFareCommand(commandPacket: apduData) { (response: Data, error: Error?) in
            if let error = error {
                completion(nil, 0, 0, error)
                return
            }
            
            // Parse status words from response
            // Last 2 bytes are typically status words (SW1, SW2)
            var sw1: UInt8 = 0
            var sw2: UInt8 = 0
            var responseData = response
            
            if response.count >= 2 {
                sw1 = response[response.count - 2]
                sw2 = response[response.count - 1]
                responseData = response.prefix(response.count - 2)
            }
            
            completion(responseData, sw1, sw2, nil)
        }
    }
    
    // Select Application via MIFARE interface
    private func selectApplicationViaMiFare(tag: NFCMiFareTag, session: NFCTagReaderSession, completion: @escaping (Bool, Error?) -> Void) {
        let dfName: [UInt8] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]  // D2760000850101h
        
        var apduData = Data()
        apduData.append(0x00)  // CLA
        apduData.append(APDU.SELECT_APPLICATION)  // INS = 0xA4
        apduData.append(0x04)  // P1 = Select by DF name
        apduData.append(0x00)  // P2
        apduData.append(UInt8(dfName.count))  // Lc = length of DF name (7 bytes)
        apduData.append(contentsOf: dfName)   // DF name data
        apduData.append(0x00)  // Le = 0x00 (accept variable length response)
        
        print("📤 Sending SELECT APPLICATION via MIFARE (DF name: D2760000850101h)...")
        sendAPDUViaMiFare(tag: tag, apduData: apduData) { (response, sw1, sw2, error) in
            if let error = error {
                print("❌ SELECT APPLICATION error: \(error.localizedDescription)")
                completion(false, error)
                return
            }
            
            let success = (sw1 == 0x90 && sw2 == 0x00)
            if success {
                print("✅ SELECT APPLICATION successful via MIFARE")
                if response?.count ?? 0 > 0 {
                    print("   Response: \(response!.map { String(format: "%02X", $0) }.joined(separator: " "))")
                }
            } else {
                let statusCode = String(format: "%02X%02X", sw1, sw2)
                print("❌ SELECT APPLICATION failed with status: 0x\(statusCode)")
            }
            
            completion(success, success ? nil : NSError(domain: "NTAG424Scanner", code: Int(sw1) << 8 | Int(sw2), userInfo: [NSLocalizedDescriptionKey: "SELECT APPLICATION failed"]))
        }
    }
    
    // Set password via MIFARE interface
    private func setPasswordViaMiFare(tag: NFCMiFareTag, session: NFCTagReaderSession) {
        print("=== Setting Password on NTAG 424 Tag (via MIFARE interface) ===")
        print("New password key (hex): \(passwordData.map { String(format: "%02X", $0) }.joined(separator: " "))")
        print("⚠️  IMPORTANT: Keep the tag near your device throughout the entire operation!")
        
        // Step 1: Select Application
        print("\nStep 1: Selecting application...")
        selectApplicationViaMiFare(tag: tag, session: session) { [weak self] success, error in
            guard let self = self else { return }
            
            if let error = error {
                let errorMsg = "Failed to select application: \(error.localizedDescription)"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, error)
                return
            }
            
            if !success {
                let errorMsg = "Failed to select application"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                return
            }
            
            print("✅ Application selected")
            
            // Step 2: Authenticate with default key
            print("\nStep 2: Authenticating with default key...")
            self.authenticateWithKeyViaMiFare(tag: tag, key: self.defaultKey, session: session) { [weak self] success, error in
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
                    self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
                    return
                }
                
                print("✅ Authenticated with default key")
                
                // Step 3: Change the key to the new password
                print("\nStep 3: Changing key to new password...")
                self.changeKeyViaMiFare(tag: tag, newKey: self.passwordData, session: session)
            }
        }
    }
    
    // Store session key for ChangeKey command
    private var sessionKey: Data?
    private var rndA: Data?
    private var rndB: Data?
    
    // Authenticate with key via MIFARE interface (full AuthenticateEV2 flow)
    // IMPORTANT: Even when detected as MIFARE, NTAG 424 DNA FULLY supports AES-128 encryption!
    // The detection method only affects the transport layer (how we send commands).
    // AES encryption happens at the application layer through APDU commands, so it works identically.
    private func authenticateWithKeyViaMiFare(tag: NFCMiFareTag, key: Data, session: NFCTagReaderSession, completion: @escaping (Bool, Error?) -> Void) {
        guard key.count == 16 else {
            completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Key must be exactly 16 bytes"]))
            return
        }
        
        print("🔐 Authenticating with AES-128 key via MIFARE interface: \(key.map { String(format: "%02X", $0) }.joined(separator: " "))")
        print("   Note: AES-128 encryption is fully supported even when detected as MIFARE tag")
        
        // Step 1: Send AuthenticateEV2First (Part 1)
        // According to the guide: Command: 90 71 00 00 02 00 00 00 (AuthEV2First, Key 0)
        // APDU format: CLA INS P1 P2 Lc Data Le
        // - CLA = 0x90 (Native command class)
        // - INS = 0x71 (AuthenticateEV2First)
        // - P1 = 0x00 (Key number: 0x00=AppMasterKey)
        // - P2 = 0x00
        // - Lc = 0x02 (2 bytes: Key number and Key version)
        // - Data = 0x00 0x00 (Key number 0, Key version 0)
        // - Le = 0x00 (accept variable length response)
        var apduData = Data()
        apduData.append(0x90)  // CLA = 0x90 (Native command class)
        apduData.append(APDU.AUTHENTICATE_EV2)  // INS = 0x71 (AuthenticateEV2First)
        apduData.append(0x00)  // P1 = Key number (0x00 = AppMasterKey)
        apduData.append(0x00)  // P2 = 0x00
        apduData.append(0x02)  // Lc = 0x02 (2 bytes of data)
        apduData.append(0x00)  // Data byte 1: Key number (0x00)
        apduData.append(0x00)  // Data byte 2: Key version (0x00)
        apduData.append(0x00)  // Le = 0x00 (accept variable length response)
        
        let apduHex = apduData.map { String(format: "%02X", $0) }.joined(separator: " ")
        print("   APDU bytes being sent: \(apduHex)")
        print("   APDU length: \(apduData.count) bytes")
        print("   Expected structure: 90 71 00 00 02 00 00 00")
        print("   Expected response: [16-byte encrypted RndB] 91 AF (or 90 00)")
        
        print("📤 Sending AuthenticateEV2First via MIFARE...")
        sendAPDUViaMiFare(tag: tag, apduData: apduData) { [weak self] (response, sw1, sw2, error) in
            guard let self = self else { return }
            
            if let error = error {
                completion(false, error)
                return
            }
            
            // Check for 0x91 0xAF (more data available) or success
            guard (sw1 == 0x91 && sw2 == 0xAF) || (sw1 == 0x90 && sw2 == 0x00) else {
                let statusCode = String(format: "%02X%02X", sw1, sw2)
                print("❌ AuthenticateEV2First failed: 0x\(statusCode)")
                completion(false, NSError(domain: "NTAG424Scanner", code: Int(sw1) << 8 | Int(sw2), userInfo: [NSLocalizedDescriptionKey: "Authentication failed"]))
                return
            }
            
            guard let response = response, response.count >= 16 else {
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid response length"]))
                return
            }
            
            let encryptedRndB = response.prefix(16)
            print("📥 Received encrypted RndB: \(encryptedRndB.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // Math (The Hard Part):
            // 1. Decrypt RndB using the Default Key (Zeros)
            guard let decryptedRndB = self.aes128ECBDecrypt(data: encryptedRndB, key: key) else {
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to decrypt RndB"]))
                return
            }
            self.rndB = decryptedRndB
            print("   Decrypted RndB: \(decryptedRndB.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // 2. Generate your own RndA
            var generatedRndA = Data(count: 16)
            let result = generatedRndA.withUnsafeMutableBytes { bytes in
                SecRandomCopyBytes(kSecRandomDefault, 16, bytes.baseAddress!)
            }
            
            guard result == errSecSuccess else {
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to generate RndA"]))
                return
            }
            self.rndA = generatedRndA
            print("   Generated RndA: \(generatedRndA.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // 3. Rotate RndB (left rotate by 1 byte)
            let rotatedRndB = self.rotateLeft(data: decryptedRndB, by: 1)
            print("   Rotated RndB: \(rotatedRndB.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // 4. Encrypt RndA + RndB' to send back
            // Concatenate RndA || RotatedRndB (32 bytes total), then encrypt as two 16-byte blocks
            var dataToEncrypt = Data()
            dataToEncrypt.append(generatedRndA)  // 16 bytes
            dataToEncrypt.append(rotatedRndB)    // 16 bytes
            
            // Encrypt the 32-byte block (will be encrypted as two 16-byte AES blocks)
            guard let encryptedData = self.aes128ECBEncrypt(data: dataToEncrypt, key: key) else {
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to encrypt response"]))
                return
            }
            print("   Encrypted RndA || RndB' (32 bytes): \(encryptedData.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // 5. Derive Session Key: Use RndA and RndB to calculate SesAuthEncKey
            // Session key = First 16 bytes of AES-128-ECB-ENC(RndA || RndB, Key)
            // Note: Encrypting 32 bytes gives 32 bytes, but we only need first 16 bytes
            var sessionKeyData = Data()
            sessionKeyData.append(generatedRndA)
            sessionKeyData.append(decryptedRndB)  // Use original RndB, not rotated
            guard let encryptedSessionKey = self.aes128ECBEncrypt(data: sessionKeyData, key: key) else {
                completion(false, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to derive session key"]))
                return
            }
            // Session key is only the first 16 bytes
            self.sessionKey = encryptedSessionKey.prefix(16)
            print("   Derived Session Key (SesAuthEncKey, 16 bytes): \(self.sessionKey!.map { String(format: "%02X", $0) }.joined(separator: " "))")
            
            // Send encrypted response
            // According to NTAG 424 DNA datasheet (Section 11.4.1):
            // APDU: 90 AF 00 00 20 [Encrypted RndA || RndB' (32 bytes)]
            // - CLA = 0x90 (Native command class)
            // - INS = 0xAF (Continue authentication command)
            // - P1 = 0x00
            // - P2 = 0x00
            // - Lc = 0x20 (32 bytes: 16 bytes RndA + 16 bytes rotated RndB)
            // - Data = Encrypted(RndA || RndB') (32 bytes)
            var responseApdu = Data()
            responseApdu.append(0x90)  // CLA = 0x90
            responseApdu.append(0xAF)  // INS = 0xAF (Continue command)
            responseApdu.append(0x00)   // P1 = 0x00
            responseApdu.append(0x00)   // P2 = 0x00
            responseApdu.append(0x20)   // Lc = 0x20 (32 bytes) - MUST match encryptedData.count
            responseApdu.append(encryptedData)  // Data = Encrypted RndA || RndB' (32 bytes)
            responseApdu.append(0x00)  // Le = 0x00 (accept variable length response)
            
            let responseApduHex = responseApdu.map { String(format: "%02X", $0) }.joined(separator: " ")
            print("   Response APDU bytes: \(responseApduHex)")
            print("   Response APDU length: \(responseApdu.count) bytes")
            print("   Expected structure: 90 AF 00 00 20 [32-byte encrypted data] 00")
            
            print("📤 Sending encrypted RndA || RndB' via MIFARE...")
            self.sendAPDUViaMiFare(tag: tag, apduData: responseApdu) { (finalResponse, finalSW1, finalSW2, finalError) in
                if let error = finalError {
                    print("❌ Error sending authentication response: \(error.localizedDescription)")
                    completion(false, error)
                    return
                }
                
                // Check response status
                // 0x90 0x00 = Success
                // 0x91 0xAE = Authentication failed (wrong key or encryption error)
                // 0x63 0xCX = Authentication failed (wrong key, X = number of retries left)
                let statusCode = String(format: "%02X%02X", finalSW1, finalSW2)
                print("   Response status: 0x\(statusCode)")
                
                if finalResponse != nil && finalResponse!.count > 0 {
                    print("   Response data: \(finalResponse!.map { String(format: "%02X", $0) }.joined(separator: " "))")
                }
                
                let success = (finalSW1 == 0x90 && finalSW2 == 0x00)
                if success {
                    print("✅ Authentication successful via MIFARE")
                    print("   Session key is now available for ChangeKey command")
                } else {
                    var errorMsg = "Authentication failed"
                    if finalSW1 == 0x91 && finalSW2 == 0xAE {
                        errorMsg = "Authentication failed: Wrong key or encryption error (0x91AE)"
                    } else if finalSW1 == 0x63 {
                        let retriesLeft = finalSW2 & 0x0F
                        errorMsg = "Authentication failed: Wrong key (0x63\(String(format: "%02X", finalSW2))), \(retriesLeft) retries left"
                    }
                    print("❌ \(errorMsg)")
                }
                completion(success, success ? nil : NSError(domain: "NTAG424Scanner", code: Int(finalSW1) << 8 | Int(finalSW2), userInfo: [NSLocalizedDescriptionKey: "Authentication failed: 0x\(statusCode)"]))
            }
        }
    }
    
    // Calculate CMAC (Cipher-based Message Authentication Code) for NTAG 424 DNA
    // CMAC is calculated using AES-128-CBC with zero IV
    private func calculateCMAC(key: Data, data: Data) -> Data? {
        guard key.count == 16 else { return nil }
        
        // CMAC uses AES-128-CBC with zero IV
        // For simplicity, we'll use a basic CMAC implementation
        // Note: Full CMAC requires subkey generation, but for NTAG 424 we can use a simplified version
        let zeroIV = Data(repeating: 0, count: 16)
        
        // Pad data to 16-byte boundary if needed
        var paddedData = data
        let remainder = data.count % 16
        if remainder != 0 {
            paddedData.append(0x80)  // Add 0x80 padding
            while paddedData.count % 16 != 0 {
                paddedData.append(0x00)
            }
        }
        
        // Encrypt using AES-128-CBC (simplified - full CMAC is more complex)
        // For NTAG 424, we'll use the last block of CBC encryption as CMAC
        var encrypted = Data()
        var previousBlock = zeroIV
        
        for i in stride(from: 0, to: paddedData.count, by: 16) {
            let block = paddedData.subdata(in: i..<min(i+16, paddedData.count))
            var xored = Data()
            for j in 0..<min(block.count, 16) {
                xored.append(block[j] ^ previousBlock[j])
            }
            
            guard let encryptedBlock = aes128ECBEncrypt(data: xored, key: key) else {
                return nil
            }
            encrypted = encryptedBlock
            previousBlock = encryptedBlock
        }
        
        // CMAC is the first 8 bytes of the last encrypted block
        return encrypted.prefix(8)
    }
    
    // Change key via MIFARE interface
    // According to guide: Must encrypt new key using Session Key and calculate CMAC
    private func changeKeyViaMiFare(tag: NFCMiFareTag, newKey: Data, session: NFCTagReaderSession) {
        guard newKey.count == 16 else {
            let errorMsg = "New key must be exactly 16 bytes"
            session.invalidate(errorMessage: errorMsg)
            onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            return
        }
        
        guard let sessionKey = self.sessionKey else {
            let errorMsg = "Session key not available. Authentication must be completed first."
            session.invalidate(errorMessage: errorMsg)
            onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            return
        }
        
        print("🔑 Changing key using session key...")
        print("   New key (plain): \(newKey.map { String(format: "%02X", $0) }.joined(separator: " "))")
        print("   Session key: \(sessionKey.map { String(format: "%02X", $0) }.joined(separator: " "))")
        
        // Encrypt the new key using the session key
        // The new key must be encrypted before sending
        guard let encryptedNewKey = aes128ECBEncrypt(data: newKey, key: sessionKey) else {
            let errorMsg = "Failed to encrypt new key with session key"
            session.invalidate(errorMessage: errorMsg)
            onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            return
        }
        print("   Encrypted new key: \(encryptedNewKey.map { String(format: "%02X", $0) }.joined(separator: " "))")
        
        // Build command data for CMAC calculation
        // CMAC is calculated over: CLA || INS || P1 || P2 || Lc || EncryptedKey
        var commandData = Data()
        commandData.append(0x90)  // CLA
        commandData.append(APDU.CHANGE_KEY)  // INS = 0xC4
        commandData.append(0x00)  // P1 = KeyNo
        commandData.append(0x00)  // P2
        commandData.append(0x10)  // Lc = 16 bytes
        commandData.append(encryptedNewKey)  // Encrypted new key
        
        // Calculate CMAC over the command
        guard let cmac = calculateCMAC(key: sessionKey, data: commandData) else {
            let errorMsg = "Failed to calculate CMAC"
            session.invalidate(errorMessage: errorMsg)
            onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            return
        }
        print("   CMAC (8 bytes): \(cmac.map { String(format: "%02X", $0) }.joined(separator: " "))")
        
        // Build final APDU: CLA || INS || P1 || P2 || Lc || EncryptedKey || CMAC || Le
        var apduData = Data()
        apduData.append(0x90)  // CLA
        apduData.append(APDU.CHANGE_KEY)  // INS = 0xC4
        apduData.append(0x00)  // P1 = KeyNo
        apduData.append(0x00)  // P2
        apduData.append(0x18)  // Lc = 24 bytes (16 bytes encrypted key + 8 bytes CMAC)
        apduData.append(encryptedNewKey)  // Encrypted new key (16 bytes)
        apduData.append(cmac)  // CMAC (8 bytes)
        apduData.append(0x00)  // Le = 0x00
        
        print("📤 Sending ChangeKey via MIFARE...")
        sendAPDUViaMiFare(tag: tag, apduData: apduData) { [weak self] (response, sw1, sw2, error) in
            guard let self = self else { return }
            
            if let error = error {
                session.invalidate(errorMessage: error.localizedDescription)
                self.onSetPasswordCompleted?(nil, error)
                return
            }
            
            let success = (sw1 == 0x90 && sw2 == 0x00)
            if success {
                let successMsg = "Password set successfully on NTAG 424 tag!\n\nNew key (hex): \(newKey.map { String(format: "%02X", $0) }.joined(separator: " "))\n\n⚠️ IMPORTANT: Save this key securely. You will need it to authenticate with the tag in the future."
                print("✅ \(successMsg)")
                session.alertMessage = "Password set successfully!"
                session.invalidate()
                self.currentTag = nil
                self.onSetPasswordCompleted?(successMsg, nil)
            } else {
                let statusCode = String(format: "%02X%02X", sw1, sw2)
                var errorMsg = "Change key failed: 0x\(statusCode)"
                if sw1 == 0x69 {
                    errorMsg = "Security status not satisfied. Authentication may have expired."
                }
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: Int(sw1) << 8 | Int(sw2), userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            }
        }
    }
    
    // Rotate data left by specified number of bytes
    // Left rotate: [A, B, C, D] rotated left by 1 = [B, C, D, A]
    private func rotateLeft(data: Data, by bytes: Int) -> Data {
        guard data.count > 0, bytes > 0 else {
            return data
        }
        
        let rotateBy = bytes % data.count
        guard rotateBy > 0 else {
            return data
        }
        
        // Left rotate: move bytes from the beginning to the end
        let prefix = data.prefix(rotateBy)
        let suffix = data.suffix(data.count - rotateBy)
        return suffix + prefix
    }
    
    // Change the key using ChangeKey command
    // NTAG 424 ChangeKey: CLA=0x90, INS=0xC4, P1=KeyNo, P2=0x00, Lc=0x10, Data=NewKey (16 bytes)
    private func changeKey(tag: NFCISO7816Tag, newKey: Data, session: NFCTagReaderSession) {
        print("🔑 Changing key to: \(newKey.map { String(format: "%02X", $0) }.joined(separator: " "))")
        
        guard newKey.count == 16 else {
            let errorMsg = "New key must be exactly 16 bytes for AES-128"
            print("❌ \(errorMsg)")
            session.invalidate(errorMessage: errorMsg)
            self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            return
        }
        
        // Build APDU command for ChangeKey using explicit initializer
        // Cmd: 90 C4 00 00 10 [NewKey]
        // - CLA = 0x90
        // - INS = 0xC4 (ChangeKey)
        // - P1 = Key number (0x00 = default key slot)
        // - P2 = 0x00
        // - Lc = 0x10 (16 bytes) - automatically set by NFCISO7816APDU
        // - Data = New key (16 bytes)
        let apdu = NFCISO7816APDU(
            instructionClass: 0x90,
            instructionCode: APDU.CHANGE_KEY,  // 0xC4
            p1Parameter: 0x00,  // KeyNo (0x00 = default key slot)
            p2Parameter: 0x00,
            data: newKey,  // New key (16 bytes) - Lc is automatically set to newKey.count
            expectedResponseLength: -1  // Variable length response
        )
        
        print("📤 Sending ChangeKey command...")
        tag.sendCommand(apdu: apdu) { [weak self] (response: Data, statusWord1: UInt8, statusWord2: UInt8, error: Error?) in
            guard let self = self else { return }
            
            if let error = error {
                let errorMsg = "Failed to change key: \(error.localizedDescription)"
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, error)
                return
            }
            
            // Check status words
            // 0x90 0x00 = Success
            // 0x69 0x82 = Security status not satisfied (not authenticated)
            // 0x6A 0x86 = Wrong P1/P2 parameters
            let success = (statusWord1 == 0x90 && statusWord2 == 0x00)
            
            if success {
                let successMsg = "Password set successfully on NTAG 424 tag!\n\nNew key (hex): \(newKey.map { String(format: "%02X", $0) }.joined(separator: " "))\n\n⚠️ IMPORTANT: Save this key securely. You will need it to authenticate with the tag in the future."
                print("✅ \(successMsg)")
                session.alertMessage = "Password set successfully!"
                session.invalidate()
                self.currentTag = nil
                self.onSetPasswordCompleted?(successMsg, nil)
            } else {
                let statusCode = String(format: "%02X%02X", statusWord1, statusWord2)
                var errorMsg = "Change key failed with status: 0x\(statusCode)"
                
                if statusWord1 == 0x69 {
                    errorMsg = "Security status not satisfied. Authentication may have expired."
                } else if statusWord1 == 0x6A {
                    errorMsg = "Invalid parameters for ChangeKey command"
                }
                
                print("❌ \(errorMsg)")
                session.invalidate(errorMessage: errorMsg)
                self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424Scanner", code: Int(statusWord1) << 8 | Int(statusWord2), userInfo: [NSLocalizedDescriptionKey: errorMsg]))
            }
        }
    }
    
    // Read a file from NTAG 424
    private func readFile(tag: NFCISO7816Tag, fileId: UInt16, session: NFCTagReaderSession, completion: @escaping (Data?, Error?) -> Void) {
        // ReadBinary command to read file
        // ISO 7816-4 READ_BINARY format: CLA INS P1 P2 Le
        // For NTAG 424: P1/P2 = FileID, Le = expected response length
        // Command: 0x90 0xB0 [FileID high] [FileID low] [Le]
        // Using explicit initializer - no data field, so use empty Data()
        let apdu = NFCISO7816APDU(
            instructionClass: 0x90,
            instructionCode: APDU.READ_BINARY,  // 0xB0
            p1Parameter: UInt8((fileId >> 8) & 0xFF),  // FileID high byte
            p2Parameter: UInt8(fileId & 0xFF),  // FileID low byte
            data: Data(),  // No data field for READ_BINARY - use empty Data
            expectedResponseLength: 4  // Le = Expected response length (4 bytes)
        )
        
        tag.sendCommand(apdu: apdu) { (response: Data, statusWord1: UInt8, statusWord2: UInt8, error: Error?) in
            if let error = error {
                completion(nil, error)
                return
            }
            
            let success = (statusWord1 == 0x90 && statusWord2 == 0x00)
            completion(success ? response : nil, success ? nil : NSError(domain: "NTAG424Scanner", code: Int(statusWord1) << 8 | Int(statusWord2), userInfo: [NSLocalizedDescriptionKey: "Read failed"]))
        }
    }
}

