//
//  NTAG424DNAScanner.swift
//  NFCTagWriter
//
//  Created for NTAG 424 DNA tag support using NfcDnaKit
//
import CoreNFC
import Foundation

// NTAG 424 DNA Scanner using NfcDnaKit third-party library
// This is a refactored version using NfcDnaKit instead of manual APDU commands
class NTAG424DNAScanner: NSObject, NFCTagReaderSessionDelegate {
    
    var session: NFCTagReaderSession?
    
    // Store strong reference to tag and communicator
    private var currentTag: NFCISO7816Tag?
    private var communicator: DnaCommunicator?
    
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
    
    // Begin setting password on NTAG 424 tag
    func beginSettingPassword(password: String) {
        self.password = password
        currentAction = .setPassword
        
        // Use ISO14443 polling which supports ISO 7816 tags
        session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        session?.alertMessage = "Hold your iPhone near the NTAG 424 tag to set password."
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
                    self.onSetPasswordCompleted?(nil, error)
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
                        self.onSetPasswordCompleted?(nil, beginError)
                        return
                    }
                    
                    print("✅ Communicator initialized")
                    
                    // Route to appropriate handler based on action
                    switch self.currentAction {
                    case .setPassword:
                        self.setPassword(communicator: comm, session: session)
                    case .authenticate:
                        // Authentication is handled as part of other operations
                        break
                    }
                }
            }
        } else if case let .miFare(miFareTag) = firstTag {
            // Detected as MIFARE - NfcDnaKit cannot be used
            // Inform user that they should use NTAG424Scanner instead, or we could fall back
            let errorMsg = "NTAG 424 DNA detected as MIFARE tag.\n\nNfcDnaKit requires ISO 7816 tags.\n\nPlease use NTAG424Scanner instead, which supports both ISO 7816 and MIFARE detection.\n\nNote: NTAG 424 DNA tags support AES-128 encryption even when detected as MIFARE."
            print("❌ \(errorMsg)")
            print("   Detected tag type: MIFARE")
            print("   Solution: Use NTAG424Scanner which handles MIFARE tags via sendMiFareCommand()")
            session.invalidate(errorMessage: "Tag detected as MIFARE. Use NTAG424Scanner instead.")
            
            // Call completion with error
            DispatchQueue.main.async {
                self.onSetPasswordCompleted?(nil, NSError(domain: "NTAG424DNAScanner", code: -1, userInfo: [NSLocalizedDescriptionKey: errorMsg]))
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
    
}

