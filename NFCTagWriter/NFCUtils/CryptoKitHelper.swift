//
// CryptoKitHelper.swift
// Created on 2025-11-14
// Copyright (c) 2025 Rottiesoft LLC. All rights reserved.
//

import Foundation
import CryptoKit
import CommonCrypto

@objc public class CryptoKitHelper: NSObject {
    
    /// Encrypts data using AES-GCM with a passphrase
    /// - Parameters:
    ///   - data: The data to encrypt
    ///   - passphrase: The passphrase to derive the encryption key from
    /// - Returns: Encrypted data containing salt + nonce + ciphertext + tag, or nil if encryption fails
    @objc public static func encryptData(_ data: Data, withPassphrase passphrase: String) -> Data? {
        do {
            // Generate random salt (32 bytes for stronger security)
            let salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            
            // Derive key from passphrase using PBKDF2
            let key = try deriveKey(from: passphrase, salt: salt)
            
            // Generate random nonce (12 bytes is standard for GCM)
            let nonce = AES.GCM.Nonce()
            
            // Encrypt the data
            let sealedBox = try AES.GCM.seal(data, using: key, nonce: nonce)
            
            // Combine salt + nonce + ciphertext + tag
            var encryptedData = Data()
            encryptedData.append(salt)
            encryptedData.append(sealedBox.nonce.withUnsafeBytes { Data($0) })
            encryptedData.append(sealedBox.ciphertext)
            encryptedData.append(sealedBox.tag)
            
            return encryptedData
            
        } catch {
            print("Encryption failed: \(error)")
            return nil
        }
    }
    
    /// Decrypts data using AES-GCM with a passphrase
    /// - Parameters:
    ///   - encryptedData: The encrypted data containing salt + nonce + ciphertext + tag
    ///   - passphrase: The passphrase to derive the decryption key from
    /// - Returns: Decrypted data, or nil if decryption fails
    @objc public static func decryptData(_ encryptedData: Data, withPassphrase passphrase: String) -> Data? {
        do {
            let saltSize = 32
            let nonceSize = 12
            let tagSize = 16
            let minDataSize = saltSize + nonceSize + tagSize
            
            guard encryptedData.count >= minDataSize else {
                print("Invalid encrypted data size")
                return nil
            }
            
            // Extract components
            let salt = encryptedData.prefix(saltSize)
            let nonceData = encryptedData.dropFirst(saltSize).prefix(nonceSize)
            let ciphertextAndTag = encryptedData.dropFirst(saltSize + nonceSize)
            let ciphertext = ciphertextAndTag.dropLast(tagSize)
            let tag = ciphertextAndTag.suffix(tagSize)
            
            // Derive key from passphrase using the extracted salt
            let key = try deriveKey(from: passphrase, salt: salt)
            
            // Create nonce from extracted data
            let nonce = try AES.GCM.Nonce(data: nonceData)
            
            // Create sealed box for decryption
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            
            // Decrypt the data
            let decryptedData = try AES.GCM.open(sealedBox, using: key)
            
            return decryptedData
            
        } catch {
            print("Decryption failed: \(error)")
            return nil
        }
    }
    
    /// Derives a symmetric key from a passphrase using PBKDF2 (iOS 13+ compatible)
    /// - Parameters:
    ///   - passphrase: The passphrase to derive the key from
    ///   - salt: The salt to use for key derivation
    /// - Returns: A 256-bit symmetric key
    /// - Throws: CryptoKitError if key derivation fails
    private static func deriveKey(from passphrase: String, salt: Data) throws -> SymmetricKey {
        let passphraseData = Data(passphrase.utf8)
        
        // Use PBKDF2 for iOS 13 compatibility (HKDF requires iOS 14+)
        let iterations: Int = 100000 // Higher iteration count for security
        let keyLength = 32 // 256 bits
        
        var derivedKeyData = Data(count: keyLength)
        let result = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            passphraseData.withUnsafeBytes { passphraseBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passphraseBytes.bindMemory(to: CChar.self).baseAddress,
                        passphraseData.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        keyLength
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            throw NSError(domain: "CryptoKitHelperErrorDomain", 
                         code: -1, 
                         userInfo: [NSLocalizedDescriptionKey: "Key derivation failed"])
        }
        
        return SymmetricKey(data: derivedKeyData)
    }
}

// MARK: - Error handling with NSError for Objective-C compatibility

extension CryptoKitHelper {
    
    /// Encrypts data using AES-GCM with a passphrase (with NSError for Objective-C)
    /// - Parameters:
    ///   - data: The data to encrypt
    ///   - passphrase: The passphrase to derive the encryption key from
    ///   - error: Error pointer for Objective-C compatibility
    /// - Returns: Encrypted data containing salt + nonce + ciphertext + tag, or nil if encryption fails
    @objc public static func encryptData(_ data: Data, withPassphrase passphrase: String, error: NSErrorPointer) -> Data? {
        do {
            // Generate random salt (32 bytes for stronger security)
            let salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            
            // Derive key from passphrase using PBKDF2
            let key = try deriveKey(from: passphrase, salt: salt)
            
            // Generate random nonce (12 bytes is standard for GCM)
            let nonce = AES.GCM.Nonce()
            
            // Encrypt the data
            let sealedBox = try AES.GCM.seal(data, using: key, nonce: nonce)
            
            // Combine salt + nonce + ciphertext + tag
            var encryptedData = Data()
            encryptedData.append(salt)
            encryptedData.append(sealedBox.nonce.withUnsafeBytes { Data($0) })
            encryptedData.append(sealedBox.ciphertext)
            encryptedData.append(sealedBox.tag)
            
            return encryptedData
            
        } catch let encryptionError {
            if let error = error {
                error.pointee = NSError(
                    domain: "CryptoKitHelperErrorDomain",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "Encryption failed: \(encryptionError.localizedDescription)"]
                )
            }
            return nil
        }
    }
    
    /// Decrypts data using AES-GCM with a passphrase (with NSError for Objective-C)
    /// - Parameters:
    ///   - encryptedData: The encrypted data containing salt + nonce + ciphertext + tag
    ///   - passphrase: The passphrase to derive the decryption key from
    ///   - error: Error pointer for Objective-C compatibility
    /// - Returns: Decrypted data, or nil if decryption fails
    @objc public static func decryptData(_ encryptedData: Data, withPassphrase passphrase: String, error: NSErrorPointer) -> Data? {
        do {
            let saltSize = 32
            let nonceSize = 12
            let tagSize = 16
            let minDataSize = saltSize + nonceSize + tagSize
            
            guard encryptedData.count >= minDataSize else {
                if let error = error {
                    error.pointee = NSError(
                        domain: "CryptoKitHelperErrorDomain",
                        code: -2,
                        userInfo: [NSLocalizedDescriptionKey: "Invalid encrypted data size"]
                    )
                }
                return nil
            }
            
            // Extract components
            let salt = encryptedData.prefix(saltSize)
            let nonceData = encryptedData.dropFirst(saltSize).prefix(nonceSize)
            let ciphertextAndTag = encryptedData.dropFirst(saltSize + nonceSize)
            let ciphertext = ciphertextAndTag.dropLast(tagSize)
            let tag = ciphertextAndTag.suffix(tagSize)
            
            // Derive key from passphrase using the extracted salt
            let key = try deriveKey(from: passphrase, salt: salt)
            
            // Create nonce from extracted data
            let nonce = try AES.GCM.Nonce(data: nonceData)
            
            // Create sealed box for decryption
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            
            // Decrypt the data
            let decryptedData = try AES.GCM.open(sealedBox, using: key)
            
            return decryptedData
            
        } catch let decryptionError {
            if let error = error {
                error.pointee = NSError(
                    domain: "CryptoKitHelperErrorDomain",
                    code: -3,
                    userInfo: [NSLocalizedDescriptionKey: "Decryption failed: \(decryptionError.localizedDescription)"]
                )
            }
            return nil
        }
    }
}