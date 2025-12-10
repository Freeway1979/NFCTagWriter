//
//  ClipHelper.swift
//  NFCTagWriter
//
//  Created by 刘平安 on 12/10/25.
//

import Foundation
import CommonCrypto

//// Deterministic encryption (default) - same input = same output
//let encrypted1 = ClipHelper.encrypt(data: "Hello", key: "1234567890123456")
//let encrypted2 = ClipHelper.encrypt(data: "Hello", key: "1234567890123456")
//// encrypted1 == encrypted2 ✅
//
//// Non-deterministic encryption (AES-GCM) - different output each time
//let encrypted3 = ClipHelper.encrypt(data: "Hello", key: "1234567890123456", withAESGCM: true)
//let encrypted4 = ClipHelper.encrypt(data: "Hello", key: "1234567890123456", withAESGCM: true)
//// encrypted3 != encrypted4 ✅ (different salt/nonce each time)

struct ClipHelper {
    // FOR DEMO
    // WHEN PROD, THE KEY SHOULD BE SAVED IN keychain and one box one key.
    // Another WAY: Use AES_GCM encrypt/decrpt every time, so the chksum is changed every time for the same
    // gid and rule id. So Save the chksum in keychain and box every time.
    // Consider exception: the key or the chksum is lost, how to recover the user tag(Wirte again to update it with correct key or chksum).
    static let AES_KEY = "1234567890123456"

    static func encrypt(data: String, key: String = ClipHelper.AES_KEY,
                        withAESGCM: Bool = false) -> String {
        let dataData = Data(data.utf8)
        
        if withAESGCM {
            // Use AES-GCM encryption via CryptoKitHelper
            guard let encryptedData = CryptoKitHelper.encryptData(dataData, withPassphrase: key) else {
                return ""
            }
            // Return as hex string
            return encryptedData.map { String(format: "%02X", $0) }.joined()
        } else {
            // Use AES-128-ECB encryption (deterministic)
            let keyData = Data(key.utf8)
            
            // Ensure key is exactly 16 bytes (AES-128)
            var paddedKey = keyData
            if paddedKey.count < 16 {
                paddedKey.append(contentsOf: Array(repeating: UInt8(0), count: 16 - paddedKey.count))
            } else if paddedKey.count > 16 {
                paddedKey = paddedKey.prefix(16)
            }
            
            guard let encryptedData = dataData.aes128ECBEncrypt(key: paddedKey) else {
                return ""
            }
            // Return as hex string
            return encryptedData.map { String(format: "%02X", $0) }.joined()
        }
    }

    static func decrypt(data: String, key: String = ClipHelper.AES_KEY,
                        withAESGCM: Bool = false) -> String {
        // Convert hex string to Data (matching encrypt which returns hex string)
        var hexString = data
        if hexString.count % 2 != 0 {
            hexString = "0" + hexString
        }
        var dataData = Data()
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            if let byte = UInt8(hexString[index..<nextIndex], radix: 16) {
                dataData.append(byte)
            }
            index = nextIndex
        }
        
        if withAESGCM {
            // Use AES-GCM decryption via CryptoKitHelper
            guard let decryptedData = CryptoKitHelper.decryptData(dataData, withPassphrase: key),
                  let text = String(data: decryptedData, encoding: .utf8) else {
                return "" // Return empty string on failure (matching encrypt pattern)
            }
            return text
        } else {
            // Use AES-128-ECB decryption
            let keyData = Data(key.utf8)
            // Ensure key is exactly 16 bytes (AES-128)
            var paddedKey = keyData
            if paddedKey.count < 16 {
                paddedKey.append(contentsOf: Array(repeating: UInt8(0), count: 16 - paddedKey.count))
            } else if paddedKey.count > 16 {
                paddedKey = paddedKey.prefix(16)
            }
            
            guard let decryptedData = dataData.aes128ECBDecrypt(key: paddedKey),
                  let text = String(data: decryptedData, encoding: .utf8) else {
                return "" // Return empty string on failure (matching encrypt pattern)
            }
            return text
        }
    }

    static func genCheckSum(gid: String, rid: String, key: String = ClipHelper.AES_KEY) -> String {
        let checksum = encrypt(data: "\(gid)\(rid)", key: key)
        // When key is stored safely, we can just use md5 as checksum
        // let checksum = "\(gid)\(rid)\(key)".md5()
        print("genCheckSum \(gid) \(rid) \(checksum)")
        return String(checksum.prefix(10))
    }

    static func verifyCheckSum(checksum: String, gid: String, rid: String,
                               key: String = ClipHelper.AES_KEY ) -> Bool {
        let expectedChecksum = genCheckSum(gid: gid, rid: rid, key: key)
        print("verifyCheckSum expectedChecksum \(expectedChecksum) checksum:\(checksum)")
        return checksum == String(expectedChecksum.prefix(10))
    }
}

// MARK: - Data Extensions for AES-128-ECB (Deterministic Encryption)

extension Data {
    /// AES-128 ECB mode encryption (deterministic - same input always produces same output)
    /// Supports any length (padded to 16-byte blocks)
    func aes128ECBEncrypt(key: Data) -> Data? {
        guard key.count == 16 else {
            return nil
        }
        
        // Pad data to 16-byte boundary if needed
        var paddedData = self
        let remainder = self.count % 16
        if remainder != 0 {
            paddedData.append(0x80)  // Add 0x80 padding
            while paddedData.count % 16 != 0 {
                paddedData.append(0x00)
            }
        }
        
        // Encrypt each 16-byte block
        var encrypted = Data()
        for i in stride(from: 0, to: paddedData.count, by: 16) {
            let endIndex = Swift.min(i + 16, paddedData.count)
            let block = paddedData.subdata(in: i..<endIndex)
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
        
        return encrypted
    }
    
    /// AES-128 ECB mode decryption
    /// Decrypts data that was encrypted in 16-byte blocks
    func aes128ECBDecrypt(key: Data) -> Data? {
        guard self.count % 16 == 0, key.count == 16 else {
            return nil
        }
        
        // Decrypt each 16-byte block
        var decrypted = Data()
        for i in stride(from: 0, to: self.count, by: 16) {
            let endIndex = Swift.min(i + 16, self.count)
            let block = self.subdata(in: i..<endIndex)
            if block.count == 16 {
                // Decrypt single 16-byte block
                var decryptedBlock = [UInt8](repeating: 0, count: 16)
                var numBytesDecrypted: size_t = 0
                
                let keyBytes = key.withUnsafeBytes { $0.baseAddress! }
                let blockBytes = block.withUnsafeBytes { $0.baseAddress! }
                
                let status = decryptedBlock.withUnsafeMutableBytes { decryptedBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyBytes, key.count,
                        nil, // No IV for ECB mode
                        blockBytes, 16,
                        decryptedBytes.baseAddress, 16,
                        &numBytesDecrypted
                    )
                }
                
                guard status == kCCSuccess, numBytesDecrypted == 16 else {
                    return nil
                }
                
                decrypted.append(contentsOf: decryptedBlock)
            }
        }
        
        // Remove padding (0x80 followed by zeros)
        while decrypted.count > 0 && decrypted.last == 0x00 {
            decrypted = decrypted.dropLast()
        }
        if decrypted.count > 0 && decrypted.last == 0x80 {
            decrypted = decrypted.dropLast()
        }
        
        return decrypted
    }
}

