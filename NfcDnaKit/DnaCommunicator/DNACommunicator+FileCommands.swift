//
//  File.swift
//
//
//  Created by Jonathan Bartlett on 7/19/21.
//

import Foundation

public extension DnaCommunicator {
    func writeFileData(fileNum: UInt8, data: [UInt8], mode: CommuncationMode? = nil, offset: Int = 0, completion: @escaping (Error?) -> Void) {
        // Pg. 75
        
        // Auto-detect mode if not specified
        if mode == nil {
            getFileSettings(fileNum: fileNum) { settings, err in
                if let settings = settings {
                    print("[\(fileNum)] file settings: mode:\(settings.communicationMode) read: \(settings.readPermission) read/write:\(settings.readWritePermission) write:\(settings.writePermission) change:\(settings.changePermission) sdmEnabled:\(settings.sdmEnabled)" )
                }
                if err != nil {
                    completion(err)
                } else {
                    self.writeFileData(fileNum: fileNum, data: data, mode: settings?.communicationMode, offset: offset) { err in
                        completion(err)
                    }
                }
            }
            return
        }
        
        let dataSizeBytes = Helper.byteArrayLE(from: Int32(data.count))[0...2]
        let offsetBytes = Helper.byteArrayLE(from: Int32(offset))[0...2]
        
        nxpSwitchedCommand(mode: mode!, command: 0x8d, header: [fileNum] + offsetBytes + dataSizeBytes, data: data) { result, err in
            completion(self.makeErrorIfNotExpectedStatus(result, error: err))
        }
    }
    
    func readFileData(fileNum: UInt8, length: Int, mode: CommuncationMode? = nil, offset: Int = 0, completion: @escaping ([UInt8], Error?) -> Void) {
        // Pg. 73
        // Auto-detect mode if not specified
        if mode == nil {
            getFileSettings(fileNum: fileNum) { settings, err in
                if let settings = settings {
                    print("[\(fileNum)] file settings: mode:\(settings.communicationMode) read: \(settings.readPermission) read/write:\(settings.readWritePermission) write:\(settings.writePermission) change:\(settings.changePermission) sdmEnabled:\(settings.sdmEnabled)" )
                }
                if err != nil {
                    completion([], err)
                } else {
                    self.readFileData(fileNum: fileNum, length: length, mode: settings?.communicationMode, offset: offset) { data, err in
                        completion(data, err)
                    }
                }
            }
            return
        }
        
        let offsetBytes = Helper.byteArrayLE(from: Int32(offset))[0...2]
        let lengthBytes = Helper.byteArrayLE(from: Int32(length))[0...2]  // Fix: Use only 3 bytes for length (little endian)
        
        nxpSwitchedCommand(mode: mode!, command: 0xad, header: [fileNum] + offsetBytes + lengthBytes, data: []) { result, err in
            completion(result.data, self.makeErrorIfNotExpectedStatus(result, error: err))
        }
    }
    
    func getFileSettings(fileNum: UInt8, completion: @escaping (FileSettings?, Error?) -> Void) {
        // Pg. 69
        
        nxpMacCommand(command: 0xf5, header: [fileNum], data: []) { result, err in
            
            let settings = FileSettings(fromResultData:result)
            
            print("[\(fileNum)] file settings: mode:\(settings.communicationMode) read: \(settings.readPermission) read/write:\(settings.readWritePermission) write:\(settings.writePermission) change:\(settings.changePermission) sdmEnabled:\(settings.sdmEnabled)" )
            
            completion(settings, self.makeErrorIfNotExpectedStatus(result, error: err))
        }
    }
    
    /// Changes the file settings for a specific file number.
    /// - Parameters:
    ///   - fileNo: The file ID (e.g., 0x01 for CC File)
    ///   - fileOption: Communication mode (0x00 for Plain, 0x40 for SDM/Mirroring)
    ///   - accessRights: 2 Bytes defining Read/Write/RW/Change permissions
    ///   - completion: Result handler
    func changeFileSettings(fileNo: UInt8, fileOption: UInt8, accessRights: Data, completion: @escaping (Result<Void, Error>) -> Void) {
        
        // Command Hex: 0x5F (ChangeFileSettings)
        let cmd: UInt8 = 0x5F
        
        // Construct Payload: [FileNo] + [FileOption] + [AccessRights (2 bytes)]
        var commandData: [UInt8] = []
        commandData.append(fileOption)
        for byte in accessRights.byteArray {
            commandData.append(byte)
        }
        // We use 'nxpMacCommand' because you are in an Authenticated EV2 session.
        // This automatically calculates the CMAC signature required by Key 0.
        self.nxpEncryptedCommand(command: cmd, header: [fileNo], data: commandData) { responseData, error in
            if let error = error {
                completion(.failure(error))
            } else {
                completion(.success(()))
            }
        }
    }
}
