//
//  NTAG424View.swift
//  NFCTagWriter
//
//  Created for NTAG 424 tag support
//
import SwiftUI

struct NTAG424View: View {
    // Use NTAG424Scanner instead of NTAG424DNAScanner because:
    // - NTAG424DNAScanner requires ISO 7816 tags (NfcDnaKit limitation)
    // - NTAG424Scanner supports both ISO 7816 and MIFARE detection
    // - NTAG 424 DNA tags may be detected as either type by CoreNFC
    @State private var scanner = NTAG424DNAScanner()
    @State private var nfcMessage: String = ""
    @State private var nfcError: String = ""
    @State private var tagUID: String = ""  // Store the last detected tag UID
    
    @State private var password: String = "915565AB915565AB"  // 16 characters for 16-byte key
    @State private var textToWrite: String = "https://firewalla.com/nfc?gid=915565a3-65c7-4a2b-8629-194d80ed824b&rule=249"
    @State private var textRead: String = ""
    @FocusState private var isPasswordFocused: Bool
    @FocusState private var isTextFieldFocused: Bool
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    Image(systemName: "lock.shield.fill")
                        .imageScale(.large)
                        .foregroundStyle(.tint)
                        .font(.system(size: 50))
                    
                    Text("NTAG 424 DNA")
                        .font(.title2)
                        .fontWeight(.bold)
                    
                    Text("Advanced NFC Tag with AES-128 Encryption")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    
                    // Tag UID Display
                    if !tagUID.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Tag UID:")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(tagUID)
                                .font(.system(.body, design: .monospaced))
                                .padding(8)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.blue.opacity(0.1))
                                .cornerRadius(8)
                        }
                        .padding(.horizontal)
                    }
                    
                    Divider()
                    
                    // Password Input Section
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Password (Key):")
                            .font(.headline)
                        Text("Enter 16 characters (will be converted to 16-byte AES-128 key)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        TextField("Enter 16-character password", text: $password)
                            .textFieldStyle(.roundedBorder)
                            .focused($isPasswordFocused)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.asciiCapable)
                            .submitLabel(.done)
                            .onChange(of: password) { oldValue, newValue in
                                // Limit to 16 characters
                                if newValue.count > 16 {
                                    password = String(newValue.prefix(16))
                                }
                            }
                    }
                    .padding(.horizontal)
                    
                    // Set Password Button
                    Button(action: {
                        setPassword()
                    }) {
                        HStack {
                            Image(systemName: "lock.fill")
                            Text("Set Password")
                        }
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(Color.orange)
                        .cornerRadius(10)
                    }
                    .padding(.horizontal)
                    
                    // Configure CC File Button (for iOS Background Detection)
                    Button(action: {
                        configureCCFile()
                    }) {
                        HStack {
                            Image(systemName: "iphone.radiowaves.left.and.right")
                            Text("Configure CC File (iOS Background)")
                        }
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(Color.blue)
                        .cornerRadius(10)
                    }
                    .padding(.horizontal)
                    
                    // Configure File Access Button
                    Button(action: {
                        configureFileAccess()
                    }) {
                        HStack {
                            Image(systemName: "shield.checkered")
                            Text("Configure File Access")
                        }
                        .font(.headline)
                        .foregroundColor(.white)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(Color.purple)
                        .cornerRadius(10)
                    }
                    .padding(.horizontal)
                    
                    Divider()
                    
                    // Read/Write Section
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Data to Write:")
                            .font(.headline)
                        TextField("Enter text to write to NTAG 424 tag", text: $textToWrite)
                            .textFieldStyle(.roundedBorder)
                            .focused($isTextFieldFocused)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.default)
                            .submitLabel(.done)
                    }
                    .padding(.horizontal)
                    
                    HStack(spacing: 15) {
                        // Read Button
                        Button(action: {
                            readData()
                        }) {
                            HStack {
                                Image(systemName: "arrow.down.circle.fill")
                                Text("Read")
                            }
                            .font(.headline)
                            .foregroundColor(.white)
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(Color.blue)
                            .cornerRadius(10)
                        }
                        
                        // Write Button
                        Button(action: {
                            writeData()
                        }) {
                            HStack {
                                Image(systemName: "arrow.up.circle.fill")
                                Text("Write")
                            }
                            .font(.headline)
                            .foregroundColor(.white)
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(Color.green)
                            .cornerRadius(10)
                        }
                    }
                    .padding(.horizontal)
                    
                    // Read Result Display
                    if !textRead.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Read Result:")
                                .font(.headline)
                            Text(textRead)
                                .font(.body)
                                .padding()
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.gray.opacity(0.1))
                                .cornerRadius(8)
                        }
                        .padding(.horizontal)
                    }
                    
                    // Display messages
                    if !nfcMessage.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Message:")
                                .font(.headline)
                            Text(nfcMessage)
                                .font(.body)
                                .padding()
                                .background(Color.gray.opacity(0.1))
                                .cornerRadius(8)
                        }
                        .padding(.horizontal)
                    }
                    
                    if !nfcError.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Error:")
                                .font(.headline)
                                .foregroundColor(.red)
                            Text(nfcError)
                                .font(.body)
                                .foregroundColor(.red)
                                .padding()
                                .background(Color.red.opacity(0.1))
                                .cornerRadius(8)
                        }
                        .padding(.horizontal)
                    }
                }
                .padding()
            }
            .navigationTitle("NTAG 424")
            .navigationBarTitleDisplayMode(.inline)
            .scrollDismissesKeyboard(.interactively)
        }
    }
    
    // MARK: - Actions
    
    private func setupScannerCallbacks() {
        // Set up UID detection callback
        scanner.onUIDDetected = { uid in
            DispatchQueue.main.async {
                self.tagUID = uid
            }
        }
    }
    
    private func setPassword() {
        nfcMessage = ""
        nfcError = ""
        
        setupScannerCallbacks()
        
        guard password.count == 16 else {
            nfcError = "Password must be exactly 16 characters"
            return
        }
        
        scanner.onSetPasswordCompleted = { message, error in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Set Password Error: \(error.localizedDescription)"
                    nfcMessage = ""
                } else if let message = message {
                    nfcMessage = message
                    nfcError = ""
                } else {
                    nfcMessage = "Password set successfully!"
                    nfcError = ""
                }
            }
        }
        
        scanner.beginSettingPassword(password: password)
    }
    
    private func readData() {
        nfcMessage = ""
        nfcError = ""
        textRead = ""
        
//        let dataToEncrypt = "Hello.World"
//        print("ClipHelper.encrypt(data: dataToEncrypt) \(ClipHelper.encrypt(data: dataToEncrypt))")
//        print("ClipHelper.encrypt(data: dataToEncrypt) \(ClipHelper.encrypt(data: dataToEncrypt))")
//       
//        let encrypted = ClipHelper.encrypt(data: dataToEncrypt)
//        let decrypted = ClipHelper.decrypt(data: encrypted)
//        print("original \(dataToEncrypt), encrypted:\(encrypted) decrypted:\(decrypted)")
        setupScannerCallbacks()
        
        scanner.onReadDataCompleted = { text, error in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Read Error: \(error.localizedDescription)"
                    nfcMessage = ""
                    textRead = ""
                } else if let text = text {
                    textRead = text
                    // 3. Parse the components
                    guard let url = URL(string: textRead) else {
                        nfcError = "Failed to get gid and rid"
                        return
                    }
                    guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else { return }
                    // 4. Extract Query Parameters
                    if let gidItem = components.queryItems?.first(where: { $0.name == "gid" }),
                       let gid = gidItem.value,
                       let ruleItem = components.queryItems?.first(where: { $0.name == "rule" }),
                       let rid = ruleItem.value,
                       let checkSumItem = components.queryItems?.first(where: { $0.name == "chksum" }),
                           let chksumPrefix = checkSumItem.value {
                        // Read full checksum from UserDefaults using the prefix as key
                        if let fullChecksum = ClipHelper.readChecksum(checksumPrefix: chksumPrefix) {
                            let validated = ClipHelper.verifyCheckSum(checksum: fullChecksum, gid: gid, rid: rid,
                                                                      withAESGCM: false)
                            if validated {
                                nfcMessage = "Data read success and chksum validated"
                            } else {
                                nfcMessage = "Data read success and chksum NOT validated"
                            }
                        } else {
                            nfcMessage = "Data read success but chksum not found in storage"
                        }
                        print(nfcMessage)
                        nfcError = ""
                        return
                    }
                    nfcMessage = "Data read successfully!"
                    nfcError = ""
                } else {
                    nfcError = "No data read from tag"
                    nfcMessage = ""
                    textRead = ""
                }
            }
        }
        
        scanner.beginReadingData(password: password)
    }
    
    private func writeData() {
        nfcMessage = ""
        nfcError = ""
        
        setupScannerCallbacks()
        
        guard !textToWrite.isEmpty else {
            nfcError = "Please enter text to write"
            return
        }
        // get gid and rid from the textToWrite
        // use queryParams to get gid and rid
        
        // 3. Parse the components
        guard let url = URL(string: textToWrite) else {
            nfcError = "Invalid URL"
            return
        }
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            nfcError = "Invalid URL"
            return
        }
        // 4. Extract Query Parameters
        if let gidItem = components.queryItems?.first(where: { $0.name == "gid" }),
           let gid = gidItem.value,
           let ruleItem = components.queryItems?.first(where: { $0.name == "rule" }),
           let rid = ruleItem.value {
            let checksum = ClipHelper.genCheckSum(gid: gid, rid: rid, withAESGCM: false)
            if checksum.isEmpty {
                nfcError = "Failed to generate checksum"
                return
            }
            
            // Save checksum to UserDefaults using first 10 characters as key
            ClipHelper.saveChecksum(checksum: checksum)
            
            // Remove any existing chksum parameter
            components.queryItems = components.queryItems?.filter { $0.name != "chksum" }
            
            // Add the new chksum parameter (use only first 10 characters as the stored value)
            let checksumPrefix = String(checksum.prefix(10))
            let chksumItem = URLQueryItem(name: "chksum", value: checksumPrefix)
            if components.queryItems == nil {
                components.queryItems = []
            }
            components.queryItems?.append(chksumItem)
            
            // Reconstruct the URL string
            if let updatedURL = components.url {
                textToWrite = updatedURL.absoluteString
            }
        }
        print("textToWrite with checksum:\(textToWrite)")
        scanner.onWriteDataCompleted = { success, error in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Write Error: \(error.localizedDescription)"
                    nfcMessage = ""
                } else if success {
                    nfcMessage = "Data written successfully!"
                    nfcError = ""
                } else {
                    nfcError = "Write failed"
                    nfcMessage = ""
                }
            }
        }
        
        scanner.beginWritingData(data: textToWrite, password: password)
    }
    
    private func configureCCFile() {
        nfcMessage = ""
        nfcError = ""
        
        setupScannerCallbacks()
        
        guard !password.isEmpty else {
            nfcError = "Password is required to configure CC file"
            return
        }
        
        scanner.onConfigureCCFileCompleted = { message, error in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Configure CC File Error: \(error.localizedDescription)"
                    nfcMessage = ""
                } else if let message = message {
                    nfcMessage = message
                    nfcError = ""
                } else {
                    nfcMessage = "CC file configured successfully!"
                    nfcError = ""
                }
            }
        }
        
        scanner.beginConfiguringCCFile(password: password)
    }
    
    private func configureFileAccess() {
        nfcMessage = ""
        nfcError = ""
        
        setupScannerCallbacks()
        
        guard !password.isEmpty else {
            nfcError = "Password is required to configure file access"
            return
        }
        
        scanner.onConfigureFileAccessCompleted = { message, error in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Configure File Access Error: \(error.localizedDescription)"
                    nfcMessage = ""
                } else if let message = message {
                    nfcMessage = message
                    nfcError = ""
                } else {
                    nfcMessage = "File access configured successfully!"
                    nfcError = ""
                }
            }
        }
        
        scanner.beginConfiguringFileAccess(password: password)
    }
}

#Preview {
    NTAG424View()
}

