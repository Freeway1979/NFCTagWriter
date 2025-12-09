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
    
    @State private var password: String = "915565AB915565AB"  // 16 characters for 16-byte key
    @State private var textToWrite: String = "https://mesh.firewalla.net/nfc?gid=915565a3-65c7-4a2b-8629-194d80ed824b&rule=249&chksum=34fd"
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
    
    private func setPassword() {
        nfcMessage = ""
        nfcError = ""
        
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
        
        // TODO: Implement read data functionality in NTAG424Scanner
        nfcError = "Read data functionality not yet implemented."
    }
    
    private func writeData() {
        nfcMessage = ""
        nfcError = ""
        
        // TODO: Implement write data functionality in NTAG424Scanner
        nfcError = "Write data functionality not yet implemented."
    }
}

#Preview {
    NTAG424View()
}

