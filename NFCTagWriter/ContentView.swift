//
//  ContentView.swift
//  NFCTagWriter
//
//  Created by 刘平安 on 11/26/25.
//
import Foundation
import SwiftUI
import CoreNFC


struct ContentView: View {
    @State private var scanner = NFCScanner()
    @State private var nfcMessage: String = ""
    @State private var nfcError: String = ""
    
    @State private var textPassword: String = "5678"
    @State private var textRead: String = ""
    @State private var textToWrite: String = "https://firewalla.com/194d80ed824b/rule/362"
    @State private var tagInfo: NFCTagInfo? = nil
    @State private var alertMessage: String = ""
    @State private var showAlert: Bool = false
    @State private var writeOnlyProtection: Bool = true  // Default: Write Protected Only (Read full access)
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Image(systemName: "sensor.tag.radiowaves.forward")
                    .imageScale(.large)
                    .foregroundStyle(.tint)
                    .font(.system(size: 50))
                
                Text("NFC Tag Reader/Writer")
                    .font(.title2)
                    .fontWeight(.bold)
            
            // Display read result above Read Button
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
            
            // Read Button
            Button(action: {
                readNFC()
            }) {
                HStack {
                    Image(systemName: "arrow.down.circle.fill")
                    Text("Read NFC Tag")
                }
                .font(.headline)
                .foregroundColor(.white)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.blue)
                .cornerRadius(10)
            }
            .padding(.horizontal)
            
            // TextField for input text to write
            VStack(alignment: .leading, spacing: 8) {
                Text("Text to Write:")
                    .font(.headline)
                TextField("Enter text to write to NFC tag", text: $textToWrite)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .autocapitalization(.none)
                    .submitLabel(.done)
                    .keyboardType(.default)
            }
            .padding(.horizontal)
            
            // Write Button
            Button(action: {
                writeNFC()
            }) {
                HStack {
                    Image(systemName: "arrow.up.circle.fill")
                    Text("Write NFC Tag")
                }
                .font(.headline)
                .foregroundColor(.white)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.green)
                .cornerRadius(10)
            }
            .padding(.horizontal)
            
            // Protection Mode Toggle
            VStack(alignment: .leading, spacing: 8) {
                Text("Password Protection Mode:")
                    .font(.headline)
                Picker("Protection Mode", selection: $writeOnlyProtection) {
                    Text("Write Protected").tag(true)
                    Text("Read & Write Protected").tag(false)
                }
                .pickerStyle(.segmented)
            }
            .padding(.horizontal)
            
            // Set Password Button
            Button(action: {
                setPassword()
            }) {
                HStack {
                    Image(systemName: "lock.fill")
                    Text("Set Password (\(textPassword))")
                }
                .font(.headline)
                .foregroundColor(.white)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.orange)
                .cornerRadius(10)
            }
            .padding(.horizontal)
            
            // Read Tag Info Button
            Button(action: {
                readTagInfo()
            }) {
                HStack {
                    Image(systemName: "info.circle.fill")
                    Text("Read Tag Information")
                }
                .font(.headline)
                .foregroundColor(.white)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.purple)
                .cornerRadius(10)
            }
            .padding(.horizontal)
            
            // Display read results
            if !nfcMessage.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("NFC Message:")
                        .font(.headline)
                    Text(nfcMessage)
                        .font(.body)
                        .padding()
                        .background(Color.gray.opacity(0.1))
                        .cornerRadius(8)
                }
                .padding()
            }
            
            if !nfcError.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text("NFC Error:")
                        .font(.headline)
                        .foregroundColor(.red)
                    Text(nfcError)
                        .font(.body)
                        .foregroundColor(.red)
                        .padding()
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(8)
                }
                .padding()
            }
            
            // Tag Information Display at the bottom
            if let info = tagInfo {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Tag Information:")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(info.details.components(separatedBy: "\n").enumerated()), id: \.offset) { index, line in
                            Text(line)
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.blue.opacity(0.1))
                    .cornerRadius(8)
                }
                .padding()
            }
            }
            .padding()
        }
        .alert("Rule Status", isPresented: $showAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(alertMessage)
        }
    }
    
    private func readNFC() {
        nfcMessage = ""
        nfcError = ""
        scanner.onWriteCompleted = nil
        scanner.onReadCompleted = { text, message, error in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = error.localizedDescription
                    nfcMessage = ""
                } else if let message = message {
                    nfcMessage = message
                    nfcError = ""
                }
                textRead = text
                
                // Parse URL and handle rule activation/deactivation
                if !text.isEmpty {
                    handleRuleFromText(text)
                }
            }
        }
        
        scanner.beginReading(password: textPassword)
    }
    
    // Parse URL and extract rule number, toggle state, show alert
    private func handleRuleFromText(_ text: String) {
        // Pattern: https://firewalla.com/rule/666 or similar
        let pattern = #"https?://firewalla\.com/rule/(\d+)"#
        
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else {
            return
        }
        
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        guard let match = regex.firstMatch(in: text, options: [], range: range) else {
            return
        }
        
        // Extract rule number
        guard match.numberOfRanges > 1,
              let ruleNumberRange = Range(match.range(at: 1), in: text),
              let ruleNumber = Int(text[ruleNumberRange]) else {
            return
        }
        
        // Get current state from UserDefaults
        let key = "rule_\(ruleNumber)_activated"
        let currentState = UserDefaults.standard.bool(forKey: key)
        
        // Toggle state
        let newState = !currentState
        UserDefaults.standard.set(newState, forKey: key)
        
        // Show alert with new state
        let status = newState ? "activated" : "deactivated"
        alertMessage = "The rule \(ruleNumber) is \(status)"
        showAlert = true
        
        print("📋 Rule \(ruleNumber) toggled: \(currentState ? "activated" : "deactivated") -> \(newState ? "activated" : "deactivated")")
    }
    
    private func readTagInfo() {
        nfcError = ""
        scanner.onReadCompleted = nil
        scanner.onWriteCompleted = nil
        scanner.onSetPasswordCompleted = nil
        scanner.onTagInfoCompleted = { info, error in
            DispatchQueue.main.async {
                if let error = error {
                    // Show error but don't clear existing tag info
                    nfcError = "Tag Info Error: \(error.localizedDescription)"
                    print("Tag info read error: \(error.localizedDescription)")
                } else if let info = info {
                    tagInfo = info
                    nfcError = ""
                }
            }
        }
        scanner.beginReadingTagInfo()
    }
    
    private func writeNFC() {
        nfcMessage = ""
        nfcError = ""
        scanner.onReadCompleted = nil
        scanner.onSetPasswordCompleted = nil
        scanner.onWriteCompleted = { (msg, error) in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Write Error: \(error.localizedDescription)"
                } else {
                    nfcMessage = "Write Successful!"
                }
            }
        }
        scanner.beginWriting(password: textPassword, textToWrite: textToWrite)
    }
    
    private func setPassword() {
        nfcMessage = ""
        nfcError = ""
        scanner.onReadCompleted = nil
        scanner.onWriteCompleted = nil
        scanner.textPassword = textPassword
        scanner.onSetPasswordCompleted = { (msg, error) in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Set Password Error: \(error.localizedDescription)"
                    nfcMessage = ""
                } else if let message = msg {
                    nfcMessage = message
                    nfcError = ""
                } else {
                    nfcMessage = "Password set successfully!"
                    nfcError = ""
                }
            }
        }
        scanner.beginSettingPassword(password: textPassword, writeOnlyProtection: writeOnlyProtection)
    }
}

#Preview {
    ContentView()
}
