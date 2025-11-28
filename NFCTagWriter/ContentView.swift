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
    @State private var textToWrite: String = "resume rule xxx"
    @State private var tagInfo: NFCTagInfo? = nil
    
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
            }
        }
        
        scanner.beginReading()
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
        scanner.textToWrite = textToWrite
        scanner.onWriteCompleted = { (msg, error) in
            DispatchQueue.main.async {
                if let error = error {
                    nfcError = "Write Error: \(error.localizedDescription)"
                } else {
                    nfcMessage = "Write Successful!"
                }
            }
        }
        scanner.beginWriting()
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
        scanner.beginSettingPassword()
    }
}

#Preview {
    ContentView()
}
