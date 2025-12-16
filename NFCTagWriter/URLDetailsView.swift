//
//  URLDetailsView.swift
//  NFCTagWriter
//
//  Created for displaying URL details from NFC tags
//
import SwiftUI

struct URLDetailsView: View {
    let details: URLDetails
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Header
                    HStack {
                        Image(systemName: "link.circle.fill")
                            .font(.system(size: 40))
                            .foregroundColor(.blue)
                        Text("URL Details")
                            .font(.title2)
                            .fontWeight(.bold)
                    }
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.top)
                    
                    Divider()
                    
                    // Full URL
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Full URL:")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Text(details.fullURL)
                            .font(.system(.body, design: .monospaced))
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.blue.opacity(0.1))
                            .cornerRadius(8)
                    }
                    
                    // URL Components
                    VStack(alignment: .leading, spacing: 12) {
                        Text("URL Components:")
                            .font(.headline)
                        
                        if let scheme = details.scheme {
                            DetailRow(label: "Scheme", value: scheme)
                        }
                        
                        if let host = details.host {
                            DetailRow(label: "Host", value: host)
                        }
                        
                        if let path = details.path, !path.isEmpty {
                            DetailRow(label: "Path", value: path)
                        }
                    }
                    
                    // Query Parameters
                    if let queryItems = details.queryItems, !queryItems.isEmpty {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Query Parameters:")
                                .font(.headline)
                            
                            ForEach(queryItems, id: \.name) { item in
                                DetailRow(label: item.name, value: item.value ?? "")
                            }
                        }
                    }
                    
                    // Important Parameters
                    if details.gid != nil || details.rule != nil {
                        Divider()
                        
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Key Parameters:")
                                .font(.headline)
                                .foregroundColor(.blue)
                            
                            if let gid = details.gid {
                                DetailRow(label: "GID", value: gid, highlight: true)
                            }
                            
                            if let rule = details.rule {
                                DetailRow(label: "Rule ID", value: rule, highlight: true)
                            }
                            
                            if let chksum = details.chksum {
                                DetailRow(label: "Checksum", value: chksum, highlight: true)
                            }
                        }
                    }
                    
                    // Checksum Validation
                    if let validated = details.checksumValidated {
                        Divider()
                        
                        HStack {
                            Image(systemName: validated ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundColor(validated ? .green : .red)
                                .font(.title2)
                            
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Checksum Validation")
                                    .font(.headline)
                                Text(validated ? "Valid ✓" : "Invalid ✗")
                                    .font(.subheadline)
                                    .foregroundColor(validated ? .green : .red)
                            }
                        }
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(validated ? Color.green.opacity(0.1) : Color.red.opacity(0.1))
                        .cornerRadius(8)
                    }
                }
                .padding()
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }
}

// Helper view for detail rows
struct DetailRow: View {
    let label: String
    let value: String
    var highlight: Bool = false
    
    var body: some View {
        HStack(alignment: .top) {
            Text("\(label):")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .frame(width: 100, alignment: .leading)
            
            Text(value)
                .font(.system(.body, design: .monospaced))
                .foregroundColor(highlight ? .blue : .primary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    URLDetailsView(details: URLDetails(
        fullURL: "https://mesh.firewalla.com/nfc?gid=915565a3-65c7-4a2b-8629-194d80ed824b&rule=249&chksum=1234567890",
        scheme: "https",
        host: "mesh.firewalla.com",
        path: "/nfc",
        queryItems: [
            URLQueryItem(name: "gid", value: "915565a3-65c7-4a2b-8629-194d80ed824b"),
            URLQueryItem(name: "rule", value: "249"),
            URLQueryItem(name: "chksum", value: "1234567890")
        ],
        gid: "915565a3-65c7-4a2b-8629-194d80ed824b",
        rule: "249",
        chksum: "1234567890",
        checksumValidated: true
    ))
}

