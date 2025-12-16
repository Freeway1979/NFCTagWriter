//
//  AppRouter.swift
//  NFCTagWriter
//
//  Created by 刘平安 on 12/16/25.
//

import SwiftUI

// 1. Define your app's top-level tabs for easy switching
enum AppTab: String {
    case home
    case menu
    case settings
}

// URL Details Model
struct URLDetails {
    let fullURL: String
    let scheme: String?
    let host: String?
    let path: String?
    let queryItems: [URLQueryItem]?
    let gid: String?
    let rule: String?
    let chksum: String?
    let checksumValidated: Bool?
}

class AppRouter: ObservableObject {
    // MARK: - Navigation State
    @Published var currentTab: AppTab = .home
    
    // When this is set to a non-nil value, the UI will navigate to the Detail View
    @Published var selectedMenuID: String?
    
    // URL Details Popup
    @Published var showURLDetails: Bool = false
    @Published var urlDetails: URLDetails? = nil
    
    // MARK: - URL Handling
    func handle(url: URL) {
        // Example URL: https://myapp.com/menu?id=42
        
        // 1. Ensure we parse correctly
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            print("Router: Invalid URL format")
            return
        }
        
        print("Router processing: \(url.absoluteString)")
        
        // 2. Parse Path to determine the Tab
        // Note: Lowercase comparison is safer
        let path = components.path.lowercased()
        
        // 3. Extract URL details for popup
        var gid: String? = nil
        var rule: String? = nil
        var chksum: String? = nil
        var checksumValidated: Bool? = nil
        
        // Extract query parameters
        if let gidItem = components.queryItems?.first(where: { $0.name == "gid" }),
           let gidValue = gidItem.value,
           let ruleItem = components.queryItems?.first(where: { $0.name == "rule" }),
           let rid = ruleItem.value {
            gid = gidValue
            rule = rid
            
            // Check for checksum and validate if present
            if let checkSumItem = components.queryItems?.first(where: { $0.name == "chksum" }),
               let chksumPrefix = checkSumItem.value {
                chksum = chksumPrefix
                // Read full checksum from UserDefaults using the prefix as key
                if let fullChecksum = ClipHelper.readChecksum(checksumPrefix: chksumPrefix) {
                    let validated = ClipHelper.verifyCheckSum(checksum: fullChecksum, gid: gidValue, rid: rid,
                                                              withAESGCM: false)
                    checksumValidated = validated
                }
            }
        }
        
        // Create URL details
        let details = URLDetails(
            fullURL: url.absoluteString,
            scheme: url.scheme,
            host: url.host,
            path: url.path,
            queryItems: components.queryItems,
            gid: gid,
            rule: rule,
            chksum: chksum,
            checksumValidated: checksumValidated
        )
        
        // 4. Update UI on Main Thread
        DispatchQueue.main.async {
            // A. Switch Tabs based on path
            if path.contains("menu") {
                self.currentTab = .menu
            } else if path.contains("settings") {
                self.currentTab = .settings
            } else {
                self.currentTab = .home
            }
            
            // B. Check for Deep Link ID (Query Parameters)
            if let idValue = components.queryItems?.first(where: { $0.name == "id" })?.value {
                // Setting this triggers the NavigationLink in the View
                self.selectedMenuID = idValue
            }
            
            // C. Show URL Details Popup
            self.urlDetails = details
            self.showURLDetails = true
        }
    }
}
