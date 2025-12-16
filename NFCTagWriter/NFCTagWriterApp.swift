//
//  NFCTagWriterApp.swift
//  NFCTagWriter
//
//  Created by 刘平安 on 11/26/25.
//

import SwiftUI

@main
struct NFCTagWriterApp: App {
    @StateObject private var router = AppRouter()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(router)
                // 1. Handle REAL Deep Links (Production)
                // This fires when a user taps a link or scans a code
                .onOpenURL { incomingURL in
                    print("📱 System Deep Link received: \(incomingURL)")
                    router.handle(url: incomingURL)
                }
                
                // 2. Handle XCODE SIMULATED Links (Debug)
                // This checks the Environment Variable we set in the Scheme
                .onAppear {
                    checkForDebugURL()
                }
                .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { userActivity in
                    guard let url = userActivity.webpageURL else { return }
                    print("Opened via Universal Link: \(url)")
                    router.handle(url: url)
                }
                // Show URL Details Popup when router triggers it
                .sheet(isPresented: $router.showURLDetails) {
                    if let details = router.urlDetails {
                        URLDetailsView(details: details)
                    }
                }
        }
    }
    
    // MARK: - Debug Helper
    private func checkForDebugURL() {
#if DEBUG
        // strictly for testing; this code is stripped out in App Store builds
        
        // Check if the environment variable exists
        if let urlString = ProcessInfo.processInfo.environment["_XCAppClipURL"],
           let url = URL(string: urlString) {
            
            print("🐞 DEBUG: Simulating launch via Xcode Argument: \(url)")
            
            // Artificial delay to ensure the UI is ready to navigate
            // (Optional, but helps if your app does heavy setup on launch)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                router.handle(url: url)
            }
        }
#endif
    }
    
    func handleActivity(_ userActivity: NSUserActivity) {
        // Extract data from the activity
        if let productId = userActivity.userInfo?["id"] as? String {
            print("Restore state for product: \(productId)")
        }
    }
}
