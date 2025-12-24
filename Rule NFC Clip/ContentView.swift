//
//  ContentView.swift
//  Rule NFC Clip
//
//  Created by 刘平安 on 12/15/25.
//

import SwiftUI
import StoreKit

struct ContentView: View {
    let firewallaAppleId = "1180904053"
    @State private var showOverlay = false

    var body: some View {
        VStack {
        }
        .onAppear {
            showOverlay = true
        }
        .appStoreOverlay(isPresented: $showOverlay) {
            SKOverlay.AppConfiguration(appIdentifier: firewallaAppleId,
                                       position: .bottom)
        }
    }
}

#Preview {
    ContentView()
}
