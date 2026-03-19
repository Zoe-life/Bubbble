import Foundation
import UIKit
import SwiftUI

// MARK: - Phase 3: iOS Share Extension

/**
 * BubbbleShareHandler
 *
 * Provides the implementation for the Bubbble Share Extension.
 * The Share Extension target's principal class (`ShareViewController`) should
 * call `BubbbleShareHandler.handle(extensionContext:)` from `viewDidLoad`.
 *
 * The extension appears in the iOS Share Sheet whenever the user shares text
 * or a URL from any app (Safari, Mail, WhatsApp, etc.). It extracts the URL,
 * triggers a scan, and presents the bubble overlay result.
 *
 * Info.plist activation rules for the extension:
 *
 *   NSExtensionAttributes:
 *     NSExtensionActivationRule:
 *       NSExtensionActivationSupportsWebURLWithMaxCount: 1
 *       NSExtensionActivationSupportsText: true
 */
public class BubbbleShareHandler: NSObject {

    // MARK: - Public entry point

    public static func handle(extensionContext: NSExtensionContext) async {
        guard let url = await extractURL(from: extensionContext) else {
            extensionContext.cancelRequest(withError: ShareError.noURLFound)
            return
        }

        // Present the scanning overlay in a separate window
        await MainActor.run {
            presentOverlay(url: url, extensionContext: extensionContext)
        }
    }

    // MARK: - URL extraction

    private static func extractURL(from context: NSExtensionContext) async -> URL? {
        for item in context.inputItems as? [NSExtensionItem] ?? [] {
            for provider in item.attachments ?? [] {
                if provider.hasItemConformingToTypeIdentifier("public.url") {
                    if let url = try? await provider.loadItem(
                        forTypeIdentifier: "public.url",
                        options: nil
                    ) as? URL {
                        return url
                    }
                }
                if provider.hasItemConformingToTypeIdentifier("public.plain-text") {
                    if let text = try? await provider.loadItem(
                        forTypeIdentifier: "public.plain-text",
                        options: nil
                    ) as? String {
                        return firstURL(in: text)
                    }
                }
            }
        }
        return nil
    }

    private static func firstURL(in text: String) -> URL? {
        let detector = try? NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
        let range = NSRange(text.startIndex..., in: text)
        return detector?.firstMatch(in: text, options: [], range: range).flatMap {
            $0.url
        }
    }

    // MARK: - Overlay presentation

    private static func presentOverlay(url: URL, extensionContext: NSExtensionContext) {
        let overlayView = ShareOverlayView(
            url: url,
            onDismiss: { extensionContext.cancelRequest(withError: ShareError.userDismissed) },
            onOpenInBrowser: { targetURL in
                let openItem = NSExtensionItem()
                extensionContext.completeRequest(
                    returningItems: [openItem],
                    completionHandler: { _ in
                        // The host app (Safari, etc.) handles the open action
                    }
                )
            }
        )

        let hostVC = UIHostingController(rootView: overlayView)
        hostVC.modalPresentationStyle = .overFullScreen
        hostVC.view.backgroundColor = .clear

        // Find the key window's root view controller to present from
        if let windowScene = UIApplication.shared.connectedScenes
            .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene,
           let rootVC = windowScene.windows.first?.rootViewController {
            rootVC.present(hostVC, animated: false)
        }
    }

    // MARK: - Errors

    enum ShareError: Error {
        case noURLFound
        case userDismissed
    }
}

// MARK: - SwiftUI Overlay

private struct ShareOverlayView: View {
    let url: URL
    let onDismiss: () -> Void
    let onOpenInBrowser: (URL) -> Void

    @State private var scanState: ShareScanState = .scanning

    var body: some View {
        ZStack {
            Color.black.opacity(0.75).ignoresSafeArea()

            VStack(spacing: 0) {
                Spacer()
                scanCard
                    .padding(24)
                Spacer()
            }
        }
        .task { await performScan() }
    }

    @ViewBuilder
    private var scanCard: some View {
        VStack(spacing: 16) {
            switch scanState {
            case .scanning:
                ProgressView()
                    .scaleEffect(2)
                    .tint(.blue)
                Text("Scanning link…")
                    .font(.headline).foregroundColor(.white)
                Text(url.absoluteString.prefix(60) + (url.absoluteString.count > 60 ? "…" : ""))
                    .font(.caption).foregroundColor(.gray)
                    .multilineTextAlignment(.center)

            case .safe:
                Text("✅").font(.system(size: 48))
                Text("Link is safe").font(.title2).bold().foregroundColor(Color(hex: "#22C55E"))
                HStack(spacing: 12) {
                    Button("Dismiss", action: onDismiss)
                        .buttonStyle(.bordered).tint(.white)
                    Button("Open link") { onOpenInBrowser(url) }
                        .buttonStyle(.borderedProminent).tint(Color(hex: "#22C55E"))
                }

            case .danger(let threatType, let action):
                Text("⚠️").font(.system(size: 48))
                Text("Danger — link blocked")
                    .font(.title2).bold().foregroundColor(Color(hex: "#EF4444"))
                Text(threatType).font(.subheadline).foregroundColor(.gray).multilineTextAlignment(.center)
                Text(action).font(.caption).foregroundColor(.white).multilineTextAlignment(.center)
                HStack(spacing: 12) {
                    Button("Keep me safe", action: onDismiss)
                        .buttonStyle(.borderedProminent).tint(Color(hex: "#22C55E"))
                    Button("Proceed anyway") { onOpenInBrowser(url) }
                        .buttonStyle(.bordered).tint(Color(hex: "#EF4444"))
                }

            case .error:
                Text("⚠️").font(.system(size: 48))
                Text("Could not scan link").font(.headline).foregroundColor(.white)
                Text("Proceed with caution.").font(.subheadline).foregroundColor(.gray)
                HStack(spacing: 12) {
                    Button("Dismiss", action: onDismiss).buttonStyle(.bordered).tint(.white)
                    Button("Open anyway") { onOpenInBrowser(url) }
                        .buttonStyle(.bordered).tint(.gray)
                }
            }
        }
        .padding(24)
        .background(Color(hex: "#1E1E2E"))
        .cornerRadius(20)
    }

    private func performScan() async {
        do {
            let result = try await LinkInterceptor.shared.scanURL(url)
            if result.isSafe {
                scanState = .safe
            } else {
                scanState = .danger(
                    threatType: result.threatType ?? "Malicious link",
                    action: result.recommendedAction
                        ?? "Do not visit this link. Report it to the platform you received it from."
                )
            }
        } catch {
            scanState = .error
        }
    }
}

private enum ShareScanState {
    case scanning
    case safe
    case danger(threatType: String, action: String)
    case error
}

// MARK: - Color hex helper

private extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let r = Double((int >> 16) & 0xFF) / 255
        let g = Double((int >> 8) & 0xFF) / 255
        let b = Double(int & 0xFF) / 255
        self.init(red: r, green: g, blue: b)
    }
}
