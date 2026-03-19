//
// Phase 3, Point 3 — iOS Universal Links / system-level link interception
//
// Bubbble intercepts https URLs on iOS via two complementary mechanisms:
//
//   1. Universal Links (apple-app-site-association) — intercept links to
//      Bubbble's own domain (bubbble.com) automatically.
//   2. Share Sheet Extension — user can share any URL to Bubbble from Safari
//      or any other app for on-demand scanning.
//
// This file implements the shared LinkInterceptor that both paths call into.
//

import Foundation
import SafariServices
import SwiftUI

// MARK: - Scan Result

struct BubbleScanResult: Decodable {
    let safe: Bool
    let reason: String?
    let url: String?
}

// MARK: - LinkInterceptor

/// Central class that submits a URL to the Bubbble backend and returns a scan
/// result. Used by both the Universal Link handler in AppDelegate and the
/// Share Sheet Extension.
final class LinkInterceptor {

    static let shared = LinkInterceptor()

    private let session: URLSession
    private let apiBase: URL
    private let apiKey: String

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 15
        self.session = URLSession(configuration: config)

        guard
            let base = URL(string: Bundle.main.infoDictionary?["BUBBBLE_API_BASE_URL"] as? String ?? ""),
            let key = Bundle.main.infoDictionary?["BUBBBLE_API_KEY"] as? String
        else {
            fatalError("BUBBBLE_API_BASE_URL and BUBBBLE_API_KEY must be set in Info.plist")
        }
        self.apiBase = base
        self.apiKey = key
    }

    // ----------------------------------------------------------------
    // Public API
    // ----------------------------------------------------------------

    /// Scan `url` against the Bubbble backend.
    /// - Returns: A `BubbleScanResult`. On network/parse errors, fails open
    ///            (returns safe: true) to avoid blocking legitimate traffic.
    func scan(url: URL) async -> BubbleScanResult {
        do {
            return try await performScan(url: url)
        } catch {
            // Fail open on any error
            return BubbleScanResult(safe: true, reason: "Scan error — proceeding.", url: url.absoluteString)
        }
    }

    // ----------------------------------------------------------------
    // Internal
    // ----------------------------------------------------------------

    private func performScan(url: URL) async throws -> BubbleScanResult {
        var request = URLRequest(url: apiBase.appendingPathComponent("v1/scan"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONSerialization.data(
            withJSONObject: ["url": url.absoluteString]
        )

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            // Non-200 — fail open
            return BubbleScanResult(safe: true, reason: nil, url: url.absoluteString)
        }

        return try JSONDecoder().decode(BubbleScanResult.self, from: data)
    }
}

// MARK: - Universal Link handler (call from AppDelegate / SceneDelegate)

/// Drop-in handler for `application(_:continue:restorationHandler:)`.
/// Returns `true` when Bubbble handled the URL, `false` otherwise.
@MainActor
func handleUniversalLink(
    userActivity: NSUserActivity,
    present: @escaping (UIViewController) -> Void
) -> Bool {
    guard
        userActivity.activityType == NSUserActivityTypeBrowsingWeb,
        let url = userActivity.webpageURL
    else { return false }

    let hostVC = BubbleOverlayViewController(targetURL: url) { result in
        if result.safe, let destination = URL(string: result.url ?? url.absoluteString) {
            // Open in the default browser after scan passes
            UIApplication.shared.open(destination)
        }
        // If not safe, BubbleOverlayViewController already shows the block UI.
    }
    present(hostVC)
    return true
}

// MARK: - BubbleOverlayViewController

/// A translucent UIViewController that shows the bubble scanning UI and
/// handles safe / danger outcomes. Wraps the SwiftUI BubbleOverlayView.
final class BubbleOverlayViewController: UIHostingController<BubbleOverlayView> {

    init(targetURL: URL, onComplete: @escaping (BubbleScanResult) -> Void) {
        let vm = BubbleOverlayViewModel(targetURL: targetURL, onComplete: onComplete)
        super.init(rootView: BubbleOverlayView(viewModel: vm))
        modalPresentationStyle = .overFullScreen
        modalTransitionStyle = .crossDissolve
        view.backgroundColor = .clear
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("Use init(targetURL:onComplete:)") }
}

// MARK: - ViewModel

@MainActor
final class BubbleOverlayViewModel: ObservableObject {

    enum State { case scanning, safe, danger }

    @Published var state: State = .scanning
    @Published var result: BubbleScanResult?

    private let targetURL: URL
    private let onComplete: (BubbleScanResult) -> Void

    init(targetURL: URL, onComplete: @escaping (BubbleScanResult) -> Void) {
        self.targetURL = targetURL
        self.onComplete = onComplete
        Task { await self.runScan() }
    }

    /** Nanoseconds to display the safe state before auto-dismissing (mirrors SAFE_DISMISS_DELAY_MS in the browser extension). */
    private static let safeDismissDelayNs: UInt64 = 600_000_000 // 0.6 s

    private func runScan() async {
        let scanResult = await LinkInterceptor.shared.scan(url: targetURL)
        result = scanResult
        state = scanResult.safe ? .safe : .danger
        if scanResult.safe {
            try? await Task.sleep(nanoseconds: BubbleOverlayViewModel.safeDismissDelayNs)
            onComplete(scanResult)
        }
    }

    func proceedAnyway() {
        guard let r = result else { return }
        onComplete(BubbleScanResult(safe: true, reason: r.reason, url: r.url ?? targetURL.absoluteString))
    }
}

// MARK: - SwiftUI View

struct BubbleOverlayView: View {

    @ObservedObject var viewModel: BubbleOverlayViewModel

    var body: some View {
        ZStack {
            Color.black.opacity(0.55).ignoresSafeArea()

            VStack(spacing: 24) {
                bubbleSphere
                labelStack
                if viewModel.state == .danger { actionButtons }
            }
            .padding(32)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityDescription)
    }

    // ── Bubble sphere ────────────────────────────────────────────────
    @ViewBuilder
    private var bubbleSphere: some View {
        ZStack {
            Circle()
                .fill(sphereGradient)
                .frame(width: 140, height: 140)
                .shadow(color: sphereGlowColor.opacity(0.5), radius: 30)
                .scaleEffect(viewModel.state == .scanning ? 1.0 : 0.0)
                .animation(
                    viewModel.state == .scanning
                        ? .easeInOut(duration: 1.2).repeatForever(autoreverses: true)
                        : .spring(response: 0.4, dampingFraction: 0.5),
                    value: viewModel.state
                )
        }
        .frame(width: 160, height: 160)
    }

    private var sphereGradient: RadialGradient {
        switch viewModel.state {
        case .scanning:
            return RadialGradient(
                colors: [.white, Color(red: 0.51, green: 0.78, blue: 1.0), Color(red: 0.31, green: 0.55, blue: 1.0)],
                center: UnitPoint(x: 0.35, y: 0.3), startRadius: 5, endRadius: 70
            )
        case .safe:
            return RadialGradient(
                colors: [.white, Color(red: 0.51, green: 1.0, blue: 0.7), Color(red: 0.16, green: 0.78, blue: 0.39)],
                center: UnitPoint(x: 0.35, y: 0.3), startRadius: 5, endRadius: 70
            )
        case .danger:
            return RadialGradient(
                colors: [.white, Color(red: 1.0, green: 0.59, blue: 0.39), Color(red: 0.86, green: 0.2, blue: 0.12)],
                center: UnitPoint(x: 0.35, y: 0.3), startRadius: 5, endRadius: 70
            )
        }
    }

    private var sphereGlowColor: Color {
        switch viewModel.state {
        case .scanning: return Color(red: 0.39, green: 0.71, blue: 1.0)
        case .safe:     return Color(red: 0.16, green: 0.78, blue: 0.39)
        case .danger:   return Color(red: 0.86, green: 0.2, blue: 0.12)
        }
    }

    // ── Labels ───────────────────────────────────────────────────────
    @ViewBuilder
    private var labelStack: some View {
        VStack(spacing: 8) {
            Text(labelTitle)
                .font(.title2.bold())
                .foregroundColor(.white)
                .multilineTextAlignment(.center)
            Text(labelSub)
                .font(.subheadline)
                .foregroundColor(.white.opacity(0.75))
                .multilineTextAlignment(.center)
        }
    }

    private var labelTitle: String {
        switch viewModel.state {
        case .scanning: return "Checking link…"
        case .safe:     return "Link is safe ✓"
        case .danger:   return "Link blocked 🚫"
        }
    }

    private var labelSub: String {
        switch viewModel.state {
        case .scanning: return "Bubbble is scanning this URL for threats."
        case .safe:     return viewModel.result?.reason ?? "Taking you there now."
        case .danger:
            return viewModel.result?.reason
                ?? "This link appears malicious. We've blocked it to protect you."
        }
    }

    // ── Action buttons (danger only) ─────────────────────────────────
    @ViewBuilder
    private var actionButtons: some View {
        HStack(spacing: 12) {
            Button("Keep me safe") {
                // Dismiss without navigating — handled by parent
            }
            .buttonStyle(.borderedProminent)

            Button("Proceed anyway") { viewModel.proceedAnyway() }
                .buttonStyle(.bordered)
                .tint(.white)
        }
    }

    private var accessibilityDescription: String {
        "\(labelTitle). \(labelSub)"
    }
}
