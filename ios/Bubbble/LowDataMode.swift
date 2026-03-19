import Foundation
import Network
import Combine

// MARK: - Phase 3: iOS Low-Data Mode

/**
 * LowDataModeMonitor
 *
 * Observes the device's active network path to determine the appropriate
 * scan strategy, mirroring the Android LowDataModeManager:
 *
 *   Wi-Fi / Ethernet  → .full        (all signals)
 *   Cellular          → .lightweight (Safe Browsing + PhishTank; skips VirusTotal + preview)
 *   No connectivity   → .offline     (local blocklist only)
 *
 * Uses Apple's `Network.framework` NWPathMonitor, which is available on
 * iOS 12+ and does not require special entitlements.
 *
 * Usage::
 *
 *   let monitor = LowDataModeMonitor.shared
 *   monitor.start()
 *
 *   // React to changes in SwiftUI:
 *   @StateObject var monitor = LowDataModeMonitor.shared
 *   Text(monitor.strategy.displayName)
 *
 *   // Or in plain Swift:
 *   monitor.$strategy.sink { strategy in ... }.store(in: &cancellables)
 */
public enum ScanStrategy: String {
    case full        = "full"
    case lightweight = "lightweight"
    case offline     = "offline"

    public var displayName: String {
        switch self {
        case .full:        return "Full Scan"
        case .lightweight: return "Lightweight Scan (mobile data)"
        case .offline:     return "Offline Mode"
        }
    }

    /// Returns the API query parameters to activate this strategy.
    public var apiParams: [String: Any] {
        switch self {
        case .full:
            return ["signals": ["safe_browsing", "virustotal", "phishtank", "whois", "ssl", "content_preview"]]
        case .lightweight:
            return ["signals": ["safe_browsing", "phishtank"], "lightweight": true]
        case .offline:
            return ["offline": true]
        }
    }
}

public final class LowDataModeMonitor: ObservableObject {

    public static let shared = LowDataModeMonitor()

    @Published public private(set) var strategy: ScanStrategy = .offline

    private let pathMonitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "com.bubbble.networkMonitor", qos: .utility)

    private init() {}

    // MARK: - Lifecycle

    public func start() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                self?.strategy = Self.strategyFor(path: path)
            }
        }
        pathMonitor.start(queue: queue)
    }

    public func stop() {
        pathMonitor.cancel()
    }

    // MARK: - Strategy selection

    private static func strategyFor(path: NWPath) -> ScanStrategy {
        guard path.status == .satisfied else { return .offline }

        // Constrained path = Low Data Mode enabled by the user in iOS Settings
        // Expensive path = cellular (or personal hotspot)
        if path.isConstrained || path.isExpensive {
            return .lightweight
        }
        // Wi-Fi or Ethernet
        if path.usesInterfaceType(.wifi) || path.usesInterfaceType(.wiredEthernet) {
            return .full
        }
        // Cellular without Low Data Mode
        if path.usesInterfaceType(.cellular) {
            return .lightweight
        }
        return .offline
    }
}
