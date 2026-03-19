import Foundation
import UserNotifications

// MARK: - Phase 3: iOS Push Notifications

/**
 * BubbblePushManager
 *
 * Manages APNs registration, permission requests, and notification handling.
 *
 * Call from AppDelegate:
 *
 *   func application(_ application: UIApplication,
 *                    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
 *       BubbblePushManager.shared.requestPermission()
 *       return true
 *   }
 *
 *   func application(_ application: UIApplication,
 *                    didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
 *       BubbblePushManager.shared.didRegister(deviceToken: deviceToken)
 *   }
 *
 *   func application(_ application: UIApplication,
 *                    didFailToRegisterForRemoteNotificationsWithError error: Error) {
 *       BubbblePushManager.shared.didFailToRegister(error: error)
 *   }
 */
public final class BubbblePushManager: NSObject {

    public static let shared = BubbblePushManager()

    private override init() { super.init() }

    // MARK: - Registration

    public func requestPermission() {
        UNUserNotificationCenter.current().delegate = self
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound, .badge]
        ) { granted, error in
            if let error { print("[Bubbble] Push permission error: \(error)") }
            guard granted else { return }
            DispatchQueue.main.async {
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }

    public func didRegister(deviceToken: Data) {
        let tokenString = deviceToken.map { String(format: "%02x", $0) }.joined()
        print("[Bubbble] APNs token: \(tokenString)")
        Task { await BubbbleAPIClient.shared.registerPushToken(tokenString) }
    }

    public func didFailToRegister(error: Error) {
        print("[Bubbble] APNs registration failed: \(error)")
    }

    // MARK: - Local notification helpers

    /// Schedule a local notification for an audit report that is ready.
    public func scheduleAuditReportNotification(reportId: String, blockedURL: String) {
        let content = UNMutableNotificationContent()
        content.title = "📋 Audit Report Ready"
        content.body = "A malicious link was blocked and your audit report is ready."
        content.sound = .default
        content.userInfo = ["type": "audit_report", "report_id": reportId, "url": blockedURL]
        content.categoryIdentifier = NotificationCategory.auditReport

        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        let request = UNNotificationRequest(
            identifier: "audit-\(reportId)",
            content: content,
            trigger: trigger,
        )
        UNUserNotificationCenter.current().add(request) { error in
            if let error { print("[Bubbble] Notification schedule error: \(error)") }
        }
    }

    /// Schedule a high-priority threat alert notification.
    public func scheduleThreatAlertNotification(threatType: String, url: String) {
        let content = UNMutableNotificationContent()
        content.title = "⚠ Threat Detected"
        content.body = "A \(threatType) link was blocked. Tap to view the full report."
        content.sound = .defaultCritical
        content.userInfo = ["type": "threat_alert", "url": url, "threat_type": threatType]
        content.categoryIdentifier = NotificationCategory.threatAlert
        content.interruptionLevel = .timeSensitive

        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
        let request = UNNotificationRequest(
            identifier: "threat-\(UUID().uuidString)",
            content: content,
            trigger: trigger,
        )
        UNUserNotificationCenter.current().add(request) { error in
            if let error { print("[Bubbble] Threat alert schedule error: \(error)") }
        }
    }

    // MARK: - Notification categories

    public func registerCategories() {
        let viewReportAction = UNNotificationAction(
            identifier: "VIEW_REPORT",
            title: "View Report",
            options: [.foreground],
        )
        let dismissAction = UNNotificationAction(
            identifier: "DISMISS",
            title: "Dismiss",
            options: [.destructive],
        )

        let auditCategory = UNNotificationCategory(
            identifier: NotificationCategory.auditReport,
            actions: [viewReportAction, dismissAction],
            intentIdentifiers: [],
            options: [],
        )
        let threatCategory = UNNotificationCategory(
            identifier: NotificationCategory.threatAlert,
            actions: [viewReportAction, dismissAction],
            intentIdentifiers: [],
            options: [],
        )

        UNUserNotificationCenter.current().setNotificationCategories([auditCategory, threatCategory])
    }

    private enum NotificationCategory {
        static let auditReport = "BUBBBLE_AUDIT_REPORT"
        static let threatAlert = "BUBBBLE_THREAT_ALERT"
    }
}

// MARK: - UNUserNotificationCenterDelegate

extension BubbblePushManager: UNUserNotificationCenterDelegate {

    /// Called when a notification is received while the app is in the foreground.
    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void,
    ) {
        completionHandler([.banner, .sound])
    }

    /// Called when the user taps a notification or an action button.
    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void,
    ) {
        let userInfo = response.notification.request.content.userInfo

        switch response.actionIdentifier {
        case "VIEW_REPORT":
            if let reportId = userInfo["report_id"] as? String {
                NotificationCenter.default.post(
                    name: .bubbbleOpenAuditReport,
                    object: nil,
                    userInfo: ["report_id": reportId],
                )
            }
        default:
            break
        }
        completionHandler()
    }
}

// MARK: - Notification name

public extension Notification.Name {
    static let bubbbleOpenAuditReport = Notification.Name("com.bubbble.openAuditReport")
}

// MARK: - API client stub (for push token registration)

import UIKit

final class BubbbleAPIClient {
    static let shared = BubbbleAPIClient()
    private init() {}

    private let baseURL = URL(string: ProcessInfo.processInfo.environment["BUBBBLE_API_URL"]
                              ?? "https://api.bubbble.com/v1")!

    func registerPushToken(_ token: String) async {
        var request = URLRequest(url: baseURL.appendingPathComponent("push/register"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONEncoder().encode(["token": token, "platform": "ios"])
        _ = try? await URLSession.shared.data(for: request)
    }
}
