package com.bubbble

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/**
 * Phase 3 — Android Push Notifications (Firebase Cloud Messaging)
 *
 * Handles FCM messages sent by the Bubbble backend after an audit report is
 * generated. Two notification channels are defined:
 *
 *   1. CHANNEL_AUDIT_REPORT  — a new audit report is available
 *   2. CHANNEL_THREAT_ALERT  — a high-severity threat was detected in real-time
 *
 * The backend sends FCM data payloads with the following keys:
 *   type           : "audit_report" | "threat_alert"
 *   title          : notification title
 *   body           : notification body text
 *   report_id      : (optional) audit report ID for deep-link
 *   url            : (optional) blocked URL
 *   threat_type    : (optional) threat category label
 *
 * Registration in AndroidManifest.xml:
 *
 *   <service
 *     android:name=".PushNotificationService"
 *     android:exported="false">
 *     <intent-filter>
 *       <action android:name="com.google.firebase.MESSAGING_EVENT" />
 *     </intent-filter>
 *   </service>
 */
class PushNotificationService : FirebaseMessagingService() {

    override fun onMessageReceived(message: RemoteMessage) {
        val data = message.data
        val type = data["type"] ?: "audit_report"
        val title = data["title"] ?: defaultTitle(type)
        val body = data["body"] ?: defaultBody(type, data)

        val channelId = if (type == "threat_alert") CHANNEL_THREAT_ALERT else CHANNEL_AUDIT_REPORT
        val notificationId = System.currentTimeMillis().toInt()

        ensureChannelsCreated()

        val pendingIntent = buildDeepLinkIntent(data)

        val notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_bubble_notification)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(
                if (type == "threat_alert")
                    NotificationCompat.PRIORITY_HIGH
                else
                    NotificationCompat.PRIORITY_DEFAULT
            )
            .setAutoCancel(true)
            .apply { if (pendingIntent != null) setContentIntent(pendingIntent) }
            .build()

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(notificationId, notification)
    }

    override fun onNewToken(token: String) {
        // Forward the refreshed FCM token to the Bubbble backend
        kotlinx.coroutines.GlobalScope.launch {
            BubbbleApiClient.registerPushToken(token)
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun ensureChannelsCreated() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (manager.getNotificationChannel(CHANNEL_AUDIT_REPORT) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_AUDIT_REPORT,
                    "Audit Reports",
                    NotificationManager.IMPORTANCE_DEFAULT,
                ).apply { description = "New audit report available after a link was blocked" }
            )
        }

        if (manager.getNotificationChannel(CHANNEL_THREAT_ALERT) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_THREAT_ALERT,
                    "Threat Alerts",
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply {
                    description = "Real-time alerts for high-severity threats"
                    enableVibration(true)
                }
            )
        }
    }

    private fun buildDeepLinkIntent(data: Map<String, String>): PendingIntent? {
        val reportId = data["report_id"] ?: return null
        val deepLinkIntent = Intent(
            Intent.ACTION_VIEW,
            android.net.Uri.parse("bubbble://audit/$reportId"),
            this,
            LinkInterceptorActivity::class.java,
        ).apply {
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        return PendingIntent.getActivity(
            this,
            reportId.hashCode(),
            deepLinkIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private fun defaultTitle(type: String) = when (type) {
        "threat_alert" -> "⚠ Threat Detected"
        else -> "📋 Audit Report Ready"
    }

    private fun defaultBody(type: String, data: Map<String, String>) = when (type) {
        "threat_alert" -> "A malicious link was blocked: ${data["threat_type"] ?: "unknown threat"}"
        else -> "Your audit report is ready. Tap to view."
    }

    companion object {
        const val CHANNEL_AUDIT_REPORT = "bubbble_audit_reports"
        const val CHANNEL_THREAT_ALERT = "bubbble_threat_alerts"
    }
}
