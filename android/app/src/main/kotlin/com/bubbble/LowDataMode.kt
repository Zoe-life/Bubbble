package com.bubbble

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Phase 3 — Android Low-Data Mode
 *
 * When the user is on a metered mobile-data connection, Bubbble switches to
 * a lightweight scan strategy:
 *
 *   Wi-Fi / unmetered   → Full cloud scan (all signals: Safe Browsing,
 *                          VirusTotal, PhishTank, headless preview, WHOIS, SSL)
 *   Mobile data         → Lightweight scan (offline blocklist only +
 *                          Safe Browsing API; skips VirusTotal + content preview)
 *   No connectivity     → Offline blocklist only
 *
 * The scan strategy is exposed via a StateFlow so any composable or coroutine
 * can react to connectivity changes without polling.
 */
enum class ScanStrategy {
    /** Full cloud scan — all signals. */
    FULL,
    /** Mobile-data mode — fast lightweight scan; skips expensive operations. */
    LIGHTWEIGHT,
    /** No connectivity — offline blocklist only. */
    OFFLINE,
}

class LowDataModeManager(private val context: Context) {

    private val _strategy = MutableStateFlow(detectCurrentStrategy())
    val strategy: StateFlow<ScanStrategy> = _strategy

    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(
            network: Network,
            capabilities: NetworkCapabilities,
        ) {
            _strategy.value = strategyFromCapabilities(capabilities)
        }

        override fun onLost(network: Network) {
            _strategy.value = ScanStrategy.OFFLINE
        }
    }

    /** Start monitoring network changes. Call from Application.onCreate(). */
    fun startMonitoring() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager.registerNetworkCallback(request, networkCallback)
    }

    /** Stop monitoring. Call when no longer needed. */
    fun stopMonitoring() {
        try {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        } catch (_: IllegalArgumentException) {
            // Not registered — safe to ignore
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun detectCurrentStrategy(): ScanStrategy {
        val capabilities = connectivityManager
            .getNetworkCapabilities(connectivityManager.activeNetwork)
            ?: return ScanStrategy.OFFLINE
        return strategyFromCapabilities(capabilities)
    }

    private fun strategyFromCapabilities(capabilities: NetworkCapabilities): ScanStrategy {
        if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
            return ScanStrategy.OFFLINE
        }
        // NOT_METERED means Wi-Fi / Ethernet — use full scan
        if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) {
            return ScanStrategy.FULL
        }
        return ScanStrategy.LIGHTWEIGHT
    }
}

/**
 * Extension function: build the scan parameters for BubbbleApiClient based on
 * the active strategy.
 */
fun ScanStrategy.toApiParams(): Map<String, Any> = when (this) {
    ScanStrategy.FULL -> mapOf(
        "signals" to listOf("safe_browsing", "virustotal", "phishtank", "whois", "ssl", "content_preview"),
    )
    ScanStrategy.LIGHTWEIGHT -> mapOf(
        "signals" to listOf("safe_browsing", "phishtank"),
        "lightweight" to true,
    )
    ScanStrategy.OFFLINE -> mapOf(
        "offline" to true,
    )
}
