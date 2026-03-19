package com.bubbble

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * Lightweight Bubbble API client for Android.
 * Uses only HttpURLConnection (no third-party HTTP library) to keep the
 * dependency surface minimal.
 *
 * Base URL is read from BuildConfig.BUBBBLE_API_URL at compile time.
 */
object BubbbleApiClient {

    private val baseUrl: String =
        System.getenv("BUBBBLE_API_URL") ?: "https://api.bubbble.com/v1"

    data class ScanResult(
        val safe: Boolean,
        val score: Int,
        val threatType: String?,
        val recommendedAction: String?,
    )

    /** Scan a URL against the Bubbble cloud API. Throws on network error. */
    suspend fun scanUrl(url: String, params: Map<String, Any> = emptyMap()): ScanResult =
        withContext(Dispatchers.IO) {
            val body = JSONObject().apply {
                put("url", url)
                params.forEach { (k, v) -> put(k, v) }
            }.toString()

            val conn = (URL("$baseUrl/scan").openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 8_000
                readTimeout = 12_000
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
            }
            OutputStreamWriter(conn.outputStream).use { it.write(body) }

            val responseBody = conn.inputStream.bufferedReader().readText()
            conn.disconnect()

            val json = JSONObject(responseBody)
            ScanResult(
                safe = json.optBoolean("safe", true),
                score = json.optInt("score", 0),
                threatType = json.optString("threatType").takeIf { it.isNotEmpty() },
                recommendedAction = json.optString("recommendedAction").takeIf { it.isNotEmpty() },
            )
        }

    /** Register an FCM push token with the backend. Fire-and-forget. */
    suspend fun registerPushToken(token: String) = withContext(Dispatchers.IO) {
        runCatching {
            val body = JSONObject().apply {
                put("token", token)
                put("platform", "android")
            }.toString()

            val conn = (URL("$baseUrl/push/register").openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                connectTimeout = 5_000
                readTimeout = 5_000
                setRequestProperty("Content-Type", "application/json")
            }
            OutputStreamWriter(conn.outputStream).use { it.write(body) }
            conn.responseCode  // trigger the request
            conn.disconnect()
        }
    }
}
