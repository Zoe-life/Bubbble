/*
 * Phase 3, Point 3 — System-level link interception via Android Intent filters
 *
 * This Activity declares Intent filters in AndroidManifest.xml so Android
 * routes every http/https link tap (from any app) through Bubbble before
 * allowing navigation. The URL is submitted to the Bubbble scanning API;
 * the result determines whether the user is forwarded or shown a block screen.
 */

package com.bubbble

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

private const val TAG = "BubbbleLinkInterceptor"

/**
 * LinkInterceptorActivity
 *
 * Register in AndroidManifest.xml with the following Intent filter to intercept
 * every http/https link opened system-wide:
 *
 * ```xml
 * <activity
 *     android:name=".LinkInterceptorActivity"
 *     android:exported="true"
 *     android:launchMode="singleTask"
 *     android:theme="@style/Theme.Bubbble.Translucent">
 *
 *     <!-- Deep-link / App Link interception -->
 *     <intent-filter android:autoVerify="true">
 *         <action android:name="android.intent.action.VIEW" />
 *         <category android:name="android.intent.category.DEFAULT" />
 *         <category android:name="android.intent.category.BROWSABLE" />
 *         <data android:scheme="https" />
 *         <data android:scheme="http" />
 *     </intent-filter>
 * </activity>
 * ```
 */
class LinkInterceptorActivity : ComponentActivity() {

    // ------------------------------------------------------------------
    // Scan states
    // ------------------------------------------------------------------

    private sealed class ScanState {
        object Scanning : ScanState()
        data class Safe(val url: String) : ScanState()
        data class Danger(val url: String, val reason: String) : ScanState()
        data class Error(val url: String, val message: String) : ScanState()
    }

    // ------------------------------------------------------------------
    // HTTP client shared across the activity lifetime
    // ------------------------------------------------------------------

    private val httpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
    }

    // ------------------------------------------------------------------
    // Activity lifecycle
    // ------------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val targetUrl = resolveTargetUrl(intent)
        if (targetUrl == null) {
            Log.w(TAG, "No URL found in Intent — finishing immediately")
            finish()
            return
        }

        Log.d(TAG, "Intercepted URL: $targetUrl")

        val scanState = mutableStateOf<ScanState>(ScanState.Scanning)

        setContent {
            MaterialTheme {
                BubbleOverlayScreen(
                    state = scanState.value,
                    onKeepSafe = { finish() },
                    onProceedAnyway = {
                        openInBrowser(targetUrl)
                        finish()
                    }
                )
            }
        }

        // Kick off scanning coroutine
        lifecycleScope.launch {
            scanState.value = scanUrl(targetUrl)
            if (scanState.value is ScanState.Safe) {
                // Auto-forward to the original destination
                openInBrowser(targetUrl)
                finish()
            }
        }
    }

    // ------------------------------------------------------------------
    // URL extraction
    // ------------------------------------------------------------------

    private fun resolveTargetUrl(intent: Intent?): String? {
        intent ?: return null
        return when {
            intent.action == Intent.ACTION_VIEW && intent.data != null ->
                intent.data.toString()
            intent.hasExtra(EXTRA_URL) ->
                intent.getStringExtra(EXTRA_URL)
            else -> null
        }
    }

    // ------------------------------------------------------------------
    // URL scanning (calls Bubbble backend API)
    // ------------------------------------------------------------------

    private suspend fun scanUrl(url: String): ScanState = withContext(Dispatchers.IO) {
        return@withContext try {
            val body = JSONObject().put("url", url).toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(BuildConfig.BUBBBLE_API_BASE_URL + "/v1/scan")
                .post(body)
                .addHeader("Authorization", "Bearer ${BuildConfig.BUBBBLE_API_KEY}")
                .build()

            val response = httpClient.newCall(request).execute()
            val responseBody = response.body?.string() ?: ""

            if (!response.isSuccessful) {
                Log.e(TAG, "Scan API error ${response.code}: $responseBody")
                // Fail open — treat as safe to avoid blocking legitimate links
                ScanState.Safe(url)
            } else {
                val json = JSONObject(responseBody)
                val safe = json.optBoolean("safe", true)
                val reason = json.optString("reason", "")
                if (safe) ScanState.Safe(url) else ScanState.Danger(url, reason)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Scan request failed: ${e.message}", e)
            // Fail open on network errors
            ScanState.Error(url, e.message ?: "Unknown error")
        }
    }

    // ------------------------------------------------------------------
    // Browser forwarding
    // ------------------------------------------------------------------

    private fun openInBrowser(url: String) {
        val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
            // Exclude ourselves to prevent a routing loop
            `package` = getDefaultBrowserPackage() ?: return@apply
        }
        startActivity(browserIntent)
    }

    private fun getDefaultBrowserPackage(): String? {
        val dummyIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com"))
        val resolvedPackage = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            packageManager.resolveActivity(
                dummyIntent,
                android.content.pm.PackageManager.ResolveInfoFlags.of(0)
            )?.activityInfo?.packageName
        } else {
            @Suppress("DEPRECATION")
            packageManager.resolveActivity(dummyIntent, 0)?.activityInfo?.packageName
        }
        return resolvedPackage?.takeIf { it != packageName }
    }

    companion object {
        const val EXTRA_URL = "bubbble_target_url"
    }
}

// ---------------------------------------------------------------------------
// Composable UI — mirrors the BubbleOverlay React component for mobile
// ---------------------------------------------------------------------------

@Composable
private fun BubbleOverlayScreen(
    state: LinkInterceptorActivity.ScanState,
    onKeepSafe: () -> Unit,
    onProceedAnyway: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            BubbleSphere(state = state)

            val (label, sub) = when (state) {
                is LinkInterceptorActivity.ScanState.Scanning ->
                    "Checking link…" to "Bubbble is scanning this URL for threats."
                is LinkInterceptorActivity.ScanState.Safe ->
                    "Link is safe ✓" to "Taking you there now."
                is LinkInterceptorActivity.ScanState.Danger ->
                    "Link blocked 🚫" to (state.reason.ifBlank {
                        "This link appears malicious. We've blocked it to protect you."
                    })
                is LinkInterceptorActivity.ScanState.Error ->
                    "Link is safe ✓" to "Scan encountered an issue — proceeding."
            }

            Text(
                text = label,
                style = MaterialTheme.typography.headlineSmall,
                textAlign = TextAlign.Center,
            )
            Text(
                text = sub,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )

            if (state is LinkInterceptorActivity.ScanState.Danger) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = onKeepSafe) { Text("Keep me safe") }
                    OutlinedButton(onClick = onProceedAnyway) { Text("Proceed anyway") }
                }
            }
        }
    }
}

/**
 * Placeholder for the animated bubble sphere composable.
 * Replace with a Lottie animation or custom Canvas drawing.
 */
@Composable
private fun BubbleSphere(state: LinkInterceptorActivity.ScanState) {
    val color = when (state) {
        is LinkInterceptorActivity.ScanState.Danger -> MaterialTheme.colorScheme.error
        is LinkInterceptorActivity.ScanState.Safe,
        is LinkInterceptorActivity.ScanState.Error -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.secondary
    }
    Surface(
        modifier = Modifier.size(140.dp),
        shape = androidx.compose.foundation.shape.CircleShape,
        color = color.copy(alpha = 0.2f),
        tonalElevation = 4.dp,
    ) {}
}
