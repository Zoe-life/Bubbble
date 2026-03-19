package com.bubbble

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

/**
 * Phase 3 — Android Share-Sheet Integration
 *
 * Allows users to share any link from any app into Bubbble for analysis.
 * Registered as an ACTION_SEND handler for text/plain MIME type so Bubbble
 * appears in the system share sheet when the user shares a URL.
 *
 * Register in AndroidManifest.xml:
 *
 *   <activity android:name=".ShareSheetActivity" android:exported="true">
 *     <intent-filter>
 *       <action android:name="android.intent.action.SEND" />
 *       <category android:name="android.intent.category.DEFAULT" />
 *       <data android:mimeType="text/plain" />
 *     </intent-filter>
 *   </activity>
 */
class ShareSheetActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val sharedUrl = extractUrl(intent)
        if (sharedUrl == null) {
            finish()
            return
        }

        setContent {
            ShareSheetScreen(
                url = sharedUrl,
                onDismiss = { finish() },
                onOpenInBrowser = { url ->
                    openInBrowser(url)
                    finish()
                }
            )
        }
    }

    private fun extractUrl(intent: Intent?): String? {
        if (intent?.action != Intent.ACTION_SEND) return null
        if (intent.type != "text/plain") return null
        val text = intent.getStringExtra(Intent.EXTRA_TEXT) ?: return null
        // Extract the first URL-like substring from the shared text
        return URL_REGEX.find(text)?.value ?: text.trim().takeIf { it.startsWith("http") }
    }

    private fun openInBrowser(url: String) {
        val browserIntent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(browserIntent)
    }

    companion object {
        private val URL_REGEX = Regex("""https?://[^\s]+""")
    }
}

// ── Composable UI ─────────────────────────────────────────────────────────────

@Composable
fun ShareSheetScreen(
    url: String,
    onDismiss: () -> Unit,
    onOpenInBrowser: (String) -> Unit,
) {
    val coroutineScope = rememberCoroutineScope()
    var scanState by remember { mutableStateOf<ScanState>(ScanState.Scanning) }

    LaunchedEffect(url) {
        coroutineScope.launch {
            scanState = performScan(url)
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color(0xCC000000)),
        contentAlignment = Alignment.Center,
    ) {
        Card(
            modifier = Modifier
                .padding(24.dp)
                .fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E2E)),
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                when (val state = scanState) {
                    is ScanState.Scanning -> {
                        CircularProgressIndicator(color = Color(0xFF3B82F6), modifier = Modifier.size(56.dp))
                        Spacer(Modifier.height(16.dp))
                        Text("Scanning link…", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                        Spacer(Modifier.height(8.dp))
                        Text(
                            url.take(60) + if (url.length > 60) "…" else "",
                            color = Color(0xFFAAAAAA),
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center,
                        )
                    }
                    is ScanState.Safe -> {
                        Text("✅", fontSize = 48.sp)
                        Spacer(Modifier.height(12.dp))
                        Text("Link is safe", color = Color(0xFF22C55E), fontSize = 20.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(20.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            OutlinedButton(onClick = onDismiss) { Text("Dismiss", color = Color.White) }
                            Button(
                                onClick = { onOpenInBrowser(url) },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF22C55E)),
                            ) { Text("Open link") }
                        }
                    }
                    is ScanState.Danger -> {
                        Text("⚠️", fontSize = 48.sp)
                        Spacer(Modifier.height(12.dp))
                        Text("Danger — link blocked", color = Color(0xFFEF4444), fontSize = 18.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(8.dp))
                        Text(state.threatType, color = Color(0xFFAAAAAA), fontSize = 13.sp, textAlign = TextAlign.Center)
                        Spacer(Modifier.height(8.dp))
                        Text(state.recommendedAction, color = Color.White, fontSize = 12.sp, textAlign = TextAlign.Center)
                        Spacer(Modifier.height(20.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            Button(
                                onClick = onDismiss,
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF22C55E)),
                            ) { Text("Keep me safe") }
                            OutlinedButton(onClick = { onOpenInBrowser(url) }) {
                                Text("Proceed anyway", color = Color(0xFFEF4444))
                            }
                        }
                    }
                    is ScanState.Error -> {
                        Text("⚠️", fontSize = 48.sp)
                        Spacer(Modifier.height(12.dp))
                        Text("Could not scan link", color = Color.White, fontSize = 16.sp)
                        Spacer(Modifier.height(8.dp))
                        Text("Proceed with caution.", color = Color(0xFFAAAAAA), fontSize = 13.sp)
                        Spacer(Modifier.height(20.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            OutlinedButton(onClick = onDismiss) { Text("Dismiss", color = Color.White) }
                            Button(
                                onClick = { onOpenInBrowser(url) },
                                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF6B7280)),
                            ) { Text("Open anyway") }
                        }
                    }
                }
            }
        }
    }
}

// ── Scan logic (reuses the same API client as LinkInterceptorActivity) ────────

sealed class ScanState {
    object Scanning : ScanState()
    object Safe : ScanState()
    data class Danger(val threatType: String, val recommendedAction: String) : ScanState()
    data class Error(val message: String) : ScanState()
}

private suspend fun performScan(url: String): ScanState {
    return try {
        val result = BubbbleApiClient.scanUrl(url)
        when {
            result.safe -> ScanState.Safe
            else -> ScanState.Danger(
                threatType = result.threatType ?: "Malicious link",
                recommendedAction = result.recommendedAction
                    ?: "Do not visit this link. Report it to the platform you received it from.",
            )
        }
    } catch (e: Exception) {
        ScanState.Error(e.message ?: "Unknown error")
    }
}
