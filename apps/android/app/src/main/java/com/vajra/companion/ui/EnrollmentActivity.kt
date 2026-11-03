package com.vajra.companion.ui

import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.vajra.companion.R
import com.vajra.companion.crypto.DeviceRequestSigner
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.identity.DeviceNaming
import com.vajra.companion.network.VajraApiClient
import com.vajra.companion.work.CommandPollWorker
import com.vajra.companion.work.HeartbeatWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

class EnrollmentActivity : AppCompatActivity() {

    data class ParsedPairingBundle(
        val serverUrl: String?,
        val enrollmentToken: String,
        val deviceId: String,
        val challengeNonce: String
    )

    companion object {
        fun parsePairingBundleJson(rawJson: String): ParsedPairingBundle? {
            return try {
                val obj = JSONObject(rawJson.trim())
                val token = obj.optString("enrollmentToken").trim()
                    .ifEmpty { obj.optString("token").trim() }
                val deviceId = obj.optString("deviceId").trim()
                val challengeNonce = obj.optString("challengeNonce").trim()
                if (token.isEmpty() || deviceId.isEmpty() || challengeNonce.isEmpty()) {
                    return null
                }
                val origin = obj.optString("origin").trim()
                    .ifEmpty { obj.optString("serverBaseUrl").trim() }
                    .ifEmpty { obj.optString("server").trim() }
                    .trimEnd('/')
                    .takeIf { it.startsWith("http://") || it.startsWith("https://") }
                ParsedPairingBundle(
                    serverUrl = origin,
                    enrollmentToken = token,
                    deviceId = deviceId,
                    challengeNonce = challengeNonce
                )
            } catch (_: Exception) {
                null
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_enrollment)

        val prefs = getSharedPreferences("vajra_settings", MODE_PRIVATE)
        val serverUrlInput = findViewById<EditText>(R.id.inputServerUrl)
        val token = findViewById<EditText>(R.id.inputToken)
        val deviceId = findViewById<EditText>(R.id.inputDeviceId)
        val challenge = findViewById<EditText>(R.id.inputChallenge)
        val result = findViewById<TextView>(R.id.txtEnrollResult)
        val btnPasteBundle = findViewById<Button>(R.id.btnPasteBundle)
        val btn = findViewById<Button>(R.id.btnSubmitEnroll)

        val existingBaseUrl = prefs.getString("serverBaseUrl", getString(R.string.default_server_url))
            ?: getString(R.string.default_server_url)
        serverUrlInput.setText(existingBaseUrl)

        btnPasteBundle.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            val clipText = clipboard?.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()?.trim().orEmpty()
            if (clipText.isEmpty()) {
                result.text = getString(R.string.bundle_empty_clipboard)
                return@setOnClickListener
            }
            val parsed = parsePairingBundleJson(clipText)
            if (parsed == null) {
                result.text = getString(R.string.bundle_invalid)
                return@setOnClickListener
            }
            parsed.serverUrl?.let { origin ->
                serverUrlInput.setText(origin)
                prefs.edit().putString("serverBaseUrl", origin).apply()
            }
            token.setText(parsed.enrollmentToken)
            deviceId.setText(parsed.deviceId)
            challenge.setText(parsed.challengeNonce)
            result.text = getString(R.string.bundle_applied)
        }

        btn.setOnClickListener {
            val configuredUrl = serverUrlInput.text.toString().trim().trimEnd('/')
            if (!configuredUrl.startsWith("http://") && !configuredUrl.startsWith("https://")) {
                result.text = getString(R.string.invalid_server_url)
                return@setOnClickListener
            }
            prefs.edit().putString("serverBaseUrl", configuredUrl).apply()

            val t = token.text.toString().trim()
            val d = deviceId.text.toString().trim()
            val c = challenge.text.toString().trim()
            if (t.isEmpty() || d.isEmpty() || c.isEmpty()) {
                result.text = getString(R.string.enroll_fields_required)
                return@setOnClickListener
            }
            btn.isEnabled = false
            result.text = getString(R.string.enroll_submitting)
            lifecycleScope.launch {
                val message = withContext(Dispatchers.IO) {
                    submitEnrollment(configuredUrl, t, d, c)
                }
                result.text = message
                btn.isEnabled = true
            }
        }
    }

    private fun submitEnrollment(
        baseUrl: String,
        token: String,
        deviceId: String,
        challengeNonce: String
    ): String {
        return try {
            val identity = AndroidKeystoreIdentity(this)
            val pub = identity.rotateKey()

            val timestamp = DeviceRequestSigner.utcTimestampIso()
            val clientNonce = DeviceRequestSigner.newNonce()
            val transcript = DeviceRequestSigner.buildEnrollmentTranscript(
                deviceId, token, challengeNonce, pub.fingerprint, timestamp, clientNonce
            )
            val signature = DeviceRequestSigner.signEcdsaSha256(identity.getPrivateKey(), transcript)
            val resolvedName = DeviceNaming.resolveDeviceName(this)

            val body = JSONObject()
                .put("enrollmentToken", token)
                .put("publicKeyPem", pub.publicKeyPem)
                .put("keyAlgorithm", "ECDSA_P256")
                .put("signatureBase64", signature)
                .put("timestampIso", timestamp)
                .put("clientNonce", clientNonce)
                .put("deviceName", resolvedName)

            val api = VajraApiClient(identity) { baseUrl }
            api.enrollmentSubmit(body).use { res ->
                if (!res.isSuccessful) {
                    return@use "Enrollment failed: HTTP ${res.code}"
                }
                identity.saveMeta(deviceId, baseUrl, "ENROLLMENT_PENDING")
                HeartbeatWorker.schedule(this)
                CommandPollWorker.schedule(this)
                "Submitted. Confirm this device in the VAJRA web console. Local state: ENROLLMENT_PENDING."
            }
        } catch (e: Exception) {
            "Error: ${e.message ?: e.javaClass.simpleName}"
        }
    }
}
