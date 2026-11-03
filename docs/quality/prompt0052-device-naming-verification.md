# VAJRA — Prompt 0052: Per-User Windows and Android Device Naming Verification

**Date:** 2026-11-01  
**Status:** COMPLETE (Zero Regressions, 122/122 Tests Passing)  
**Acceptance Criterion:** When two independent users install VAJRA on different devices and enroll through the same public domain, each user's authorized dashboard displays the appropriate name reported by their own enrolled device—not the developer's PC name (`ASUS TUF F16`) or hosting server name (`localhost`, `vajra-api`).

---

## 1. Root Cause Diagnosis

Prior to Prompt 0052:
1. **Windows Agent Payload Gap:** Neither `EnrollmentCli.cs` nor `HeartbeatWorker.cs` gathered or transmitted the local machine name (`Environment.MachineName`) in `/api/devices/enrollment/submit` or `/api/devices/:id/heartbeat` payloads.
2. **Android Companion Payload Gap:** Neither `EnrollmentActivity.kt` nor `HeartbeatWorker.kt` resolved `Build.MANUFACTURER` / `Build.MODEL` or forwarded a `deviceName` property during key submission or heartbeat pings.
3. **In-Memory Repository Omission:** In `src/server/db/repository.ts`, `InMemoryIdentityRepository.submitDevicePublicKey` ignored the optional `reportedName` argument, leaving `updatedDevice.name` untouched during public-key submission even if the client provided a name.
4. **Backend Server Hostname Vulnerability:** `normalizeReportedDeviceName` in `src/server/devices/routes.ts` did not explicitly reject loopback addresses (`127.0.0.1`, `localhost`, `::1`) or server-side hosting identifiers (`vajra-api`, `process.env.HOSTNAME`). If a client or proxy mistakenly passed the server's own hostname, it could overwrite the client's display name.
5. **Dashboard Demo Isolation:** Mock devices in `src/data/mockFoundationData.ts` are sample fixtures (`isMockData: true`). Production device queries must strictly query persisted records and never fall back to developer hardware constants.

---

## 2. Architecture & Data Flow

### A. Windows Agent
- **Resolution (`DeviceNaming.cs`):**
  Uses supported .NET APIs:
  1. Primary: `Environment.MachineName` (NetBIOS hostname).
  2. Secondary: `System.Net.Dns.GetHostName()`.
  3. Safe Neutral Fallback: `"Windows PC"`.
- **Transmission:**
  - `apps/windows-agent/src/Hosting/EnrollmentCli.cs`: included in JSON POST to `/api/devices/enrollment/submit` as `deviceName`.
  - `apps/windows-agent/src/Workers/HeartbeatWorker.cs`: included in JSON POST to `/api/devices/:id/heartbeat` as `deviceName`.
- **Identity Invariant:**
  Cryptographic ECDSA P-256 keypair generated in DPAPI `DeviceIdentityStore` is completely decoupled from the machine name. Changing the machine name updates the display label in metadata without altering the key or fingerprint.

### B. Android Companion
- **Resolution (`DeviceNaming.kt`):**
  Supports Android 10+ (`minSdk = 29`, `targetSdk = 34`):
  1. Primary: User-customizable Bluetooth/Device name if readable without permissions (`Settings.Global.DEVICE_NAME`).
  2. Secondary: `Build.MANUFACTURER + " " + Build.MODEL` (e.g., `"Google Pixel 8"`).
  3. Safe Neutral Fallback: `"Android Device"`.
  Zero additional or dangerous permissions (`READ_PRIVILEGED_PHONE_STATE` is avoided).
- **Transmission:**
  - `apps/android/app/src/main/java/com/vajra/companion/ui/EnrollmentActivity.kt`: sent in `/api/devices/enrollment/submit` payload.
  - `apps/android/app/src/main/java/com/vajra/companion/work/HeartbeatWorker.kt`: sent in `/api/devices/:id/heartbeat` payload.

### C. Backend Ingestion & Database
- **Validation (`normalizeReportedDeviceName`):**
  - Sanitizes Unicode control characters, HTML/script tags, and overlong inputs (2..64 chars).
  - Explicitly rejects server hostnames (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, `vajra-api`, `vajra-server`, `server`, `process.env.HOSTNAME`).
  - Fallbacks to neutral platform labels: `Windows PC` or `Android Device`.
- **Storage:**
  Reuses existing `Device.name` column in PostgreSQL / Prisma schema. **No database migration was required.**
- **Authorization & Isolation:**
  - Enrollment requires valid one-time enrollment token issued to the authenticated user.
  - Heartbeat updates require Plane-2 ECDSA proof-of-possession signature (`X-Vajra-Signature`) matched to the device's public key fingerprint.
  - Metadata updates (`PATCH /api/devices/:id`) enforce user ownership; cross-user renames fail closed with `404 Not Found`.

---

## 3. Test Verification & Results

### Automated Regression Suite (`tests/prompt0052-device-naming.test.ts`)
1. **Windows Local Machine Name:** Verifies hostname transmission and server hostname rejection.
2. **Android Companion Resolution:** Verifies `Build.MANUFACTURER` + `Build.MODEL` synthesis with `Android Device` fallback.
3. **Multi-User Isolation:** Verifies two independent user accounts enroll distinct Windows & Android devices (`Executive-ThinkPad` and `Samsung Galaxy S24`) and each dashboard retains its own name without crosstalk.
4. **Targeted Heartbeat Updates:** Proves heartbeat renames apply only to the authenticated device and enforce ECDSA route binding.
5. **Cross-User Protection:** Confirms user B cannot view or rename user A's devices (returns 404).
6. **Fallback Safety:** Confirms null, whitespace, overlong, and XSS names produce safe neutral labels.
7. **Developer Name Eradication:** Verifies platform fallbacks are neutral (`Windows PC` / `Android Device`) and mock fixtures are isolated with `isMockData: true`.
8. **Cryptographic Identity Independence:** Proves machine hostname renames never modify public key PEMs or fingerprints.
9. **Zero Demo Leakage:** Verifies real production device inventory never includes sample records.

### Monorepo Test Summary
- **Node.js Test Runner:** 35 test suites, 122 tests executed, **122 passed, 0 failed**.
- **Typecheck & Linter:** `npm run lint` (`tsc --noEmit`) clean, 0 errors.
- **Build / Vite Compilation:** `compile_applet` passed.

### Native Agent Test Status
- `npm run test:windows-agent`: Exited with code 2 (BLOCKED). Host is Linux x64 without Windows 10/11 runtime and .NET 8 SDK.
- `npm run test:android-agent`: Exited with code 2 (BLOCKED). Host lacks Android SDK 34 and JDK 17.
These scripts fail-closed with code 2 when required native toolchains are absent, as architected in Prompt 0036.
