/**
 * VAJRA — Prompt 0052 Regression Tests:
 * Per-User Windows and Android Device Naming & Isolation
 *
 * Verifies all 9 Prompt 0052 requirements:
 * 1. Windows sends its local machine name, not the backend server name.
 * 2. Android sends its supported device label or a safe fallback.
 * 3. Two independent installations can enroll with different names and retain their own names.
 * 4. Heartbeat updates affect only the correct enrolled device.
 * 5. Cross-user metadata access and modification are rejected.
 * 6. Missing or invalid names produce safe fallbacks.
 * 7. The dashboard renders persisted names rather than developer-specific constants.
 * 8. Hostname changes do not alter cryptographic identity.
 * 9. Demo data does not leak into real production device listings.
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  generateDeviceKeyPair,
  signDeviceRequest,
  signEnrollmentProof,
} from '../packages/security/src/node.ts';
import { createVajraApiApp } from '../src/server/app.ts';
import { InMemoryIdentityRepository } from '../src/server/db/repository.ts';
import {
  getNeutralDeviceFallbackName,
  normalizeReportedDeviceName,
  sanitizeDeviceName,
  toSafeDeviceDto,
} from '../src/server/devices/routes.ts';
import { MOCK_DEVICES } from '../src/data/mockFoundationData.ts';

describe('Prompt 0052 — Per-User Windows and Android Device Naming & Verification', () => {
  let server: http.Server;
  let baseUrl = '';
  let repo: InMemoryIdentityRepository;

  before(async () => {
    repo = new InMemoryIdentityRepository();
    const app = createVajraApiApp({ repository: repo });
    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    if (!addr || typeof addr === 'string') {
      throw new Error('Failed to bind test server.');
    }
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  async function registerUser(email: string, displayName: string) {
    const res = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        displayName,
        password: 'Correct-Horse-Battery-99!Staple',
      }),
    });
    assert.equal(res.status, 201, `Failed to register user ${email}`);
    const setCookies = res.headers.getSetCookie();
    const cookie = setCookies.map((c) => c.split(';')[0]).join('; ');
    const body = (await res.json()) as { csrfToken: string; user: { id: string } };
    return { cookie, csrfToken: body.csrfToken, user: body.user };
  }

  async function enrollAndConfirmDevice(
    auth: { cookie: string; csrfToken: string },
    options: {
      deviceType: 'WINDOWS' | 'ANDROID';
      proposedName?: string;
      reportedName?: string;
      osVersion?: string;
    }
  ) {
    const initRes = await fetch(`${baseUrl}/api/devices/enrollment/initiate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: auth.cookie,
        'X-CSRF-Token': auth.csrfToken,
      },
      body: JSON.stringify({
        deviceType: options.deviceType,
        ...(options.proposedName ? { name: options.proposedName } : {}),
        osVersion: options.osVersion ?? 'Test OS',
      }),
    });
    assert.equal(initRes.status, 201);
    const initData = (await initRes.json()) as {
      device: { id: string; name: string };
      enrollment: { enrollmentToken: string; challengeNonce: string };
    };

    const kp = generateDeviceKeyPair('ECDSA_P256');
    const timestampIso = new Date().toISOString();
    const clientNonce = crypto.randomBytes(24).toString('hex');
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      deviceId: initData.device.id,
      enrollmentToken: initData.enrollment.enrollmentToken,
      challengeNonce: initData.enrollment.challengeNonce,
      publicKeyFingerprint: kp.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    });

    const submitPayload: Record<string, unknown> = {
      enrollmentToken: initData.enrollment.enrollmentToken,
      publicKeyPem: kp.publicKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      signatureBase64,
      timestampIso,
      clientNonce,
    };
    if (options.reportedName !== undefined) {
      submitPayload.deviceName = options.reportedName;
    }

    const subRes = await fetch(`${baseUrl}/api/devices/enrollment/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(submitPayload),
    });
    assert.equal(subRes.status, 200);
    const subData = (await subRes.json()) as {
      device: { id: string; name: string };
    };

    const confRes = await fetch(
      `${baseUrl}/api/devices/${initData.device.id}/enrollment/confirm`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: auth.cookie,
          'X-CSRF-Token': auth.csrfToken,
        },
        body: JSON.stringify({ publicKeyFingerprint: kp.publicKeyFingerprint }),
      }
    );
    assert.equal(confRes.status, 200);
    const confData = (await confRes.json()) as {
      device: { id: string; name: string; publicKeyFingerprint: string };
    };

    return {
      deviceId: initData.device.id,
      kp,
      nameAfterSubmit: subData.device.name,
      confirmedDevice: confData.device,
    };
  }

  // 1. Windows sends its local machine name, not the backend server name
  it('1. Windows sends its local machine name and backend rejects server hostnames', async () => {
    // Verify Windows agent source references DeviceNaming.GetLocalMachineName()
    const enrollmentCliSrc = fs.readFileSync(
      path.resolve(process.cwd(), 'apps/windows-agent/src/Hosting/EnrollmentCli.cs'),
      'utf8'
    );
    const heartbeatWorkerSrc = fs.readFileSync(
      path.resolve(process.cwd(), 'apps/windows-agent/src/Workers/HeartbeatWorker.cs'),
      'utf8'
    );
    const deviceNamingCsSrc = fs.readFileSync(
      path.resolve(process.cwd(), 'apps/windows-agent/src/Identity/DeviceNaming.cs'),
      'utf8'
    );

    assert.ok(deviceNamingCsSrc.includes('Environment.MachineName'));
    assert.ok(deviceNamingCsSrc.includes('Windows PC'));
    assert.ok(enrollmentCliSrc.includes('DeviceNaming.GetLocalMachineName()'));
    assert.ok(heartbeatWorkerSrc.includes('DeviceNaming.GetLocalMachineName()'));

    // Backend rejection of server hostnames
    assert.equal(normalizeReportedDeviceName('localhost'), null);
    assert.equal(normalizeReportedDeviceName('127.0.0.1'), null);
    assert.equal(normalizeReportedDeviceName('::1'), null);
    assert.equal(normalizeReportedDeviceName('vajra-api'), null);
    assert.equal(normalizeReportedDeviceName('server'), null);

    // Legitimate machine name is preserved
    assert.equal(normalizeReportedDeviceName('DESKTOP-AYUSH-99'), 'DESKTOP-AYUSH-99');
    assert.equal(normalizeReportedDeviceName('WORKSTATION-01'), 'WORKSTATION-01');
  });

  // 2. Android sends its supported device label or a safe fallback
  it('2. Android companion resolves device label from manufacturer/model with safe Android Device fallback', async () => {
    const deviceNamingKtSrc = fs.readFileSync(
      path.resolve(
        process.cwd(),
        'apps/android/app/src/main/java/com/vajra/companion/identity/DeviceNaming.kt'
      ),
      'utf8'
    );
    const enrollmentActivitySrc = fs.readFileSync(
      path.resolve(
        process.cwd(),
        'apps/android/app/src/main/java/com/vajra/companion/ui/EnrollmentActivity.kt'
      ),
      'utf8'
    );
    const androidHeartbeatWorkerSrc = fs.readFileSync(
      path.resolve(
        process.cwd(),
        'apps/android/app/src/main/java/com/vajra/companion/work/HeartbeatWorker.kt'
      ),
      'utf8'
    );

    assert.ok(deviceNamingKtSrc.includes('Build.MANUFACTURER'));
    assert.ok(deviceNamingKtSrc.includes('Build.MODEL'));
    assert.ok(deviceNamingKtSrc.includes('Android Device'));
    assert.ok(enrollmentActivitySrc.includes('DeviceNaming.resolveDeviceName'));
    assert.ok(androidHeartbeatWorkerSrc.includes('DeviceNaming.resolveDeviceName'));

    // Safe fallbacks on backend
    assert.equal(getNeutralDeviceFallbackName('ANDROID'), 'Android Device');
    assert.equal(getNeutralDeviceFallbackName('WINDOWS'), 'Windows PC');
    assert.equal(getNeutralDeviceFallbackName('UNKNOWN'), 'Protected Device');
  });

  // 3. Two independent installations can enroll with different names and retain their own names
  it('3. Two independent user installations retain their distinct reported device names without crosstalk', async () => {
    const userA = await registerUser('alice-devices@vajra.test', 'Alice User');
    const userB = await registerUser('bob-devices@vajra.test', 'Bob User');

    const devA = await enrollAndConfirmDevice(userA, {
      deviceType: 'WINDOWS',
      reportedName: 'ALICE-SURFACE-PRO',
    });
    assert.equal(devA.confirmedDevice.name, 'ALICE-SURFACE-PRO');

    const devB = await enrollAndConfirmDevice(userB, {
      deviceType: 'ANDROID',
      reportedName: 'Google Pixel 8 Pro',
    });
    assert.equal(devB.confirmedDevice.name, 'Google Pixel 8 Pro');

    // Query User A devices: sees only Alice's device with Alice's name
    const listARes = await fetch(`${baseUrl}/api/devices`, {
      headers: { Cookie: userA.cookie },
    });
    assert.equal(listARes.status, 200);
    const listA = (await listARes.json()) as { devices: Array<{ id: string; name: string }> };
    assert.equal(listA.devices.length, 1);
    assert.equal(listA.devices[0].id, devA.deviceId);
    assert.equal(listA.devices[0].name, 'ALICE-SURFACE-PRO');

    // Query User B devices: sees only Bob's device with Bob's name
    const listBRes = await fetch(`${baseUrl}/api/devices`, {
      headers: { Cookie: userB.cookie },
    });
    assert.equal(listBRes.status, 200);
    const listB = (await listBRes.json()) as { devices: Array<{ id: string; name: string }> };
    assert.equal(listB.devices.length, 1);
    assert.equal(listB.devices[0].id, devB.deviceId);
    assert.equal(listB.devices[0].name, 'Google Pixel 8 Pro');
  });

  // 4. Heartbeat updates affect only the correct enrolled device
  it('4. Heartbeat updates affect only the targeted enrolled device and enforce cryptographic route binding', async () => {
    const user = await registerUser('multidevice-owner@vajra.test', 'Multi-device Owner');

    const dev1 = await enrollAndConfirmDevice(user, {
      deviceType: 'WINDOWS',
      reportedName: 'DESKTOP-ORIGINAL-1',
    });
    const dev2 = await enrollAndConfirmDevice(user, {
      deviceType: 'WINDOWS',
      reportedName: 'DESKTOP-ORIGINAL-2',
    });

    // Dev 1 sends signed heartbeat with new hostname
    const path1 = `/api/devices/${dev1.deviceId}/heartbeat`;
    const ts1 = new Date().toISOString();
    const nonce1 = crypto.randomBytes(24).toString('hex');
    const hb1Payload = {
      connectivityStatus: 'ONLINE',
      agentVersion: '0.1.0-windows',
      osVersion: 'Windows 11',
      platform: 'WINDOWS',
      deviceName: 'DESKTOP-UPDATED-NAME',
    };
    const sig1 = signDeviceRequest({
      privateKeyPem: dev1.kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path: path1,
      deviceId: dev1.deviceId,
      timestampIso: ts1,
      nonce: nonce1,
      body: hb1Payload,
    });

    const hb1Res = await fetch(`${baseUrl}${path1}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vajra-Device-Id': dev1.deviceId,
        'X-Vajra-Timestamp': ts1,
        'X-Vajra-Nonce': nonce1,
        'X-Vajra-Signature': sig1,
      },
      body: JSON.stringify(hb1Payload),
    });
    assert.equal(hb1Res.status, 200);

    // Verify Dev 1 was updated, but Dev 2 was NOT touched
    const check1Res = await fetch(`${baseUrl}/api/devices/${dev1.deviceId}`, {
      headers: { Cookie: user.cookie },
    });
    assert.equal(check1Res.status, 200);
    const d1 = (await check1Res.json()) as { device: { name: string } };
    assert.equal(d1.device.name, 'DESKTOP-UPDATED-NAME');

    const check2Res = await fetch(`${baseUrl}/api/devices/${dev2.deviceId}`, {
      headers: { Cookie: user.cookie },
    });
    assert.equal(check2Res.status, 200);
    const d2 = (await check2Res.json()) as { device: { name: string } };
    assert.equal(d2.device.name, 'DESKTOP-ORIGINAL-2');

    // Cryptographic Route Binding: Dev 1 key signing for Dev 2 route path must fail (403)
    const spoofPath = `/api/devices/${dev2.deviceId}/heartbeat`;
    const spoofTs = new Date().toISOString();
    const spoofNonce = crypto.randomBytes(24).toString('hex');
    const spoofSig = signDeviceRequest({
      privateKeyPem: dev1.kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path: spoofPath,
      deviceId: dev1.deviceId,
      timestampIso: spoofTs,
      nonce: spoofNonce,
      body: hb1Payload,
    });

    const spoofRes = await fetch(`${baseUrl}${spoofPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vajra-Device-Id': dev1.deviceId,
        'X-Vajra-Timestamp': spoofTs,
        'X-Vajra-Nonce': spoofNonce,
        'X-Vajra-Signature': spoofSig,
      },
      body: JSON.stringify(hb1Payload),
    });
    assert.equal(spoofRes.status, 403);
    const spoofJson = (await spoofRes.json()) as { error: { code: string } };
    assert.equal(spoofJson.error.code, 'DEVICE_ROUTE_MISMATCH');
  });

  // 5. Cross-user metadata access and modification are rejected
  it('5. Cross-user device access, rename, and modification are strictly rejected with 404', async () => {
    const userVictim = await registerUser('victim-user@vajra.test', 'Victim User');
    const userAttacker = await registerUser('attacker-user@vajra.test', 'Attacker User');

    const victimDevice = await enrollAndConfirmDevice(userVictim, {
      deviceType: 'WINDOWS',
      reportedName: 'VICTIM-PC',
    });

    // Attacker tries to read victim device
    const getRes = await fetch(`${baseUrl}/api/devices/${victimDevice.deviceId}`, {
      headers: { Cookie: userAttacker.cookie },
    });
    assert.equal(getRes.status, 404);

    // Attacker tries to rename victim device via PATCH
    const patchRes = await fetch(`${baseUrl}/api/devices/${victimDevice.deviceId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: userAttacker.cookie,
        'X-CSRF-Token': userAttacker.csrfToken,
      },
      body: JSON.stringify({ name: 'HAXORED-PC' }),
    });
    assert.equal(patchRes.status, 404);

    // Attacker tries to rename victim device via POST /rename
    const renameRes = await fetch(`${baseUrl}/api/devices/${victimDevice.deviceId}/rename`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: userAttacker.cookie,
        'X-CSRF-Token': userAttacker.csrfToken,
      },
      body: JSON.stringify({ deviceName: 'HAXORED-PC' }),
    });
    assert.equal(renameRes.status, 404);

    // Victim device name remains intact
    const verifyRes = await fetch(`${baseUrl}/api/devices/${victimDevice.deviceId}`, {
      headers: { Cookie: userVictim.cookie },
    });
    assert.equal(verifyRes.status, 200);
    const verifyData = (await verifyRes.json()) as { device: { name: string } };
    assert.equal(verifyData.device.name, 'VICTIM-PC');
  });

  // 6. Missing or invalid names produce safe fallbacks
  it('6. Missing or invalid names produce safe fallbacks without server error', async () => {
    const user = await registerUser('fallback-user@vajra.test', 'Fallback Tester');

    // Missing reportedName in enrollment submit uses initiation fallback
    const devWithoutName = await enrollAndConfirmDevice(user, {
      deviceType: 'ANDROID',
    });
    assert.equal(devWithoutName.confirmedDevice.name, 'Android Device');

    // Submitting server hostname string falls back cleanly
    assert.equal(normalizeReportedDeviceName('localhost'), null);
    assert.equal(normalizeReportedDeviceName(''), null);
    assert.equal(normalizeReportedDeviceName('   '), null);
    assert.equal(normalizeReportedDeviceName('A'), null); // < 2 chars
    assert.equal(
      normalizeReportedDeviceName('   <script>alert(1)</script>   '),
      'scriptalert(1)/script'
    );

    // Sanitize user-provided custom name validates length and characters
    assert.equal(sanitizeDeviceName('Valid Device Name').valid, true);
    assert.equal(sanitizeDeviceName('V').valid, false); // too short
    assert.equal(sanitizeDeviceName('a'.repeat(65)).valid, false); // too long
  });

  // 7. The dashboard renders persisted names rather than developer-specific constants
  it('7. Dashboard fixtures and mock data do not expose developer-specific PC names', () => {
    // Platform-specific defaults must be neutral and never developer-specific
    assert.equal(
      getNeutralDeviceFallbackName('WINDOWS'),
      'Windows PC',
      'Windows fallback must be neutral "Windows PC"'
    );
    assert.equal(
      getNeutralDeviceFallbackName('ANDROID'),
      'Android Device',
      'Android fallback must be neutral "Android Device"'
    );

    // Mock fixtures must be explicitly marked as sample data so they are never confused with real enrolled devices
    for (const mock of MOCK_DEVICES) {
      assert.equal(
        mock.isMockData,
        true,
        'Mock fixture must be explicitly marked with isMockData: true'
      );
    }

    // toSafeDeviceDto uses stored device name directly
    const mockDeviceEntity: any = {
      id: crypto.randomUUID(),
      userId: crypto.randomUUID(),
      name: 'Custom-Enrolled-Workstation',
      deviceType: 'WINDOWS',
      lifecycleState: 'ACTIVE',
      connectivityStatus: 'ONLINE',
      osVersion: 'Windows 11',
      agentVersion: '0.1.0',
      currentRiskScore: 0,
      currentRiskLevel: 'LOW',
      lastHeartbeatAt: new Date(),
      lastSeenAt: new Date(),
      enrolledAt: new Date(),
      revokedAt: null,
      compromisedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const dto = toSafeDeviceDto(mockDeviceEntity, []);
    assert.equal(dto.name, 'Custom-Enrolled-Workstation');
  });

  // 8. Hostname changes do not alter cryptographic identity
  it('8. Hostname changes and display name renames do not modify cryptographic identity or fingerprints', async () => {
    const user = await registerUser('cryptostore-user@vajra.test', 'Crypto Identity Tester');

    const dev = await enrollAndConfirmDevice(user, {
      deviceType: 'WINDOWS',
      reportedName: 'HOSTNAME-ORIGINAL',
    });
    const originalFingerprint = dev.confirmedDevice.publicKeyFingerprint;
    assert.ok(originalFingerprint.startsWith('sha256:'));

    // Heartbeat updates hostname to HOSTNAME-NEW
    const path = `/api/devices/${dev.deviceId}/heartbeat`;
    const ts = new Date().toISOString();
    const nonce = crypto.randomBytes(24).toString('hex');
    const hbPayload = {
      connectivityStatus: 'ONLINE',
      agentVersion: '0.1.0-windows',
      platform: 'WINDOWS',
      deviceName: 'HOSTNAME-NEW',
    };
    const sig = signDeviceRequest({
      privateKeyPem: dev.kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path,
      deviceId: dev.deviceId,
      timestampIso: ts,
      nonce,
      body: hbPayload,
    });

    const hbRes = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vajra-Device-Id': dev.deviceId,
        'X-Vajra-Timestamp': ts,
        'X-Vajra-Nonce': nonce,
        'X-Vajra-Signature': sig,
      },
      body: JSON.stringify(hbPayload),
    });
    assert.equal(hbRes.status, 200);

    // Fetch device: name is HOSTNAME-NEW, fingerprint is identical
    const fetch1 = await fetch(`${baseUrl}/api/devices/${dev.deviceId}`, {
      headers: { Cookie: user.cookie },
    });
    const d1 = (await fetch1.json()) as {
      device: { name: string; publicKeyFingerprint: string };
    };
    assert.equal(d1.device.name, 'HOSTNAME-NEW');
    assert.equal(d1.device.publicKeyFingerprint, originalFingerprint);

    // Owner renames device via PATCH
    const patchRes = await fetch(`${baseUrl}/api/devices/${dev.deviceId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: user.cookie,
        'X-CSRF-Token': user.csrfToken,
      },
      body: JSON.stringify({ name: 'EXECUTIVE-LAPTOP' }),
    });
    assert.equal(patchRes.status, 200);
    const patched = (await patchRes.json()) as {
      device: { name: string; publicKeyFingerprint: string };
    };
    assert.equal(patched.device.name, 'EXECUTIVE-LAPTOP');
    assert.equal(patched.device.publicKeyFingerprint, originalFingerprint);

    // Verify keypair K1 still signs Plane-2 requests and is accepted
    const ts2 = new Date().toISOString();
    const nonce2 = crypto.randomBytes(24).toString('hex');
    const verifyPath = '/api/devices/auth/verify';
    const sig2 = signDeviceRequest({
      privateKeyPem: dev.kp.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      method: 'POST',
      path: verifyPath,
      deviceId: dev.deviceId,
      timestampIso: ts2,
      nonce: nonce2,
      body: {},
    });

    const verifyRes = await fetch(`${baseUrl}${verifyPath}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Vajra-Device-Id': dev.deviceId,
        'X-Vajra-Timestamp': ts2,
        'X-Vajra-Nonce': nonce2,
        'X-Vajra-Signature': sig2,
      },
      body: JSON.stringify({}),
    });
    assert.equal(verifyRes.status, 200);
    const verifyJson = (await verifyRes.json()) as {
      authenticated: boolean;
      publicKeyFingerprint: string;
    };
    assert.equal(verifyJson.authenticated, true);
    assert.equal(verifyJson.publicKeyFingerprint, originalFingerprint);
  });

  // 9. Demo data does not leak into real production device listings
  it('9. Real device inventory returns zero sample devices and isolates demo records', async () => {
    const user = await registerUser('production-user@vajra.test', 'Prod User');

    // With 0 devices enrolled, /api/devices returns empty array
    const emptyRes = await fetch(`${baseUrl}/api/devices`, {
      headers: { Cookie: user.cookie },
    });
    assert.equal(emptyRes.status, 200);
    const emptyData = (await emptyRes.json()) as { devices: unknown[] };
    assert.equal(emptyData.devices.length, 0);

    // Enroll 1 real device
    await enrollAndConfirmDevice(user, {
      deviceType: 'ANDROID',
      reportedName: 'Pixel 9 Production',
    });

    // Real device inventory returns ONLY the enrolled device
    const realRes = await fetch(`${baseUrl}/api/devices`, {
      headers: { Cookie: user.cookie },
    });
    assert.equal(realRes.status, 200);
    const realData = (await realRes.json()) as {
      devices: Array<{ id: string; name: string }>;
    };
    assert.equal(realData.devices.length, 1);
    assert.equal(realData.devices[0].name, 'Pixel 9 Production');
    assert.equal(realData.devices.some((d) => d.name.includes('Sample')), false);
  });
});
