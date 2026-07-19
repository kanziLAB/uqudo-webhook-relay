'use strict';
// Self-contained checks: no network, no live tenant. Generates a throwaway RSA
// key, signs a payload shaped like a real Uqudo SDK result, and asserts the
// verify -> decode -> map chain, including the two structural traps:
//   documents at data.documents[]  and  deviceAttestation at the JWT top level.
const assert = require('assert');
const crypto = require('crypto');
const jws = require('../lib/jws');
const mapper = require('../lib/mapper');

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function sign(payload, privateKey, alg = 'RS256') {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.sign('sha256', Buffer.from(`${header}.${body}`), privateKey);
  return `${header}.${body}.${b64url(sig)}`;
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' });

// Payload mirrors the real SDK result: documents nested under `data`, and
// deviceAttestation at the TOP level (not inside data).
const SDK_RESULT = {
  jti: 'sess-abc-123',
  data: {
    source: { sourceIp: '5.6.7.8', devicePlatform: 'Android', deviceModel: 'SM-A256E', deviceIdentifier: 'dev-9f9f', sdkVersion: '3.8.0' },
    documents: [{
      documentType: 'NATIONAL_ID',
      scan: {
        data: {
          fullName: 'ALEX,SAMPLE,,,TESTER,',
          firstName: 'ALEX', lastName: 'TESTER',
          documentNumber: '784-1999-1234567-8',
          identityNumber: '784199912345678',
          dateOfBirth: '1990-01-01',
          nationality: 'Sudan', nationalityCode: 'SDN',
          issuingCountry: 'QAT', gender: 'M'
        },
        verifications: {
          // Real SDK/Info-API key names — objects with { enabled, score }
          idScreenDetection: { enabled: true, score: 12.5 },
          idPrintDetection: { enabled: true, score: 97.5 },
          idPhotoTamperingDetection: { enabled: true, score: 0 }
        }
      },
      reading: { data: { expiryDate: '2030-01-31' } }
    }]
  },
  deviceAttestation: {
    risk: { deviceRiskLevel: 'HIGH', deviceRiskScore: 88, riskCauses: 'emulator' },
    info: {
      deviceIdentifier: '0e22c2fcf50d3300143591c98d4521be',
      manufacturer: 'samsung', osVersion: '14',
      ipCountry: 'PK', ipCity: 'Karachi', gpsCountry: 'QA',
      rooted: 'false', emulator: 'true'
    }
  }
};

let passed = 0;
const check = (name, fn) => { fn(); console.log(`  ok  ${name}`); passed++; };

console.log('jws:');
check('verify() accepts a correctly signed token', () => {
  const p = jws.verify(sign(SDK_RESULT, privateKey), pubPem);
  assert.strictEqual(p.jti, 'sess-abc-123');
});
check('verify() rejects a tampered payload', () => {
  const token = sign(SDK_RESULT, privateKey);
  const [h, , s] = token.split('.');
  const forged = `${h}.${b64url(JSON.stringify({ ...SDK_RESULT, jti: 'evil' }))}.${s}`;
  assert.throws(() => jws.verify(forged, pubPem), /verification failed/);
});
check('verify() rejects a token signed by a different key', () => {
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  assert.throws(() => jws.verify(sign(SDK_RESULT, other), pubPem), /verification failed/);
});
check('split() rejects a malformed token', () => {
  assert.throws(() => jws.decode('not-a-jwt'), /well-formed/);
});

console.log('mapper:');
const payload = mapper.buildIntuitionPayload(jws.verify(sign(SDK_RESULT, privateKey), pubPem), {
  clientId: 'uqudo-testing', clientName: 'uqudo - Testing'
});

check('TRAP 1: reads documents from data.documents[]', () => {
  assert.strictEqual(payload.documentInfo[0].document_number, '784-1999-1234567-8');
  assert.strictEqual(payload.documentInfo[0].document_type, 'NATIONAL_ID');
});
check('TRAP 2: reads deviceAttestation from the JWT top level', () => {
  const da = payload.DeviceAttestation[0];
  assert.strictEqual(da.deviceIdentifier, '0e22c2fcf50d3300143591c98d4521be');
  assert.strictEqual(da.deviceRiskLevel, 'HIGH');
  assert.strictEqual(da.deviceRiskScore, 88);
  assert.strictEqual(da.IPLocation_country, 'PK');
  assert.strictEqual(da.emulator, 'true');
});
check('full name is de-delimited', () => {
  assert.strictEqual(payload.personalInfo[0].full_name, 'ALEX SAMPLE TESTER');
});
check('merges NFC reading data over scan data', () => {
  assert.strictEqual(payload.documentInfo[0].expiry_date, '2030-01-31');
});
check('detection scores are carried under the schema id_ names', () => {
  assert.strictEqual(payload.fraudDetection[0].id_print_detection_score, 97.5);
  assert.strictEqual(payload.fraudDetection[0].id_screen_detection_score, 12.5);
  assert.strictEqual(payload.fraudDetection[0].photo_tampering_score, 0);
});
check('TRAP 3: device key is the field NAME, never the -UqudoShield label', () => {
  const da = payload.DeviceAttestation[0];
  assert.ok(!Object.keys(da).some(k => /UqudoShield/.test(k)),
    'no key may carry the -UqudoShield label suffix');
});
check('TRAP 4: schema types (Intuition rejects the doc on a mismatch)', () => {
  const da = payload.DeviceAttestation[0];
  assert.strictEqual(typeof da.GPSLocation_latitude, 'number', 'GPSLocation_latitude must be Number');
  assert.strictEqual(typeof da.GPSLocation_longitude, 'string', 'GPSLocation_longitude must be String');
  assert.strictEqual(typeof da.IPLocation_latitude, 'string', 'IPLocation_latitude must be String');
  assert.strictEqual(typeof da.deviceRiskScore, 'number', 'deviceRiskScore must be Number');
  assert.strictEqual(typeof payload.biometricVerification[0].face_match_level, 'string',
    'face_match_level must be String');
  assert.strictEqual(typeof payload.RiskIndicators[0].nationality_risk, 'number',
    'RiskIndicators.nationality_risk must be Number');
});
check('contactInfo maps the real homeAddress* NFC keys (feeds MA_EM/MA_PH)', () => {
  const kyc = { jti: 'x', data: { documents: [{ reading: { data: {
    homeAddressEmail: 'user@example.com',
    homeAddressMobilePhoneNo: '0500000000',
    homeAddressEmirateDesc: 'Dubai'
  } } }] } };
  const p = mapper.buildIntuitionPayload(kyc, {});
  assert.strictEqual(p.contactInfo[0].email, 'user@example.com');
  assert.strictEqual(p.contactInfo[0].mobile_phone, '0500000000');
  assert.strictEqual(p.contactInfo[0].emirate, 'Dubai');
});
check('info-doc reading.data fills contact gaps when the raw JWT lacks it', () => {
  const kyc = { jti: 'x', data: { documents: [{ scan: { data: {} } }] },
    infoApiDocuments: [{ reading: { data: { homeAddressEmail: 'nfc@example.com' } } }] };
  const p = mapper.buildIntuitionPayload(kyc, {});
  assert.strictEqual(p.contactInfo[0].email, 'nfc@example.com');
});
check('REAL webhook JWT shape maps device/face/mrz (regression from captured session)', () => {
  // Mirrors the structure captured from a live portal webhook on 2026-07-19:
  // scan.front/back (no scan.data), face at document level, verifications[] at
  // data level, deviceAttestation.info.identifier + boolean risk flags.
  const kyc = { jti: 'real-shape', data: {
    source: { devicePlatform: 'ANDROID' },
    documents: [{
      documentType: 'ID',
      face: { match: true, matchLevel: 5, falseAcceptRate: null },
      scan: {
        front: { fullName: 'ALEX SAMPLE TESTER', identityNumber: '784199912345678', nationality: 'ARE' },
        back: { documentNumber: '145217945', mrzVerified: true }
      },
      reading: { data: { homeAddressEmail: 'real@example.com', homeAddressMobilePhoneNo: '0555555555' } }
    }],
    verifications: [{
      biometric: { type: 'FACIAL_RECOGNITION', enabled: true, matchLevel: 5 },
      mrzChecksum: { valid: true, enabled: true },
      reading: { enabled: true, passiveAuthentication: { enabled: true, documentDataSignatureValid: true } }
    }],
    deviceAttestation: {
      info: { model: 'sm-a256e', version: '16', platform: 'ANDROID', timezone: '4',
              identifier: '0e22c2fcf50d3300143591c98d4521be', manufacturer: 'samsung',
              cpuArchitecture: 'aarch64', ipInfo: [{ ip: '2001:db8::1', countryCode: 'AE' }] },
      risk: { rooted: false, emulated: false, hooking: false, proxy: false, vpnRunning: false,
              debugging: false, deviceMasked: false, payloadTampered: false,
              applicationStore: 'com.android.vending' }
    }
  } };
  const p = mapper.buildIntuitionPayload(kyc, {});
  const da = p.DeviceAttestation[0];
  assert.strictEqual(da.deviceIdentifier, '0e22c2fcf50d3300143591c98d4521be', 'info.identifier must map');
  assert.strictEqual(da.osVersion, '16');
  assert.strictEqual(da.emulator, 'false');
  assert.strictEqual(da.IP, '2001:db8::1');
  assert.strictEqual(da.IPLocation_country, 'AE');
  assert.strictEqual(da.appInstallerSource, 'com.android.vending');
  const bio = p.biometricVerification[0];
  assert.strictEqual(bio.face_match, 'true');
  assert.strictEqual(bio.face_match_level, '5');
  assert.strictEqual(bio.biometric_type, 'FACIAL_RECOGNITION');
  assert.strictEqual(bio.mrz_checksum_valid, 'true');
  assert.strictEqual(bio.passive_auth_valid, 'true');
  assert.strictEqual(bio.reading_enabled, 'true');
  assert.strictEqual(p.contactInfo[0].email, 'real@example.com');
  assert.strictEqual(p.personalInfo[0].full_name, 'ALEX SAMPLE TESTER', 'scan.front fields must map');
  assert.strictEqual(p.customer_number, '784199912345678');
  assert.strictEqual(p.fraudDetection[0].is_face_matched, 'true', 'derived from face.match');
});
check('legacy bare detection keys still map (fallback)', () => {
  const legacy = { jti: 'x', documents: [{ scan: { data: {}, verifications: {
    printDetection: { score: 55 }, screenDetection: { score: 44 }, photoTampering: { score: 33 }
  } } }] };
  const p = mapper.buildIntuitionPayload(legacy, {});
  assert.strictEqual(p.fraudDetection[0].id_print_detection_score, 55);
  assert.strictEqual(p.fraudDetection[0].id_screen_detection_score, 44);
  assert.strictEqual(p.fraudDetection[0].photo_tampering_score, 33);
});
check('Info API documents take precedence for detection scores', () => {
  // Real webhook JWTs carry NO detection scores; enrichment attaches
  // infoApiDocuments whose scan.verifications must win over the raw doc.
  const kyc = JSON.parse(JSON.stringify(SDK_RESULT));
  delete kyc.data.documents[0].scan.verifications;   // like a real webhook JWT
  kyc.infoApiDocuments = [{ scan: { verifications: {
    idPrintDetection: { enabled: true, score: 88 },
    idScreenDetection: { enabled: true, score: 77 },
    idPhotoTamperingDetection: { enabled: true, score: 66 }
  } } }];
  const p = mapper.buildIntuitionPayload(kyc, {});
  assert.strictEqual(p.fraudDetection[0].id_print_detection_score, 88);
  assert.strictEqual(p.fraudDetection[0].id_screen_detection_score, 77);
  assert.strictEqual(p.fraudDetection[0].photo_tampering_score, 66);
});
check('without enrichment a real-shaped JWT maps zero scores (the PEP_SIMILAR-only case)', () => {
  const kyc = JSON.parse(JSON.stringify(SDK_RESULT));
  delete kyc.data.documents[0].scan.verifications;
  const p = mapper.buildIntuitionPayload(kyc, {});
  assert.strictEqual(p.fraudDetection[0].id_print_detection_score, 0);
  assert.strictEqual(p.fraudDetection[0].id_screen_detection_score, 0);
});
check('enrich module: disabled without credentials, decodes JWS payloads', async () => {
  const enrich = require('../lib/enrich');
  assert.strictEqual(enrich.enabled(), false, 'no creds in test env => disabled');
  assert.strictEqual(await enrich.fetchInfoDocuments('any-jti'), null, 'disabled => null, never throws');
  const payload = { data: { documents: [{ id: 1 }] } };
  const seg = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  assert.deepStrictEqual(enrich._decodePayload(`eyJhbGciOiJub25lIn0.${seg}.sig`), payload);
});
check('customer_number falls back to the identity number', () => {
  assert.strictEqual(payload.customer_number, '784199912345678');
});
check('verification_id carries the session jti', () => {
  assert.strictEqual(payload.verification_id, 'sess-abc-123');
});
check('subsets are arrays (Intuition subset shape)', () => {
  for (const k of ['personalInfo', 'documentInfo', 'DeviceAttestation', 'uqudoMetadata', 'fraudDetection']) {
    assert.ok(Array.isArray(payload[k]), `${k} must be an array`);
  }
});
check('timestamp format is YYYY-MM-DD HH:mm:ss', () => {
  assert.match(payload.verification_timestamp, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
});
check('flat-shaped payloads still map (documents[] at top level)', () => {
  const flat = { jti: 'x', documents: SDK_RESULT.data.documents, source: SDK_RESULT.data.source, deviceAttestation: SDK_RESULT.deviceAttestation };
  const p = mapper.buildIntuitionPayload(flat, {});
  assert.strictEqual(p.documentInfo[0].document_number, '784-1999-1234567-8');
});
check('empty/garbage payload does not throw', () => {
  const p = mapper.buildIntuitionPayload({}, {});
  assert.strictEqual(p.personalInfo[0].full_name, '');
  assert.ok(Array.isArray(p.DeviceAttestation));
});

console.log(`\n${passed} checks passed`);
