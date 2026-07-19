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
          screenDetection: { score: 12.5 },
          printDetection: { score: 97.5 },
          photoTampering: { score: 0 }
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
