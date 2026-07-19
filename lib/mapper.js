'use strict';
// Maps a decoded Uqudo SDK result (the `jwsResult` JWT payload) onto the
// Uqudo_KYC_Data document shape the Intuition Data API expects.
//
// Port of intuition_api_service.dart (the Flutter app's server-side twin), so
// the same two structural traps apply and are handled with dual-path lookups:
//   1. documents live at data.documents[], NOT documents[]
//   2. deviceAttestation sits at the JWT TOP LEVEL, NOT inside data
// Getting either wrong yields a document that uploads cleanly but carries no
// device fields, so no device rule can ever fire.

const str = (v) => (v === undefined || v === null ? '' : String(v));

// ---- structural accessors (dual-path) --------------------------------------
function getDocuments(kyc) {
  const direct = kyc.documents;
  if (Array.isArray(direct) && direct.length) return direct;
  const nested = kyc.data && kyc.data.documents;
  if (Array.isArray(nested) && nested.length) return nested;
  return [];
}
function getSource(kyc) {
  const direct = kyc.source;
  if (direct && typeof direct === 'object' && Object.keys(direct).length) return direct;
  const nested = kyc.data && kyc.data.source;
  if (nested && typeof nested === 'object' && Object.keys(nested).length) return nested;
  return {};
}
function getDeviceAttestation(kyc) {
  // Top level first — this is the one that bit us before.
  return kyc.deviceAttestation || (kyc.data && kyc.data.deviceAttestation) || {};
}
const firstDoc = (kyc) => getDocuments(kyc)[0] || {};
const scanData = (kyc) => ((firstDoc(kyc).scan || {}).data) || {};
const readingData = (kyc) => ((firstDoc(kyc).reading || {}).data) || {};
const mergedDocData = (kyc) => ({ ...scanData(kyc), ...readingData(kyc) });

// ---- formatting -------------------------------------------------------------
const pad = (n, w = 2) => String(n).padStart(w, '0');
function formatTimestamp(d = new Date()) {
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
         `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
function formatDate(v) {
  if (v === undefined || v === null || v === '' || v === 'null') return undefined;
  // SDK sends epoch millis or an ISO/`YYYY-MM-DD` string.
  let d;
  if (typeof v === 'number') d = new Date(v);
  else if (/^\d+$/.test(String(v))) d = new Date(Number(v));
  else d = new Date(String(v));
  if (isNaN(d.getTime())) return undefined;
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

/** SDK returns names like "YAHIA,ELHADI,,,ELKANZI," — normalise to spaces. */
function cleanFullName(raw, { firstName, lastName, middleName } = {}) {
  if (raw) {
    const cleaned = String(raw).replace(/,/g, ' ').replace(/\s+/g, ' ').trim();
    if (cleaned) return cleaned;
  }
  return [firstName, middleName, lastName].filter(Boolean).join(' ');
}

// ---- section builders -------------------------------------------------------
function buildUqudoMetadata(kyc) {
  const s = getSource(kyc);
  const doc = firstDoc(kyc);
  return {
    source_ip: str(s.sourceIp),
    device_platform: str(s.devicePlatform),
    device_model: str(s.deviceModel),
    device_identifier: str(s.deviceIdentifier || s.deviceId || kyc.deviceIdentifier || kyc.deviceId),
    sdk_version: str(s.sdkVersion),
    documentOcr: doc.scan ? 'available' : 'not_available',
    documentNfc: doc.reading ? 'available' : 'not_available'
  };
}

function buildPersonalInfo(kyc) {
  const d = mergedDocData(kyc);
  const out = {
    full_name: cleanFullName(d.fullName, d),
    full_name_arabic: cleanFullName(d.fullNameArabic),
    first_name: str(d.firstName),
    last_name: str(d.lastName),
    middle_name: str(d.middleName),
    gender: str(d.gender),
    nationality: str(d.nationality),
    nationality_code: str(d.nationalityCode),
    marital_status: str(d.maritalStatus),
    place_of_birth: str(d.placeOfBirth)
  };
  const dob = formatDate(d.dateOfBirth);
  if (dob) out.date_of_birth = dob;
  return out;
}

function buildDocumentInfo(kyc) {
  const d = mergedDocData(kyc);
  const out = {
    document_type: str(firstDoc(kyc).documentType),
    document_number: str(d.documentNumber),
    identity_number: str(d.idNumber || d.identityNumber),
    issuer_country: str(d.issuingCountry),
    place_of_issue: str(d.placeOfIssue)
  };
  const issue = formatDate(d.issueDate);
  const expiry = formatDate(d.expiryDate);
  if (issue) out.issue_date = issue;
  if (expiry) out.expiry_date = expiry;
  return out;
}

function buildPassportInfo(kyc) {
  const d = mergedDocData(kyc);
  const out = {
    passport_number: str(d.passportNumber),
    passport_country: str(d.passportCountry || d.issuingCountry)
  };
  const pi = formatDate(d.passportIssueDate);
  const pe = formatDate(d.passportExpiryDate);
  if (pi) out.passport_issue_date = pi;
  if (pe) out.passport_expiry_date = pe;
  return out;
}

function buildResidencyInfo(kyc) {
  const d = mergedDocData(kyc);
  const out = {
    residency_type: str(d.residencyType),
    residency_number: str(d.residencyNumber),
    sponsor_unified_number: str(d.sponsorUnifiedNumber),
    sponsor_type: str(d.sponsorType)
  };
  const re = formatDate(d.residencyExpiryDate);
  if (re) out.residency_expiry_date = re;
  return out;
}

function buildEmploymentInfo(kyc) {
  const d = mergedDocData(kyc);
  return {
    employer: str(d.employer),
    employer_arabic: str(d.employerArabic),
    occupation: str(d.occupation)
  };
}

function buildContactInfo(kyc) {
  const d = mergedDocData(kyc);
  return {
    mobile_phone: str(d.mobilePhone),
    resident_phone: str(d.residentPhone),
    email: str(d.email),
    emirate: str(d.emirate),
    emirate_code: str(d.emirateCode),
    city: str(d.city),
    area: str(d.area),
    area_code: str(d.areaCode)
  };
}

function buildEducationInfo(kyc) {
  const d = mergedDocData(kyc);
  return {
    qualification_level: str(d.qualificationLevel),
    degree_description: str(d.degreeDescription),
    place_of_study: str(d.placeOfStudy)
  };
}

// NOTE: field names and types below are taken from the Uqudo_KYC_Data dataset
// template, not guessed. Intuition validates types strictly and rejects the
// whole document on a mismatch (e.g. a Number where it wants a String).
function buildBiometricVerification(kyc) {
  const face = kyc.face || (kyc.data && kyc.data.face) || {};
  const enroll = face.enrollment || face.match || {};
  const doc = firstDoc(kyc);
  const reading = doc.reading || {};
  const rv = reading.verifications || {};
  return {
    face_match: str(enroll.match !== undefined ? enroll.match : face.match),
    // schema: String (not Number)
    face_match_level: str(enroll.matchLevel !== undefined ? enroll.matchLevel : face.matchLevel),
    face_false_accept_rate: str(enroll.falseAcceptRate || face.falseAcceptRate),
    biometric_type: str(face.type),
    mrz_verified: str(rv.mrzVerified),
    mrz_checksum_valid: str(rv.mrzChecksumValid),
    passive_auth_valid: str(rv.passiveAuthValid),
    reading_enabled: doc.reading ? 'true' : 'false',
    nfc_verified: str(rv.nfcVerified)
  };
}

function buildFraudDetection(kyc) {
  const scan = firstDoc(kyc).scan || {};
  const v = scan.verifications || {};
  const num = (x) => (x === undefined || x === null || x === '' ? 0 : Number(x));
  return {
    // schema names are id_-prefixed for the two detection scores
    id_print_detection_score: num(v.printDetection && v.printDetection.score),
    id_screen_detection_score: num(v.screenDetection && v.screenDetection.score),
    photo_tampering_score: num(v.photoTampering && v.photoTampering.score),
    is_expired: str(v.isExpired),
    is_face_matched: str(v.isFaceMatched),
    is_document_authentic: str(v.isDocumentAuthentic)
  };
}

function buildRiskIndicators(kyc) {
  const d = mergedDocData(kyc);
  const scan = firstDoc(kyc).scan || {};
  const v = scan.verifications || {};
  return {
    // schema: nationality_risk is a Number here (it is a String in fraudDetection)
    nationality_risk: 0,
    is_face_matched: str(v.isFaceMatched),
    is_document_authentic: str(v.isDocumentAuthentic),
    is_known_fraudester: str(v.isKnownFraudster),
    is_expired: str(v.isExpired)
  };
}

function buildDocumentImages(kyc) {
  const doc = firstDoc(kyc);
  const images = doc.images || (doc.scan && doc.scan.images) || {};
  return {
    front_image: str(images.front),
    back_image: str(images.back),
    face_image: str(images.face || (kyc.face && kyc.face.image))
  };
}

/** DeviceAttestation subset — the fields the OFTI/ATO device rules match on.
 *
 *  CRITICAL: the dataset's sub-field NAME is `deviceIdentifier`; the portal
 *  merely LABELS it "deviceIdentifier-UqudoShield". The JSON payload keys must
 *  use the name. Sending the label instead uploads cleanly but leaves the
 *  device fields empty, so OFTI_ATO_011/051 can never match — the exact silent
 *  failure that broke OFTI_ATO_051 before.
 *
 *  Types come from the dataset template and are enforced by Intuition:
 *  GPSLocation_latitude is a Number, GPSLocation_longitude is a String, and the
 *  IPLocation lat/long pair are both Strings. Yes, it is inconsistent.
 */
function buildDeviceAttestation(kyc) {
  const da = getDeviceAttestation(kyc);
  const risk = (da && typeof da.risk === 'object' && da.risk) || {};
  const info = (da && typeof da.info === 'object' && da.info) || {};
  const pick = (...keys) => {
    for (const k of keys) {
      const v = info[k] !== undefined ? info[k] : (risk[k] !== undefined ? risk[k] : da[k]);
      if (v !== undefined && v !== null && v !== '') return v;
    }
    return '';
  };
  const num = (v) => { const n = Number(v); return isNaN(n) ? 0 : n; };

  return {
    // Stable per-device id used by the KYC device-binding rules (OFTI_ATO_011/051).
    deviceIdentifier: str(pick('deviceIdentifier', 'deviceId')),
    deviceMasked: str(pick('deviceMasked')),
    payloadTampered: str(pick('payloadTampered')),
    manufacturer: str(pick('manufacturer')),
    osVersion: str(pick('osVersion')),
    cpuArchitecture: str(pick('cpuArchitecture')),
    timezone: str(pick('timezone')),
    userAgent: str(pick('userAgent')),

    deviceRiskLevel: str(pick('deviceRiskLevel')),
    deviceRiskScore: num(pick('deviceRiskScore')),          // Number
    deviceTrustScore: num(pick('deviceTrustScore')),        // Number
    riskCauses: str(pick('riskCauses')),
    rooted: str(pick('rooted')),
    emulator: str(pick('emulator')),
    developerMode: str(pick('developerMode')),
    debuggable: str(pick('debuggable')),
    mockgps: str(pick('mockgps', 'mockGps')),
    isAppTampered: str(pick('isAppTampered')),
    isAppCloned: str(pick('isAppCloned')),
    googlePlayStoreInstall: str(pick('googlePlayStoreInstall')),
    appInstallerSource: str(pick('appInstallerSource')),
    OS: str(pick('os', 'OS')),
    model: str(pick('model', 'deviceModel')),

    GPSLocation_city: str(pick('gpsCity')),
    GPSLocation_country: str(pick('gpsCountry')),
    GPSLocation_latitude: num(pick('gpsLatitude')),          // Number
    GPSLocation_longitude: str(pick('gpsLongitude')),        // String

    IP: str(pick('ip', 'sourceIp')),
    IPLocation_country: str(pick('ipCountry')),
    IPLocation_latitude: str(pick('ipLatitude')),            // String
    IPLocation_longitude: str(pick('ipLongitude')),          // String
    IPLocation_region: str(pick('ipRegion')),
    IPSecurity_VPN: str(pick('vpn', 'isVpn')),
    IPSecurity_isProxy: str(pick('isProxy')),
    IPSecurity_isTor: str(pick('isTor')),
    IPSecurity_isCrawler: str(pick('isCrawler')),
    IPSecurity_threatLevel: str(pick('threatLevel')),
    IPType: str(pick('ipType'))
  };
}

/**
 * Build the Intuition document from a decoded jwsResult payload.
 * @param {object} kyc   decoded JWT payload
 * @param {object} opts  { clientId, clientName, customerNumber }
 */
function buildIntuitionPayload(kyc, opts = {}) {
  const d = mergedDocData(kyc);
  // customer_number is the join key across KYC and transactions. Prefer an
  // explicit override, else the document/identity number, else the session id.
  const customerNumber = opts.customerNumber
    || str(d.identityNumber || d.idNumber || d.documentNumber)
    || str(kyc.jti || kyc.sessionId);

  return {
    customer_number: customerNumber,
    verification_id: str(kyc.jti || kyc.sessionId || ''),
    verification_timestamp: formatTimestamp(new Date()),

    uqudoMetadata: [buildUqudoMetadata(kyc)],
    personalInfo: [buildPersonalInfo(kyc)],
    documentInfo: [buildDocumentInfo(kyc)],
    passportInfo: [buildPassportInfo(kyc)],
    residencyInfo: [buildResidencyInfo(kyc)],
    employmentInfo: [buildEmploymentInfo(kyc)],
    contactInfo: [buildContactInfo(kyc)],
    educationInfo: [buildEducationInfo(kyc)],
    biometricVerification: [buildBiometricVerification(kyc)],
    fraudDetection: [buildFraudDetection(kyc)],
    DeviceAttestation: [buildDeviceAttestation(kyc)],
    RiskIndicators: [buildRiskIndicators(kyc)],
    documentImages: [buildDocumentImages(kyc)],

    Client_Id: opts.clientId || '',
    Client_Name: opts.clientName || ''
  };
}

module.exports = {
  buildIntuitionPayload,
  // exported for tests / debugging
  getDocuments, getSource, getDeviceAttestation, cleanFullName, formatDate, formatTimestamp
};
