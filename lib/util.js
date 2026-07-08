'use strict';

/**
 * Pure, dependency-free helpers and constants shared across the server.
 * Kept here (separate from server.js) so they can be unit-tested without a DB
 * connection and reused as the codebase grows.
 */

// ---- canonical enums (no more magic strings) ----
const STATUS = { PENDING: 'pending', APPROVED: 'approved', REJECTED: 'rejected' };
const VISIBILITY = { PUBLIC: 'public', HIDDEN: 'hidden' };
const ROLES = { SUPERUSER: 'superuser', ADMIN: 'admin' };
const IDENTIFIER_TYPE = { PHONE: 'phone', NID: 'nid', NAME: 'imposter_name', MFS: 'mfs_wallet', BANK: 'bank_account' };

// ---- upload config ----
const ALLOWED_IMAGE = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_PROOF = [
    ...ALLOWED_IMAGE,
    'video/mp4', 'video/quicktime', 'video/webm',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
];
const MAX_PROOFS = 20;
const DESC_MIN = 30;
const DESC_MAX = 500;

// Per-field maximum lengths for public submissions (anti-abuse: without these an
// anonymous user could store multi-megabyte strings that bloat the index/sitemap).
const FIELD_MAX = {
    imposter_name: 120, imposter_nickname: 80, imposter_nid: 40, imposter_address: 300,
    social_media_account: 300, scam_type: 80, loss_item: 120, scam_location: 200,
    gd_number: 40, reporter_name: 120, reporter_phone: 40, reporter_email: 160,
    mfs_wallet: 40, mfs_trxid: 40, bank_account: 60, contact: 200
};
const MAX_ALT_PHONES = 10;

// Mobile-financial-service providers (Bangladesh). Money-trail identifiers.
const MFS_PROVIDERS = ['bKash', 'Nagad', 'Rocket', 'Upay', 'mCash', 'SureCash', 'Tap'];

// Unicode-aware normalization: keep letters/numbers of ANY script (so Bengali
// names no longer collapse to an empty string), drop case/whitespace/punctuation.
const normalize = (text) =>
    (text === null || text === undefined)
        ? ''
        : String(text).normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');

// Coerce a request value to a string; anything else (objects from NoSQL
// injection attempts, arrays, etc.) becomes '' — never reaches a query operator.
const str = (v) => (typeof v === 'string' ? v : '');

// Trim + hard-cap a string field to its configured maximum length.
const capField = (v, key) => {
    const s = str(v).trim();
    const max = FIELD_MAX[key];
    return max ? s.slice(0, max) : s;
};

// Escape user input before putting it into a RegExp (prevents regex injection).
const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// BD phone validation, mirrors the client-side rule.
const validPhone = (p) => /^(\+?880|0)?[1-9]\d{9}$/.test(String(p).replace(/[\s\-()]/g, ''));

// Normalize a phone/MFS wallet number to its canonical 11-digit BD local form
// (01XXXXXXXXX) when possible, else digits-only. Used to correlate wallets.
const normalizeWallet = (p) => {
    const digits = String(p == null ? '' : p).replace(/\D/g, '');
    if (/^8801\d{9}$/.test(digits)) return digits.slice(2);
    if (/^01\d{9}$/.test(digits)) return digits;
    return digits;
};

// Mask a national ID for public display — publishing full NIDs is an identity-theft
// vector, so only the last 4 digits are ever shown publicly.
const maskNid = (nid) => {
    const s = String(nid == null ? '' : nid).trim();
    if (!s) return '';
    if (s.length <= 4) return '••••';
    return '••••••' + s.slice(-4);
};

// Intrinsic risk of a phone number independent of any reports: a real bank/MFS
// never calls from a foreign or non-standard number, and the operator prefix is a
// quick impersonation sanity-check. Returns { level, label, operator }.
const BD_OPERATORS = {
    '013': 'Grameenphone', '017': 'Grameenphone', '019': 'Banglalink',
    '014': 'Banglalink', '018': 'Robi', '016': 'Airtel', '015': 'Teletalk'
};
function phoneRisk(raw) {
    const s = String(raw == null ? '' : raw).replace(/[\s\-()]/g, '');
    if (!s) return { level: 'unknown', label: '', operator: '' };
    // Explicit non-BD international dialling code.
    if (/^\+/.test(s) && !/^\+880/.test(s)) {
        return { level: 'high', label: 'Foreign number — banks and MFS never call from these', operator: '' };
    }
    const local = s.replace(/^(\+?880)/, '0');
    if (!/^01[3-9]\d{8}$/.test(local)) {
        return { level: 'caution', label: 'Non-standard number format', operator: '' };
    }
    const prefix = local.slice(0, 3);
    return { level: 'low', label: '', operator: BD_OPERATORS[prefix] || '' };
}

// Evidence-quality score (0-100) from structured signals — powers the risk-sorted
// moderation queue (weak, thin accusations surface first for hardest scrutiny).
function scoreEvidence(ev = {}) {
    let s = 0;
    const proofs = Array.isArray(ev.scam_proofs) ? ev.scam_proofs.length : (Number(ev.proof_count) || 0);
    s += Math.min(proofs, 3) * 10;                 // up to 30
    if (ev.imposter_picture || ev.has_photo) s += 10;
    if (str(ev.gd_number).trim()) s += 15;
    if (str(ev.imposter_nid).trim()) s += 10;
    const descLen = str(ev.description).length;
    s += descLen >= 200 ? 20 : descLen >= 100 ? 12 : descLen >= DESC_MIN ? 6 : 0;
    if (str(ev.reporter_phone).trim() || str(ev.reporter_email).trim()) s += 10;
    if (str(ev.mfs_wallet).trim() || str(ev.bank_account).trim() || str(ev.mfs_trxid).trim()) s += 10;
    if (validPhone(str(ev.imposter_phone))) s += 5;
    return Math.max(0, Math.min(100, s));
}

// Aggregate public risk score (0-100 + band) for a number/profile, blending
// corroboration, recency, loss and open disputes. Returns { score, band }.
function riskScore({ reportCount = 0, distinctReporters = 0, totalLoss = 0, recencyDays = null, openDisputes = 0 } = {}) {
    if (!reportCount) return { score: 0, band: 'none' };
    let s = Math.min(reportCount, 10) * 6;               // up to 60
    s += Math.min(distinctReporters, 5) * 4;             // up to 20
    if (recencyDays != null && recencyDays <= 30) s += 10;
    if (totalLoss >= 100000) s += 10; else if (totalLoss >= 10000) s += 5;
    s -= Math.min(openDisputes, 3) * 5;
    s = Math.max(0, Math.min(100, s));
    const band = s >= 60 ? 'high' : s >= 25 ? 'medium' : 'low';
    return { score: s, band };
}

// Extract structured tokens from pasted raw scam text (SMS/WhatsApp/Messenger).
// Pure + dependency-free so it is unit-testable. Returns deduped arrays.
function extractFromText(text) {
    const t = String(text == null ? '' : text);
    const uniq = (arr) => Array.from(new Set(arr));
    const phones = uniq((t.match(/(?:\+?880|0)1[3-9]\d{8}/g) || []).map((p) => p.replace(/^(\+?880)/, '0')));
    // bKash/Nagad TrxIDs are typically 10-char uppercase alphanumeric tokens.
    const trxids = uniq((t.match(/\b[A-Z0-9]{10}\b/g) || []).filter((x) => /[A-Z]/.test(x) && /[0-9]/.test(x)));
    const urls = uniq(t.match(/https?:\/\/[^\s<>"')]+/gi) || []);
    // Amounts: ৳/Tk/BDT followed by a number, or a number followed by taka/tk.
    const amounts = uniq(
        (t.match(/(?:৳|Tk\.?|BDT|taka)\s*[\d,]+(?:\.\d+)?/gi) || [])
            .concat(t.match(/[\d,]+(?:\.\d+)?\s*(?:৳|tk|taka)/gi) || [])
    );
    // Bangladeshi NID numbers: 10 (smart card), 13, or 17 digits. Exclude 11-digit
    // phones and the 13-digit "8801…" phone form to reduce false positives.
    const nids = uniq((t.match(/\b\d{10}\b|\b\d{13}\b|\b\d{17}\b/g) || [])
        .filter((n) => !/^8801\d/.test(n) && !/^01\d{9}$/.test(n)));
    return { phones, trxids, urls, amounts, nids };
}

// Magic-byte sniffing: return a coarse family for a file buffer, or 'unknown'.
// Used to reject uploads whose real bytes contradict the client-declared MIME.
function sniffFamily(buf) {
    if (!buf || buf.length < 4) return 'unknown';
    const b = buf;
    const hex = (i) => b[i];
    if (hex(0) === 0xff && hex(1) === 0xd8 && hex(2) === 0xff) return 'jpeg';
    if (hex(0) === 0x89 && hex(1) === 0x50 && hex(2) === 0x4e && hex(3) === 0x47) return 'png';
    if (hex(0) === 0x47 && hex(1) === 0x49 && hex(2) === 0x46 && hex(3) === 0x38) return 'gif';
    if (b.length >= 12 && b.toString('ascii', 0, 4) === 'RIFF' && b.toString('ascii', 8, 12) === 'WEBP') return 'webp';
    if (b.toString('ascii', 0, 4) === '%PDF') return 'pdf';
    if (b.length >= 8 && b.toString('ascii', 4, 8) === 'ftyp') return 'mp4';       // mp4 / mov share ftyp
    if (hex(0) === 0x1a && hex(1) === 0x45 && hex(2) === 0xdf && hex(3) === 0xa3) return 'webm';
    if (hex(0) === 0x50 && hex(1) === 0x4b && hex(2) === 0x03 && hex(3) === 0x04) return 'zip'; // docx
    if (hex(0) === 0xd0 && hex(1) === 0xcf && hex(2) === 0x11 && hex(3) === 0xe0) return 'ole'; // legacy .doc
    return 'unknown';
}

// Does a sniffed family plausibly match the client-declared MIME type?
const MIME_FAMILY = {
    'image/jpeg': ['jpeg'], 'image/png': ['png'], 'image/gif': ['gif'], 'image/webp': ['webp'],
    'video/mp4': ['mp4'], 'video/quicktime': ['mp4'], 'video/webm': ['webm'],
    'application/pdf': ['pdf'],
    'application/msword': ['ole'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['zip']
};
function typeMatches(declaredMime, family) {
    const allowed = MIME_FAMILY[declaredMime];
    if (!allowed) return false;          // declared type not in our allowlist at all
    if (family === 'unknown') return false; // could not verify -> reject (blocks spoofed HTML/SVG/scripts)
    return allowed.includes(family);
}

// Parse pagination params with sane caps. Accepts either an Express req or a
// plain query object so it can be tested without a request.
function paging(reqOrQuery = {}, defLimit = 20, maxLimit = 100) {
    const q = (reqOrQuery && reqOrQuery.query) || reqOrQuery || {};
    let limit = parseInt(q.limit, 10);
    if (isNaN(limit) || limit <= 0) limit = defLimit;
    limit = Math.min(limit, maxLimit);
    let skip = parseInt(q.skip, 10);
    if (isNaN(skip) || skip < 0) skip = 0;
    skip = Math.min(skip, 100000); // cap: deep pagination forces costly collection walks
    return { limit, skip };
}

// Strip sensitive reporter contact info and heavy media from an event before
// returning it to public, unauthenticated clients. Admin endpoints do NOT use this.
function sanitizeEvent(event, { includeProofs = false } = {}) {
    if (!event || typeof event !== 'object') return event;
    const safe = { ...event };
    delete safe.reporter_phone;
    delete safe.reporter_email;
    if (safe.reporter_visibility !== VISIBILITY.PUBLIC) {
        delete safe.reporter_name;
    }
    // Never expose a full national ID publicly (identity-theft vector) — mask to last 4.
    if (safe.imposter_nid) safe.imposter_nid = maskNid(safe.imposter_nid);
    // Photo served separately via /api/events/:id/picture.
    delete safe.imposter_picture;
    // Proofs metadata only (name/type/size); bytes streamed via /proofs/:index.
    if (includeProofs && Array.isArray(safe.scam_proofs)) {
        safe.scam_proofs = safe.scam_proofs.map(p => ({ name: p.name, mimetype: p.mimetype, size: p.size }));
    } else {
        delete safe.scam_proofs;
    }
    return safe;
}

/**
 * Validate + normalize a public fraud-report submission (scalar fields only;
 * file validation happens in the route because it needs the upload objects).
 * Returns { error } on the first problem, or { value } with cleaned fields.
 */
function validateSubmission(body = {}) {
    const v = {
        imposter_name: capField(body.imposter_name, 'imposter_name'),
        imposter_phone: str(body.imposter_phone).trim(),
        scam_type: capField(body.scam_type, 'scam_type'),
        loss_item: capField(body.loss_item, 'loss_item'),
        description: str(body.description),
        scam_location: capField(body.scam_location, 'scam_location'),
        gd_number: capField(body.gd_number, 'gd_number'),
        imposter_nickname: capField(body.imposter_nickname, 'imposter_nickname'),
        imposter_nid: capField(body.imposter_nid, 'imposter_nid'),
        imposter_address: capField(body.imposter_address, 'imposter_address'),
        social_media_account: capField(body.social_media_account, 'social_media_account'),
        reporter_name: capField(body.reporter_name, 'reporter_name'),
        reporter_phone: str(body.reporter_phone).trim().slice(0, FIELD_MAX.reporter_phone),
        reporter_email: capField(body.reporter_email, 'reporter_email'),
        reporter_visibility: str(body.reporter_visibility) === VISIBILITY.HIDDEN ? VISIBILITY.HIDDEN : VISIBILITY.PUBLIC,
        // Money-trail (MFS / bank) fields — the durable identifiers in BD fraud.
        mfs_provider: MFS_PROVIDERS.includes(str(body.mfs_provider).trim()) ? str(body.mfs_provider).trim() : '',
        mfs_wallet: capField(body.mfs_wallet, 'mfs_wallet'),
        mfs_trxid: capField(body.mfs_trxid, 'mfs_trxid'),
        bank_account: capField(body.bank_account, 'bank_account')
    };
    const lossNum = parseFloat(body.loss_amount);
    v.loss_amount = isFinite(lossNum) && lossNum >= 0 ? lossNum : 0;

    if (!v.imposter_name || !v.imposter_phone || !v.scam_type || !v.loss_item || !body.loss_amount || !v.description) {
        return { error: 'Missing required fields.' };
    }
    if (!validPhone(v.imposter_phone)) return { error: 'Invalid imposter phone number format.' };
    if (v.description.length < DESC_MIN || v.description.length > DESC_MAX) {
        return { error: `Description must be between ${DESC_MIN} and ${DESC_MAX} characters.` };
    }
    if (v.reporter_phone && !validPhone(v.reporter_phone)) {
        return { error: 'Invalid reporter phone number format.' };
    }
    if (v.mfs_wallet && !validPhone(v.mfs_wallet)) {
        return { error: 'MFS wallet number must be a valid phone number.' };
    }

    let altPhones = [];
    if (body.alt_phones) {
        try { const a = JSON.parse(body.alt_phones); if (Array.isArray(a)) altPhones = a.map(String); } catch (e) { /* ignore */ }
    }
    altPhones = altPhones.slice(0, MAX_ALT_PHONES); // cap array length (anti-abuse)
    for (const p of altPhones) {
        if (!validPhone(p)) return { error: 'Invalid alternative phone number format: ' + p };
    }
    v.alt_phones = altPhones;

    // Truthful-reporting attestation (defamation guardrail). Accept boolean true or 'true'.
    if (body.consent !== true && body.consent !== 'true' && body.consent !== 'on') {
        return { error: 'You must confirm this report is truthful and first-hand.' };
    }
    v.reporter_consent = true;

    return { value: v };
}

module.exports = {
    STATUS, VISIBILITY, ROLES, IDENTIFIER_TYPE,
    ALLOWED_IMAGE, ALLOWED_PROOF, MAX_PROOFS, DESC_MIN, DESC_MAX,
    FIELD_MAX, MAX_ALT_PHONES, MFS_PROVIDERS,
    normalize, str, capField, escapeRegex, validPhone, normalizeWallet, maskNid,
    phoneRisk, scoreEvidence, riskScore, extractFromText, sniffFamily, typeMatches,
    paging, sanitizeEvent, validateSubmission
};
