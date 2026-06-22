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
const IDENTIFIER_TYPE = { PHONE: 'phone', NID: 'nid', NAME: 'imposter_name' };

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

// Unicode-aware normalization: keep letters/numbers of ANY script (so Bengali
// names no longer collapse to an empty string), drop case/whitespace/punctuation.
const normalize = (text) =>
    (text === null || text === undefined)
        ? ''
        : String(text).normalize('NFKC').toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');

// Coerce a request value to a string; anything else (objects from NoSQL
// injection attempts, arrays, etc.) becomes '' — never reaches a query operator.
const str = (v) => (typeof v === 'string' ? v : '');

// Escape user input before putting it into a RegExp (prevents regex injection).
const escapeRegex = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// BD phone validation, mirrors the client-side rule.
const validPhone = (p) => /^(\+?880|0)?[1-9]\d{9}$/.test(String(p).replace(/[\s\-()]/g, ''));

// Parse pagination params with sane caps. Accepts either an Express req or a
// plain query object so it can be tested without a request.
function paging(reqOrQuery = {}, defLimit = 20, maxLimit = 100) {
    const q = (reqOrQuery && reqOrQuery.query) || reqOrQuery || {};
    let limit = parseInt(q.limit, 10);
    if (isNaN(limit) || limit <= 0) limit = defLimit;
    limit = Math.min(limit, maxLimit);
    let skip = parseInt(q.skip, 10);
    if (isNaN(skip) || skip < 0) skip = 0;
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
        imposter_name: str(body.imposter_name).trim(),
        imposter_phone: str(body.imposter_phone).trim(),
        scam_type: str(body.scam_type).trim(),
        loss_item: str(body.loss_item).trim(),
        description: str(body.description),
        scam_location: str(body.scam_location).trim(),
        gd_number: str(body.gd_number).trim(),
        imposter_nickname: str(body.imposter_nickname).trim(),
        imposter_nid: str(body.imposter_nid).trim(),
        imposter_address: str(body.imposter_address).trim(),
        social_media_account: str(body.social_media_account).trim(),
        reporter_name: str(body.reporter_name).trim(),
        reporter_phone: str(body.reporter_phone).trim(),
        reporter_email: str(body.reporter_email).trim(),
        reporter_visibility: str(body.reporter_visibility) === VISIBILITY.HIDDEN ? VISIBILITY.HIDDEN : VISIBILITY.PUBLIC
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

    let altPhones = [];
    if (body.alt_phones) {
        try { const a = JSON.parse(body.alt_phones); if (Array.isArray(a)) altPhones = a.map(String); } catch (e) { /* ignore */ }
    }
    for (const p of altPhones) {
        if (!validPhone(p)) return { error: 'Invalid alternative phone number format: ' + p };
    }
    v.alt_phones = altPhones;
    return { value: v };
}

module.exports = {
    STATUS, VISIBILITY, ROLES, IDENTIFIER_TYPE,
    ALLOWED_IMAGE, ALLOWED_PROOF, MAX_PROOFS, DESC_MIN, DESC_MAX,
    normalize, str, escapeRegex, validPhone, paging, sanitizeEvent, validateSubmission
};
