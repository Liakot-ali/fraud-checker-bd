const express = require('express');
const { MongoClient, ObjectId, GridFSBucket } = require('mongodb');
const path = require('path');
const fileUpload = require('express-fileupload');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();
const {
    STATUS, VISIBILITY, ROLES,
    ALLOWED_IMAGE, ALLOWED_PROOF, MAX_PROOFS,
    normalize, str, capField, escapeRegex, validPhone, normalizeWallet, maskNid,
    phoneRisk, scoreEvidence, riskScore, extractFromText, extractPerson, sniffFamily, typeMatches,
    extractMoneyTrail, extractReporterContact,
    paging, sanitizeEvent, validateSubmission
} = require('./lib/util');
const { aiExtract } = require('./lib/ai');

// Minimal structured (JSON-line) logger — no sensitive payloads, no stack traces
// leaked to clients (those only ever get a generic message).
function log(level, msg, extra) {
    const line = Object.assign({ t: new Date().toISOString(), level, msg }, extra || {});
    (level === 'error' ? console.error : console.log)(JSON.stringify(line));
}

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'fraud_checker_db';
const IS_PROD = process.env.NODE_ENV === 'production';
// Canonical public origin for sitemap/OG/canonical URLs (never trust the Host header).
const BASE_URL = (process.env.BASE_URL || '').replace(/\/+$/, '');
// Seed credentials for the first admin (never hard-code the password in production).
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

// JWT secret — must be set in production. In development, fall back to an ephemeral
// random one (sessions won't survive a restart) with a loud warning.
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    if (IS_PROD) {
        console.error('✗ JWT_SECRET is not set. Refusing to start in production. Generate one with: openssl rand -hex 48');
        process.exit(1);
    }
    JWT_SECRET = crypto.randomBytes(48).toString('hex');
    console.warn('⚠ JWT_SECRET not set in .env — using an ephemeral secret (admin sessions reset on restart).');
}

if (!MONGODB_URI) {
    console.error('✗ MONGODB_URI is not set in .env. Aborting.');
    process.exit(1);
}

// Trust the first proxy hop so req.ip / rate-limit keys reflect the real client
// behind a reverse proxy (without this, all clients share the proxy IP).
app.set('trust proxy', 1);

// Resolve the public base URL for absolute links: prefer the configured BASE_URL,
// fall back to the request Host only in development.
function baseUrl(req) {
    if (BASE_URL) return BASE_URL;
    return `${req.protocol}://${req.get('host')}`;
}

let db = null;
let bucket = null; // GridFS bucket for uploaded files

// ---- security headers (helmet + CSP) ----
// CSS is now built locally (public/tailwind.css), so no external CDN is needed.
// 'unsafe-inline' for scripts is a pragmatic compromise: the pages use inline
// event handlers. Stored XSS is closed at the source by escaping all user
// output on the client (see public/shared.js), not by this directive.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            // Inline event handlers (onclick/onerror) — helmet's default is
            // script-src-attr 'none', which would silently break every button.
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'blob:'],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", 'data:'],
            objectSrc: ["'none'"],
            frameAncestors: ["'self'"],
            // Do not force https upgrades — this app is served over http on localhost.
            upgradeInsecureRequests: null
        }
    },
    crossOriginEmbedderPolicy: false
}));

// Small JSON/form bodies only — admin actions are tiny; large bodies are a DoS
// vector (they are buffered in RAM). File uploads use multipart, handled below.
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));
// Bounded multipart: cap per-file size AND file count, abort (don't silently
// truncate) when a file is too big, so a flood of huge parts can't exhaust memory.
const MAX_FILE_BYTES = 10 * 1024 * 1024;
app.use(fileUpload({
    limits: { fileSize: MAX_FILE_BYTES, files: MAX_PROOFS + 2 },
    abortOnLimit: true,
    responseOnLimit: 'A file exceeds the 10MB limit.',
    safeFileNames: true,
    preserveExtension: true
}));
app.use(express.static(path.join(__dirname, 'public')));

// Lightweight request logging for anything that reaches the API (static assets
// are served above and intentionally not logged).
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => log('info', 'request', { method: req.method, path: req.path, status: res.statusCode, ms: Date.now() - start }));
    next();
});

// Liveness/readiness probe — actually pings MongoDB so it reports 'degraded'
// during an outage instead of falsely reporting 'ok' whenever `db` is truthy.
app.get('/healthz', async (req, res) => {
    let dbOk = false;
    try { if (db) { await db.command({ ping: 1 }); dbOk = true; } } catch (e) { dbOk = false; }
    res.status(dbOk ? 200 : 503).json({
        status: dbOk ? 'ok' : (db ? 'degraded' : 'starting'),
        uptime: Math.round(process.uptime())
    });
});

// ===================== Helpers (DB/JWT-bound; pure helpers live in lib/util) =====================

// JWT helpers / auth middleware. The token is only accepted from the
// Authorization header — never a URL query string (query tokens leak into
// browser history and proxy logs).
function getToken(req) {
    const header = req.headers.authorization || '';
    return header.replace(/^Bearer\s+/i, '');
}
function verifyToken(req) {
    const token = getToken(req);
    if (!token) return null;
    try { return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); } catch (e) { return null; }
}
// Full admin check: verifies the signature AND re-checks the account against the
// DB so a deleted/demoted admin (or one whose password changed) is revoked
// immediately rather than staying valid until the 8h token expiry.
async function requireAdmin(req, res, next) {
    const payload = verifyToken(req);
    if (!payload || !payload.sub) return res.status(401).json({ error: 'Authentication required' });
    let admin;
    try { admin = await db.collection('admin_users').findOne({ _id: new ObjectId(payload.sub) }); }
    catch (e) { return res.status(401).json({ error: 'Authentication required' }); }
    if (!admin) return res.status(401).json({ error: 'Session no longer valid' });
    if ((admin.token_version || 0) !== (payload.tv || 0)) {
        return res.status(401).json({ error: 'Session expired, please sign in again' });
    }
    // Use the CURRENT role/username from the DB, not whatever was baked into the token.
    req.admin = { sub: admin._id.toString(), username: admin.username, role: admin.role || ROLES.ADMIN };
    next();
}

// Write a moderation audit entry (best-effort, never blocks the response path).
async function audit(action, eventId, req, extra = {}) {
    try {
        await db.collection('audit_logs').insertOne({
            action,
            event_id: eventId,
            admin: req.admin ? req.admin.username : 'system',
            at: new Date().toISOString(),
            ...extra
        });
    } catch (e) { /* non-fatal */ }
}

// Store one uploaded file in GridFS, returning a lightweight metadata record.
// A SHA-256 of the bytes is kept for integrity / future dedup.
function storeFile(file) {
    return new Promise((resolve, reject) => {
        const sha256 = crypto.createHash('sha256').update(file.data).digest('hex');
        const stream = bucket.openUploadStream(file.name, {
            contentType: file.mimetype,
            metadata: { size: file.size, sha256 }
        });
        const fileId = stream.id;
        stream.on('error', reject);
        stream.on('finish', () => resolve({
            name: file.name,
            mimetype: file.mimetype,
            size: file.size,
            sha256,
            file_id: fileId
        }));
        stream.end(file.data);
    });
}

// Best-effort removal of already-stored GridFS files (used to clean up when a
// submission fails partway, so uploads are never left orphaned).
async function deleteFiles(records) {
    for (const r of records || []) {
        if (r && r.file_id) { try { await bucket.delete(r.file_id); } catch (e) { /* non-fatal */ } }
    }
}

// OCR a set of image buffers into plain text (used by the quick-start extractor so
// victims can drop screenshots / ID cards and have fields auto-filled). tesseract.js
// is loaded lazily (never at boot) and a fresh worker is created per request and
// terminated afterwards to bound memory. Failures are non-fatal — the caller falls
// back to whatever text was recognised. Language set is tunable via OCR_LANGS.
// Returns an array of recognised text, one entry per input buffer (empty string on
// failure), so callers can classify/extract per document.
async function ocrImages(buffers) {
    const out = (buffers || []).map(() => '');
    if (!out.length) return out;
    let createWorker;
    try { ({ createWorker } = require('tesseract.js')); } catch (e) { log('error', 'tesseract.js unavailable', { err: e.message }); return out; }
    // Default to English + Bengali so Bangladeshi NID cards and Bengali posts are
    // read, not garbled. The Bengali model downloads once and is then cached.
    const langs = process.env.OCR_LANGS || 'eng+ben';
    // Cache the downloaded language model in the OS temp dir (not the app dir).
    const cachePath = process.env.OCR_CACHE_PATH || path.join(require('os').tmpdir(), 'fcbd-ocr');
    try { require('fs').mkdirSync(cachePath, { recursive: true }); } catch (e) { /* ignore */ }
    let worker = null;
    try {
        worker = await createWorker(langs, 1, { cachePath });
        for (let i = 0; i < buffers.length; i++) {
            try { const { data } = await worker.recognize(buffers[i]); out[i] = data.text || ''; }
            catch (e) { log('error', 'ocr recognize failed', { err: e.message }); }
        }
    } catch (e) {
        log('error', 'ocr worker failed', { err: e.message });
    } finally {
        if (worker) { try { await worker.terminate(); } catch (e) { /* ignore */ } }
    }
    return out;
}

// Stream a media record (GridFS file_id OR legacy inline base64) to the response.
function streamMedia(res, media, inline) {
    const type = media.mimetype || 'application/octet-stream';
    const safeName = String(media.name || 'file').replace(/[^\w.\- ]/g, '_');
    res.set('Content-Type', type);
    res.set('Cache-Control', 'private, max-age=3600');
    // Sandbox served uploads so even a spoofed/polyglot file cannot run scripts.
    res.set('Content-Security-Policy', "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'");
    res.set('X-Content-Type-Options', 'nosniff');
    // Never let browsers render uploads as active content (e.g. SVG/HTML XSS):
    // only images and PDFs are shown inline, everything else downloads.
    const canInline = /^image\/(jpeg|png|gif|webp)$/.test(type) || type === 'application/pdf';
    res.set('Content-Disposition', `${inline && canInline ? 'inline' : 'attachment'}; filename="${safeName}"`);
    if (media.file_id) {
        bucket.openDownloadStream(media.file_id)
            .on('error', () => { if (!res.headersSent) res.status(404).end(); })
            .pipe(res);
    } else if (media.data) {
        res.send(Buffer.from(media.data, 'base64'));
    } else {
        res.status(404).end();
    }
}

// ===================== DB init / migrations =====================

async function connectToDatabase() {
    const client = new MongoClient(MONGODB_URI);
    // Retry with backoff so a transient DB unavailability at boot (common with
    // docker-compose start ordering) waits instead of crash-looping the container.
    const maxAttempts = 10;
    for (let attempt = 1; ; attempt++) {
        try {
            await client.connect();
            break;
        } catch (err) {
            if (attempt >= maxAttempts) {
                console.error(`✗ MongoDB connection failed after ${attempt} attempts:`, err.message);
                process.exit(1);
            }
            const wait = Math.min(1000 * attempt, 8000);
            console.warn(`⚠ MongoDB connect attempt ${attempt} failed (${err.message}); retrying in ${wait}ms…`);
            await new Promise((r) => setTimeout(r, wait));
        }
    }
    console.log('✓ Connected to MongoDB Atlas');
    db = client.db(DB_NAME);
    bucket = new GridFSBucket(db, { bucketName: 'uploads' });
    // Surface connection drops in logs (the driver auto-reconnects for later ops).
    client.on('serverHeartbeatFailed', () => log('error', 'mongodb heartbeat failed'));
    await initializeDatabase();

    // Graceful shutdown
    const shutdown = async () => { try { await client.close(); } catch (e) {} process.exit(0); };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    return client;
}

async function ensureCollections() {
    const names = (await db.listCollections().toArray()).map(c => c.name);
    for (const c of ['cheater_profiles', 'identifiers', 'fraud_events', 'event_phones', 'audit_logs', 'admin_users', 'disputes']) {
        if (!names.includes(c)) { await db.createCollection(c); console.log('✓ Created collection:', c); }
    }
}

async function ensureIndexes() {
    const fe = db.collection('fraud_events');
    try {
        await fe.createIndex({
            imposter_name: 'text', imposter_nickname: 'text', imposter_phone: 'text',
            imposter_nid: 'text', gd_number: 'text', scam_type: 'text',
            description: 'text', scam_location: 'text'
        });
    } catch (e) { /* text index already exists with different fields */ }
    await fe.createIndex({ status: 1 });
    await fe.createIndex({ profile_id: 1 });
    await fe.createIndex({ submitted_at: -1 });
    // Sort/lookup fields used by list + trust queries (avoids in-memory sorts/scans).
    await fe.createIndex({ approved_at: -1 });
    await fe.createIndex({ rejected_at: -1 });
    await fe.createIndex({ loss_amount: -1 });
    await fe.createIndex({ imposter_normalized_phone: 1 });
    await fe.createIndex({ status: 1, evidence_score: 1 });
    await fe.createIndex({ mfs_normalized_wallet: 1 });
    await db.collection('audit_logs').createIndex({ at: -1 });
    await db.collection('identifiers').createIndex({ normalized_value: 1 });
    await db.collection('identifiers').createIndex({ profile_id: 1 });
    await db.collection('identifiers').createIndex({ identifier_type: 1 });
    await db.collection('event_phones').createIndex({ event_id: 1 });
    await db.collection('event_phones').createIndex({ normalized_phone: 1 });
    await db.collection('cheater_profiles').createIndex({ normalized_name: 1 });
    await db.collection('disputes').createIndex({ created_at: -1 });
    await db.collection('disputes').createIndex({ event_id: 1 });
    console.log('✓ Indexes ensured');
}

async function seedAdmin() {
    const adminUsers = db.collection('admin_users');
    const existing = await adminUsers.findOne({ username: ADMIN_USERNAME });
    if (!existing) {
        // In production, refuse to seed a guessable default password.
        if (IS_PROD && !ADMIN_PASSWORD) {
            console.error('✗ No admin exists and ADMIN_PASSWORD is not set. Set ADMIN_USERNAME/ADMIN_PASSWORD to seed the first admin.');
            process.exit(1);
        }
        const initialPassword = ADMIN_PASSWORD || 'admin123';
        await adminUsers.insertOne({
            username: ADMIN_USERNAME,
            password_hash: await bcrypt.hash(initialPassword, 10),
            role: ROLES.SUPERUSER,
            token_version: 0,
            must_change_password: !ADMIN_PASSWORD,
            created_at: new Date().toISOString()
        });
        console.log(ADMIN_PASSWORD
            ? `✓ Seeded admin user "${ADMIN_USERNAME}" from ADMIN_PASSWORD`
            : '✓ Seeded admin user (admin/admin123 — CHANGE THIS immediately via the admin panel!)');
        return;
    }
    const set = {};
    // Migrate a legacy plaintext password to a bcrypt hash in place.
    if (!/^\$2[aby]\$/.test(existing.password_hash || '')) {
        set.password_hash = await bcrypt.hash(existing.password_hash || 'admin123', 10);
        console.log('✓ Migrated legacy admin password to bcrypt hash');
    }
    // Backfill the role so the default admin can manage other admins.
    if (!existing.role) {
        set.role = ROLES.SUPERUSER;
        console.log('✓ Backfilled default admin role -> superuser');
    }
    if (existing.token_version === undefined) set.token_version = 0;
    if (Object.keys(set).length) await adminUsers.updateOne({ _id: existing._id }, { $set: set });
    // Warn loudly if the well-known default password still works.
    if (await bcrypt.compare('admin123', existing.password_hash || set.password_hash || '')) {
        console.warn('⚠ The default admin password (admin123) is still active — change it in the admin panel.');
    }
}

async function migrateLegacyEvents() {
    const fe = db.collection('fraud_events');
    // Standardize reporter visibility to the canonical enum.
    await fe.updateMany({ reporter_visibility: { $nin: [VISIBILITY.PUBLIC, VISIBILITY.HIDDEN] } },
        { $set: { reporter_visibility: VISIBILITY.HIDDEN } });
    // Backfill old-schema events that predate the imposter_* fields.
    const legacy = await fe.find({ imposter_name: { $exists: false } }).toArray();
    for (const ev of legacy) {
        const set = { imposter_name: 'Unknown Imposter' };
        if (ev.profile_id) {
            const p = await db.collection('cheater_profiles').findOne({ _id: ev.profile_id });
            if (p && p.display_name) set.imposter_name = p.display_name;
        }
        set.imposter_phone = ev.imposter_phone || '';
        set.imposter_nickname = ev.imposter_nickname || '';
        set.imposter_nid = ev.imposter_nid || '';
        set.alt_phones = Array.isArray(ev.alt_phones) ? ev.alt_phones : [];
        if (ev.address && !ev.scam_location) set.scam_location = ev.address;
        await fe.updateOne({ _id: ev._id }, { $set: set });
    }
    if (legacy.length) console.log(`✓ Migrated ${legacy.length} legacy event(s) to current schema`);
}

async function seedSampleData() {
    // Only seed demo data when explicitly requested — never pollute a real
    // (empty) production database with a fake, already-approved sample record.
    if (process.env.SEED_SAMPLE !== 'true') return;
    const profiles = db.collection('cheater_profiles');
    if (await profiles.countDocuments() > 0) return;
    const ts = new Date().toISOString();
    const sampleProfile = await profiles.insertOne({
        display_name: 'Sample Fraudster', normalized_name: normalize('Sample Fraudster'),
        profile_status: 'verified', created_at: ts, updated_at: ts
    });
    const samplePhone = '+1-234-567-8900';
    await db.collection('identifiers').insertOne({
        profile_id: sampleProfile.insertedId, identifier_type: 'phone',
        identifier_value: samplePhone, normalized_value: normalize(samplePhone), is_primary: true
    });
    await db.collection('fraud_events').insertOne({
        profile_id: sampleProfile.insertedId,
        imposter_name: 'Sample Fraudster', imposter_phone: samplePhone,
        imposter_normalized_phone: normalize(samplePhone),
        imposter_nickname: '', imposter_nid: '', imposter_address: 'Sample Address',
        social_media_account: '', imposter_picture: null, alt_phones: [], scam_proofs: [],
        scam_type: 'Online Payment Fraud', loss_item: 'Money', loss_amount: 5000,
        description: 'Sample fraud case for demonstration purposes.', scam_location: 'Online',
        gd_number: 'GD001',
        reporter_name: 'Test Reporter', reporter_phone: '', reporter_email: '',
        reporter_visibility: VISIBILITY.PUBLIC,
        status: STATUS.APPROVED, submitted_at: ts, approved_at: ts, rejected_at: null
    });
    console.log('✓ Seeded sample fraudster profile');
}

async function initializeDatabase() {
    try {
        await ensureCollections();
        await seedAdmin();
        await seedSampleData();
        await migrateLegacyEvents();
        await ensureIndexes();
        console.log(`✓ Database initialized: ${DB_NAME}`);
    } catch (err) {
        console.error('Database initialization error:', err.message);
        throw err;
    }
}

// Resolve (or create) the consolidated fraudster profile for an approved event,
// matching on ANY of its phones or NID, and recording all known identifiers.
async function resolveProfile(event, timestamp) {
    const identifiers = db.collection('identifiers');
    const phones = await db.collection('event_phones').find({ event_id: event._id }).toArray();
    const phoneNorms = phones.map(p => normalize(p.phone_number)).filter(Boolean);
    const nidNorm = event.imposter_nid ? normalize(event.imposter_nid) : null;
    const walletNorm = event.mfs_wallet ? normalize(event.mfs_wallet) : null;
    const bankNorm = event.bank_account ? normalize(event.bank_account) : null;
    const lookup = [...phoneNorms];
    if (nidNorm) lookup.push(nidNorm);
    if (walletNorm) lookup.push(walletNorm);
    if (bankNorm) lookup.push(bankNorm);

    let profileId = null;
    if (lookup.length) {
        const match = await identifiers.findOne({ normalized_value: { $in: lookup }, profile_id: { $ne: null } });
        if (match) profileId = match.profile_id;
    }
    if (!profileId) {
        const name = event.imposter_name || 'Unidentified Fraudster';
        const created = await db.collection('cheater_profiles').insertOne({
            display_name: name, normalized_name: normalize(name),
            profile_status: 'verified', created_at: timestamp, updated_at: timestamp
        });
        profileId = created.insertedId;
    }

    // Upsert this event's identifiers under the profile (dedup by value+type).
    const ops = [];
    phones.forEach((p, i) => {
        const nv = normalize(p.phone_number);
        if (!nv) return;
        ops.push({ updateOne: {
            filter: { profile_id: profileId, identifier_type: 'phone', normalized_value: nv },
            update: { $setOnInsert: { profile_id: profileId, identifier_type: 'phone', identifier_value: p.phone_number, normalized_value: nv, is_primary: i === 0 } },
            upsert: true
        } });
    });
    if (nidNorm) ops.push({ updateOne: {
        filter: { profile_id: profileId, identifier_type: 'nid', normalized_value: nidNorm },
        update: { $setOnInsert: { profile_id: profileId, identifier_type: 'nid', identifier_value: event.imposter_nid, normalized_value: nidNorm, is_primary: true } },
        upsert: true
    } });
    if (walletNorm) ops.push({ updateOne: {
        filter: { profile_id: profileId, identifier_type: 'mfs_wallet', normalized_value: walletNorm },
        update: { $setOnInsert: { profile_id: profileId, identifier_type: 'mfs_wallet', identifier_value: event.mfs_wallet, mfs_provider: event.mfs_provider || '', normalized_value: walletNorm, is_primary: true } },
        upsert: true
    } });
    if (bankNorm) ops.push({ updateOne: {
        filter: { profile_id: profileId, identifier_type: 'bank_account', normalized_value: bankNorm },
        update: { $setOnInsert: { profile_id: profileId, identifier_type: 'bank_account', identifier_value: event.bank_account, normalized_value: bankNorm, is_primary: true } },
        upsert: true
    } });
    const nameNorm = normalize(event.imposter_name || '');
    if (nameNorm) ops.push({ updateOne: {
        filter: { profile_id: profileId, identifier_type: 'imposter_name', normalized_value: nameNorm },
        update: { $setOnInsert: { profile_id: profileId, identifier_type: 'imposter_name', identifier_value: event.imposter_name, normalized_value: nameNorm, is_primary: true } },
        upsert: true
    } });
    if (ops.length) await identifiers.bulkWrite(ops);
    await db.collection('cheater_profiles').updateOne({ _id: profileId }, { $set: { updated_at: timestamp } });
    return profileId;
}

// ----- public rate limiters (anti-abuse) -----
const submitLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many submissions from this device. Please try again later.' }
});
const disputeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many disputes from this device. Please try again later.' }
});
// General limiter for public read endpoints (search/check/media/details) so they
// can't be used for cheap DB/bandwidth exhaustion. Generous enough for real use.
const readLimiter = rateLimit({
    windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many requests. Please slow down and try again shortly.' }
});
// OCR is CPU-heavy, so the quick-start extractor gets a tighter limiter.
const ocrLimiter = rateLimit({
    windowMs: 60 * 1000, max: 12, standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many extraction requests. Please wait a moment and try again.' }
});

// ===================== PUBLIC API =====================

// GET /api/search?q=&category=&sort=&limit=&skip=
// Returns an array of approved events; the total match count is in the
// `X-Total-Count` header and the match strategy in `X-Search-Mode`.
app.get('/api/search', readLimiter, async (req, res) => {
    try {
        const query = str(req.query.q).trim().slice(0, 200);
        if (!query) return res.json([]);
        const { limit, skip } = paging(req, 30, 100);
        const fraudEvents = db.collection('fraud_events');
        const projection = { scam_proofs: 0, imposter_picture: 0, reporter_phone: 0, reporter_email: 0 };

        const category = str(req.query.category).trim();
        const sortMap = { recent: { approved_at: -1 }, loss: { loss_amount: -1 } };
        const sort = sortMap[str(req.query.sort)] || { approved_at: -1 };

        const filter = { status: STATUS.APPROVED };
        if (category) filter.scam_type = category;

        // Phone-first: when the query looks like a phone number, match normalized
        // numbers (primary + alternates) rather than the text index.
        const looksLikePhone = /^[\d+\-\s()]+$/.test(query) && query.replace(/\D/g, '').length >= 6;
        let mode = 'text';
        if (looksLikePhone) {
            mode = 'phone';
            const nq = normalize(query);
            // Anchored prefix match so the query can use the normalized_phone index
            // instead of an unanchored substring scan of the whole collection.
            const phoneRows = await db.collection('event_phones')
                .find({ normalized_phone: { $regex: '^' + escapeRegex(nq) } })
                .project({ event_id: 1 }).limit(2000).toArray();
            const ids = phoneRows.map(p => p.event_id);
            // Also match the money trail: reports whose MFS wallet equals the number.
            const walletMatches = await fraudEvents
                .find({ status: STATUS.APPROVED, mfs_normalized_wallet: normalizeWallet(query) })
                .project({ _id: 1 }).limit(2000).toArray();
            for (const w of walletMatches) ids.push(w._id);
            filter._id = { $in: ids };
        } else {
            filter.$text = { $search: query };
        }

        let total, matches;
        try {
            total = await fraudEvents.countDocuments(filter);
            matches = await fraudEvents.find(filter, { projection }).sort(sort).skip(skip).limit(limit).toArray();
        } catch (textErr) {
            // Text index unavailable -> regex fallback.
            delete filter.$text;
            const rx = new RegExp(escapeRegex(query), 'i');
            filter.$or = [
                { imposter_name: rx }, { imposter_nickname: rx }, { imposter_phone: rx },
                { alt_phones: rx }, { imposter_nid: rx }, { gd_number: rx },
                { scam_type: rx }, { description: rx }, { scam_location: rx }
            ];
            total = await fraudEvents.countDocuments(filter);
            matches = await fraudEvents.find(filter, { projection }).sort(sort).skip(skip).limit(limit).toArray();
        }

        res.set('X-Total-Count', String(total));
        res.set('X-Search-Mode', mode);
        res.json(matches.map(e => sanitizeEvent(e)));
    } catch (err) {
        res.status(500).json({ error: 'Search failed' });
    }
});

// GET /api/recent — latest approved reports for the browse/landing feed (so the
// homepage shows value before the visitor types a query).
app.get('/api/recent', readLimiter, async (req, res) => {
    try {
        const { limit } = paging(req, 6, 24);
        const projection = { scam_proofs: 0, imposter_picture: 0, reporter_phone: 0, reporter_email: 0 };
        const rows = await db.collection('fraud_events')
            .find({ status: STATUS.APPROVED }, { projection }).sort({ approved_at: -1 }).limit(limit).toArray();
        res.json(rows.map((e) => sanitizeEvent(e)));
    } catch (err) {
        res.status(500).json({ error: 'Failed to load recent reports' });
    }
});

// POST /api/extract — quick-start helper. Accepts pasted `text` and/or uploaded
// `images` (screenshots, ID cards); OCRs the images, merges with the text, and
// returns extracted fields (phones, wallets, TrxIDs, amounts, URLs, NIDs) plus the
// raw OCR text so the client can pre-fill the report form. The images themselves
// are NOT stored here — the client re-attaches them as proof on final submission.
app.post('/api/extract', ocrLimiter, async (req, res) => {
    try {
        let files = [];
        if (req.files && req.files.images) files = Array.isArray(req.files.images) ? req.files.images : [req.files.images];
        // Keep each image's ORIGINAL client index; only accept genuine images.
        const valid = files.slice(0, 5).map((f, idx) => ({ f, idx }))
            .filter(({ f }) => !f.truncated && ALLOWED_IMAGE.includes(f.mimetype) && typeMatches(f.mimetype, sniffFamily(f.data)));
        const pasted = str(req.body && req.body.text).slice(0, 5000);

        // AI path (opt-in + key configured): more precise multimodal extraction and
        // an AI-written description. Any failure falls through to OCR below.
        if (str(req.body && req.body.ai_consent) === 'true' && process.env.GEMINI_API_KEY) {
            try {
                const ai = await aiExtract({ text: pasted, images: valid.map((v) => ({ data: v.f.data, mimetype: v.f.mimetype })) });
                if (ai) {
                    // Remap AI's order-based image indices back to the client's indices.
                    const images = (ai.images || []).map((im) => ({ ...im, index: valid[im.index] ? valid[im.index].idx : im.index }));
                    return res.json({ source: 'ai', fields: ai.fields, images, low_confidence: ai.low_confidence || [] });
                }
            } catch (e) { log('error', 'ai extract failed', { err: e.message }); }
        }

        // OCR + regex fallback (works with no key / no consent / AI failure).
        const texts = await ocrImages(valid.map((v) => v.f.data));
        let ocrCombined = '';
        const images = valid.map((v, k) => {
            const text = texts[k] || '';
            ocrCombined += '\n' + text;
            const compact = text.replace(/\s+/g, '');
            // A document (e.g. NID) has ID markers or substantial text; a plain photo
            // has almost none — the client uses this to choose the imposter picture.
            const isDoc = /nid|national\s*id|জাতীয়|পরিচয়|গণপ্রজাতন্ত্রী|government/i.test(text) ||
                extractFromText(text).nids.length > 0 || compact.length > 40;
            return { index: v.idx, is_document: isDoc, is_photo: compact.length < 15 };
        });
        // Return the two sources SEPARATELY so the client can apply the rules:
        // description only from `paste`, name/phone/address/NID from both.
        const paste = { ...extractFromText(pasted), ...extractPerson(pasted) };
        const image = { ...extractFromText(ocrCombined), ...extractPerson(ocrCombined) };
        // Money-trail (receiving wallet + provider + trxid) and the reporter's own
        // number, detected across both sources, so the client can route the wallet to
        // the money field and keep the reporter's number out of the accused's phones.
        const combined = pasted + '\n' + ocrCombined;
        const money = extractMoneyTrail(combined);
        const reporter = extractReporterContact(pasted); // reporter cues come from the victim's own message
        res.json({ source: 'ocr', ocr_used: valid.length > 0, images_read: valid.length, images, paste, image, money, reporter });
    } catch (err) {
        log('error', 'extract failed', { err: err.message });
        res.status(500).json({ error: 'Could not read the images. Please fill the form manually.' });
    }
});

// GET /api/check?phone=&nid= — quick public lookup of how many APPROVED reports
// match a phone and/or NID (counts only, no personal data). Powers the submit
// form's duplicate hint and can back a standalone "is this number reported?" check.
app.get('/api/check', readLimiter, async (req, res) => {
    try {
        const fraudEvents = db.collection('fraud_events');
        const phone = str(req.query.phone).trim().slice(0, 40);
        const nid = str(req.query.nid).trim().slice(0, 40);
        const out = { phone_reports: 0, nid_reports: 0, wallet_reports: 0 };
        let matchedIds = [];
        if (phone) {
            const nq = normalize(phone);
            if (nq) {
                const ids = await db.collection('event_phones')
                    .find({ normalized_phone: nq }).project({ event_id: 1 }).toArray();
                matchedIds = ids.map((i) => i.event_id);
                out.phone_reports = await fraudEvents.countDocuments({ status: STATUS.APPROVED, _id: { $in: matchedIds } });
            }
            // Money-trail: reports whose MFS wallet equals this number.
            out.wallet_reports = await fraudEvents.countDocuments({ status: STATUS.APPROVED, mfs_normalized_wallet: normalizeWallet(phone) });
            // Intrinsic risk of the number itself (independent of any reports).
            out.phone_risk = phoneRisk(phone);
        }
        if (nid) {
            out.nid_reports = await fraudEvents.countDocuments({ status: STATUS.APPROVED, imposter_nid: nid });
        }
        // Aggregate risk score for the number (corroboration + recency + loss + disputes).
        const totalReports = out.phone_reports + out.wallet_reports;
        if (totalReports > 0 && (matchedIds.length || out.wallet_reports)) {
            const agg = await fraudEvents.aggregate([
                { $match: { status: STATUS.APPROVED, $or: [{ _id: { $in: matchedIds } }, { mfs_normalized_wallet: normalizeWallet(phone) }] } },
                { $group: { _id: null, loss: { $sum: '$loss_amount' }, last: { $max: '$approved_at' },
                    reporters: { $addToSet: { $ifNull: ['$reporter_phone', '$reporter_name'] } } } }
            ]).toArray();
            const a = agg[0] || {};
            const recencyDays = a.last ? Math.floor((Date.now() - new Date(a.last).getTime()) / 86400000) : null;
            const openDisputes = matchedIds.length
                ? await db.collection('disputes').countDocuments({ event_id: { $in: matchedIds }, status: 'open' })
                : 0;
            out.risk = riskScore({
                reportCount: totalReports,
                distinctReporters: Array.isArray(a.reporters) ? a.reporters.filter(Boolean).length : 0,
                totalLoss: a.loss || 0, recencyDays, openDisputes
            });
        } else {
            out.risk = riskScore({ reportCount: 0 });
        }
        res.json(out);
    } catch (err) {
        res.status(500).json({ error: 'Check failed' });
    }
});

// GET /api/stats/public — non-sensitive numbers for the public transparency panel.
app.get('/api/stats/public', readLimiter, async (req, res) => {
    try {
        const fe = db.collection('fraud_events');
        const since = new Date(Date.now() - 30 * 86400000).toISOString();
        const [total, lossAgg, fraudsters, recent, topCats] = await Promise.all([
            fe.countDocuments({ status: STATUS.APPROVED }),
            fe.aggregate([{ $match: { status: STATUS.APPROVED } }, { $group: { _id: null, total: { $sum: '$loss_amount' } } }]).toArray(),
            db.collection('cheater_profiles').countDocuments(),
            fe.countDocuments({ status: STATUS.APPROVED, approved_at: { $gte: since } }),
            fe.aggregate([
                { $match: { status: STATUS.APPROVED } },
                { $group: { _id: '$scam_type', count: { $sum: 1 } } },
                { $sort: { count: -1 } }, { $limit: 5 }
            ]).toArray()
        ]);
        res.json({
            total_reports: total,
            total_loss: (lossAgg[0] && lossAgg[0].total) || 0,
            fraudsters,
            reports_last_30d: recent,
            top_categories: topCats.map((c) => ({ category: c._id || 'Unknown', count: c.count }))
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to load stats' });
    }
});

// POST /api/events/:id/dispute — right-of-reply: anyone can contest a report.
app.post('/api/events/:id/dispute', disputeLimiter, async (req, res) => {
    try {
        const eventId = new ObjectId(req.params.id);
        // Only approved (public) reports are disputable — pending/rejected IDs return
        // the same 404 as nonexistent ones (no existence oracle).
        const event = await db.collection('fraud_events').findOne({ _id: eventId, status: STATUS.APPROVED }, { projection: { _id: 1 } });
        if (!event) return res.status(404).json({ error: 'Report not found.' });
        const reason = str(req.body && req.body.reason).trim();
        const contact = str(req.body && req.body.contact).trim().slice(0, 200);
        if (reason.length < 20 || reason.length > 1000) {
            return res.status(400).json({ error: 'Please describe the dispute in 20–1000 characters.' });
        }
        await db.collection('disputes').insertOne({ event_id: eventId, reason, contact, status: 'open', created_at: new Date().toISOString() });
        res.json({ message: '✓ Your dispute has been submitted for review.' });
    } catch (err) {
        res.status(500).json({ error: 'Could not submit your dispute.' });
    }
});

// GET /sitemap.xml — home, submit, and every approved report (SEO).
app.get('/sitemap.xml', async (req, res) => {
    try {
        const base = baseUrl(req);
        const events = await db.collection('fraud_events')
            .find({ status: STATUS.APPROVED }, { projection: { _id: 1, approved_at: 1 } }).limit(5000).toArray();
        const profiles = await db.collection('cheater_profiles')
            .find({}, { projection: { _id: 1, updated_at: 1 } }).limit(5000).toArray();
        const urls = [
            `<url><loc>${base}/</loc></url>`,
            `<url><loc>${base}/submit.html</loc></url>`,
            `<url><loc>${base}/check.html</loc></url>`,
            ...events.map((e) => `<url><loc>${base}/report/${e._id}</loc><lastmod>${(e.approved_at || '').slice(0, 10)}</lastmod></url>`),
            ...profiles.map((p) => `<url><loc>${base}/profile/${p._id}</loc><lastmod>${(p.updated_at || '').slice(0, 10)}</lastmod></url>`)
        ];
        res.set('Content-Type', 'application/xml');
        res.send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>`);
    } catch (err) {
        res.status(500).end();
    }
});

// Small HTML-escape helper for server-rendered share pages.
const escHtml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Render a server-side share/redirect page with real OG/meta + JSON-LD for
// crawlers and social previews; humans are redirected to the interactive page.
function renderShare(res, { title, desc, canonical, target, jsonLd }) {
    res.set('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escHtml(title)}</title>
<meta name="description" content="${escHtml(desc)}">
<meta property="og:title" content="${escHtml(title)}"><meta property="og:description" content="${escHtml(desc)}">
<meta property="og:type" content="article"><meta property="og:url" content="${escHtml(canonical)}">
<meta name="twitter:card" content="summary">
<link rel="canonical" href="${escHtml(canonical)}">
${jsonLd ? `<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>` : ''}
<meta http-equiv="refresh" content="0; url=${escHtml(target)}"></head>
<body><p>Redirecting to the <a href="${escHtml(target)}">fraud report</a>…</p></body></html>`);
}

// GET /report/:id — server-rendered share page with real OG/meta for crawlers
// and social previews; humans are redirected to the interactive detail page.
app.get('/report/:id', async (req, res) => {
    try {
        const event = await db.collection('fraud_events').findOne(
            { _id: new ObjectId(req.params.id), status: STATUS.APPROVED },
            { projection: { imposter_name: 1, scam_type: 1, description: 1 } }
        );
        if (!event) return res.redirect('/');
        const name = event.imposter_name || 'Fraud report';
        const title = `${name} — ${event.scam_type || 'Scam'} (reported) | Fraud-Checker-BD`;
        const desc = 'Community-reported fraud allegation (pending independent verification) on Fraud-Checker-BD. ' +
            (event.description || '').slice(0, 140);
        const target = `/event-detail.html?id=${event._id}`;
        const canonical = `${baseUrl(req)}${target}`;
        renderShare(res, {
            title, desc, canonical, target,
            jsonLd: {
                '@context': 'https://schema.org', '@type': 'Article', headline: title,
                description: desc.slice(0, 200), url: canonical,
                about: { '@type': 'Thing', name }
            }
        });
    } catch (err) {
        res.redirect('/');
    }
});

// GET /number/:phone — crawlable canonical page for a reported number (Bangladeshis
// routinely Google a number before paying COD). Redirects humans to a lookup.
app.get('/number/:phone', async (req, res) => {
    try {
        const raw = str(req.params.phone).replace(/[^\d+]/g, '').slice(0, 20);
        const nq = normalize(raw);
        let count = 0;
        if (nq) {
            const ids = await db.collection('event_phones').find({ normalized_phone: { $regex: '^' + escapeRegex(nq) } }).project({ event_id: 1 }).limit(2000).toArray();
            count = await db.collection('fraud_events').countDocuments({ status: STATUS.APPROVED, _id: { $in: ids.map((i) => i.event_id) } });
        }
        const title = count > 0
            ? `${raw} — reported ${count} time(s) as a scam number | Fraud-Checker-BD`
            : `${raw} — check this number for scam reports | Fraud-Checker-BD`;
        const desc = count > 0
            ? `The number ${raw} appears in ${count} community fraud report(s) (allegations, pending verification). Check before you pay.`
            : `No fraud reports found for ${raw} yet on Fraud-Checker-BD. Search Bangladesh's community fraud database before you trust a number.`;
        const target = `/?q=${encodeURIComponent(raw)}`;
        const canonical = `${baseUrl(req)}/number/${encodeURIComponent(raw)}`;
        renderShare(res, {
            title, desc, canonical, target,
            jsonLd: { '@context': 'https://schema.org', '@type': 'WebPage', name: title, description: desc.slice(0, 200), url: canonical }
        });
    } catch (err) {
        res.redirect('/');
    }
});

// GET /profile/:id — crawlable share bridge for a consolidated fraudster profile.
app.get('/profile/:id', async (req, res) => {
    try {
        const profile = await db.collection('cheater_profiles').findOne({ _id: new ObjectId(req.params.id) });
        if (!profile) return res.redirect('/');
        const name = profile.display_name || 'Reported fraudster';
        const count = await db.collection('fraud_events').countDocuments({ profile_id: profile._id, status: STATUS.APPROVED });
        const title = `${name} — ${count} reported fraud incident(s) | Fraud-Checker-BD`;
        const desc = `Consolidated community fraud reports for ${name} (allegations, pending verification). ${count} linked incident(s).`;
        const target = `/imposter-profile.html?id=${profile._id}`;
        const canonical = `${baseUrl(req)}${target}`;
        renderShare(res, {
            title, desc, canonical, target,
            jsonLd: { '@context': 'https://schema.org', '@type': 'ProfilePage', name: title, description: desc.slice(0, 200), url: canonical }
        });
    } catch (err) {
        res.redirect('/');
    }
});

// GET /api/events/:id/details
app.get('/api/events/:id/details', readLimiter, async (req, res) => {
    try {
        const eventId = new ObjectId(req.params.id);
        const event = await db.collection('fraud_events').findOne(
            { _id: eventId, status: STATUS.APPROVED },
            { projection: { imposter_picture: 0, 'scam_proofs.data': 0, 'scam_proofs.file_id': 0 } }
        );
        if (!event) return res.status(404).json({ error: 'Event not found' });

        let profile = null;
        if (event.profile_id) profile = await db.collection('cheater_profiles').findOne({ _id: event.profile_id });

        // Trust signals: how many approved reports share this imposter's phone,
        // plus the first/last time it was reported.
        const trust = { report_count: 1, first_seen: event.approved_at, last_seen: event.approved_at, risk: riskScore({ reportCount: 1 }) };
        if (event.imposter_normalized_phone) {
            const agg = await db.collection('fraud_events').aggregate([
                { $match: { status: STATUS.APPROVED, imposter_normalized_phone: event.imposter_normalized_phone } },
                { $group: { _id: null, count: { $sum: 1 }, loss: { $sum: '$loss_amount' },
                    first: { $min: '$approved_at' }, last: { $max: '$approved_at' },
                    reporters: { $addToSet: { $ifNull: ['$reporter_phone', '$reporter_name'] } } } }
            ]).toArray();
            if (agg[0]) {
                trust.report_count = agg[0].count;
                trust.first_seen = agg[0].first;
                trust.last_seen = agg[0].last;
                const recencyDays = agg[0].last ? Math.floor((Date.now() - new Date(agg[0].last).getTime()) / 86400000) : null;
                trust.risk = riskScore({
                    reportCount: agg[0].count,
                    distinctReporters: Array.isArray(agg[0].reporters) ? agg[0].reporters.filter(Boolean).length : 0,
                    totalLoss: agg[0].loss || 0, recencyDays
                });
            }
        }

        res.json({ event: sanitizeEvent(event, { includeProofs: true }), profile, trust });
    } catch (err) {
        res.status(404).json({ error: 'Event not found' });
    }
});

// GET /api/events/:id/picture — public for approved events; admins may view any.
app.get('/api/events/:id/picture', readLimiter, async (req, res) => {
    try {
        const event = await db.collection('fraud_events').findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { imposter_picture: 1, status: 1 } }
        );
        if (!event || !event.imposter_picture) return res.status(404).end();
        if (event.status !== STATUS.APPROVED && !verifyToken(req)) return res.status(404).end();
        return streamMedia(res, event.imposter_picture, true);
    } catch (err) {
        return res.status(404).end();
    }
});

// GET /api/events/:id/proofs/:index — public for approved events; admins may view any.
app.get('/api/events/:id/proofs/:index', readLimiter, async (req, res) => {
    try {
        const event = await db.collection('fraud_events').findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { scam_proofs: 1, status: 1 } }
        );
        if (!event || !Array.isArray(event.scam_proofs)) return res.status(404).end();
        if (event.status !== STATUS.APPROVED && !verifyToken(req)) return res.status(404).end();
        const proof = event.scam_proofs[parseInt(req.params.index, 10)];
        if (!proof) return res.status(404).end();
        return streamMedia(res, proof, true);
    } catch (err) {
        return res.status(404).end();
    }
});

// GET /api/profiles/:id
app.get('/api/profiles/:id', readLimiter, async (req, res) => {
    try {
        const profileId = new ObjectId(req.params.id);
        const profile = await db.collection('cheater_profiles').findOne({ _id: profileId });
        if (!profile) return res.status(404).json({ error: 'Profile not found' });

        const events = await db.collection('fraud_events').find(
            { profile_id: profileId, status: STATUS.APPROVED },
            { projection: { scam_proofs: 0, imposter_picture: 0, reporter_phone: 0, reporter_email: 0 } }
        ).toArray();

        const idents = await db.collection('identifiers')
            .find({ profile_id: profileId })
            .project({ identifier_type: 1, identifier_value: 1, mfs_provider: 1 }).toArray();
        // Never expose full NIDs publicly — mask to last 4 (same policy as sanitizeEvent).
        const safeIdents = idents.map((i) => i.identifier_type === 'nid'
            ? { ...i, identifier_value: maskNid(i.identifier_value) }
            : i);

        res.json({ profile, events: events.map(e => sanitizeEvent(e)), identifiers: safeIdents });
    } catch (err) {
        res.status(404).json({ error: 'Profile not found' });
    }
});

// POST /api/events — public submission
app.post('/api/events', submitLimiter, async (req, res) => {
    try {
        // Bot traps: a honeypot field humans never see, and a minimum fill time.
        if (str(req.body && req.body.website)) return res.status(400).json({ error: 'Spam detected.' });
        const loadedAt = parseInt(str(req.body && req.body.form_loaded_at), 10);
        if (loadedAt && Date.now() - loadedAt < 3000) {
            return res.status(400).json({ error: 'That was too fast — please take a moment and resubmit.' });
        }

        const { error, value } = validateSubmission(req.body);
        if (error) return res.status(400).json({ error });

        // Validate ALL file types/counts BEFORE storing anything, so a bad proof
        // never leaves an orphaned photo in GridFS. Validation checks the DECLARED
        // MIME *and* the actual magic bytes so a payload can't masquerade as an image.
        const picFile = (req.files && req.files.imposter_picture) || null;
        if (picFile) {
            if (picFile.truncated) return res.status(400).json({ error: 'Imposter picture exceeds the 10MB limit.' });
            if (!ALLOWED_IMAGE.includes(picFile.mimetype) || !typeMatches(picFile.mimetype, sniffFamily(picFile.data))) {
                return res.status(400).json({ error: 'Imposter picture must be a genuine JPEG, PNG, GIF, or WEBP image.' });
            }
        }
        let proofFiles = [];
        if (req.files && req.files.scam_proofs) {
            proofFiles = Array.isArray(req.files.scam_proofs) ? req.files.scam_proofs : [req.files.scam_proofs];
        }
        if (proofFiles.length === 0) return res.status(400).json({ error: 'At least one proof file is required.' });
        if (proofFiles.length > MAX_PROOFS) return res.status(400).json({ error: `Maximum ${MAX_PROOFS} files allowed.` });
        for (const f of proofFiles) {
            if (f.truncated) return res.status(400).json({ error: `Proof file too large (10MB max): ${f.name}` });
            if (!ALLOWED_PROOF.includes(f.mimetype) || !typeMatches(f.mimetype, sniffFamily(f.data))) {
                return res.status(400).json({ error: `Unsupported or mislabeled proof file: ${f.name} (${f.mimetype}).` });
            }
        }

        // Store files first, but clean them up if any later DB write fails (no orphans).
        const stored = [];
        let eventId;
        try {
            const imposterPicture = picFile ? await storeFile(picFile) : null;
            if (imposterPicture) stored.push(imposterPicture);
            const scamProofs = [];
            for (const f of proofFiles) { const rec = await storeFile(f); stored.push(rec); scamProofs.push(rec); }

            const timestamp = new Date().toISOString();
            const fraudEvents = db.collection('fraud_events');
            const eventPhones = db.collection('event_phones');

            const evidenceScore = scoreEvidence({
                scam_proofs: scamProofs, imposter_picture: imposterPicture, gd_number: value.gd_number,
                imposter_nid: value.imposter_nid, description: value.description,
                reporter_phone: value.reporter_phone, reporter_email: value.reporter_email,
                mfs_wallet: value.mfs_wallet, bank_account: value.bank_account, imposter_phone: value.imposter_phone
            });

            const result = await fraudEvents.insertOne({
                imposter_name: value.imposter_name,
                imposter_phone: value.imposter_phone,
                imposter_normalized_phone: normalize(value.imposter_phone),
                imposter_nickname: value.imposter_nickname,
                imposter_nid: value.imposter_nid,
                imposter_address: value.imposter_address,
                social_media_account: value.social_media_account,
                imposter_picture: imposterPicture,
                scam_type: value.scam_type,
                loss_item: value.loss_item,
                loss_amount: value.loss_amount,
                description: value.description,
                scam_location: value.scam_location,
                gd_number: value.gd_number,
                alt_phones: value.alt_phones,
                scam_proofs: scamProofs,
                // Money-trail (MFS / bank) identifiers.
                mfs_provider: value.mfs_provider,
                mfs_wallet: value.mfs_wallet,
                mfs_normalized_wallet: value.mfs_wallet ? normalizeWallet(value.mfs_wallet) : '',
                mfs_trxid: value.mfs_trxid,
                bank_account: value.bank_account,
                reporter_name: value.reporter_name,
                reporter_phone: value.reporter_phone,
                reporter_email: value.reporter_email,
                reporter_visibility: value.reporter_visibility,
                reporter_consent: true,
                evidence_score: evidenceScore,
                profile_id: null,
                status: STATUS.PENDING,
                submitted_at: timestamp,
                approved_at: null,
                rejected_at: null
            });

            eventId = result.insertedId;
            // Single round-trip for all phones (primary + alternates) — no N+1 loop.
            const phoneDocs = [{ event_id: eventId, phone_number: value.imposter_phone, normalized_phone: normalize(value.imposter_phone) }];
            for (const phone of value.alt_phones) {
                phoneDocs.push({ event_id: eventId, phone_number: phone, normalized_phone: normalize(phone) });
            }
            await eventPhones.insertMany(phoneDocs);
            // Note: profile-scoped identifiers are created at approval time by
            // resolveProfile(); we no longer insert orphan profile_id:null rows here.
        } catch (dbErr) {
            await deleteFiles(stored);
            if (eventId) { try { await db.collection('fraud_events').deleteOne({ _id: eventId }); } catch (e) {} }
            throw dbErr;
        }

        res.json({ message: '✓ Fraud report submitted successfully! Your report will be reviewed by our team.', eventId });
    } catch (err) {
        log('error', 'Event submission failed', { err: err.message });
        res.status(500).json({ error: 'Could not submit report. Please try again.' });
    }
});

// ===================== ADMIN API =====================

// Brute-force protection on login.
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 10,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many login attempts. Please try again later.' }
});

// POST /api/admin/login
app.post('/api/admin/login', loginLimiter, async (req, res) => {
    try {
        const username = str(req.body && req.body.username);
        const password = str(req.body && req.body.password);
        if (!username || !password) return res.status(400).json({ success: false, error: 'Username and password required' });

        const admin = await db.collection('admin_users').findOne({ username });
        if (!admin || !admin.password_hash || !(await bcrypt.compare(password, admin.password_hash))) {
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
        }
        const token = jwt.sign(
            { sub: admin._id.toString(), username: admin.username, role: admin.role || ROLES.ADMIN, tv: admin.token_version || 0 },
            JWT_SECRET, { algorithm: 'HS256', expiresIn: '8h' }
        );
        await db.collection('audit_logs').insertOne({ action: 'login', admin: admin.username, at: new Date().toISOString() });
        res.json({ success: true, token, must_change_password: !!admin.must_change_password });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Build a server-side filter for the admin event lists from query params:
// q (free text), scam_type, min_loss, has_gd, has_photo. Lets moderators search
// the WHOLE collection, not just the ~20 rows already loaded client-side.
function adminEventFilter(req, baseFilter) {
    const filter = { ...baseFilter };
    const q = str(req.query.q).trim().slice(0, 100);
    if (q) {
        const rx = new RegExp(escapeRegex(q), 'i');
        filter.$or = [
            { imposter_name: rx }, { imposter_phone: rx }, { imposter_nid: rx }, { imposter_nickname: rx },
            { scam_type: rx }, { scam_location: rx }, { description: rx }, { reporter_name: rx },
            { mfs_wallet: rx }, { gd_number: rx }
        ];
    }
    const scamType = str(req.query.scam_type).trim();
    if (scamType) filter.scam_type = scamType;
    const minLoss = parseFloat(req.query.min_loss);
    if (isFinite(minLoss) && minLoss > 0) filter.loss_amount = { $gte: minLoss };
    if (str(req.query.has_gd) === 'true') filter.gd_number = { $nin: ['', null] };
    if (str(req.query.has_photo) === 'true') filter.imposter_picture = { $ne: null };
    return filter;
}

// Everything below requires a valid admin session.
app.get('/api/admin/moderation-queue', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req);
        // Sort weakest-evidence first when requested, so thin/risky accusations get
        // the hardest scrutiny; otherwise newest-first.
        const sort = str(req.query.sort) === 'evidence' ? { evidence_score: 1, submitted_at: -1 } : { submitted_at: -1 };
        const events = await db.collection('fraud_events')
            .find(adminEventFilter(req, { status: STATUS.PENDING })).sort(sort).skip(skip).limit(limit).toArray();
        res.json(events);
    } catch (err) { res.status(500).json({ error: 'Failed to load queue' }); }
});

app.get('/api/admin/events/live', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req);
        const events = await db.collection('fraud_events')
            .find(adminEventFilter(req, { status: STATUS.APPROVED })).sort({ approved_at: -1 }).skip(skip).limit(limit).toArray();
        res.json(events);
    } catch (err) { res.status(500).json({ error: 'Failed to load live events' }); }
});

app.get('/api/admin/events/rejected', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req);
        const events = await db.collection('fraud_events')
            .find(adminEventFilter(req, { status: STATUS.REJECTED })).sort({ rejected_at: -1 }).skip(skip).limit(limit).toArray();
        res.json(events);
    } catch (err) { res.status(500).json({ error: 'Failed to load rejected events' }); }
});

// GET /api/admin/events/:id/details — metadata only (media via stream endpoints)
app.get('/api/admin/events/:id/details', requireAdmin, async (req, res) => {
    try {
        const eventId = new ObjectId(req.params.id);
        const event = await db.collection('fraud_events').findOne(
            { _id: eventId },
            { projection: { 'imposter_picture.data': 0, 'scam_proofs.data': 0 } }
        );
        if (!event) return res.status(404).json({ error: 'Event not found' });
        const phones = await db.collection('event_phones').find({ event_id: eventId }).toArray();
        let profile = null;
        if (event.profile_id) profile = await db.collection('cheater_profiles').findOne({ _id: event.profile_id });
        const identifiers = event.profile_id
            ? await db.collection('identifiers').find({ profile_id: event.profile_id }).toArray()
            : [];
        res.json({ event, phones, profile, identifiers });
    } catch (err) {
        res.status(404).json({ error: 'Event not found' });
    }
});

// PATCH /api/admin/events/:id/approve
app.patch('/api/admin/events/:id/approve', requireAdmin, async (req, res) => {
    try {
        const eventId = new ObjectId(req.params.id);
        const fraudEvents = db.collection('fraud_events');
        const event = await fraudEvents.findOne({ _id: eventId });
        if (!event) return res.status(404).json({ error: 'Event not found' });

        const timestamp = new Date().toISOString();
        // Resolve the profile FIRST, then flip status + set profile_id in a single
        // write, so a failure can never leave an approved-but-unlinked event.
        const profileId = await resolveProfile(event, timestamp);
        await fraudEvents.updateOne({ _id: eventId }, { $set: { status: STATUS.APPROVED, approved_at: timestamp, profile_id: profileId } });
        await audit('approve', eventId, req, { profile_id: profileId });

        res.json({ message: '✓ Event approved and linked to a fraudster profile.', profile_id: profileId });
    } catch (err) {
        res.status(500).json({ error: 'Approve failed' });
    }
});

// PATCH /api/admin/events/:id/reject
app.patch('/api/admin/events/:id/reject', requireAdmin, async (req, res) => {
    try {
        const eventId = new ObjectId(req.params.id);
        const fraudEvents = db.collection('fraud_events');
        const event = await fraudEvents.findOne({ _id: eventId });
        if (!event) return res.status(404).json({ error: 'Event not found' });

        const reason = str(req.body && req.body.rejection_reason) || 'No reason specified';
        const timestamp = new Date().toISOString();
        await fraudEvents.updateOne({ _id: eventId },
            { $set: { status: STATUS.REJECTED, rejected_at: timestamp, rejection_reason: reason } });
        await audit('reject', eventId, req, { reason });

        res.json({ message: '✓ Event rejected successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Reject failed' });
    }
});

// DELETE /api/admin/events/:id (soft delete -> rejected)
app.delete('/api/admin/events/:id', requireAdmin, async (req, res) => {
    try {
        const eventId = new ObjectId(req.params.id);
        const fraudEvents = db.collection('fraud_events');
        const event = await fraudEvents.findOne({ _id: eventId });
        if (!event) return res.status(404).json({ error: 'Event not found' });

        const timestamp = new Date().toISOString();
        await fraudEvents.updateOne({ _id: eventId },
            { $set: { status: STATUS.REJECTED, rejected_at: timestamp, rejection_reason: 'Admin deletion - live event removed' } });
        await audit('delete', eventId, req);

        res.json({ message: '✓ Event deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

// GET /api/admin/imposters — aggregation (no N+1)
app.get('/api/admin/imposters', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req, 50, 200);
        const rows = await db.collection('cheater_profiles').aggregate([
            { $lookup: {
                from: 'fraud_events',
                let: { pid: '$_id' },
                pipeline: [
                    { $match: { $expr: { $and: [{ $eq: ['$profile_id', '$$pid'] }, { $eq: ['$status', STATUS.APPROVED] }] } } },
                    { $project: { loss_amount: 1, approved_at: 1 } }
                ],
                as: 'evs'
            } },
            { $lookup: {
                from: 'identifiers',
                let: { pid: '$_id' },
                pipeline: [
                    { $match: { $expr: { $and: [{ $eq: ['$profile_id', '$$pid'] }, { $eq: ['$identifier_type', 'phone'] }] } } },
                    { $limit: 1 }
                ],
                as: 'ph'
            } },
            { $project: {
                id: '$_id', name: '$display_name',
                phone: { $ifNull: [{ $arrayElemAt: ['$ph.identifier_value', 0] }, 'N/A'] },
                scam_count: { $size: '$evs' },
                total_loss: { $sum: '$evs.loss_amount' },
                last_active: { $max: '$evs.approved_at' }
            } },
            { $sort: { scam_count: -1, name: 1 } },
            { $skip: skip }, { $limit: limit }
        ]).toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to load imposters' });
    }
});

// GET /api/admin/reporters — aggregation, keyed by phone/email/name (in that order)
app.get('/api/admin/reporters', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req, 50, 200);
        const rows = await db.collection('fraud_events').aggregate([
            { $addFields: { _rk: { $let: {
                vars: { ph: { $ifNull: ['$reporter_phone', ''] }, em: { $ifNull: ['$reporter_email', ''] }, nm: { $ifNull: ['$reporter_name', ''] } },
                in: { $cond: [{ $ne: ['$$ph', ''] }, { $concat: ['p:', '$$ph'] },
                     { $cond: [{ $ne: ['$$em', ''] }, { $concat: ['e:', '$$em'] }, { $concat: ['n:', '$$nm'] }] }] }
            } } } },
            { $group: {
                _id: '$_rk',
                name: { $first: '$reporter_name' },
                phone: { $first: '$reporter_phone' },
                email: { $first: '$reporter_email' },
                report_count: { $sum: 1 },
                approved_count: { $sum: { $cond: [{ $eq: ['$status', STATUS.APPROVED] }, 1, 0] } },
                first_report: { $min: '$submitted_at' }
            } },
            { $sort: { report_count: -1 } },
            { $skip: skip }, { $limit: limit }
        ]).toArray();
        res.json(rows.map(r => ({
            name: r.name || 'Anonymous',
            phone: r.phone || 'N/A',
            email: r.email || 'N/A',
            report_count: r.report_count,
            approved_count: r.approved_count,
            first_report: r.first_report
        })));
    } catch (err) {
        res.status(500).json({ error: 'Failed to load reporters' });
    }
});

// Restrict an action to superuser admins (used for managing admin accounts).
function requireSuperuser(req, res, next) {
    if (!req.admin || req.admin.role !== ROLES.SUPERUSER) return res.status(403).json({ error: 'Superuser role required' });
    next();
}

// GET /api/admin/stats — moderation overview for the dashboard.
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
    try {
        const fe = db.collection('fraud_events');
        const since = new Date(Date.now() - 7 * 86400000).toISOString();
        const [pending, approved, rejected, profiles, lossAgg, recent, topCats] = await Promise.all([
            fe.countDocuments({ status: STATUS.PENDING }),
            fe.countDocuments({ status: STATUS.APPROVED }),
            fe.countDocuments({ status: STATUS.REJECTED }),
            db.collection('cheater_profiles').countDocuments(),
            fe.aggregate([{ $match: { status: STATUS.APPROVED } }, { $group: { _id: null, total: { $sum: '$loss_amount' } } }]).toArray(),
            fe.countDocuments({ submitted_at: { $gte: since } }),
            fe.aggregate([
                { $match: { status: STATUS.APPROVED } },
                { $group: { _id: '$scam_type', count: { $sum: 1 } } },
                { $sort: { count: -1 } }, { $limit: 5 }
            ]).toArray()
        ]);
        res.json({
            pending, approved, rejected, profiles,
            total_loss: (lossAgg[0] && lossAgg[0].total) || 0,
            reports_last_7d: recent,
            top_categories: topCats.map((c) => ({ category: c._id || 'Unknown', count: c.count }))
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to load stats' });
    }
});

// GET /api/admin/audit — paginated moderation audit log (most recent first).
app.get('/api/admin/audit', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req, 30, 100);
        const rows = await db.collection('audit_logs').find({}).sort({ at: -1 }).skip(skip).limit(limit).toArray();
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Failed to load audit log' });
    }
});

// PATCH /api/admin/events/:id — edit an event's scalar fields (the "Edit" action).
app.patch('/api/admin/events/:id', requireAdmin, async (req, res) => {
    try {
        const eventId = new ObjectId(req.params.id);
        const fe = db.collection('fraud_events');
        const event = await fe.findOne({ _id: eventId });
        if (!event) return res.status(404).json({ error: 'Event not found' });

        const b = req.body || {};
        const set = {};
        const textFields = ['imposter_name', 'imposter_nickname', 'imposter_nid', 'imposter_address', 'social_media_account', 'scam_type', 'loss_item', 'scam_location', 'gd_number'];
        for (const f of textFields) { if (typeof b[f] === 'string') set[f] = capField(b[f], f); }
        if (typeof b.description === 'string') {
            if (b.description.length < 30 || b.description.length > 500) {
                return res.status(400).json({ error: 'Description must be between 30 and 500 characters.' });
            }
            set.description = b.description;
        }
        if (typeof b.imposter_phone === 'string') {
            if (!validPhone(b.imposter_phone)) return res.status(400).json({ error: 'Invalid phone number format.' });
            set.imposter_phone = b.imposter_phone.trim();
            set.imposter_normalized_phone = normalize(set.imposter_phone);
        }
        if (b.loss_amount !== undefined && b.loss_amount !== '') {
            const n = parseFloat(b.loss_amount);
            set.loss_amount = isFinite(n) && n >= 0 ? n : 0;
        }
        if (Object.keys(set).length === 0) return res.status(400).json({ error: 'No editable fields provided.' });

        await fe.updateOne({ _id: eventId }, { $set: set });
        if (set.imposter_phone) {
            await db.collection('event_phones').updateOne(
                { event_id: eventId, phone_number: event.imposter_phone },
                { $set: { phone_number: set.imposter_phone, normalized_phone: set.imposter_normalized_phone } }
            );
        }
        // Keep the linked profile's display/normalized name in sync on a rename so
        // search and profile pages don't go stale.
        if (set.imposter_name && event.profile_id) {
            await db.collection('cheater_profiles').updateOne(
                { _id: event.profile_id },
                { $set: { display_name: set.imposter_name, normalized_name: normalize(set.imposter_name), updated_at: new Date().toISOString() } }
            );
        }
        await audit('edit', eventId, req, { fields: Object.keys(set) });
        res.json({ message: '✓ Event updated', fields: Object.keys(set) });
    } catch (err) {
        res.status(500).json({ error: 'Edit failed' });
    }
});

// POST /api/admin/change-password — the signed-in admin rotates their own password.
// Bumps token_version so all of that admin's existing sessions are invalidated.
app.post('/api/admin/change-password', requireAdmin, async (req, res) => {
    try {
        const current = str(req.body && req.body.current_password);
        const next = str(req.body && req.body.new_password);
        if (!current || !next) return res.status(400).json({ error: 'Current and new password are required.' });
        if (next.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
        if (/^admin123$/i.test(next)) return res.status(400).json({ error: 'Choose a stronger password.' });
        const admin = await db.collection('admin_users').findOne({ _id: new ObjectId(req.admin.sub) });
        if (!admin || !(await bcrypt.compare(current, admin.password_hash || ''))) {
            return res.status(401).json({ error: 'Current password is incorrect.' });
        }
        await db.collection('admin_users').updateOne(
            { _id: admin._id },
            { $set: { password_hash: await bcrypt.hash(next, 10), must_change_password: false }, $inc: { token_version: 1 } }
        );
        await audit('change_password', null, req, { target: admin.username });
        res.json({ message: '✓ Password changed. Please sign in again.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// ---- Admin user management (superuser only) ----
app.get('/api/admin/admins', requireAdmin, requireSuperuser, async (req, res) => {
    try {
        const rows = await db.collection('admin_users').find({}, { projection: { password_hash: 0 } }).toArray();
        res.json(rows.map((a) => ({ id: a._id, username: a.username, role: a.role || ROLES.ADMIN, created_at: a.created_at })));
    } catch (err) {
        res.status(500).json({ error: 'Failed to load admins' });
    }
});

app.post('/api/admin/admins', requireAdmin, requireSuperuser, async (req, res) => {
    try {
        const username = str(req.body && req.body.username).trim();
        const password = str(req.body && req.body.password);
        const role = str(req.body && req.body.role) === ROLES.SUPERUSER ? ROLES.SUPERUSER : ROLES.ADMIN;
        if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
        if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
        if (await db.collection('admin_users').findOne({ username })) {
            return res.status(409).json({ error: 'That username already exists.' });
        }
        const result = await db.collection('admin_users').insertOne({
            username, password_hash: await bcrypt.hash(password, 10), role, token_version: 0, created_at: new Date().toISOString()
        });
        await audit('admin_create', null, req, { target: username, role });
        res.json({ message: '✓ Admin created', id: result.insertedId });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create admin' });
    }
});

app.delete('/api/admin/admins/:id', requireAdmin, requireSuperuser, async (req, res) => {
    try {
        if (req.admin && req.admin.sub === req.params.id) return res.status(400).json({ error: 'You cannot delete your own account.' });
        if ((await db.collection('admin_users').countDocuments()) <= 1) {
            return res.status(400).json({ error: 'Cannot delete the last admin.' });
        }
        const result = await db.collection('admin_users').deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Admin not found.' });
        await audit('admin_delete', null, req, { target_id: req.params.id });
        res.json({ message: '✓ Admin deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete admin' });
    }
});

// GET /api/admin/disputes — disputes with a short summary of the linked event.
app.get('/api/admin/disputes', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req, 30, 100);
        const rows = await db.collection('disputes').aggregate([
            { $sort: { created_at: -1 } }, { $skip: skip }, { $limit: limit },
            { $lookup: { from: 'fraud_events', localField: 'event_id', foreignField: '_id', as: 'ev' } },
            { $addFields: { event: { $arrayElemAt: ['$ev', 0] } } }
        ]).toArray();
        res.json(rows.map((d) => ({
            id: d._id, event_id: d.event_id, reason: d.reason, contact: d.contact,
            status: d.status, created_at: d.created_at, note: d.note,
            event_imposter: d.event && d.event.imposter_name,
            event_scam: d.event && d.event.scam_type,
            event_status: d.event && d.event.status
        })));
    } catch (err) {
        res.status(500).json({ error: 'Failed to load disputes' });
    }
});

// PATCH /api/admin/disputes/:id — resolve / dismiss / reopen a dispute.
app.patch('/api/admin/disputes/:id', requireAdmin, async (req, res) => {
    try {
        const status = str(req.body && req.body.status);
        if (!['open', 'resolved', 'dismissed'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
        const r = await db.collection('disputes').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { status, note: str(req.body && req.body.note), resolved_at: new Date().toISOString(), resolved_by: req.admin.username } }
        );
        if (!r.matchedCount) return res.status(404).json({ error: 'Dispute not found.' });
        res.json({ message: '✓ Dispute updated' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update dispute' });
    }
});

// Unknown API routes -> consistent JSON 404 (instead of the static 404 page).
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// Central error handler — logs the real error server-side, returns a generic
// message to the client (no stack traces / internals leaked).
app.use((err, req, res, next) => {
    log('error', 'unhandled error', { path: req.originalUrl, err: err && err.message });
    if (res.headersSent) return next(err);
    res.status(err && err.status ? err.status : 500).json({ error: 'Internal server error' });
});

// Start server after connecting to database (guarded so tests can require this
// module without opening a DB connection or binding the port).
if (require.main === module) {
    connectToDatabase().then(() => {
        app.listen(PORT, () => console.log(`✓ Fraud-checker-bd operational framework running on port ${PORT}`));
    });
}

module.exports = { app };
