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
    normalize, str, escapeRegex, paging, sanitizeEvent, validateSubmission
} = require('./lib/util');

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

// JWT secret — must be set in production. Fall back to an ephemeral random one
// (sessions won't survive a restart) with a loud warning.
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    JWT_SECRET = crypto.randomBytes(48).toString('hex');
    console.warn('⚠ JWT_SECRET not set in .env — using an ephemeral secret (admin sessions reset on restart).');
}

if (!MONGODB_URI) {
    console.error('✗ MONGODB_URI is not set in .env. Aborting.');
    process.exit(1);
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

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(fileUpload({ limits: { fileSize: 50 * 1024 * 1024 } }));
app.use(express.static(path.join(__dirname, 'public')));

// Lightweight request logging for anything that reaches the API (static assets
// are served above and intentionally not logged).
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => log('info', 'request', { method: req.method, path: req.path, status: res.statusCode, ms: Date.now() - start }));
    next();
});

// Liveness/readiness probe.
app.get('/healthz', (req, res) => res.json({ status: db ? 'ok' : 'starting', uptime: Math.round(process.uptime()) }));

// ===================== Helpers (DB/JWT-bound; pure helpers live in lib/util) =====================

// JWT helpers / auth middleware
function getToken(req) {
    const header = req.headers.authorization || '';
    const fromHeader = header.replace(/^Bearer\s+/i, '');
    return fromHeader || str(req.query.token);
}
function verifyToken(req) {
    const token = getToken(req);
    if (!token) return null;
    try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; }
}
function requireAdmin(req, res, next) {
    const payload = verifyToken(req);
    if (!payload) return res.status(401).json({ error: 'Authentication required' });
    req.admin = payload;
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
function storeFile(file) {
    return new Promise((resolve, reject) => {
        const stream = bucket.openUploadStream(file.name, {
            contentType: file.mimetype,
            metadata: { size: file.size }
        });
        const fileId = stream.id;
        stream.on('error', reject);
        stream.on('finish', () => resolve({
            name: file.name,
            mimetype: file.mimetype,
            size: file.size,
            file_id: fileId
        }));
        stream.end(file.data);
    });
}

// Stream a media record (GridFS file_id OR legacy inline base64) to the response.
function streamMedia(res, media, inline) {
    const type = media.mimetype || 'application/octet-stream';
    const safeName = String(media.name || 'file').replace(/[^\w.\- ]/g, '_');
    res.set('Content-Type', type);
    res.set('Cache-Control', 'private, max-age=3600');
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
    try {
        const client = new MongoClient(MONGODB_URI);
        await client.connect();
        console.log('✓ Connected to MongoDB Atlas');
        db = client.db(DB_NAME);
        bucket = new GridFSBucket(db, { bucketName: 'uploads' });
        await initializeDatabase();

        // Graceful shutdown
        const shutdown = async () => { try { await client.close(); } catch (e) {} process.exit(0); };
        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);

        return client;
    } catch (err) {
        console.error('✗ MongoDB Connection Error:', err.message);
        process.exit(1);
    }
}

async function ensureCollections() {
    const names = (await db.listCollections().toArray()).map(c => c.name);
    for (const c of ['cheater_profiles', 'identifiers', 'fraud_events', 'event_phones', 'audit_logs', 'admin_users']) {
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
    await db.collection('identifiers').createIndex({ normalized_value: 1 });
    await db.collection('identifiers').createIndex({ profile_id: 1 });
    await db.collection('identifiers').createIndex({ identifier_type: 1 });
    await db.collection('event_phones').createIndex({ event_id: 1 });
    await db.collection('event_phones').createIndex({ normalized_phone: 1 });
    await db.collection('cheater_profiles').createIndex({ normalized_name: 1 });
    console.log('✓ Indexes ensured');
}

async function seedAdmin() {
    const adminUsers = db.collection('admin_users');
    const existing = await adminUsers.findOne({ username: 'admin' });
    if (!existing) {
        await adminUsers.insertOne({
            username: 'admin',
            password_hash: await bcrypt.hash('admin123', 10),
            role: 'superuser',
            created_at: new Date().toISOString()
        });
        console.log('✓ Seeded admin user (admin/admin123 — change this!)');
    } else if (!/^\$2[aby]\$/.test(existing.password_hash || '')) {
        // Migrate a legacy plaintext password to a bcrypt hash in place.
        await adminUsers.updateOne(
            { _id: existing._id },
            { $set: { password_hash: await bcrypt.hash(existing.password_hash || 'admin123', 10) } }
        );
        console.log('✓ Migrated legacy admin password to bcrypt hash');
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
    const lookup = [...phoneNorms];
    if (nidNorm) lookup.push(nidNorm);

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

// ===================== PUBLIC API =====================

// GET /api/search?q=&category=&sort=&limit=&skip=
// Returns an array of approved events; the total match count is in the
// `X-Total-Count` header and the match strategy in `X-Search-Mode`.
app.get('/api/search', async (req, res) => {
    try {
        const query = str(req.query.q).trim();
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
            const phoneRows = await db.collection('event_phones')
                .find({ normalized_phone: { $regex: escapeRegex(nq) } })
                .project({ event_id: 1 }).limit(2000).toArray();
            filter._id = { $in: phoneRows.map(p => p.event_id) };
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

// GET /api/check?phone=&nid= — quick public lookup of how many APPROVED reports
// match a phone and/or NID (counts only, no personal data). Powers the submit
// form's duplicate hint and can back a standalone "is this number reported?" check.
app.get('/api/check', async (req, res) => {
    try {
        const fraudEvents = db.collection('fraud_events');
        const phone = str(req.query.phone).trim();
        const nid = str(req.query.nid).trim();
        const out = { phone_reports: 0, nid_reports: 0 };
        if (phone) {
            const nq = normalize(phone);
            if (nq) {
                const ids = await db.collection('event_phones')
                    .find({ normalized_phone: nq }).project({ event_id: 1 }).toArray();
                out.phone_reports = await fraudEvents.countDocuments({ status: STATUS.APPROVED, _id: { $in: ids.map((i) => i.event_id) } });
            }
        }
        if (nid) {
            out.nid_reports = await fraudEvents.countDocuments({ status: STATUS.APPROVED, imposter_nid: nid });
        }
        res.json(out);
    } catch (err) {
        res.status(500).json({ error: 'Check failed' });
    }
});

// GET /api/events/:id/details
app.get('/api/events/:id/details', async (req, res) => {
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
        const trust = { report_count: 1, first_seen: event.approved_at, last_seen: event.approved_at };
        if (event.imposter_normalized_phone) {
            const agg = await db.collection('fraud_events').aggregate([
                { $match: { status: STATUS.APPROVED, imposter_normalized_phone: event.imposter_normalized_phone } },
                { $group: { _id: null, count: { $sum: 1 }, first: { $min: '$approved_at' }, last: { $max: '$approved_at' } } }
            ]).toArray();
            if (agg[0]) { trust.report_count = agg[0].count; trust.first_seen = agg[0].first; trust.last_seen = agg[0].last; }
        }

        res.json({ event: sanitizeEvent(event, { includeProofs: true }), profile, trust });
    } catch (err) {
        res.status(404).json({ error: 'Event not found' });
    }
});

// GET /api/events/:id/picture — public for approved events; admins may view any.
app.get('/api/events/:id/picture', async (req, res) => {
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
app.get('/api/events/:id/proofs/:index', async (req, res) => {
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
app.get('/api/profiles/:id', async (req, res) => {
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
            .project({ identifier_type: 1, identifier_value: 1 }).toArray();

        res.json({ profile, events: events.map(e => sanitizeEvent(e)), identifiers: idents });
    } catch (err) {
        res.status(404).json({ error: 'Profile not found' });
    }
});

// POST /api/events — public submission
app.post('/api/events', async (req, res) => {
    try {
        const { error, value } = validateSubmission(req.body);
        if (error) return res.status(400).json({ error });

        // Validate ALL file types/counts BEFORE storing anything, so a bad proof
        // never leaves an orphaned photo in GridFS.
        const picFile = (req.files && req.files.imposter_picture) || null;
        if (picFile && !ALLOWED_IMAGE.includes(picFile.mimetype)) {
            return res.status(400).json({ error: 'Imposter picture must be a JPEG, PNG, GIF, or WEBP image.' });
        }
        let proofFiles = [];
        if (req.files && req.files.scam_proofs) {
            proofFiles = Array.isArray(req.files.scam_proofs) ? req.files.scam_proofs : [req.files.scam_proofs];
        }
        if (proofFiles.length === 0) return res.status(400).json({ error: 'At least one proof file is required.' });
        if (proofFiles.length > MAX_PROOFS) return res.status(400).json({ error: `Maximum ${MAX_PROOFS} files allowed.` });
        for (const f of proofFiles) {
            if (!ALLOWED_PROOF.includes(f.mimetype)) {
                return res.status(400).json({ error: `Unsupported proof file type: ${f.name} (${f.mimetype}).` });
            }
        }

        const imposterPicture = picFile ? await storeFile(picFile) : null;
        const scamProofs = [];
        for (const f of proofFiles) scamProofs.push(await storeFile(f));

        const timestamp = new Date().toISOString();
        const fraudEvents = db.collection('fraud_events');
        const eventPhones = db.collection('event_phones');
        const identifiers = db.collection('identifiers');

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
            reporter_name: value.reporter_name,
            reporter_phone: value.reporter_phone,
            reporter_email: value.reporter_email,
            reporter_visibility: value.reporter_visibility,
            profile_id: null,
            status: STATUS.PENDING,
            submitted_at: timestamp,
            approved_at: null,
            rejected_at: null
        });

        const eventId = result.insertedId;
        await eventPhones.insertOne({ event_id: eventId, phone_number: value.imposter_phone, normalized_phone: normalize(value.imposter_phone) });
        for (const phone of value.alt_phones) {
            await eventPhones.insertOne({ event_id: eventId, phone_number: phone, normalized_phone: normalize(phone) });
        }
        await identifiers.insertOne({ profile_id: null, identifier_type: 'imposter_name', identifier_value: value.imposter_name, normalized_value: normalize(value.imposter_name) });
        if (value.imposter_nid) {
            await identifiers.insertOne({ profile_id: null, identifier_type: 'nid', identifier_value: value.imposter_nid, normalized_value: normalize(value.imposter_nid) });
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
            { sub: admin._id.toString(), username: admin.username, role: admin.role || ROLES.ADMIN },
            JWT_SECRET, { expiresIn: '8h' }
        );
        res.json({ success: true, token });
    } catch (err) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// Everything below requires a valid admin session.
app.get('/api/admin/moderation-queue', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req);
        const events = await db.collection('fraud_events')
            .find({ status: STATUS.PENDING }).sort({ submitted_at: -1 }).skip(skip).limit(limit).toArray();
        res.json(events);
    } catch (err) { res.status(500).json({ error: 'Failed to load queue' }); }
});

app.get('/api/admin/events/live', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req);
        const events = await db.collection('fraud_events')
            .find({ status: STATUS.APPROVED }).sort({ approved_at: -1 }).skip(skip).limit(limit).toArray();
        res.json(events);
    } catch (err) { res.status(500).json({ error: 'Failed to load live events' }); }
});

app.get('/api/admin/events/rejected', requireAdmin, async (req, res) => {
    try {
        const { limit, skip } = paging(req);
        const events = await db.collection('fraud_events')
            .find({ status: STATUS.REJECTED }).sort({ rejected_at: -1 }).skip(skip).limit(limit).toArray();
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
        await fraudEvents.updateOne({ _id: eventId }, { $set: { status: STATUS.APPROVED, approved_at: timestamp } });

        const profileId = await resolveProfile(event, timestamp);
        await fraudEvents.updateOne({ _id: eventId }, { $set: { profile_id: profileId } });
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
