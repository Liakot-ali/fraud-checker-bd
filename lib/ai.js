'use strict';

/**
 * Optional AI-assisted extraction for the quick-start form, using Google Gemini
 * (multimodal Flash, free tier). The model reads the pasted text + document images
 * and returns structured fields + a factual description. The API key stays
 * server-side. Any failure (no key, network, timeout, non-200, bad JSON) returns
 * null so the caller transparently falls back to the OCR + regex pipeline.
 */

const { capField, validPhone, str } = require('./util');

// Response schema (Gemini/OpenAPI subset — type names are upper-case enums).
const RESPONSE_SCHEMA = {
    type: 'OBJECT',
    properties: {
        imposter_name: { type: 'STRING' },
        phones: { type: 'ARRAY', items: { type: 'STRING' } },
        address: { type: 'STRING' },
        nid: { type: 'STRING' },
        social_media: { type: 'STRING' },
        scam_type: { type: 'STRING' },
        loss_item: { type: 'STRING' },
        loss_amount: { type: 'NUMBER' },
        mfs_provider: { type: 'STRING' },
        mfs_wallet: { type: 'STRING' },
        mfs_trxid: { type: 'STRING' },
        // The REPORTER/victim's own contact — a dedicated sink so their number/name
        // never contaminates the accused's fields.
        reporter_name: { type: 'STRING' },
        reporter_phone: { type: 'STRING' },
        description: { type: 'STRING' },
        // Field keys the model was NOT confident about (client flags these for review).
        low_confidence: { type: 'ARRAY', items: { type: 'STRING' } },
        images: {
            type: 'ARRAY',
            items: {
                type: 'OBJECT',
                properties: {
                    index: { type: 'INTEGER' },
                    is_document: { type: 'BOOLEAN' },
                    is_photo: { type: 'BOOLEAN' }
                }
            }
        }
    }
};

const PROMPT = [
    'You extract structured data for a community fraud-reporting platform in Bangladesh.',
    'You are given a reporter\'s (the VICTIM\'s) pasted message and zero or more images (e.g. the ACCUSED person\'s NID, screenshots of chats/payments, or a photo of the accused).',
    'Return ONLY facts that are actually present in the message or the images. NEVER invent, guess, or infer facts that are not stated. It is better to leave a field empty than to guess.',
    '',
    'CRITICAL — keep three groups of people/numbers strictly separate:',
    '  (1) THE ACCUSED (the fraudster) — goes into imposter_name, phones, address, nid, social_media.',
    '  (2) THE REPORTER (the victim writing the message) — goes into reporter_name and reporter_phone. First-person cues ("আমি/আমার", "I", "my number", "amar number", a sign-off name) identify the reporter. NEVER put the reporter\'s own name or number into the accused fields.',
    '  (3) THE MONEY TRAIL — goes into mfs_provider / mfs_wallet / mfs_trxid, NOT into phones.',
    '',
    'Fields:',
    '- imposter_name: the ACCUSED person/company name if stated (never the reporter).',
    '- phones: the ACCUSED\'s contact phone number(s) ONLY, each in Bangladeshi form (e.g. 01XXXXXXXXX). Do NOT include the reporter\'s own number, and do NOT include the receiving payment wallet number here (that goes in mfs_wallet).',
    '- address, nid (national ID number), social_media (profile URL or @handle) of the ACCUSED.',
    '- scam_type: choose the closest of: Ticket Fraud, Hotel Booking, Tour/Travel, Reservation, E-Commerce, Mobile Banking, Job Offer, Loan/Investment, Romance, Other.',
    '- loss_item (e.g. Money), loss_amount (the TOTAL number of BDT the victim lost).',
    '- mfs_provider (bKash/Nagad/Rocket/Upay/mCash/SureCash/Tap), mfs_wallet (the RECEIVING wallet number the victim SENT money TO — this is a payment destination, not a contact number), mfs_trxid (transaction id).',
    '- reporter_name: the VICTIM\'s own name if they identify themselves (e.g. a sign-off). Leave "" if unclear.',
    '- reporter_phone: the VICTIM\'s OWN phone number if they give it as theirs (e.g. "my number is ..."). Leave "" if unclear.',
    '- description: a NEUTRAL, FACTUAL 2-4 sentence summary (between 30 and 500 characters) of what allegedly happened, based on BOTH the message and the images. Write it in the SAME language as the message (Bengali if the message is Bengali). Frame it as an allegation (e.g. "The reporter alleges that ..."). Do NOT embellish, dramatize, or add anything not present in the input.',
    '- low_confidence: an array of the field keys above whose value you are UNSURE about (guessed, ambiguous, or hard to read). The client will ask the user to double-check these. Use the exact key names (e.g. "imposter_name", "phones", "mfs_wallet").',
    '- images: for EACH image, in the order provided (indexed from 0), set is_document=true if it is an ID card / NID / official document, and is_photo=true if it is a photo of a person\'s face.',
    'Leave any unknown string field as "" and unknown numbers as 0.'
].join('\n');

async function aiExtract({ text = '', images = [] } = {}) {
    const key = process.env.GEMINI_API_KEY;
    if (!key) return null;
    const model = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
    const base = (process.env.GEMINI_BASE_URL || 'https://generativelanguage.googleapis.com').replace(/\/+$/, '');
    const url = `${base}/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key)}`;

    const imgs = (images || []).slice(0, 5);
    const parts = [{ text: PROMPT }];
    if (text && text.trim()) parts.push({ text: 'MESSAGE TEXT:\n' + text.slice(0, 5000) });
    imgs.forEach((img, i) => {
        parts.push({ text: `Image [${i}]:` });
        parts.push({ inlineData: { mimeType: img.mimetype || 'image/png', data: Buffer.from(img.data).toString('base64') } });
    });

    const body = {
        contents: [{ role: 'user', parts }],
        generationConfig: { responseMimeType: 'application/json', responseSchema: RESPONSE_SCHEMA, temperature: 0.2 }
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Number(process.env.GEMINI_TIMEOUT_MS || 20000));
    let res;
    try {
        res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            signal: controller.signal
        });
    } catch (e) {
        return null; // network error / timeout -> fall back
    } finally {
        clearTimeout(timer);
    }
    if (!res || !res.ok) return null; // 429 / 4xx / 5xx -> fall back

    let json;
    try { json = await res.json(); } catch (e) { return null; }
    const cand = json && json.candidates && json.candidates[0];
    const out = cand && cand.content && Array.isArray(cand.content.parts)
        ? cand.content.parts.map((p) => (p && p.text) || '').join('')
        : '';
    if (!out) return null;
    let parsed;
    try { parsed = JSON.parse(out); } catch (e) { return null; }
    return sanitize(parsed, imgs.length);
}

// Never trust the model output verbatim: cap lengths, validate phones, coerce the
// amount, clamp the description, bound image indices, and — crucially — keep the
// reporter's own number and the receiving wallet OUT of the accused's phone list.
function sanitize(p, imageCount) {
    p = p && typeof p === 'object' ? p : {};
    const cleanPhone = (x) => str(x).replace(/[\s\-()]/g, '').trim();
    const reporterPhone = validPhone(cleanPhone(p.reporter_phone)) ? cleanPhone(p.reporter_phone) : '';
    const wallet = cleanPhone(p.mfs_wallet);
    const phones = Array.isArray(p.phones)
        ? Array.from(new Set(p.phones.map(cleanPhone).filter((x) => validPhone(x))))
            // The accused's contact numbers must not include the victim's own number
            // or the payment-destination wallet (both are phone-shaped).
            .filter((x) => x !== reporterPhone && x !== wallet)
        : [];
    const amount = parseFloat(p.loss_amount);
    const fields = {
        imposter_name: capField(p.imposter_name, 'imposter_name'),
        phones: phones.slice(0, 10),
        address: capField(p.address, 'imposter_address'),
        nid: capField(p.nid, 'imposter_nid'),
        social_media: capField(p.social_media, 'social_media_account'),
        scam_type: capField(p.scam_type, 'scam_type'),
        loss_item: capField(p.loss_item, 'loss_item'),
        loss_amount: isFinite(amount) && amount >= 0 ? amount : 0,
        mfs_provider: str(p.mfs_provider).trim().slice(0, 20),
        mfs_wallet: wallet.slice(0, 40),
        mfs_trxid: capField(p.mfs_trxid, 'mfs_trxid'),
        reporter_name: capField(p.reporter_name, 'reporter_name'),
        reporter_phone: reporterPhone.slice(0, 40),
        description: str(p.description).trim().slice(0, 500)
    };
    // Only surface flags for fields that actually have a value to review.
    const allowedFlags = new Set([
        'imposter_name', 'phones', 'address', 'nid', 'social_media', 'scam_type',
        'loss_item', 'loss_amount', 'mfs_provider', 'mfs_wallet', 'mfs_trxid',
        'reporter_name', 'reporter_phone', 'description'
    ]);
    const low_confidence = Array.isArray(p.low_confidence)
        ? Array.from(new Set(p.low_confidence.map((x) => str(x).trim()).filter((k) => allowedFlags.has(k))))
        : [];
    const images = Array.isArray(p.images)
        ? p.images
            .filter((im) => im && Number.isInteger(im.index) && im.index >= 0 && im.index < imageCount)
            .map((im) => ({ index: im.index, is_document: !!im.is_document, is_photo: !!im.is_photo }))
        : [];
    return { fields, images, low_confidence };
}

module.exports = { aiExtract, sanitize, RESPONSE_SCHEMA };
