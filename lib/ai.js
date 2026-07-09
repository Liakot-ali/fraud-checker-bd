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
        description: { type: 'STRING' },
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
    'You are given a reporter\'s pasted message and zero or more document images (e.g. the accused person\'s NID, screenshots of chats/payments, or a photo of the person).',
    'Return ONLY facts that are actually present in the message or the images. NEVER invent, guess, or infer facts that are not stated.',
    'Fields:',
    '- imposter_name: the accused person/company name if stated.',
    '- phones: ALL phone numbers of the ACCUSED, each in Bangladeshi form (e.g. 01XXXXXXXXX). Do not include the reporter\'s own number if it is identifiable as theirs.',
    '- address, nid (national ID number), social_media (profile URL or @handle) of the accused.',
    '- scam_type: choose the closest of: Ticket Fraud, Hotel Booking, Tour/Travel, Reservation, E-Commerce, Mobile Banking, Job Offer, Loan/Investment, Romance, Other.',
    '- loss_item (e.g. Money), loss_amount (a number in BDT).',
    '- mfs_provider (bKash/Nagad/Rocket/Upay/...), mfs_wallet (the RECEIVING wallet number the victim sent money to), mfs_trxid (transaction id).',
    '- description: a NEUTRAL, FACTUAL 2-4 sentence summary (between 30 and 500 characters) of what allegedly happened, based on BOTH the message and the images. Write it in the SAME language as the message (Bengali if the message is Bengali). Frame it as an allegation (e.g. "The reporter alleges that ..."). Do NOT embellish, dramatize, or add anything not present in the input.',
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
// amount, clamp the description, and bound image indices.
function sanitize(p, imageCount) {
    p = p && typeof p === 'object' ? p : {};
    const phones = Array.isArray(p.phones)
        ? Array.from(new Set(p.phones.map((x) => str(x).replace(/[\s\-()]/g, '').trim()).filter((x) => validPhone(x))))
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
        mfs_wallet: str(p.mfs_wallet).replace(/[\s\-()]/g, '').trim().slice(0, 40),
        mfs_trxid: capField(p.mfs_trxid, 'mfs_trxid'),
        description: str(p.description).trim().slice(0, 500)
    };
    const images = Array.isArray(p.images)
        ? p.images
            .filter((im) => im && Number.isInteger(im.index) && im.index >= 0 && im.index < imageCount)
            .map((im) => ({ index: im.index, is_document: !!im.is_document, is_photo: !!im.is_photo }))
        : [];
    return { fields, images };
}

module.exports = { aiExtract, sanitize, RESPONSE_SCHEMA };
