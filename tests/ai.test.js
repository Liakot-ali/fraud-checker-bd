'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { aiExtract, sanitize } = require('../lib/ai');

// Build a fake Gemini HTTP response whose candidate text is the given JSON object.
function geminiResponse(obj) {
    return {
        ok: true,
        json: async () => ({ candidates: [{ content: { parts: [{ text: JSON.stringify(obj) }] } }] })
    };
}

function withEnv(vars, fn) {
    const saved = {};
    for (const k of Object.keys(vars)) { saved[k] = process.env[k]; process.env[k] = vars[k]; }
    return Promise.resolve(fn()).finally(() => {
        for (const k of Object.keys(vars)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
    });
}

test('aiExtract returns null when GEMINI_API_KEY is not set', async () => {
    const saved = process.env.GEMINI_API_KEY;
    delete process.env.GEMINI_API_KEY;
    try { assert.strictEqual(await aiExtract({ text: 'hi' }), null); }
    finally { if (saved !== undefined) process.env.GEMINI_API_KEY = saved; }
});

test('aiExtract parses + sanitizes a valid Gemini response', async () => {
    const savedFetch = global.fetch;
    global.fetch = async () => geminiResponse({
        imposter_name: 'MD Rakib', phones: ['01711111111', 'not-a-phone', '01822222222'],
        address: 'Mirpur, Dhaka', nid: '1990123456789', social_media: 'fb.com/rakib',
        scam_type: 'Mobile Banking', loss_item: 'Money', loss_amount: 5000,
        mfs_provider: 'bKash', mfs_wallet: '01733333333', mfs_trxid: 'AB12CD34EF',
        description: 'The reporter alleges the person took an advance via bKash and disappeared.',
        images: [{ index: 0, is_document: true, is_photo: false }]
    });
    try {
        const out = await withEnv({ GEMINI_API_KEY: 'test' }, () => aiExtract({ text: 'x', images: [{ data: Buffer.from('a'), mimetype: 'image/png' }] }));
        assert.ok(out && out.fields, 'returns fields');
        assert.deepStrictEqual(out.fields.phones, ['01711111111', '01822222222'], 'invalid phone dropped');
        assert.strictEqual(out.fields.loss_amount, 5000);
        assert.strictEqual(out.fields.imposter_name, 'MD Rakib');
        assert.strictEqual(out.fields.scam_type, 'Mobile Banking');
        assert.deepStrictEqual(out.images, [{ index: 0, is_document: true, is_photo: false }]);
    } finally { global.fetch = savedFetch; }
});

test('aiExtract returns null on HTTP error (e.g. 429) or thrown fetch', async () => {
    const savedFetch = global.fetch;
    try {
        global.fetch = async () => ({ ok: false, status: 429, json: async () => ({}) });
        assert.strictEqual(await withEnv({ GEMINI_API_KEY: 'test' }, () => aiExtract({ text: 'x' })), null, '429 -> null');
        global.fetch = async () => { throw new Error('network'); };
        assert.strictEqual(await withEnv({ GEMINI_API_KEY: 'test' }, () => aiExtract({ text: 'x' })), null, 'throw -> null');
    } finally { global.fetch = savedFetch; }
});

test('aiExtract returns null on non-JSON candidate text', async () => {
    const savedFetch = global.fetch;
    global.fetch = async () => ({ ok: true, json: async () => ({ candidates: [{ content: { parts: [{ text: 'not json' }] } }] }) });
    try { assert.strictEqual(await withEnv({ GEMINI_API_KEY: 'test' }, () => aiExtract({ text: 'x' })), null); }
    finally { global.fetch = savedFetch; }
});

test('sanitize caps description length and bounds image indices', () => {
    const out = sanitize({ description: 'd'.repeat(900), phones: ['01711111111'], images: [{ index: 5, is_document: true }] }, 1);
    assert.strictEqual(out.fields.description.length, 500);
    assert.deepStrictEqual(out.images, [], 'out-of-range image index dropped');
});
