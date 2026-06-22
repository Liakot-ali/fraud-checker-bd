'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const {
    STATUS, VISIBILITY,
    normalize, str, escapeRegex, validPhone, paging, sanitizeEvent, validateSubmission
} = require('../lib/util');

test('normalize lowercases and strips punctuation/whitespace', () => {
    assert.strictEqual(normalize('  John-Doe! '), 'johndoe');
    assert.strictEqual(normalize('+1-234-567'), '1234567');
    assert.strictEqual(normalize(null), '');
    assert.strictEqual(normalize(undefined), '');
});

test('normalize preserves non-ASCII (Bengali) letters', () => {
    // Must NOT collapse to '' (the old [^a-z0-9] bug).
    assert.ok(normalize('মোঃ শুভ খান').length > 0);
    assert.strictEqual(normalize('আমি ১২৩'), normalize('আমি১২৩'));
});

test('str coerces non-strings to empty (blocks NoSQL operators)', () => {
    assert.strictEqual(str('hello'), 'hello');
    assert.strictEqual(str({ $gt: '' }), '');
    assert.strictEqual(str(['a']), '');
    assert.strictEqual(str(5), '');
    assert.strictEqual(str(null), '');
});

test('escapeRegex neutralizes regex metacharacters', () => {
    assert.strictEqual(escapeRegex('a.b*c'), 'a\\.b\\*c');
    const rx = new RegExp(escapeRegex('a.b'));
    assert.ok(rx.test('a.b'));
    assert.ok(!rx.test('axb'));
});

test('validPhone accepts BD formats, rejects junk', () => {
    assert.ok(validPhone('01799999999'));
    assert.ok(validPhone('+8801799999999'));
    assert.ok(!validPhone('not-a-phone'));
    assert.ok(!validPhone('12'));
});

test('paging clamps limit/skip and accepts a plain query object', () => {
    assert.deepStrictEqual(paging({ limit: '10', skip: '5' }), { limit: 10, skip: 5 });
    assert.deepStrictEqual(paging({}), { limit: 20, skip: 0 });
    assert.strictEqual(paging({ limit: '9999' }, 20, 100).limit, 100);
    assert.strictEqual(paging({ skip: '-3' }).skip, 0);
    // also works with an Express-like req
    assert.deepStrictEqual(paging({ query: { limit: '7' } }), { limit: 7, skip: 0 });
});

test('sanitizeEvent strips reporter PII + media for public clients', () => {
    const ev = {
        imposter_name: 'X', reporter_name: 'Bob', reporter_phone: '011', reporter_email: 'b@x.com',
        reporter_visibility: VISIBILITY.HIDDEN, imposter_picture: { data: 'xxx' },
        scam_proofs: [{ name: 'a.png', mimetype: 'image/png', size: 1, data: 'xx' }]
    };
    const pub = sanitizeEvent(ev);
    assert.ok(!('reporter_phone' in pub) && !('reporter_email' in pub));
    assert.ok(!('reporter_name' in pub), 'hidden reporter name removed');
    assert.ok(!('imposter_picture' in pub) && !('scam_proofs' in pub));
    // public reporter keeps the name; proofs become metadata-only with includeProofs
    const withProofs = sanitizeEvent({ ...ev, reporter_visibility: VISIBILITY.PUBLIC }, { includeProofs: true });
    assert.strictEqual(withProofs.reporter_name, 'Bob');
    assert.ok(!('data' in withProofs.scam_proofs[0]));
});

test('validateSubmission rejects missing/invalid fields and accepts a good one', () => {
    assert.ok(validateSubmission({}).error);
    assert.ok(validateSubmission({ imposter_name: 'A', imposter_phone: 'bad', scam_type: 'x', loss_item: 'Money', loss_amount: '1', description: 'd'.repeat(40), reporter_name: 'r' }).error, 'bad phone rejected');
    assert.ok(validateSubmission({ imposter_name: 'A', imposter_phone: '01799999999', scam_type: 'x', loss_item: 'Money', loss_amount: '1', description: 'short', reporter_name: 'r' }).error, 'short description rejected');
    const good = validateSubmission({
        imposter_name: 'A', imposter_phone: '01799999999', scam_type: 'E-Commerce',
        loss_item: 'Money', loss_amount: '1500', description: 'd'.repeat(40), reporter_name: 'r',
        reporter_visibility: 'hidden', alt_phones: JSON.stringify(['01711111111'])
    });
    assert.ok(!good.error);
    assert.strictEqual(good.value.loss_amount, 1500);
    assert.strictEqual(good.value.reporter_visibility, VISIBILITY.HIDDEN);
    assert.deepStrictEqual(good.value.alt_phones, ['01711111111']);
});

test('STATUS enum has the expected values', () => {
    assert.deepStrictEqual(STATUS, { PENDING: 'pending', APPROVED: 'approved', REJECTED: 'rejected' });
});
