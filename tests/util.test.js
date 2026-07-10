'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const {
    STATUS, VISIBILITY,
    normalize, str, escapeRegex, validPhone, paging, sanitizeEvent, validateSubmission,
    maskNid, phoneRisk, scoreEvidence, riskScore, extractFromText, extractPerson, sniffFamily, typeMatches,
    normalizeWallet, capField, extractMoneyTrail, extractReporterContact
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
    // deep-pagination skip is capped to bound collection walks
    assert.strictEqual(paging({ skip: '99999999' }).skip, 100000);
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
        reporter_visibility: 'hidden', alt_phones: JSON.stringify(['01711111111']), consent: 'true'
    });
    assert.ok(!good.error);
    assert.strictEqual(good.value.loss_amount, 1500);
    assert.strictEqual(good.value.reporter_visibility, VISIBILITY.HIDDEN);
    assert.deepStrictEqual(good.value.alt_phones, ['01711111111']);
    assert.strictEqual(good.value.reporter_consent, true);
});

test('validateSubmission requires the truthfulness consent', () => {
    const base = {
        imposter_name: 'A', imposter_phone: '01799999999', scam_type: 'E-Commerce',
        loss_item: 'Money', loss_amount: '1500', description: 'd'.repeat(40), reporter_name: 'r'
    };
    assert.ok(validateSubmission(base).error, 'missing consent rejected');
    assert.ok(!validateSubmission({ ...base, consent: 'true' }).error, 'with consent accepted');
});

test('validateSubmission caps field length and alt_phones count', () => {
    const many = JSON.stringify(Array.from({ length: 50 }, () => '01711111111'));
    const r = validateSubmission({
        imposter_name: 'x'.repeat(500), imposter_phone: '01799999999', scam_type: 'E-Commerce',
        loss_item: 'Money', loss_amount: '1', description: 'd'.repeat(40), reporter_name: 'r',
        consent: 'true', alt_phones: many
    });
    assert.ok(!r.error);
    assert.strictEqual(r.value.imposter_name.length, 120);
    assert.strictEqual(r.value.alt_phones.length, 10);
});

test('validateSubmission accepts MFS money-trail fields', () => {
    const r = validateSubmission({
        imposter_name: 'A', imposter_phone: '01799999999', scam_type: 'Mobile Banking',
        loss_item: 'Money', loss_amount: '5000', description: 'd'.repeat(40), reporter_name: 'r',
        consent: 'true', mfs_provider: 'bKash', mfs_wallet: '01711111111', mfs_trxid: 'AB12CD34EF'
    });
    assert.ok(!r.error);
    assert.strictEqual(r.value.mfs_provider, 'bKash');
    assert.strictEqual(r.value.mfs_trxid, 'AB12CD34EF');
    // unknown provider is dropped, invalid wallet rejected
    assert.strictEqual(validateSubmission({ ...r.value, mfs_provider: 'FakePay', loss_amount: '1', consent: 'true', alt_phones: undefined }).value.mfs_provider, '');
});

test('sanitizeEvent masks the national ID for public clients', () => {
    const pub = sanitizeEvent({ imposter_nid: '1990123456789', reporter_visibility: VISIBILITY.PUBLIC });
    assert.strictEqual(pub.imposter_nid, '••••••6789');
    assert.strictEqual(sanitizeEvent({ imposter_nid: '', reporter_visibility: VISIBILITY.PUBLIC }).imposter_nid, '');
});

test('maskNid keeps only the last four digits', () => {
    assert.strictEqual(maskNid('1990123456789'), '••••••6789');
    assert.strictEqual(maskNid('12'), '••••');
    assert.strictEqual(maskNid(''), '');
});

test('phoneRisk flags foreign and non-standard numbers', () => {
    assert.strictEqual(phoneRisk('+8801711111111').level, 'low');
    assert.strictEqual(phoneRisk('01711111111').operator, 'Grameenphone');
    assert.strictEqual(phoneRisk('+923001234567').level, 'high');
    assert.strictEqual(phoneRisk('12345').level, 'caution');
});

test('normalizeWallet canonicalizes to local 11-digit form', () => {
    assert.strictEqual(normalizeWallet('+8801711111111'), '01711111111');
    assert.strictEqual(normalizeWallet('01711111111'), '01711111111');
    assert.strictEqual(normalizeWallet('880-17-1111-1111'), '01711111111');
});

test('scoreEvidence rewards richer evidence', () => {
    const weak = scoreEvidence({ description: 'd'.repeat(30) });
    const strong = scoreEvidence({
        description: 'd'.repeat(220), gd_number: 'GD1', imposter_nid: '123', imposter_picture: {},
        scam_proofs: [1, 2, 3], reporter_phone: '01711111111', imposter_phone: '01711111111', mfs_wallet: '01711111111'
    });
    assert.ok(strong > weak);
    assert.ok(strong <= 100 && weak >= 0);
});

test('riskScore returns a band and handles the empty case', () => {
    assert.deepStrictEqual(riskScore({ reportCount: 0 }), { score: 0, band: 'none' });
    assert.strictEqual(riskScore({ reportCount: 10, distinctReporters: 5, recencyDays: 5, totalLoss: 200000 }).band, 'high');
    assert.ok(['low', 'medium'].includes(riskScore({ reportCount: 1, distinctReporters: 1 }).band));
});

test('extractFromText pulls phones, trxids, urls and amounts', () => {
    const out = extractFromText('Send money to 01711111111, TrxID AB12CD34EF, pay ৳5000 at http://scam.example/pay');
    assert.ok(out.phones.includes('01711111111'));
    assert.ok(out.trxids.includes('AB12CD34EF'));
    assert.ok(out.urls.some((u) => u.includes('scam.example')));
    assert.ok(out.amounts.length >= 1);
});

test('extractPerson reads labelled name/address (English + Bengali)', () => {
    const nid = 'Government of the People\'s Republic of Bangladesh\nName: MD RAKIB HASAN\nDate of Birth: 01 Jan 1990\nAddress: House 12, Road 5, Mirpur, Dhaka';
    const en = extractPerson(nid);
    assert.ok(en.names.includes('MD RAKIB HASAN'), 'English name label read');
    assert.ok(en.addresses.some((a) => a.includes('Mirpur')), 'English address label read');
    const bn = extractPerson('নাম: মোঃ রাকিব\nঠিকানা: মিরপুর, ঢাকা');
    assert.ok(bn.names.length === 1 && bn.names[0].includes('রাকিব'), 'Bengali name label read');
    assert.ok(bn.addresses.length === 1, 'Bengali address label read');
    // no labels -> nothing (best-effort, no false positives)
    assert.deepStrictEqual(extractPerson('he scammed me on facebook').names, []);
});

test('extractFromText picks up NID numbers but not phones', () => {
    const out = extractFromText('NID 1990123456789 phone 01711111111 smartcard 1234567890');
    assert.ok(out.nids.includes('1990123456789'), '13-digit NID found');
    assert.ok(out.nids.includes('1234567890'), '10-digit smart-card NID found');
    assert.ok(!out.nids.includes('01711111111'), '11-digit phone is not treated as an NID');
});

test('extractFromText tolerates separators inside a phone number', () => {
    assert.ok(extractFromText('call 017-1234-5678 now').phones.includes('01712345678'), 'dashes');
    assert.ok(extractFromText('number 017 1234 5678').phones.includes('01712345678'), 'spaces');
    assert.ok(extractFromText('intl +880 1712-345678').phones.includes('01712345678'), '+880 form');
});

test('extractFromText reads Bengali-digit phone numbers', () => {
    // ০১৭১২৩৪৫৬৭৮ in Bengali numerals -> 01712345678
    assert.ok(extractFromText('নম্বর ০১৭১২৩৪৫৬৭৮').phones.includes('01712345678'), 'Bengali digits normalised');
});

test('extractMoneyTrail routes the receiving wallet to the money field', () => {
    const out = extractMoneyTrail('He asked me to bKash 5000 to 01711111111. TrxID AB12CD34EF');
    assert.strictEqual(out.provider, 'bKash', 'provider detected');
    assert.strictEqual(out.wallet, '01711111111', 'wallet on the provider line captured');
    assert.strictEqual(out.trxid, 'AB12CD34EF', 'trxid captured');
    // Bengali provider name is recognised too.
    assert.strictEqual(extractMoneyTrail('নগদ এ ৩০০০ টাকা পাঠিয়েছি').provider, 'Nagad');
});

test('extractReporterContact finds the reporter own number from first-person cues', () => {
    assert.strictEqual(extractReporterContact('my number is 01822222222').phone, '01822222222');
    assert.strictEqual(extractReporterContact('আমার নম্বর 01833333333').phone, '01833333333');
    // No first-person cue -> nothing (so we never mistake the accused's number for the reporter's).
    assert.strictEqual(extractReporterContact('the fraudster used 01844444444').phone, '');
});

test('sniffFamily + typeMatches detect and gate spoofed uploads', () => {
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const pdf = Buffer.from('%PDF-1.7\n', 'ascii');
    const html = Buffer.from('<html><script>alert(1)</script>', 'ascii');
    assert.strictEqual(sniffFamily(png), 'png');
    assert.strictEqual(sniffFamily(pdf), 'pdf');
    assert.ok(typeMatches('image/png', sniffFamily(png)));
    assert.ok(!typeMatches('image/png', sniffFamily(pdf)), 'pdf bytes rejected as png');
    assert.ok(!typeMatches('image/png', sniffFamily(html)), 'html spoofed as png rejected');
});

test('capField trims and truncates to the configured maximum', () => {
    assert.strictEqual(capField('  hi  ', 'imposter_name'), 'hi');
    assert.strictEqual(capField('x'.repeat(500), 'imposter_nickname').length, 80);
});

test('STATUS enum has the expected values', () => {
    assert.deepStrictEqual(STATUS, { PENDING: 'pending', APPROVED: 'approved', REJECTED: 'rejected' });
});
