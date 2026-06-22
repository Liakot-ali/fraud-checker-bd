/* Shared client helpers — loaded on every page (before inline scripts). */
(function (global) {
  'use strict';

  var EMPTY = 'Not provided';

  // Escape text for safe insertion into HTML (prevents stored XSS).
  function escapeHtml(v) {
    if (v === null || v === undefined) return '';
    return String(v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Same escaping, intended for values placed inside HTML attributes.
  function escapeAttr(v) { return escapeHtml(v); }

  // A non-empty display value, escaped, or a fallback.
  function val(v, fallback) {
    if (v === null || v === undefined || String(v).trim() === '') return escapeHtml(fallback || EMPTY);
    return escapeHtml(v);
  }

  function fmtDate(d) {
    if (!d) return EMPTY;
    var dt = new Date(d);
    return isNaN(dt.getTime()) ? EMPTY : dt.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  }

  function fmtDateTime(d) {
    if (!d) return EMPTY;
    var dt = new Date(d);
    return isNaN(dt.getTime()) ? EMPTY : dt.toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  // Human "x days ago" — always grammatical (fixes the old "Today ago" bug).
  function timeAgo(d) {
    if (!d) return EMPTY;
    var dt = new Date(d);
    if (isNaN(dt.getTime())) return EMPTY;
    var days = Math.floor((Date.now() - dt.getTime()) / 86400000);
    if (days <= 0) return 'today';
    if (days === 1) return '1 day ago';
    return days + ' days ago';
  }

  // Currency in BDT.
  function money(n) {
    var v = Number(n);
    return (isFinite(v) && v > 0) ? ('৳' + v.toLocaleString()) : '৳0';
  }

  // Build a safe external link from a user-supplied social handle/URL.
  // Only http(s) URLs become real links; anything else renders as plain text.
  function socialLink(value) {
    var v = (value || '').trim();
    if (!v) return '';
    if (/^https?:\/\//i.test(v)) {
      return '<a href="' + escapeAttr(v) + '" target="_blank" rel="noopener noreferrer nofollow" class="text-blue-600 hover:underline break-all">' + escapeHtml(v) + '</a>';
    }
    return '<span class="break-all">' + escapeHtml(v) + '</span>';
  }

  global.FC = {
    EMPTY: EMPTY,
    escapeHtml: escapeHtml,
    escapeAttr: escapeAttr,
    val: val,
    fmtDate: fmtDate,
    fmtDateTime: fmtDateTime,
    timeAgo: timeAgo,
    money: money,
    socialLink: socialLink
  };
})(window);
