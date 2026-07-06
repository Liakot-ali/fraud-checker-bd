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

  // Pick a locale from the active UI language so Bengali users see Bengali
  // month names and numerals (falls back to en-US before i18n loads).
  function loc() {
    try { return (global.FC && global.FC.lang === 'bn') ? 'bn-BD' : 'en-US'; } catch (e) { return 'en-US'; }
  }

  function fmtDate(d) {
    if (!d) return EMPTY;
    var dt = new Date(d);
    return isNaN(dt.getTime()) ? EMPTY : dt.toLocaleDateString(loc(), { year: 'numeric', month: 'long', day: 'numeric' });
  }

  function fmtDateTime(d) {
    if (!d) return EMPTY;
    var dt = new Date(d);
    return isNaN(dt.getTime()) ? EMPTY : dt.toLocaleString(loc(), { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
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

  function truncate(text, n) {
    text = text || '';
    return text.length > n ? text.substring(0, n) + '…' : text;
  }

  // Escape text, then wrap case-insensitive matches of the query in <mark>.
  function highlight(text, q) {
    var safe = escapeHtml(text == null ? '' : text);
    q = (q || '').trim();
    if (!q) return safe;
    var eq = escapeHtml(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    try {
      return safe.replace(new RegExp('(' + eq + ')', 'gi'), '<mark class="bg-yellow-200 rounded px-0.5">$1</mark>');
    } catch (e) {
      return safe;
    }
  }

  // Non-blocking, screen-reader-announced toast (replaces alert() for info/errors).
  function toast(message, type) {
    var container = document.getElementById('fc-toasts');
    if (!container) {
      container = document.createElement('div');
      container.id = 'fc-toasts';
      container.setAttribute('aria-live', 'polite');
      container.setAttribute('aria-atomic', 'true');
      container.style.cssText = 'position:fixed;top:1rem;right:1rem;z-index:9999;display:flex;flex-direction:column;gap:.5rem;max-width:22rem';
      document.body.appendChild(container);
    }
    var colors = { success: '#16a34a', error: '#dc2626', info: '#2563eb' };
    var el = document.createElement('div');
    el.setAttribute('role', 'status');
    el.style.cssText = 'background:' + (colors[type] || colors.info) + ';color:#fff;padding:.6rem .9rem;border-radius:.5rem;box-shadow:0 4px 12px rgba(0,0,0,.2);font-size:.875rem;line-height:1.35';
    el.textContent = message;
    container.appendChild(el);
    setTimeout(function () {
      el.style.transition = 'opacity .3s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 300);
    }, 3800);
  }

  // Register an Escape-key handler (used to make modals keyboard-dismissable).
  function onEscape(handler) {
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') handler();
    });
  }

  // Extract structured tokens from pasted scam text (mirror of lib/util.js so the
  // browser can pre-fill the report form without a round-trip).
  function extractFromText(text) {
    var t = String(text == null ? '' : text);
    var uniq = function (a) { return a.filter(function (v, i) { return a.indexOf(v) === i; }); };
    var phones = uniq((t.match(/(?:\+?880|0)1[3-9]\d{8}/g) || []).map(function (p) { return p.replace(/^(\+?880)/, '0'); }));
    var trxids = uniq((t.match(/\b[A-Z0-9]{10}\b/g) || []).filter(function (x) { return /[A-Z]/.test(x) && /[0-9]/.test(x); }));
    var urls = uniq(t.match(/https?:\/\/[^\s<>"')]+/gi) || []);
    var amounts = uniq((t.match(/(?:৳|Tk\.?|BDT|taka)\s*[\d,]+(?:\.\d+)?/gi) || [])
      .concat(t.match(/[\d,]+(?:\.\d+)?\s*(?:৳|tk|taka)/gi) || []));
    return { phones: phones, trxids: trxids, urls: urls, amounts: amounts };
  }

  // A coloured risk badge (from /api/check `risk` { score, band }).
  function riskBadge(risk) {
    if (!risk || risk.band === 'none') return '';
    var map = {
      high: ['#dc2626', '#fef2f2', '#fecaca'],
      medium: ['#d97706', '#fffbeb', '#fed7aa'],
      low: ['#2563eb', '#eff6ff', '#bfdbfe']
    };
    var c = map[risk.band] || map.low;
    return '<span style="display:inline-block;font-weight:700;font-size:.8rem;padding:.15rem .6rem;border-radius:9999px;color:' +
      c[0] + ';background:' + c[1] + ';border:1px solid ' + c[2] + '">' +
      escapeHtml((risk.band || '').toUpperCase()) + ' risk · ' + escapeHtml(String(risk.score)) + '/100</span>';
  }

  // Build share links (pre-filled Bengali warning) for a report/number.
  function shareLinks(url, message) {
    var enc = encodeURIComponent(message + ' ' + url);
    return {
      whatsapp: 'https://wa.me/?text=' + enc,
      facebook: 'https://www.facebook.com/sharer/sharer.php?u=' + encodeURIComponent(url),
      messenger: 'https://www.facebook.com/dialog/send?link=' + encodeURIComponent(url) + '&app_id=0&redirect_uri=' + encodeURIComponent(url)
    };
  }

  // Trigger the native share sheet, falling back to clipboard.
  function nativeShare(title, text, url) {
    if (navigator.share) { navigator.share({ title: title, text: text, url: url }).catch(function () {}); return true; }
    try { navigator.clipboard && navigator.clipboard.writeText(url); toast('Link copied', 'success'); } catch (e) {}
    return false;
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
    socialLink: socialLink,
    truncate: truncate,
    highlight: highlight,
    toast: toast,
    onEscape: onEscape,
    extractFromText: extractFromText,
    riskBadge: riskBadge,
    shareLinks: shareLinks,
    nativeShare: nativeShare
  };
})(window);
