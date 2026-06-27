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
    onEscape: onEscape
  };
})(window);
