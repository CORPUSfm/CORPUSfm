/* CORPUSfm — the ONE browser formatter for UTC instants (packet 1418).
 *
 * Storage, APIs, ordering and identity stay UTC. This file only PRESENTS an instant in the browser's own
 * configured locale and time zone (Intl) — never geolocation, IP inference, a saved preference, or a
 * zone sent to the server. It is loaded by base.html AND embedded verbatim into the generated
 * Explorer/Diff reports, so it must stay dependency-free and framework-optional.
 *
 * Accepted inputs (anything else is NOT an instant and is shown as stored, never with a guessed zone):
 *   - offset-qualified ISO-8601:  2026-10-12T01:22:00Z · 2026-10-12T01:22:00.123+00:00 · …-07:00 · …+0530
 *   - CORPUSfm compact UTC:        2026-10-12_012200  · 2026-10-12_012200_123456  (parsed with Date.UTC)
 *   - finite epoch milliseconds (numbers only — the Stats series)
 * Rejected: naive ISO (no offset), date-only, empty, NaN/Infinity, impossible calendar fields.
 *
 * Server WALL-CLOCK schedule values (next_run, schedule previews, "Server time now") are not instants in
 * this sense and must never be passed here.
 */
(function (root) {
  'use strict';

  var COMPACT = /^(\d{4})-(\d{2})-(\d{2})_(\d{2})(\d{2})(\d{2})(?:_(\d{1,6}))?$/;
  var ISO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?(Z|([+-])(\d{2}):?(\d{2}))$/;
  var YMD = /^(\d{4})-(\d{2})-(\d{2})$/;

  function utcFields(y, mo, d, h, mi, s, frac) {
    var ms = frac ? Math.floor(Number((frac + '000').slice(0, 3))) : 0;
    if (h > 23 || mi > 59 || s > 59) return null;
    var t = Date.UTC(y, mo - 1, d, h, mi, s, ms);
    var c = new Date(t);
    if (!isFinite(t) || c.getUTCFullYear() !== y || c.getUTCMonth() !== mo - 1 || c.getUTCDate() !== d) return null;
    return t;
  }

  // ECMAScript's Date range: ±8.64e15 ms from the epoch. A number outside it is not an instant
  // (formatting it would throw RangeError).
  var MAX_EPOCH_MS = 8.64e15;

  // Epoch ms for an accepted instant, or null. Never consults the local zone.
  function parse(v) {
    if (typeof v === 'number') return isFinite(v) && Math.abs(v) <= MAX_EPOCH_MS ? v : null;
    if (typeof v !== 'string') return null;
    var s = v.trim(), m;
    if ((m = COMPACT.exec(s))) {
      return utcFields(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6], m[7]);
    }
    if ((m = ISO.exec(s))) {
      var base = utcFields(+m[1], +m[2], +m[3], +m[4], +m[5], m[6] ? +m[6] : 0, m[7]);
      if (base === null) return null;
      if (m[8] === 'Z') return base;
      var oh = +m[10], om = +m[11];
      if (oh > 23 || om > 59) return null;
      var off = (oh * 60 + om) * 60000;
      return m[9] === '+' ? base - off : base + off;
    }
    return null;
  }

  var SHORT = { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit',
                timeZoneName: 'short' };
  // The same instant as two separately formatted parts, for an opt-in two-line display. Each part is its
  // own Intl format of the one parsed instant — never a split of the SHORT string.
  var DATE_PART = { year: 'numeric', month: 'short', day: 'numeric' };
  var TIME_PART = { hour: 'numeric', minute: '2-digit', timeZoneName: 'short' };
  var FULL = { weekday: 'short', year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric',
               minute: '2-digit', second: '2-digit', timeZoneName: 'long' };

  function fmt(ms, opts) {
    try { return new Intl.DateTimeFormat(undefined, opts).format(new Date(ms)); }
    catch (e) { return new Date(ms).toString(); }
  }

  function utcText(ms) {
    return new Date(ms).toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
  }

  // { ok, text, full, utc, iso, title } — `text` is the visible browser-local value WITH its zone.
  function describe(v) {
    var ms = parse(v);
    if (ms === null) {
      var raw = v === null || v === undefined ? '' : String(v);
      // A placeholder ("—", "") carries no claim; a value that looks like a time but is not an accepted
      // instant says so instead of acquiring a guessed zone.
      return { ok: false, text: raw, full: '', utc: '', iso: '',
               title: /\d/.test(raw) ? 'Not a recognized time instant — shown as stored' : '' };
    }
    var full = fmt(ms, FULL), utc = utcText(ms);
    return { ok: true, text: fmt(ms, SHORT), full: full, utc: utc, iso: new Date(ms).toISOString(),
             title: full + ' — ' + utc, date: fmt(ms, DATE_PART), time: fmt(ms, TIME_PART) };
  }

  // Explicit left/top: with `auto` offsets an absolutely positioned span keeps its static position, so
  // inside a horizontally scrolled table it escapes that container and widens the page (packet 1418,
  // MCP Access at 375 px).
  var SR_STYLE = 'position:absolute;left:0;top:0;width:1px;height:1px;padding:0;margin:-1px;' +
                 'overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0';

  // Render an instant into an element: visible local text, a title with the full local value, zone and
  // original UTC, a machine-readable datetime, and the same detail for screen readers. An element with
  // data-cfm-lines="2" shows a valid instant as a date line and a time-with-zone line instead.
  function render(el, v, prefix) {
    var d = describe(v);
    while (el.firstChild) el.removeChild(el.firstChild);
    if (d.ok && el.getAttribute('data-cfm-lines') === '2') {
      var parts = [(prefix || '') + d.date, d.time];
      for (var i = 0; i < 2; i++) {
        var line = document.createElement('span');
        line.setAttribute('style', 'display:block;white-space:nowrap');
        line.textContent = parts[i];
        el.appendChild(line);
      }
    } else {
      el.appendChild(document.createTextNode((prefix || '') + d.text));
    }
    if (d.ok) {
      var sr = document.createElement('span');
      sr.setAttribute('style', SR_STYLE);
      sr.textContent = ' (' + d.title + ')';
      el.appendChild(sr);
      if (el.tagName === 'TIME') el.setAttribute('datetime', d.iso);
      el.setAttribute('data-cfm-utc', d.iso);
    } else {
      el.removeAttribute('data-cfm-utc');
      if (el.tagName === 'TIME') el.removeAttribute('datetime');
    }
    if (d.title) el.setAttribute('title', d.title); else el.removeAttribute('title');
    return d;
  }

  // Browser-local civil date → the UTC instant of its local midnight (offset-qualified, 'Z').
  // `dayOffset` 1 gives the NEXT local midnight — constructed independently, so 23- and 25-hour DST days
  // are exact. Never `new Date('YYYY-MM-DD')` (that is UTC midnight) and never "+24h".
  function localDayStartUtc(ymd, dayOffset) {
    var m = YMD.exec(typeof ymd === 'string' ? ymd.trim() : '');
    if (!m) return '';
    var y = +m[1], mo = +m[2], d = +m[3];
    var check = new Date(Date.UTC(y, mo - 1, d));
    if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d) return '';
    var t = new Date(y, mo - 1, d + (dayOffset || 0), 0, 0, 0, 0);
    return isFinite(t.getTime()) ? t.toISOString() : '';
  }

  // Concise browser-local clock text for chart axis ticks, where the surrounding range line already
  // states the zone: "18:22" or (withDate) "Oct 11, 18:22". '' for a non-instant.
  function clock(v, withDate) {
    var ms = parse(v);
    if (ms === null) return '';
    return fmt(ms, withDate ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }
                            : { hour: '2-digit', minute: '2-digit' });
  }

  var api = { parse: parse, describe: describe, render: render, clock: clock,
              text: function (v) { return describe(v).text; },
              title: function (v) { return describe(v).title; },
              utc: function (v) { return describe(v).utc; },
              localDayStartUtc: localDayStartUtc };
  root.cfmTime = api;

  // Alpine: x-cfm-time="expr" renders the instant; an optional data-cfm-prefix is prepended.
  if (typeof document !== 'undefined') {
    document.addEventListener('alpine:init', function () {
      root.Alpine.directive('cfm-time', function (el, dir, util) {
        var get = util.evaluateLater(dir.expression);
        util.effect(function () {
          get(function (v) { render(el, v, el.getAttribute('data-cfm-prefix') || ''); });
        });
      });
    });
    // Plain DOM (generated reports): <time data-cfm-instant="2026-10-12_012200">fallback</time>.
    var applyStatic = function () {
      var els = document.querySelectorAll('[data-cfm-instant]');
      for (var i = 0; i < els.length; i++) {
        render(els[i], els[i].getAttribute('data-cfm-instant'), els[i].getAttribute('data-cfm-prefix') || '');
      }
    };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', applyStatic);
    else applyStatic();
  }
})(typeof window !== 'undefined' ? window : globalThis);
