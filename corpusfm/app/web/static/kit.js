/* CORPUSfm bespoke kit — shared behaviors (overlay focus-trap, toast, dropdown).
   Framework-light; pairs with kit.css. See docs/frontend-replatform-plan.md. */
(function () {
  // ── Adaptive activity cadence (packet 1136 Stage 3) ──────────────────────
  // The ONE polling cadence for the unified activity feed, as a PURE, time-INJECTED state machine so it
  // is deterministically testable (no wall clock, no timers here — the caller schedules setTimeout(delay)).
  //
  //   phase 'idle'   — heartbeat: a slow poll that DISCOVERS newly-started work.
  //   phase 'active' — fast, DECAYING (STEPS ladder) while work is in flight and progress keeps moving.
  //
  // Silence (the progress-silence SOFT timeout) accrues ONLY on a successful observation of an in-flight
  // record from an OBSERVED source whose progress signature did NOT change. A failed fetch (ok:false), a
  // hidden tab, or in-flight work whose source was NOT observed all PAUSE the clock (retain, do not age).
  // Real progress (sig change) RESETS the fast cadence + the clock. On soft timeout the machine returns to
  // idle heartbeat and flags softTimedOut — which NEVER means success (the work's last-known state is kept;
  // success is decided only by observing a terminal record). It re-enters fast ONLY when progress resumes.
  window.CFM_CADENCE = { HEARTBEAT: 30000, STEPS: [1000, 2000, 5000], SILENCE_TIMEOUT: 90000, HIDDEN: 60000 };

  window.cfmCadence = function (state, obs) {
    var C = window.CFM_CADENCE;
    var cur = Object.assign({ phase: 'idle', step: 0, silenceMs: 0, sig: null, softTimedOut: false }, state || {});
    var n = { phase: cur.phase, step: cur.step, silenceMs: cur.silenceMs, sig: cur.sig, softTimedOut: cur.softTimedOut };
    function iv(st) { return st.phase === 'idle' ? C.HEARTBEAT : C.STEPS[Math.min(st.step, C.STEPS.length - 1)]; }

    // Visibility-aware: a backgrounded tab polls at a throttled heartbeat and does NOT age — aging a job
    // just because the tab was hidden would falsely soft-time-out a progressing job. State is unchanged.
    if (!obs.visible) { n.delay = C.HIDDEN; return n; }

    // A failed fetch is neither silence nor completion: retain everything, PAUSE the clock, keep polling.
    if (!obs.ok) { n.delay = iv(n); return n; }

    // All work terminal → idle heartbeat. Never a success signal (success is observed on the record).
    if (!obs.inFlight) {
      n.phase = 'idle'; n.step = 0; n.silenceMs = 0; n.softTimedOut = false; n.sig = null;
      n.delay = C.HEARTBEAT; return n;
    }

    var canAge = !!obs.observed;                                    // an in-flight record from an OBSERVED source
    var progressed = canAge && cur.sig !== null && obs.sig !== cur.sig;
    if (cur.phase === 'idle') {
      if (cur.softTimedOut && !progressed) {                        // already soft; re-enter fast ONLY on real progress
        n.sig = canAge ? obs.sig : cur.sig; n.delay = C.HEARTBEAT; return n;
      }
      n.phase = 'active'; n.step = 0; n.silenceMs = 0; n.softTimedOut = false;   // work began → fast, immediately
    } else if (progressed) {
      n.step = 0; n.silenceMs = 0; n.softTimedOut = false;         // real progress → reset fast + clear silence
    } else if (canAge) {                                           // in flight, observed, no progress → age + decay
      n.silenceMs = cur.silenceMs + (obs.elapsed || 0);
      n.step = Math.min(cur.step + 1, C.STEPS.length - 1);
      if (n.silenceMs >= C.SILENCE_TIMEOUT) {                      // progress-silence SOFT timeout → idle (NOT success)
        n.phase = 'idle'; n.step = 0; n.silenceMs = 0; n.softTimedOut = true; n.sig = obs.sig;
        n.delay = C.HEARTBEAT; return n;
      }
    } else {                                                       // in flight but nothing observable → pause silence
      n.step = Math.min(cur.step + 1, C.STEPS.length - 1);         // decay interval (backoff), do NOT age
    }
    n.sig = canAge ? obs.sig : cur.sig;
    n.delay = iv(n);
    return n;
  };

  // ── Per-item spinner resolution (packet 1136 Stage 4) ────────────────────
  // Reconcile ONE observed source's records into per-item spinner state, keyed by STABLE activity id, so
  // each item carries its OWN progress token + silence clock — one task's progress can NEVER mask
  // another's stall. Pure + time-injected (elapsed) → deterministically testable.
  //
  //   prev  = { items: {id:{source,progress,silenceMs,soft}}, outcomes: {id: terminal} }
  //   returns a NEW { items, outcomes } touching only THIS source's items.
  //
  // Resolution: an OBSERVED record with status done|failed|cancelled → that actual terminal. An observed
  // in-flight record with UNCHANGED progress ages its own clock → `soft` at silenceTimeout; CHANGED
  // progress restores it to active (silence 0). A tracked item of this source that DISAPPEARS from an
  // observed source → ephemeral: genChanged ? 'evicted' : 'unknown_expired'; durable: neutral 'finished'.
  // observed=false (a failed/unobserved source) RETAINS its items untouched and PAUSES their clocks.
  window.cfmReconcileItems = function (prev, source, records, observed, elapsed, genChanged, silenceTimeout) {
    var items = Object.assign({}, (prev && prev.items) || {});
    var outcomes = Object.assign({}, (prev && prev.outcomes) || {});
    if (!observed) return { items: items, outcomes: outcomes };   // retain + pause (never age unobserved)
    var present = {};
    (records || []).forEach(function (r) {
      var st = r.status;
      if (st === 'done' || st === 'failed' || st === 'cancelled') {   // observed terminal → resolve to it
        if (items[r.id]) delete items[r.id];
        outcomes[r.id] = st;
        return;
      }
      if (st !== 'running' && st !== 'queued') return;
      present[r.id] = true;
      var prog = (r.progress == null ? '' : String(r.progress));
      var cur = items[r.id];
      if (!cur || cur.source !== source) {
        items[r.id] = { source: source, progress: prog, silenceMs: 0, soft: false };
      } else if (cur.progress !== prog) {                            // renewed real progress → restore active
        items[r.id] = { source: source, progress: prog, silenceMs: 0, soft: false };
      } else {                                                       // no progress → age THIS item's own clock
        var sm = cur.silenceMs + (elapsed || 0);
        items[r.id] = { source: source, progress: prog, silenceMs: sm, soft: sm >= silenceTimeout };
      }
      if (outcomes[r.id]) delete outcomes[r.id];                     // back in flight → clear any stale terminal
    });
    Object.keys(items).forEach(function (id) {                       // disappearance of THIS source's items
      if (items[id].source !== source || present[id]) return;
      outcomes[id] = source === 'ephemeral' ? (genChanged ? 'evicted' : 'unknown_expired') : 'finished';
      delete items[id];
    });
    return { items: items, outcomes: outcomes };
  };

  // ── Focus trap for the overlay primitive ────────────────────────────────
  // Call when a dialog/drawer opens; returns a cleanup fn to call on close.
  window.cfmFocusTrap = function (container) {
    if (!container) return function () {};
    var sel = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),'
            + 'textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
    var prev = document.activeElement;
    function focusables() {
      return Array.prototype.filter.call(container.querySelectorAll(sel),
        function (el) { return el.offsetParent !== null; });
    }
    function onKey(e) {
      if (e.key !== 'Tab') return;
      var f = focusables(); if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
    container.addEventListener('keydown', onKey);
    // focus the first sensible element
    setTimeout(function () { var f = focusables(); if (f.length) f[0].focus(); }, 0);
    return function () {
      container.removeEventListener('keydown', onKey);
      try { if (prev && prev.focus) prev.focus(); } catch (_) {}
    };
  };

  // ── Typed, stacked notifications (packet 1136 Stage 5) — replaces the single-slot cfmToast ─────────
  // window.cfmNotify.{success,error,info,progress}(msg, {key, timeout}) → a handle
  // {key, update(msg), resolve(successMsg?), dismiss()}. Simultaneous messages STACK (never overwrite);
  // a repeated `key` UPDATES that one entry (dedupe). Lifetimes by type: success auto-expires, info a bit
  // longer, errors persist long enough to act on (+ always dismissable), progress persists until
  // resolved/replaced. Text is rendered as textContent (safe); the stack is an aria-live region and each
  // entry has a keyboard-focusable dismiss button. Connectivity + structural banners are SEPARATE surfaces
  // (owned by the shell), never routed here.
  var _notes = {};        // key -> { el, textEl, timer }
  var _noteSeq = 0;
  var _NOTE_LIFE = { success: 4000, info: 6000, error: 12000, progress: 0 };   // 0 = persist
  function _noteStack() {
    var s = document.getElementById('cfm-notify-stack');
    if (!s) {
      s = document.createElement('div');
      s.id = 'cfm-notify-stack';
      s.className = 'cfm-notify-stack';
      s.setAttribute('aria-live', 'polite');
      s.setAttribute('aria-relevant', 'additions text');
      document.body.appendChild(s);
    }
    return s;
  }
  function _noteDismiss(key) {
    var n = _notes[key];
    if (!n) return;
    if (n.timer) clearTimeout(n.timer);
    if (n.el && n.el.parentNode) n.el.parentNode.removeChild(n.el);
    delete _notes[key];
  }
  function _noteShow(type, msg, opts) {
    opts = opts || {};
    var key = opts.key || ('n' + (++_noteSeq));
    var life = (opts.timeout != null) ? opts.timeout : (_NOTE_LIFE[type] || 0);
    var n = _notes[key], textEl;
    if (n) {                                   // dedupe/update: reuse the existing entry
      n.el.className = 'cfm-note cfm-note--' + type;
      n.el.setAttribute('role', type === 'error' ? 'alert' : 'status');
      textEl = n.textEl;
      if (n.timer) { clearTimeout(n.timer); n.timer = null; }
    } else {
      var el = document.createElement('div');
      el.className = 'cfm-note cfm-note--' + type;
      el.setAttribute('role', type === 'error' ? 'alert' : 'status');
      textEl = document.createElement('span');
      textEl.className = 'cfm-note-text';
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cfm-note-x';
      btn.setAttribute('aria-label', 'Dismiss notification');
      btn.textContent = '×';
      btn.addEventListener('click', function () { _noteDismiss(key); });
      el.appendChild(textEl);
      el.appendChild(btn);
      _noteStack().appendChild(el);
      n = _notes[key] = { el: el, textEl: textEl, timer: null };
    }
    textEl.textContent = (msg == null ? '' : String(msg));   // SAFE — text, never HTML
    if (life > 0) n.timer = setTimeout(function () { _noteDismiss(key); }, life);
    return {
      key: key,
      update: function (m) { if (_notes[key]) _notes[key].textEl.textContent = (m == null ? '' : String(m)); },
      resolve: function (successMsg) { if (successMsg) _noteShow('success', successMsg, { key: key }); else _noteDismiss(key); },
      dismiss: function () { _noteDismiss(key); },
    };
  }
  window.cfmNotify = {
    success:  function (m, o) { return _noteShow('success', m, o); },
    error:    function (m, o) { return _noteShow('error', m, o); },
    info:     function (m, o) { return _noteShow('info', m, o); },
    progress: function (m, o) { o = o || {}; if (o.timeout == null) o.timeout = 0; return _noteShow('progress', m, o); },
    dismiss:  function (key) { _noteDismiss(key); },
  };
  // Escape dismisses the most-recent notification (keyboard accessibility; the per-entry × also works).
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    var keys = Object.keys(_notes);
    if (keys.length) _noteDismiss(keys[keys.length - 1]);
  });

  // ── Bespoke dropdown — Alpine factory (no native <select>, no search) ────
  // Usage: <div class="cfm-dd" x-data="cfmDropdown({value:'', options:[{value,label}], onChange(v){}})">
  // Options are rendered in the order given — caller alphabetizes.
  window.cfmDropdown = function (cfg) {
    cfg = cfg || {};
    return {
      open: false,
      value: cfg.value || '',
      options: cfg.options || [],
      _onChange: cfg.onChange || function () {},
      get label() {
        var o = this.options.find(function (x) { return x.value === this.value; }, this);
        return o ? o.label : (cfg.placeholder || 'Select…');
      },
      toggle() { this.open = !this.open; },
      close() { this.open = false; },
      pick(v) { this.value = v; this.open = false; this._onChange(v); },
      isOn(v) { return v === this.value; },
    };
  };

  // ── Global keyboard shortcuts (authed app shell only) ───────────────────
  // Nav jumps + search focus + a "?" help overlay. Two hard guards: never fire
  // while typing in a field, and never fire while ANY overlay/drawer is open —
  // nav jumps are full-page navigations and must not fire over a pop-over with
  // in-progress work (same hazard class as the doc-drawer links). Gated to the
  // shell (a .sidebar-nav must exist) so it no-ops on login/standalone pages.
  function _cfmInitShortcuts() {
    if (!document.querySelector('.sidebar-nav')) return;

    var NAV = { a: '/artifacts', j: '/jobs', m: '/monitoring', r: '/runs',
                l: '/logs', t: '/tags', s: '/settings' };
    var ROWS = [
      ['/', 'Focus search'], ['?', 'This help'], ['⌘/Ctrl K', 'Command palette'],
      ['g a', 'Artifacts'], ['g j', 'Jobs'], ['g m', 'Monitoring'], ['g r', 'Runs'],
      ['g l', 'Logs'], ['g t', 'Tags'], ['g s', 'Settings'], ['g d', 'Documentation'],
      ['↑ ↓ ← →', 'Move between cards'], ['Enter', 'Open the focused card'],
      ['Esc', 'Close dialogs / this help'],
    ];

    function isEditable(el) {
      if (!el) return false;
      var t = el.tagName;
      return t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || el.isContentEditable;
    }
    function visible(el) { return !!(el && (el.offsetWidth || el.offsetHeight || el.getClientRects().length)); }
    function overlayOpen() {
      var ov = document.querySelectorAll('.cfm-overlay, .cfm-drawer-wrap');
      for (var i = 0; i < ov.length; i++) {
        if (ov[i].id === 'cfm-kbd-overlay') continue;     // our own help overlay doesn't count
        if (visible(ov[i])) return true;
      }
      return false;
    }

    var helpEl = null, helpCleanup = null;
    function openHelp() {
      if (helpEl) return;
      var rows = ROWS.map(function (r) {
        var keys = r[0].split(' ').map(function (k) { return '<kbd>' + k + '</kbd>'; }).join(' ');
        return '<tr><td class="cfm-kbd-keys">' + keys + '</td><td>' + r[1] + '</td></tr>';
      }).join('');
      helpEl = document.createElement('div');
      helpEl.className = 'cfm-overlay';
      helpEl.id = 'cfm-kbd-overlay';
      helpEl.innerHTML =
        '<div class="cfm-dialog" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">'
        + '<div class="cfm-dialog-hdr"><span class="cfm-dialog-title">Keyboard shortcuts</span>'
        + '<button type="button" class="cfm-iconbtn cfm-kbd-close" aria-label="Close">✕</button></div>'
        + '<div class="cfm-dialog-body"><table class="cfm-kbd-table"><tbody>' + rows + '</tbody></table></div>'
        + '</div>';
      document.body.appendChild(helpEl);
      helpEl.addEventListener('click', function (e) {
        if (e.target === helpEl || (e.target.closest && e.target.closest('.cfm-kbd-close'))) closeHelp();
      });
      helpCleanup = window.cfmFocusTrap(helpEl);
    }
    function closeHelp() {
      if (!helpEl) return;
      if (helpCleanup) { try { helpCleanup(); } catch (_) {} helpCleanup = null; }
      helpEl.remove(); helpEl = null;
    }

    function focusSearch() {
      var el = document.querySelector('[data-kbd-search]') || document.querySelector('.cfm-filter-search');
      if (visible(el)) { el.focus(); if (el.select) el.select(); return true; }
      return false;
    }

    // ── Command palette (Cmd/Ctrl-K) — fuzzy nav, scales past the g-chords ──
    var PAGES = [
      ['Artifacts', '/artifacts'], ['Jobs', '/jobs'], ['Monitoring', '/monitoring'],
      ['Runs', '/runs'], ['Logs', '/logs'], ['Tags', '/tags'], ['ISV', '/isv'],
      ['Settings', '/settings'], ['About', '/about'],
    ];
    function paletteCommands() {
      var cmds = PAGES.map(function (p) {
        return { label: p[0], hint: p[1], run: function () { window.cfmGo(p[1]); } };
      });
      cmds.push({ label: 'Documentation', hint: 'drawer', run: function () { window.dispatchEvent(new CustomEvent('cfm-open-docs')); } });
      cmds.push({ label: 'Keyboard shortcuts', hint: '?', run: function () { openHelp(); } });
      return cmds;
    }
    var paletteEl = null, pTrap = null, pAll = [], pView = [], pSel = 0;
    function fuzzy(q, s) {                          // case-insensitive subsequence match
      q = q.toLowerCase(); s = s.toLowerCase(); var i = 0;
      for (var j = 0; j < s.length && i < q.length; j++) if (s[j] === q[i]) i++;
      return i === q.length;
    }
    function renderPalette() {
      var ul = paletteEl.querySelector('.cfm-cmdk-list');
      ul.innerHTML = pView.length ? pView.map(function (c, i) {
        return '<li class="cfm-cmdk-item' + (i === pSel ? ' is-sel' : '') + '" data-i="' + i + '">'
          + '<span>' + c.label + '</span><span class="cfm-cmdk-hint">' + (c.hint || '') + '</span></li>';
      }).join('') : '<li class="cfm-cmdk-empty">No matches</li>';
    }
    function filterPalette(q) {
      pView = q ? pAll.filter(function (c) { return fuzzy(q, c.label); }) : pAll.slice();
      pSel = 0; renderPalette();
    }
    function runPalette(i) { var c = pView[i]; closePalette(); if (c) c.run(); }
    function closePalette() {
      if (!paletteEl) return;
      if (pTrap) { try { pTrap(); } catch (_) {} pTrap = null; }
      paletteEl.remove(); paletteEl = null;
    }
    function openPalette() {
      if (paletteEl) return;
      pAll = paletteCommands(); pView = pAll.slice(); pSel = 0;
      paletteEl = document.createElement('div');
      paletteEl.className = 'cfm-overlay'; paletteEl.id = 'cfm-cmdk';
      paletteEl.innerHTML =
        '<div class="cfm-dialog cfm-cmdk" role="dialog" aria-modal="true" aria-label="Command palette">'
        + '<div class="cfm-dialog-body">'
        + '<input type="text" class="cfm-input cfm-cmdk-input" placeholder="Jump to…" aria-label="Command palette">'
        + '<ul class="cfm-cmdk-list"></ul></div></div>';
      document.body.appendChild(paletteEl);
      renderPalette();
      var input = paletteEl.querySelector('.cfm-cmdk-input');
      paletteEl.addEventListener('click', function (e) {
        if (e.target === paletteEl) { closePalette(); return; }
        var li = e.target.closest('.cfm-cmdk-item');
        if (li) runPalette(parseInt(li.getAttribute('data-i'), 10));
      });
      input.addEventListener('input', function () { filterPalette(input.value.trim()); });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
        else if (e.key === 'Enter') { e.preventDefault(); runPalette(pSel); }
        else if (e.key === 'ArrowDown') { e.preventDefault(); if (pView.length) { pSel = (pSel + 1) % pView.length; renderPalette(); } }
        else if (e.key === 'ArrowUp') { e.preventDefault(); if (pView.length) { pSel = (pSel - 1 + pView.length) % pView.length; renderPalette(); } }
        else if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); closePalette(); }
      });
      pTrap = window.cfmFocusTrap(paletteEl);    // focuses the input + traps Tab
    }

    var gPending = false, gTimer = null;
    function clearG() { gPending = false; if (gTimer) { clearTimeout(gTimer); gTimer = null; } }

    document.addEventListener('keydown', function (e) {
      if (helpEl) {                                        // help overlay owns these while open
        if (e.key === 'Escape' || e.key === '?') { e.preventDefault(); closeHelp(); }
        return;
      }
      if (paletteEl) return;                               // the palette's input owns its own keys
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
        if (overlayOpen()) return;                         // don't open over a working pop-over
        e.preventDefault(); openPalette(); return;
      }
      if (e.altKey || e.ctrlKey || e.metaKey) return;      // leave browser/OS chords alone
      if (isEditable(document.activeElement)) return;      // typing — never intercept
      if (overlayOpen()) return;                           // a pop-over/drawer is open — no shortcuts

      if (gPending) {
        var k = (e.key || '').toLowerCase();
        clearG();
        if (k === 'd') { e.preventDefault(); window.dispatchEvent(new CustomEvent('cfm-open-docs')); }
        else if (NAV[k]) { e.preventDefault(); window.cfmGo(NAV[k]); }
        return;
      }
      if (e.key === 'g') { gPending = true; gTimer = setTimeout(clearG, 1200); return; }
      if (e.key === '/') { if (focusSearch()) e.preventDefault(); return; }
      if (e.key === '?') { e.preventDefault(); openHelp(); return; }
    });

    // ── Gallery arrow-key navigation (roving tabindex over [data-kbd-grid]) ──
    // Arrow keys move focus between .cfm-card cells (2D: Left/Right step, Up/Down by
    // the live column count), Enter activates the card's own @click (opens detail).
    // One tab stop per grid (roving tabindex), re-applied when Alpine re-renders cards.
    function setupGrid(grid) {
      function cards() { return Array.prototype.slice.call(grid.querySelectorAll('.cfm-card')); }
      function applyRoving() {
        var cs = cards(); if (!cs.length) return;
        var active = null;
        cs.forEach(function (c) {
          if (!c.hasAttribute('tabindex')) c.setAttribute('tabindex', '-1');
          if (c.getAttribute('tabindex') === '0') active = c;
        });
        if (!active) cs[0].setAttribute('tabindex', '0');
      }
      function columns(cs) {
        if (cs.length < 2) return 1;
        var top0 = cs[0].offsetTop, n = 1;
        for (var i = 1; i < cs.length; i++) { if (cs[i].offsetTop === top0) n++; else break; }
        return n || 1;
      }
      function focusCard(cs, idx) {
        idx = Math.max(0, Math.min(cs.length - 1, idx));
        cs.forEach(function (c) { c.setAttribute('tabindex', '-1'); });
        cs[idx].setAttribute('tabindex', '0');
        cs[idx].focus();
      }
      grid.addEventListener('keydown', function (e) {
        var cur = (document.activeElement && document.activeElement.closest)
          ? document.activeElement.closest('.cfm-card') : null;
        if (!cur || cur.parentNode !== grid && !grid.contains(cur)) return;  // focus not on a card here
        var cs = cards(); var idx = cs.indexOf(cur); if (idx < 0) return;
        if (e.key === 'Enter') { e.preventDefault(); cur.click(); return; }
        var cols = columns(cs), nx;
        if (e.key === 'ArrowRight') nx = idx + 1;
        else if (e.key === 'ArrowLeft') nx = idx - 1;
        else if (e.key === 'ArrowDown') nx = idx + cols;
        else if (e.key === 'ArrowUp') nx = idx - cols;
        else if (e.key === 'Home') nx = 0;
        else if (e.key === 'End') nx = cs.length - 1;
        else return;
        e.preventDefault();
        if (nx >= 0 && nx < cs.length) focusCard(cs, nx);
      });
      applyRoving();
      var raf = null;
      new MutationObserver(function () {
        if (raf) cancelAnimationFrame(raf);
        raf = requestAnimationFrame(applyRoving);
      }).observe(grid, { childList: true, subtree: true });
    }
    // Grids can be rendered lazily (the gallery is behind x-if="rows.length") and re-created
    // when the row set toggles 0↔N — so scan now AND whenever the DOM changes, init each once.
    function initGrids() {
      var gs = document.querySelectorAll('[data-kbd-grid]');
      for (var i = 0; i < gs.length; i++) {
        if (!gs[i]._kbdInit) { gs[i]._kbdInit = true; setupGrid(gs[i]); }
      }
    }
    initGrids();
    var giRaf = null;
    new MutationObserver(function () {
      if (giRaf) cancelAnimationFrame(giRaf);
      giRaf = requestAnimationFrame(initGrids);
    }).observe(document.body, { childList: true, subtree: true });
  }
  // ── Bespoke dropdown positioning ────────────────────────────────────────
  // The `.cfm-dd-menu` is `position: fixed` (see kit.css) so it escapes any
  // `overflow` ancestor — chiefly a scrolling `.cfm-dialog-body`, which clips an
  // absolutely-positioned menu (acutely on short dialogs). Anchor each open menu
  // to its `.cfm-dd-trigger` rect, flipping above when there's no room below.
  function _cfmPositionMenu(menu) {
    var dd = menu.closest('.cfm-dd'); if (!dd) return;
    var trig = dd.querySelector('.cfm-dd-trigger'); if (!trig) return;
    var r = trig.getBoundingClientRect();
    menu.style.minWidth = Math.round(r.width) + 'px';
    menu.style.left = Math.round(r.left) + 'px';
    var mh = menu.offsetHeight;                       // measured now that it's displayed
    var below = window.innerHeight - r.bottom;
    if (below < mh + 8 && r.top > below) menu.style.top = Math.round(r.top - mh - 4) + 'px';
    else menu.style.top = Math.round(r.bottom + 4) + 'px';
  }
  function _cfmVisibleMenus() {
    return Array.prototype.filter.call(
      document.querySelectorAll('.cfm-dd-menu'),
      function (e) { return getComputedStyle(e).display !== 'none'; });
  }
  //: Each menu's last known visibility, so the observer below can act on the EDGE rather than on
  //  every mutation. A WeakMap because it must not keep a removed menu alive.
  var _cfmMenuVisible = new WeakMap();

  function _cfmOnMenuStyleChanged(menu) {
    var nowVisible = getComputedStyle(menu).display !== 'none';
    if (!nowVisible) { _cfmMenuVisible.set(menu, false); return; }
    if (_cfmMenuVisible.get(menu) === true) return;      // already placed; this is our own write
    // Record BEFORE placing: `_cfmPositionMenu` writes minWidth/left/top to the same `style`
    // attribute we observe, so the resulting records must take the already-visible path above.
    _cfmMenuVisible.set(menu, true);
    _cfmPositionMenu(menu);
  }

  function _cfmInitDropdownPositioning() {
    // WHY VISIBILITY, NOT THE CLICK (packet 1331). Placement has to happen AFTER Alpine's `x-show`
    // has flipped `display`, and a click listener cannot promise that. It is defeated two ways: a
    // consumer's `@click.stop` never reaches `document` (logs and runs both stop it, and their menus
    // opened at the parked `top: -9999px`), and moving the listener to the capture phase schedules
    // its rAF BEFORE Alpine schedules the one that flips display, so it measures a hidden menu.
    // Observing the style attribute is immune to both, because it fires ON the change itself.
    //
    // THE FEEDBACK GUARD IS LOAD-BEARING: the positioner writes to the very attribute this observer
    // watches, so acting on every visible-menu mutation would schedule its own next callback. The
    // hidden -> visible EDGE, recorded before placing, is what stops that.
    var obs = new MutationObserver(function (records) {
      var seen = [];
      for (var i = 0; i < records.length; i++) {
        var el = records[i].target;
        if (!el || !el.classList || !el.classList.contains('cfm-dd-menu')) continue;
        if (seen.indexOf(el) === -1) seen.push(el);      // one layout read per menu per batch
      }
      for (var j = 0; j < seen.length; j++) _cfmOnMenuStyleChanged(seen[j]);
    });
    obs.observe(document.body, { subtree: true, attributes: true, attributeFilter: ['style'] });

    // Seed menus that already exist, so initialization ORDER is not an implicit contract: a menu
    // rendered visible before this ran is placed once here rather than waiting for a mutation.
    var existing = document.querySelectorAll('.cfm-dd-menu');
    for (var k = 0; k < existing.length; k++) {
      var m = existing[k];
      var vis = getComputedStyle(m).display !== 'none';
      _cfmMenuVisible.set(m, vis);
      if (vis) _cfmPositionMenu(m);
    }

    // Keep a glued menu attached while its container scrolls (capture = catch the
    // dialog body too) or the window resizes. Reflow is deliberately NOT edge-suppressed: an
    // already-open menu must be re-anchored, which is the one case the observer must not handle.
    function reflow() { _cfmVisibleMenus().forEach(_cfmPositionMenu); }
    window.addEventListener('scroll', reflow, true);
    window.addEventListener('resize', reflow);
  }

  if (document.readyState !== 'loading') { _cfmInitShortcuts(); _cfmInitDropdownPositioning(); }
  else document.addEventListener('DOMContentLoaded', function () {
    _cfmInitShortcuts(); _cfmInitDropdownPositioning();
  });
})();
