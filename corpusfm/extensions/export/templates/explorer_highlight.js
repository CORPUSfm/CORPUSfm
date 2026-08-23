// Highlight budget (packet 1282): a CHARACTER cap, not bytes. The param tokenizer is quadratic
// in its input (each token scan can backtrack over the rest of the text), so a multi-megabyte
// single-line step would freeze the tab for minutes. Past the cap, return escaped plain text —
// linear, no tokenizer entry. Steps over the 512 KiB presentation threshold never reach the
// highlighter at all (they render as a marker; see the oversize branch in the step template).
var FM_HL_MAX_CHARS = 32768;

// FM script step syntax highlighter.
// Colorizes .step-txt content: verb, brackets, field refs, strings, separators, comments, warnings.
// Disabled steps (starting with "// ") are returned as plain escaped text — CSS dims them.
function fmStepHighlight(rawText) {
  function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  if (rawText.length > FM_HL_MAX_CHARS) return esc(rawText);
  if (rawText.startsWith('// ')) return esc(rawText);
  if (rawText.startsWith('#')) return '<span class="step-cmt">'+esc(rawText)+'</span>';

  function hlParams(s) {
    var TOKENS = [
      [/"[^"]*"/, 'step-str'],
      [/\S[^\[\];\n¶⚠]*::[^\[\];\n¶⚠]*\S/, 'step-field'],
      [/;/, 'step-sep'],
      [/¶/, 'step-sep'],
      [/[\[\]]/, 'step-bracket'],
      [/⚠[^\n]*/, 'step-warn'],
    ];
    var out = '', pos = 0, len = s.length;
    while (pos < len) {
      var best = null, bestIdx = len, bestCls = '';
      for (var i = 0; i < TOKENS.length; i++) {
        var re = new RegExp(TOKENS[i][0].source, 'g');
        re.lastIndex = pos;
        var m = re.exec(s);
        if (m && m.index < bestIdx) { best = m; bestIdx = m.index; bestCls = TOKENS[i][1]; }
      }
      if (!best) { out += esc(s.slice(pos)); break; }
      out += esc(s.slice(pos, bestIdx));
      out += '<span class="'+bestCls+'">'+esc(best[0])+'</span>';
      pos = bestIdx + best[0].length;
    }
    return out;
  }

  var bi = rawText.indexOf('[');
  if (bi === -1) {
    var wi = rawText.indexOf('⚠');
    if (wi === -1) return '<span class="step-verb">'+esc(rawText)+'</span>';
    return '<span class="step-verb">'+esc(rawText.slice(0, wi))+'</span>'
         + '<span class="step-warn">'+esc(rawText.slice(wi))+'</span>';
  }
  return '<span class="step-verb">'+esc(rawText.slice(0, bi))+'</span>' + hlParams(rawText.slice(bi));
}

// FM calculation syntax highlighter — lightweight left-to-right tokenizer.
// Returns HTML with <span class="cf-*"> tokens; all non-token text is HTML-escaped.
function fmHighlight(text) {
  var TOKENS = [
    [/\/\*[\s\S]*?\*\//, 'cf-cmt'],
    [/\/\/[^\n]*/, 'cf-cmt'],
    [/"[^"]*"/, 'cf-str'],
    [/\d+(?:\.\d+)?(?:[Ee][+-]?\d+)?/, 'cf-num'],
    [/[\w.]+::[\w.]+/, 'cf-field'],
    [/[A-Za-z][A-Za-z0-9_]*(?=\s*\()/, 'cf-func'],
    [/\b(?:True|False)\b/, 'cf-kw'],
    [/[¶≠≤≥]/, 'cf-op'],
  ];
  function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  if (text.length > FM_HL_MAX_CHARS) return esc(text);
  var out = '', pos = 0, len = text.length;
  while (pos < len) {
    var best = null, bestIdx = len, bestCls = '';
    for (var i = 0; i < TOKENS.length; i++) {
      var re = new RegExp(TOKENS[i][0].source, 'g');
      re.lastIndex = pos;
      var m = re.exec(text);
      if (m && m.index < bestIdx) { best = m; bestIdx = m.index; bestCls = TOKENS[i][1]; }
    }
    if (!best) { out += esc(text.slice(pos)); break; }
    out += esc(text.slice(pos, bestIdx));
    out += '<span class="'+bestCls+'">'+esc(best[0])+'</span>';
    pos = bestIdx + best[0].length;
  }
  return out;
}
