(function() {
var NS = 'http://www.w3.org/2000/svg';
var CL_W = 150, CL_H = 28;  // normalized node size for the By Table view
// Screen pixels per map unit for a readable subject. The reference: a 131-unit-wide occurrence at about 157 px.
var READABLE = 1.2;
// As Built occurrence anatomy. These match the sizing rule in explorer.py: 26 + 12 per row.
var HDR_H = 18, ROWS_TOP = 22, ROW_H = 12, PANE_GAP = 6;
var NOTE_COLLAPSED_H = 18;  // packet 1448: the screenshot-pair estimate; the XML keeps only the full bounds
// Presentation choices, not source facts: the top bar sits INSIDE the captured bounds, so the footprint is unchanged;
// the minimum keeps the bar's controls and a line of text usable.
var NOTE_BAR_H = 12, NOTE_MIN_W = 80, NOTE_MIN_H = 40;

function _el(tag, attrs) {
  var e = document.createElementNS(NS, tag);
  for (var k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
function _bounds(posMap, notes) {
  var pad=40, x0=1e9, y0=1e9, x1=-1e9, y1=-1e9;
  function take(p){
    if(p.x<x0)x0=p.x; if(p.y<y0)y0=p.y;
    if(p.x+p.w>x1)x1=p.x+p.w; if(p.y+p.h>y1)y1=p.y+p.h;
  }
  for (var id in posMap) take(posMap[id]);
  (notes||[]).forEach(function(n){take({x:n.x,y:n.y,w:n.w,h:n.collapsed?NOTE_COLLAPSED_H:n.h});});
  return {x:x0-pad, y:y0-pad, w:x1-x0+2*pad, h:y1-y0+2*pad};
}
function _rgb(hex){return [1,3,5].map(function(i){return parseInt(hex.substr(i,2),16);});}
function _hex(c){return '#'+c.map(function(v){return ('0'+Math.round(v).toString(16)).slice(-2);}).join('');}
function _mix(a,b,t){return a.map(function(v,i){return v*(1-t)+b[i]*t;});}
function _lum(c){
  var l=c.map(function(v){v/=255;return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4);});
  return 0.2126*l[0]+0.7152*l[1]+0.0722*l[2];
}
function _ink(c){var l=_lum(c),dark=(l+0.05)/0.05,light=1.05/(l+0.05);return dark>=light?'#000':'#fff';}

// ── Build SVG structure for one file (positions applied separately) ───────────
window._rgBuild = function(gd, svgEl, navigateFn, describe, onNodeMoved) {
  if (svgEl._rgCleanup) svgEl._rgCleanup();
  svgEl.innerHTML = '';
  var nodes=gd.nodes, edges=gd.edges;
  var isLight = (document.getElementById('fmc-root')||{}).dataset?.theme === 'light';
  var canvas = isLight ? [244,245,246] : [17,19,21];
  var nodeById = {}; for (var n of nodes) nodeById[n.id]=n;
  svgEl._rgRowIndex = {};

  var defs = _el('defs',{});
  for (var n of nodes) {
    var cp = _el('clipPath',{id:'rgcp'+n.id});
    var cpr = _el('rect',{id:'rgcpr'+n.id, x:2, y:2,
      width:Math.max(0,(n.w||0)-4), height:Math.max(0,(n.h||0)-4)});
    cp.appendChild(cpr); defs.appendChild(cp);
  }
  svgEl.appendChild(defs);

  // Notes first: captured annotations sit behind everything, later ones over earlier ones. Each has a top bar (the
  // handle, with View and expand/collapse at its right), its text below, selectable and scrollable, and a grip.
  var nl = _el('g',{'class':'rg-notes'});
  var XH='http://www.w3.org/1999/xhtml';
  function _x(tag, cls, attrs){var e=document.createElementNS(XH,tag);e.className=cls;for(var k in attrs||{})e.setAttribute(k,attrs[k]);return e;}
  (gd.notes||[]).forEach(function(note,index){
    var fo=_el('foreignObject',{'class':'rg-note','data-note':index,x:note.x,y:note.y,width:note.w,height:note.collapsed?NOTE_COLLAPSED_H:note.h});
    var d=_x('div','rg-note-body'+(note.collapsed?' rg-note-collapsed':''));
    var bar=_x('div','rg-note-bar');
    var view=_x('button','rg-note-btn rg-note-view',{type:'button','aria-label':'View full note text',title:'View full note text'});
    var tog=_x('button','rg-note-btn rg-note-toggle',{type:'button'});
    bar.appendChild(view); bar.appendChild(tog);
    var text=_x('div','rg-note-text');
    text.textContent=note.text;
    // Text first: where the grid overlaps them (the collapsed strip, the grip's corner) the later bar and grip are on top.
    d.appendChild(text); d.appendChild(bar); d.appendChild(_x('div','rg-note-grip',{'aria-hidden':'true'}));
    d.style.setProperty('--note-bar-h',NOTE_BAR_H+'px');
    view.addEventListener('click',function(){if(svgEl._rgOnNoteView)svgEl._rgOnNoteView(index,view);});
    tog.addEventListener('click',function(){
      var np=svgEl._rgNotePos[index]; if(!np)return;
      np.collapsed=!np.collapsed;
      _placeNote(svgEl,index);
      if(onNodeMoved)onNodeMoved('note:'+index,{collapsed:np.collapsed});
    });
    if(note.background){
      var b=note.background, c=b.slice(0,3);
      d.style.backgroundColor='rgba('+b.join(',')+')';
      d.style.color=note.color?'rgb('+note.color.slice(0,3).join(',')+')':_ink(_mix(canvas,c,b[3]));
    }
    fo.appendChild(d); nl.appendChild(fo);
  });
  svgEl.appendChild(nl);

  // Overlay group — cluster backgrounds sit here, behind edges
  var ov = _el('g',{'class':'rg-ov'});
  svgEl.appendChild(ov);

  // Filled once the boxes (and so their drawn rows) exist; layered here, behind the boxes.
  var eg = _el('g',{'class':'rg-edges'}), hg = _el('g',{'class':'rg-hits'}), og = _el('g',{'class':'rg-ops'});
  var nameOf = {}; for (var n of nodes) nameOf[n.id]=n.name;
  svgEl.appendChild(eg); svgEl.appendChild(hg); svgEl.appendChild(og);

  // Nodes
  var ng = _el('g',{'class':'rg-nodes'});
  for (var n of nodes) {
    var deg = n.degree||0;
    var g = _el('g',{'data-nid':n.id,'data-to-name':n.name,'data-item':n.item||'',
      tabindex:'0',role:'button','aria-label':'Occurrence: '+n.name});
    g.style.cursor='pointer';
    var src = n.source_color ? _rgb(n.source_color) : (isLight?[200,204,212]:[74,79,90]);
    var bodyFill = _mix(canvas, src, isLight?0.28:0.38);
    var edge = _mix(src, isLight?[0,0,0]:[255,255,255], 0.3);
    g._rg = {srcHex:_hex(src), bodyHex:_hex(bodyFill), edgeHex:_hex(edge), alpha:n.source_alpha==null?1:n.source_alpha,
             headInk:_ink(_mix(canvas,src,n.source_alpha==null?1:n.source_alpha)), bodyInk:_ink(bodyFill),
             hub:deg>=5, flat:n.color, flatInk:isLight?'#111':'#fff'};
    var rect = _el('rect',{'class':'rg-nr', x:0, y:0, width:n.w||0, height:n.h||0, rx:3});
    var hdr = _el('rect',{'class':'rg-hdr', x:0, y:0, width:n.w||0, height:HDR_H, rx:3, 'pointer-events':'none'});
    var txt = _el('text',{'class':'rg-nt',
      'dominant-baseline':'middle','font-size':'9','font-family':'SFMono-Regular,Consolas,monospace',
      'clip-path':'url(#rgcp'+n.id+')','pointer-events':'none'});
    txt.textContent = n.name;
    g.appendChild(rect); g.appendChild(hdr); g.appendChild(txt);
    var rowsG = _el('g',{'class':'rg-rows','pointer-events':'none','clip-path':'url(#rgcp'+n.id+')'});
    var showRows = n.h_basis==='related' || n.h_basis==='full' || (n.view==='Related' && (n.rows||[]).length);
    var rowIndex = svgEl._rgRowIndex[n.id] = {};
    if (showRows) (n.rows||[]).forEach(function(r,i){
      if (ROWS_TOP+ROW_H*(i+1) > (n.h||0)) return;
      rowIndex[r.id]=i;
      var rt=_el('text',{x:6,y:ROWS_TOP+ROW_H*i+ROW_H/2,'dominant-baseline':'middle','font-size':'8.5','font-family':'SFMono-Regular,Consolas,monospace',fill:g._rg.bodyInk});
      rt.textContent=r.name; rowsG.appendChild(rt);
    });
    if (showRows && n.rows_incomplete && ROWS_TOP+ROW_H*((n.rows||[]).length+1) <= (n.h||0)) {
      var unk=_el('text',{'class':'rg-row-unknown',x:6,y:ROWS_TOP+ROW_H*(n.rows||[]).length+ROW_H/2,'dominant-baseline':'middle','font-size':'8','font-style':'italic',fill:g._rg.bodyInk});
      unk.textContent='Field not identified'; rowsG.appendChild(unk);
    }
    g.appendChild(rowsG);
    if (n.h_basis==='full') {
      var paneTop=ROWS_TOP+ROW_H*(n.rows||[]).length+PANE_GAP-4, paneH=(n.h||0)-paneTop-2;
      if (paneH>ROW_H) {
        var pcid='rgpc'+n.id, pc=_el('clipPath',{id:pcid});
        pc.appendChild(_el('rect',{x:2,y:paneTop,width:Math.max(0,n.w-4),height:paneH})); defs.appendChild(pc);
        var paneOuter=_el('g',{'class':'rg-pane','clip-path':'url(#'+pcid+')'});
        paneOuter.appendChild(_el('rect',{x:0,y:paneTop,width:n.w,height:paneH,fill:'transparent'}));
        var pane=_el('g',{'class':'rg-pane-rows','pointer-events':'none'});
        var list=n.fields||[];
        if (n.fields_state==='captured') list.forEach(function(f,i){
          var ft=_el('text',{x:6,y:paneTop+ROW_H*i+ROW_H/2,'dominant-baseline':'middle','font-size':'8.5','font-family':'SFMono-Regular,Consolas,monospace',fill:g._rg.bodyInk});
          ft.textContent=f.name; pane.appendChild(ft);
        });
        else {
          var un=_el('text',{x:6,y:paneTop+ROW_H/2,'dominant-baseline':'middle','font-size':'8','font-style':'italic',fill:g._rg.bodyInk});
          un.textContent='Field list not available'; pane.appendChild(un);
        }
        paneOuter.appendChild(pane); g.appendChild(paneOuter);
        g.appendChild(_el('line',{'class':'rg-divider',x1:2,x2:n.w-2,y1:paneTop-1,y2:paneTop-1,stroke:g._rg.edgeHex,'stroke-width':'0.75','pointer-events':'none'}));
        paneOuter._rgPane={rows:pane,max:Math.max(0,ROW_H*list.length-paneH),top:0};
      }
    }
    if (n.external) {
      var bk=_el('rect',{'class':'rg-ext',x:(n.w||0)-14,y:2,width:12,height:10,
        fill:'#f0a000',rx:2,'pointer-events':'none'});
      var bt=_el('text',{'class':'rg-ext-t',x:(n.w||0)-8,y:7,
        'text-anchor':'middle','dominant-baseline':'middle',fill:'#000',
        'font-size':'6','pointer-events':'none'});
      bt.textContent='ext';
      g.appendChild(bk); g.appendChild(bt);
    }
    ng.appendChild(g);
  }
  svgEl.appendChild(ng);

  // One connected structure per RELATIONSHIP (packet 1448): a short branch from each distinct place a condition
  // meets a box (a drawn field row, or the header where no row can honestly be named), joined beside each box into
  // one trunk with one marker and one hit target. Conditions are never merged away: every one stays in the data,
  // the tip and the details; two relationships between the same boxes stay two trunks.
  svgEl._rgRels = [];
  for (var e of edges) {
    var pairs = e.pairs||[];
    var meta = {'data-fid':e.from_id,'data-tid':e.to_id,'data-item':e.item||''};
    var rel = {fid:e.from_id, tid:e.to_id, cartEdge:e.type==='cartesian', pairs:pairs, sides:{l:[],r:[]}, branches:[]};
    [['l','lf',e.from_id],['r','rf',e.to_id]].forEach(function(sd){
      var idx = svgEl._rgRowIndex[sd[2]]||{}, keys = {};
      (pairs.length?pairs:[{}]).forEach(function(pair){
        var f = pair[sd[1]]||'', i = f ? idx[f] : undefined, key = i===undefined ? 'h' : 'r'+i;
        if (!keys[key]) { keys[key] = {key:key, fields:[], cart:true}; rel.sides[sd[0]].push(keys[key]); }
        if (f && keys[key].fields.indexOf(f)<0) keys[key].fields.push(f);
        if (pair.op!=='CartesianProduct') keys[key].cart = false;
      });
      rel.sides[sd[0]].forEach(function(a){
        var b = _el('path', Object.assign({'class':'rg-branch','data-side':sd[0],'data-fields':a.fields.join(' ')}, meta));
        eg.appendChild(b); rel.branches.push({el:b, side:sd[0], anchor:a});
      });
    });
    rel.trunk = _el('path', Object.assign({'class':'rg-trunk','data-conds':pairs.length}, meta));
    eg.appendChild(rel.trunk);
    rel.hit = _el('path', Object.assign({'class':'rg-hit',tabindex:'0',role:'button',
      'aria-label':'Relationship: '+(nameOf[e.from_id]||'?')+' to '+(nameOf[e.to_id]||'?')}, meta));
    hg.appendChild(rel.hit);
    var ops = pairs.map(function(pair){return pair.op;}).filter(Boolean);
    if (ops.length) {
      rel.op = _el('g', Object.assign({'class':'rg-op','data-op':ops.join(' ')}, meta));
      rel.op.appendChild(_el('rect',{y:-6,height:12,rx:2}));
      rel.op.appendChild(_el('text',{'text-anchor':'middle','dominant-baseline':'central','font-size':'9'}));
      og.appendChild(rel.op);
    }
    svgEl._rgRels.push(rel);
  }

  // Index node elements by id
  svgEl._rgNodeEls = new Map(Array.from(ng.children).map(g=>[g.getAttribute('data-nid'),g]));
  svgEl._rgEdgeEls = Array.from(eg.children).concat(Array.from(hg.children));
  svgEl._rgOpEls = Array.from(og.children);
  svgEl._rgNodeById = nodeById;
  svgEl._rgNoteEls = nl;
  svgEl._rgNotePos = (gd.notes||[]).map(function(n){return {x:n.x,y:n.y,w:n.w,h:n.h,collapsed:!!n.collapsed};});   // never appData itself
  svgEl._rgOv = ov;
  svgEl._rgMode = null;

  // ── Pan, node drag, pane scroll, zoom ────────────────────────────────────────
  var vb={x:0,y:0,w:1000,h:1000}, mode=null, px=0, py=0, sx=0, sy=0, dragged=false, dragId=null, dragPane=null, dragNote=null, sizeAt=null;
  svgEl._rgVb = vb;
  function setVb(){svgEl.setAttribute('viewBox',vb.x+' '+vb.y+' '+vb.w+' '+vb.h);}
  function scrollerAt(t){
    var p=t.closest&&t.closest('.rg-pane');
    if(p&&p._rgPane&&p._rgPane.max>0)return {pane:p._rgPane};
    var d=t.closest&&t.closest('.rg-note-text');
    if(d&&d.scrollHeight>d.clientHeight&&!d.closest('.rg-note-collapsed'))return {note:d};
    return null;
  }
  function scrollBy(s,dy){
    if(s.note){var before=s.note.scrollTop;s.note.scrollTop+=dy;return s.note.scrollTop!==before;}
    var top=Math.max(0,Math.min(s.pane.max,s.pane.top+dy));
    if(top===s.pane.top)return false;
    s.pane.top=top;s.pane.rows.setAttribute('transform','translate(0,'+(-top)+')');return true;
  }
  function onDown(e){
    if(e.button!==0)return;
    hideTip();
    dragged=false;px=sx=e.clientX;py=sy=e.clientY;dragId=null;dragPane=null;dragNote=null;
    var node=e.target.closest&&e.target.closest('g[data-nid]');
    var note=svgEl._rgMode==='fm'&&e.target.closest?e.target.closest('.rg-note'):null;
    // A note's buttons act on their own click; nothing here may start a move or a pan from them.
    if(note&&e.target.closest('.rg-note-btn'))return;
    var noteIdx=note?+note.getAttribute('data-note'):null;
    var scroller=e.pointerType==='touch'&&!note?scrollerAt(e.target):null;
    if(note&&e.target.closest('.rg-note-grip')){mode='resize';dragNote=noteIdx;var rp=svgEl._rgNotePos[noteIdx];sizeAt={w:rp.w,h:rp.h};}
    else if(note&&e.target.closest('.rg-note-bar')){mode='note';dragNote=noteIdx;}
    else if(note){
      // The text belongs to the reader: a mouse selects it (the wheel scrolls it); a finger scrolls it, or pans
      // the map when there is nothing to scroll.
      if(e.pointerType!=='touch')return;
      var ns=scrollerAt(e.target);
      if(ns){mode='scroll';dragPane=ns;}else mode='pan';
    }
    else if(scroller){mode='scroll';dragPane=scroller;}
    else if(node&&svgEl._rgMode==='fm'&&svgEl._rgPos[node.getAttribute('data-nid')]){mode='node';dragId=node.getAttribute('data-nid');}
    else mode='pan';
    if(mode==='pan')svgEl.style.cursor='grabbing';
    e.preventDefault();
  }
  function onMove(e){
    if(!mode)return;
    if(Math.abs(e.clientX-sx)+Math.abs(e.clientY-sy)>4)dragged=true;
    var r=svgEl.getBoundingClientRect();if(!r.width||!r.height)return;
    // Below the drag threshold nothing is consumed, so a moved block doesn't start behind the pointer.
    if((mode==='node'||mode==='note'||mode==='resize')&&!dragged)return;
    var dx=e.clientX-px, dy=e.clientY-py; px=e.clientX;py=e.clientY;
    if(mode==='scroll'){scrollBy(dragPane,-dy/svgEl.getScreenCTM().d);return;}
    if(mode==='resize'){
      // From where the press began, through the actual transform, so the corner stays under the pointer at any zoom.
      // A note captured smaller than the minimum is never enlarged just by taking hold of it.
      var rm=svgEl.getScreenCTM(), rn=svgEl._rgNotePos[dragNote];
      rn.w=Math.max(Math.min(NOTE_MIN_W,sizeAt.w),sizeAt.w+(e.clientX-sx)/rm.a);
      rn.h=Math.max(Math.min(NOTE_MIN_H,sizeAt.h),sizeAt.h+(e.clientY-sy)/rm.d);
      _placeNote(svgEl,dragNote);
      if(onNodeMoved)onNodeMoved('note:'+dragNote,{w:rn.w,h:rn.h});
      return;
    }
    if(mode==='note'){
      var nm=svgEl.getScreenCTM(), np=svgEl._rgNotePos[dragNote];
      np.x+=dx/nm.a; np.y+=dy/nm.d;
      _placeNote(svgEl,dragNote);
      if(onNodeMoved)onNodeMoved('note:'+dragNote,{x:np.x,y:np.y});
      return;
    }
    if(mode==='node'){
      var m=svgEl.getScreenCTM(), p=svgEl._rgPos[dragId];
      p.x+=dx/m.a; p.y+=dy/m.d;
      _placeNode(svgEl,dragId);
      _placeEdges(svgEl);
      if(onNodeMoved)onNodeMoved(dragId,{x:p.x,y:p.y});
      return;
    }
    // Through the actual transform: on a letterboxed view the element's size is not the scale.
    var pm=svgEl.getScreenCTM();
    vb.x-=dx/pm.a; vb.y-=dy/pm.d;
    setVb();
  }
  function onUp(){if(mode){mode=null;dragId=null;dragPane=null;dragNote=null;svgEl.style.cursor='grab';}}
  // A sideways wheel (or tilt, or a mostly sideways trackpad stroke) pans sideways and never zooms; an upright one
  // scrolls a field or note list under the pointer, else zooms about the pointer. An event with no movement does nothing.
  function onWheel(e){
    e.preventDefault();
    var r=svgEl.getBoundingClientRect();if(!r.width||!r.height)return;
    var unit=e.deltaMode===1?16:e.deltaMode===2?r.width:1, wdx=e.deltaX*unit, wdy=e.deltaY*unit;
    if(!wdx&&!wdy)return;
    hideTip();
    if(Math.abs(wdx)>=Math.abs(wdy)){
      vb.x+=wdx/svgEl.getScreenCTM().a;
      setVb();
      return;
    }
    var s=scrollerAt(e.target);
    if(s&&scrollBy(s,e.deltaY))return;
    var f=e.deltaY>0?1.15:1/1.15;
    var m0=svgEl.getScreenCTM(), wx=(e.clientX-m0.e)/m0.a, wy=(e.clientY-m0.f)/m0.d;
    vb.w*=f;vb.h*=f;
    setVb();
    // Whatever is under the pointer stays under it.
    var m1=svgEl.getScreenCTM();
    vb.x+=wx-(e.clientX-m1.e)/m1.a;
    vb.y+=wy-(e.clientY-m1.f)/m1.d;
    setVb();
  }
  svgEl.addEventListener('pointerdown',onDown);
  document.addEventListener('pointermove',onMove);
  document.addEventListener('pointerup',onUp);
  document.addEventListener('pointercancel',onUp);
  svgEl.addEventListener('wheel',onWheel,{passive:false});

  // A resize keeps the same scale and the same point in the middle, so a full-screen toggle or a moved
  // window shows more or less of the map rather than rescaling it. A view that was hidden comes back here.
  var hidden=true;
  var resizeObs=typeof ResizeObserver==='function'?new ResizeObserver(function(){
    var r=svgEl.getBoundingClientRect();
    if(!r.width||!r.height){hidden=true;return;}
    var was=svgEl._rgSize;
    if(was&&was.w&&vb.w&&vb.h&&(was.w!==r.width||was.h!==r.height)){
      var s=Math.min(was.w/vb.w,was.h/vb.h), cx=vb.x+vb.w/2, cy=vb.y+vb.h/2;
      vb.w=r.width/s; vb.h=r.height/s; vb.x=cx-vb.w/2; vb.y=cy-vb.h/2;
      setVb();
    }
    svgEl._rgSize={w:r.width,h:r.height};
    if(hidden){hidden=false;if(svgEl._rgOnShown)svgEl._rgOnShown();}
  }):null;
  if(resizeObs)resizeObs.observe(svgEl);

  // ── Tooltip ──────────────────────────────────────────────────────────────────
  // Names can be longer than their box. Text only, never markup: these strings come from the file.
  var tip=document.getElementById('graph-tooltip'), tipFor=null, tipTimer=null, dismissed=null, GAP=14, DELAY=300, MAX_LINES=9;
  function tipTarget(e){var t=e.target.closest&&e.target.closest('[data-item]');return t&&t.getAttribute('data-item')?t:null;}
  function place(x,y,clearH){
    var w=tip.offsetWidth,h=tip.offsetHeight,vw=window.innerWidth,vh=window.innerHeight;
    var left=Math.max(4,Math.min(x+GAP,vw-w-4));
    var top=y+clearH+GAP; if(top+h>vh-4)top=y-h-GAP;
    tip.style.left=left+'px'; tip.style.top=Math.max(4,top)+'px';
  }
  function fill(t){
    var lines=describe?describe(t.hasAttribute('data-nid')?'to':'rel',t.getAttribute('data-item')):[];
    if(lines.length>MAX_LINES)lines=lines.slice(0,MAX_LINES-1).concat('+'+(lines.length-MAX_LINES+1)+' more, listed under Details');
    tip.textContent='';
    lines.forEach(function(text,i){var d=document.createElement(i===0?'strong':'div');d.textContent=text;d.style.display='block';tip.appendChild(d);});
    return lines.length>0;
  }
  function hideTip(){
    clearTimeout(tipTimer); tipTimer=null;
    if(tipFor)tipFor.removeAttribute('aria-describedby');
    var was=!!tip&&tip.style.display==='block';
    tipFor=null; if(tip)tip.style.display='none';
    return was;
  }
  // Stays dismissed for this target until the pointer leaves it.
  svgEl._rgHideTip=function(){dismissed=tipFor;return hideTip();};
  // The description has to be there when focus lands, not when the tip later appears.
  function arm(t){if(!tip||!fill(t))return false;tipFor=t;t.setAttribute('aria-describedby','graph-tooltip');return true;}
  function show(t,x,y,clearH){tip.style.display='block';place(x,y,clearH);}
  function onHover(e){
    if(e.pointerType!=='mouse'||mode)return;
    var t=tipTarget(e);
    if(!t){dismissed=null;if(tipFor||tipTimer)hideTip();return;}
    if(t===dismissed)return;
    dismissed=null;
    if(t===tipFor&&tip.style.display==='block'){place(e.clientX,e.clientY,0);return;}
    if(t===tipFor)return;
    hideTip(); if(!arm(t))return;
    var x=e.clientX,y=e.clientY;
    tipTimer=setTimeout(function(){tipTimer=null;if(tipFor===t)show(t,x,y,0);},DELAY);
  }
  function onFocusIn(e){
    var t=tipTarget(e); if(!t||!e.target.matches(':focus-visible'))return;
    hideTip(); if(!arm(t))return;
    tipTimer=setTimeout(function(){
      tipTimer=null; if(tipFor!==t)return;
      var r=t.getBoundingClientRect(); show(t,r.left,r.top,r.height);
    },DELAY);
  }
  [ng,hg].forEach(function(g){
    g.addEventListener('pointermove',onHover); g.addEventListener('pointerleave',function(){dismissed=null;hideTip();});
    g.addEventListener('focusin',onFocusIn); g.addEventListener('focusout',hideTip);
  });
  function targetOf(e){
    var t=e.target.closest&&e.target.closest('[data-item]');
    if(!t||!t.getAttribute('data-item'))return null;
    return {section:t.hasAttribute('data-nid')?'TableOccurrenceCatalog':'RelationshipCatalog',item:t.getAttribute('data-item')};
  }
  function onPick(e){
    if(dragged){dragged=false;return;}
    hideTip();
    var t=targetOf(e); if(t)navigateFn(t.section,t.item);
  }
  function onKey(e){
    if(e.key!=='Enter'&&e.key!==' ')return;
    var t=targetOf(e); if(t){e.preventDefault();hideTip();navigateFn(t.section,t.item);}
  }
  ng.addEventListener('click',onPick); hg.addEventListener('click',onPick);
  ng.addEventListener('keydown',onKey); hg.addEventListener('keydown',onKey);

  svgEl._rgCleanup = function(){
    svgEl.removeEventListener('pointerdown',onDown);
    document.removeEventListener('pointermove',onMove);
    document.removeEventListener('pointerup',onUp);
    document.removeEventListener('pointercancel',onUp);
    svgEl.removeEventListener('wheel',onWheel);
    if(resizeObs)resizeObs.disconnect();
    hideTip();
  };
};

function _placeNote(svgEl, index) {
  var fo=svgEl._rgNoteEls.children[index], p=svgEl._rgNotePos[index];
  fo.setAttribute('x',p.x); fo.setAttribute('y',p.y);
  fo.setAttribute('width',p.w); fo.setAttribute('height',p.collapsed?NOTE_COLLAPSED_H:p.h);
  var d=fo.firstChild, t=d.querySelector('.rg-note-toggle'), label=p.collapsed?'Expand note':'Collapse note';
  d.classList.toggle('rg-note-collapsed',!!p.collapsed);
  t.setAttribute('aria-label',label); t.setAttribute('title',label); t.setAttribute('aria-expanded',String(!p.collapsed));
}

function _placeNode(svgEl, id) {
  var g=svgEl._rgNodeEls.get(id), p=svgEl._rgPos[id];
  g.style.display = p ? '' : 'none';   // no captured position: off the map, never placed by guesswork
  g.setAttribute('tabindex', p ? '0' : '-1');
  if(!p)return;
  g.setAttribute('transform','translate('+p.x+','+p.y+')');
}

// Where a relationship meets an occurrence: the side facing the other end, at a drawn field row or, when no row
// can honestly be named, the header, which can never be mistaken for a field. As Built only.
var STUB = 22, ELBOW = 8, LOOP = 14;
function _anchorY(p, key) {
  return key==='h' ? p.y+Math.min(HDR_H,p.h)/2 : p.y+ROWS_TOP+ROW_H*(+key.slice(1))+ROW_H/2;
}
// Whether the XML-left box is the one read second: by box centers, as the sides are picked; top to bottom if stacked.
function _readsReversed(fp, tp) {
  var a=fp.x+fp.w/2, b=tp.x+tp.w/2;
  return a!==b ? a>b : fp.y>tp.y;
}
var _OP_LABEL={Equal:'=',NotEqual:'≠',Less:'<',Greater:'>',LessOrEqual:'≤',GreaterOrEqual:'≥',CartesianProduct:'×'};
var _OP_MIRROR={Less:'Greater',Greater:'Less',LessOrEqual:'GreaterOrEqual',GreaterOrEqual:'LessOrEqual'};
function _f(v){return Math.round(v*100)/100;}
function _placeEdges(svgEl) {
  var pos=svgEl._rgPos, fm=svgEl._rgMode==='fm';
  for (var rel of (svgEl._rgRels||[])) {
    var fp=pos[rel.fid], tp=pos[rel.tid], shown=!!(fp&&tp);
    var parts=[rel.trunk,rel.hit].concat(rel.branches.map(function(b){return b.el;}));
    parts.forEach(function(el){el.style.display=shown?'':'none';});
    if(rel.op) rel.op.style.display=(shown&&fm)?'':'none';
    if(!shown)continue;
    var d=[];
    if(!fm){
      // By Table: one plain center-to-center line per relationship, as before.
      rel.branches.forEach(function(b){b.el.style.display='none';});
      var td='M'+_f(fp.x+fp.w/2)+' '+_f(fp.y+fp.h/2)+'L'+_f(tp.x+tp.w/2)+' '+_f(tp.y+tp.h/2);
      rel.trunk.setAttribute('d',td); rel.hit.setAttribute('d',td);
      if(rel.cartEdge) rel.trunk.setAttribute('stroke-dasharray','5 3'); else rel.trunk.removeAttribute('stroke-dasharray');
      continue;
    }
    var J={};
    [['l',fp,tp],['r',tp,fp]].forEach(function(sd){
      var p=sd[1], o=sd[2], right=o.x+o.w/2>=p.x+p.w/2, s=right?1:-1, ex=right?p.x+p.w:p.x;
      var ys=rel.sides[sd[0]].map(function(a){return _anchorY(p,a.key);});
      J[sd[0]]={x:ex+s*STUB, y:ys.reduce(function(t,v){return t+v;},0)/ys.length, ex:ex, s:s};
    });
    rel.branches.forEach(function(b){
      var j=J[b.side], p=b.side==='l'?fp:tp, y=_anchorY(p,b.anchor.key);
      var bd='M'+_f(j.ex)+' '+_f(y)+'H'+_f(j.ex+j.s*ELBOW)+'L'+_f(j.x)+' '+_f(j.y);
      b.el.setAttribute('d',bd); d.push(bd);
      if(b.anchor.cart) b.el.setAttribute('stroke-dasharray','5 3'); else b.el.removeAttribute('stroke-dasharray');
    });
    var a=J.l, z=J.r, mid, td;
    if(rel.fid===rel.tid){
      // A self-join loops outside its own box, so its trunk is never drawn over the box.
      var lx=a.ex+a.s*(STUB+LOOP);
      td='M'+_f(a.x)+' '+_f(a.y)+'H'+_f(lx)+'V'+_f(z.y)+'H'+_f(z.x);
      mid={x:lx, y:(a.y+z.y)/2};
    } else {
      td='M'+_f(a.x)+' '+_f(a.y)+'L'+_f(z.x)+' '+_f(z.y);
      mid={x:(_f(a.x)+_f(z.x))/2, y:(_f(a.y)+_f(z.y))/2};
    }
    rel.trunk.setAttribute('d',td);
    rel.hit.setAttribute('d',[td].concat(d).join(''));
    var allCart=rel.pairs.length&&rel.pairs.every(function(q){return q.op==='CartesianProduct';});
    if(allCart) rel.trunk.setAttribute('stroke-dasharray','5 3'); else rel.trunk.removeAttribute('stroke-dasharray');
    if(rel.op){
      rel.op.setAttribute('transform','translate('+mid.x+','+mid.y+')');
      // Read in screen order: a relationship whose XML-left box comes second shows mirrored operators. Mixed
      // operators are all shown, in condition order, never one standing for the rest.
      var mirrored=_readsReversed(fp,tp), labels=[];
      rel.pairs.forEach(function(q){
        if(!q.op)return;
        var l=_OP_LABEL[mirrored?(_OP_MIRROR[q.op]||q.op):q.op]||q.op;
        if(labels.indexOf(l)<0)labels.push(l);
      });
      var text=labels.join(' '), w=Math.max(14,text.length*5.6+8);
      rel.op.querySelector('text').textContent=text;
      var r=rel.op.querySelector('rect'); r.setAttribute('x',-w/2); r.setAttribute('width',w);
      rel.op.classList.toggle('rg-op-mixed',labels.length>1);
    }
  }
}

// ── Apply a posMap {id:{x,y,w,h}} to the live SVG ────────────────────────────
window._rgApply = function(svgEl, posMap, layout, notePos) {
  var nodeEls=svgEl._rgNodeEls, edgeEls=svgEl._rgEdgeEls;
  if(!nodeEls||!edgeEls) return;
  svgEl._rgPos = posMap;
  svgEl._rgMode = layout;
  var fm = layout==='fm';
  if(svgEl._rgNoteEls) svgEl._rgNoteEls.style.display = fm ? '' : 'none';
  if(notePos){svgEl._rgNotePos=notePos;notePos.forEach(function(_,i){_placeNote(svgEl,i);});}
  for (var [id,g] of nodeEls) {
    _placeNode(svgEl,id);
    var p=posMap[id]; if(!p)continue;
    var s=g._rg, rect=g.querySelector('.rg-nr'), txt=g.querySelector('.rg-nt'), hdr=g.querySelector('.rg-hdr');
    rect.setAttribute('width',p.w); rect.setAttribute('height',p.h);
    var headH=Math.min(HDR_H,p.h);
    if(fm){
      rect.setAttribute('fill',s.bodyHex); rect.setAttribute('fill-opacity',s.alpha); rect.setAttribute('stroke',s.edgeHex); rect.setAttribute('stroke-width','1');
      hdr.style.display=''; hdr.setAttribute('height',headH); hdr.setAttribute('width',p.w); hdr.setAttribute('fill',s.srcHex); hdr.setAttribute('fill-opacity',s.alpha);
      txt.setAttribute('x',6); txt.setAttribute('y',headH/2); txt.setAttribute('text-anchor','start'); txt.setAttribute('fill',s.headInk); txt.setAttribute('font-weight','600');
    } else {
      rect.setAttribute('fill',s.flat); rect.setAttribute('fill-opacity','1'); rect.setAttribute('stroke',s.hub?'#f0a000':'#888'); rect.setAttribute('stroke-width',s.hub?'2.5':'1');
      hdr.style.display='none';
      txt.setAttribute('x',p.w/2); txt.setAttribute('y',p.h/2); txt.setAttribute('text-anchor','middle'); txt.setAttribute('fill',s.flatInk); txt.removeAttribute('font-weight');
    }
    g.querySelectorAll('.rg-rows,.rg-pane,.rg-divider').forEach(function(x){x.style.display=fm?'':'none';});
    var cpr=document.getElementById('rgcpr'+id);
    if(cpr){cpr.setAttribute('width',Math.max(0,p.w-4));cpr.setAttribute('height',Math.max(0,p.h-4));}
    var bk=g.querySelector('.rg-ext'); if(bk) bk.setAttribute('x',p.w-14);
    var bt=g.querySelector('.rg-ext-t'); if(bt) bt.setAttribute('x',p.w-8);
  }
  _placeEdges(svgEl);
};
window._rgBounds = function(svgEl) {
  return _bounds(svgEl._rgPos||{}, svgEl._rgMode==='fm' ? svgEl._rgNotePos : null);
};

// ── Fit viewBox (also syncs the pan/zoom vb object) ──────────────────────────
window._rgFit = function(svgEl, bounds) {
  svgEl._rgFitVb = bounds;
  var v=svgEl._rgVb; if(!v)return;
  v.x=bounds.x; v.y=bounds.y; v.w=bounds.w; v.h=bounds.h;
  svgEl.setAttribute('viewBox',v.x+' '+v.y+' '+v.w+' '+v.h);
  _fillElement(svgEl);
};

// ── Layout: As Built (FM CoordRect), with this session's temporary moves on top ──
window._rgLayoutFM = function(gd, moved) {
  var pos={};
  for (var n of gd.nodes) if (n.x !== null && n.x !== undefined) {
    var m=moved&&moved[n.id];
    pos[n.id]={x:m?m.x:n.x,y:m?m.y:n.y,w:n.w,h:n.h};
  }
  // Copies: a drag, resize or toggle writes to these, and appData must keep the captured arrangement.
  var notes=(gd.notes||[]).map(function(n,i){
    var m=(moved&&moved['note:'+i])||{};
    function at(k){return m[k]!==undefined?m[k]:n[k];}
    return {x:at('x'),y:at('y'),w:at('w'),h:at('h'),collapsed:!!at('collapsed')};
  });
  return {positions:pos, notes:notes, bounds:_bounds(pos, notes)};
};

// ── Layout: By Table (cluster grid) ──────────────────────────────────────────
window._rgLayoutCluster = function(gd) {
  var NPAD=16,GX=10,GY=8,HDR=22,CGAP=30,NW=CL_W,NH=CL_H,ROW_MAX=2400;
  var groups={};
  for (var n of gd.nodes){if(!groups[n.base_table])groups[n.base_table]=[];groups[n.base_table].push(n);}
  var sorted=Object.entries(groups).sort((a,b)=>b[1].length-a[1].length);
  var cx=0,cy=0,rowH=0,pos={},ovData=[];
  for (var [bt,bNodes] of sorted) {
    var cols=Math.max(1,Math.min(5,Math.ceil(Math.sqrt(bNodes.length))));
    var rows=Math.ceil(bNodes.length/cols);
    var cw=cols*NW+(cols-1)*GX+NPAD*2;
    var ch=rows*NH+(rows-1)*GY+NPAD*2+HDR;
    if(cx>0&&cx+cw>ROW_MAX){cx=0;cy+=rowH+CGAP;rowH=0;}
    ovData.push({x:cx,y:cy,w:cw,h:ch,label:bt,color:bNodes[0].color});
    for(var i=0;i<bNodes.length;i++){
      pos[bNodes[i].id]={x:cx+NPAD+(i%cols)*(NW+GX),y:cy+HDR+NPAD+Math.floor(i/cols)*(NH+GY),w:NW,h:NH};
    }
    cx+=cw+CGAP; rowH=Math.max(rowH,ch);
  }
  return {positions:pos, bounds:_bounds(pos), ovData:ovData};
};

window._rgBuildOverlay = function(svgEl, ovData) {
  var ov=svgEl._rgOv; if(!ov)return;
  ov.innerHTML='';
  for (var d of ovData) {
    var bg=_el('rect',{x:d.x,y:d.y,width:d.w,height:d.h,fill:d.color,
      'fill-opacity':'0.07',stroke:d.color,'stroke-opacity':'0.25','stroke-width':'1',rx:6});
    var lbl=_el('text',{x:d.x+8,y:d.y+15,
      'font-size':'11','font-weight':'600','font-family':'SFMono-Regular,Consolas,monospace',
      'pointer-events':'none'});
    lbl.style.fill='var(--text-2)';
    lbl.textContent=d.label;
    ov.appendChild(bg); ov.appendChild(lbl);
  }
};
window._rgClearOverlay = function(svgEl){var ov=svgEl._rgOv;if(ov)ov.innerHTML='';};

// ── Selection: emphasis only; positions never change ─────────────────────────
window._rgSelect = function(svgEl, sel) {
  var nodeEls=svgEl._rgNodeEls, edgeEls=svgEl._rgEdgeEls;
  if(!nodeEls||!edgeEls) return;
  for (var [id,g] of nodeEls) {
    g.classList.toggle('rg-sel', !!sel && sel.main.includes(id));
    g.classList.toggle('rg-near', !!sel && !sel.main.includes(id) && sel.near.includes(id));
    if (sel && sel.main.includes(id)) g.setAttribute('aria-current','true'); else g.removeAttribute('aria-current');
  }
  // Lines carry the emphasis: boxes and notes stay solid in their source colors, whatever is selected.
  for (var ln of edgeEls.concat(svgEl._rgOpEls||[])) {
    var item=ln.getAttribute('data-item');
    var on=!!sel && sel.edges.includes(item);
    ln.classList.toggle('rg-on', on);
    ln.classList.toggle('rg-picked', !!sel && sel.edge===item);
    ln.classList.toggle('rg-quiet', !!sel && !on);
  }
};

// A view with the element's own shape, same scale and same center, so nothing is letterboxed.
function _fillElement(svgEl) {
  var v=svgEl._rgVb, r=svgEl.getBoundingClientRect();
  if(!v||!r.width||!r.height||!v.w||!v.h)return;
  var s=Math.min(r.width/v.w,r.height/v.h), cx=v.x+v.w/2, cy=v.y+v.h/2;
  v.w=r.width/s; v.h=r.height/s; v.x=cx-v.w/2; v.y=cy-v.h/2;
  svgEl._rgSize={w:r.width,h:r.height};
  svgEl.setAttribute('viewBox',v.x+' '+v.y+' '+v.w+' '+v.h);
}

// ── Focus: a readable subject at a fixed scale, whatever the size of the whole map ──
// The policy for several boxes (a relationship's two ends): center on them all if they fit at this scale;
// otherwise center on the first, so the subject stays readable and the far end is one pan or click away.
// A box bigger than the view shows its top-left corner rather than its empty middle.
window._rgFocus = function(svgEl, ids) {
  var pos=svgEl._rgPos, v=svgEl._rgVb; if(!pos||!v) return false;
  if(svgEl._rgHideTip)svgEl._rgHideTip();
  var boxes=ids.map(function(id){return pos[id];}).filter(Boolean);
  if(!boxes.length) return false;
  var r=svgEl.getBoundingClientRect(); if(!r.width||!r.height) return false;
  var w=r.width/READABLE, h=r.height/READABLE, margin=24/READABLE;
  function span(list){
    var x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
    list.forEach(function(p){x0=Math.min(x0,p.x);y0=Math.min(y0,p.y);x1=Math.max(x1,p.x+p.w);y1=Math.max(y1,p.y+p.h);});
    return {x0:x0,y0:y0,x1:x1,y1:y1};
  }
  var all=span(boxes);
  var fits=all.x1-all.x0+2*margin<=w&&all.y1-all.y0+2*margin<=h;
  var b=fits?all:span([boxes[0]]);
  v.w=w; v.h=h;
  v.x=b.x1-b.x0+2*margin>w?b.x0-margin:(b.x0+b.x1)/2-w/2;
  v.y=b.y1-b.y0+2*margin>h?b.y0-margin:(b.y0+b.y1)/2-h/2;
  svgEl._rgSize={w:r.width,h:r.height};
  svgEl.setAttribute('viewBox',v.x+' '+v.y+' '+v.w+' '+v.h);
  return true;
};
// Where a map with nothing selected opens: its top-left box, the same one every time.
window._rgStartOfMap = function(svgEl) {
  var pos=svgEl._rgPos||{}, best=null, at=1e18;
  for (var id in pos) { var d=pos[id].x+pos[id].y; if(d<at){at=d;best=id;} }
  return best?[best]:[];
};
window._rgSetView = function(svgEl, view) {
  var v=svgEl._rgVb; if(!v||!view)return;
  if(svgEl._rgHideTip)svgEl._rgHideTip();
  v.x=view.x; v.y=view.y; v.w=view.w; v.h=view.h;
  svgEl.setAttribute('viewBox',v.x+' '+v.y+' '+v.w+' '+v.h);
  _fillElement(svgEl);
};

})(); // end graph module
