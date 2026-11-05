(function() {
var NS = 'http://www.w3.org/2000/svg';
var CL_W = 150, CL_H = 28;  // normalized node size for the By Table view
var READABLE = 0.8;  // screen pixels per map unit when first centering; node labels are 9 units high
// As Built occurrence anatomy. These match the sizing rule in explorer.py: 26 + 12 per row.
var HDR_H = 18, ROWS_TOP = 22, ROW_H = 12, PANE_GAP = 6;
var NOTE_COLLAPSED_H = 18;  // packet 1448: the screenshot-pair estimate; the XML keeps only the full bounds

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

  // Notes first: captured annotations sit behind everything, later ones over earlier ones.
  var nl = _el('g',{'class':'rg-notes'});
  (gd.notes||[]).forEach(function(note,index){
    var fo=_el('foreignObject',{'class':'rg-note','data-note':index,x:note.x,y:note.y,width:note.w,height:note.collapsed?NOTE_COLLAPSED_H:note.h});
    var d=document.createElementNS('http://www.w3.org/1999/xhtml','div');
    d.className='rg-note-body'+(note.collapsed?' rg-note-collapsed':'');
    d.textContent=note.text;
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

  // One line per condition, so each can meet its own field rows. By Table draws the first only.
  var eg = _el('g',{'class':'rg-edges'}), hg = _el('g',{'class':'rg-hits'}), og = _el('g',{'class':'rg-ops'});
  var nameOf = {}; for (var n of nodes) nameOf[n.id]=n.name;
  for (var e of edges) {
    var pairs = (e.pairs&&e.pairs.length) ? e.pairs : [{lf:null,rf:null,op:null}];
    pairs.forEach(function(pair,pi){
      var meta = {'data-cart':pair.op==='CartesianProduct'?'1':'','data-edge-cart':e.type==='cartesian'?'1':'','data-fid':e.from_id,'data-tid':e.to_id,'data-item':e.item||'','data-lf':pair.lf||'','data-rf':pair.rf||'','data-pair':pi,'data-op':pair.op||''};
      var ln = _el('line',Object.assign({},meta));
      eg.appendChild(ln);
      var hit = _el('line',Object.assign({'class':'rg-hit'},meta));
      if (pi===0) { hit.setAttribute('tabindex','0'); hit.setAttribute('role','button');
        hit.setAttribute('aria-label','Relationship: '+(nameOf[e.from_id]||'?')+' to '+(nameOf[e.to_id]||'?')); }
      hg.appendChild(hit);
      if (pair.op) {
        var op=_el('g',Object.assign({'class':'rg-op'},meta));
        op.appendChild(_el('rect',{x:-7,y:-6,width:14,height:12,rx:2}));
        var t=_el('text',{'text-anchor':'middle','dominant-baseline':'central','font-size':'9'});
        op.appendChild(t); og.appendChild(op);
      }
    });
  }
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

  // Index node elements by id
  svgEl._rgNodeEls = new Map(Array.from(ng.children).map(g=>[g.getAttribute('data-nid'),g]));
  svgEl._rgEdgeEls = Array.from(eg.children).concat(Array.from(hg.children));
  svgEl._rgOpEls = Array.from(og.children);
  svgEl._rgNodeById = nodeById;
  svgEl._rgNoteEls = nl;
  svgEl._rgNotePos = gd.notes||[];
  svgEl._rgOv = ov;
  svgEl._rgMode = null;

  // ── Pan, node drag, pane scroll, zoom ────────────────────────────────────────
  var vb={x:0,y:0,w:1000,h:1000}, mode=null, px=0, py=0, sx=0, sy=0, dragged=false, dragId=null, dragPane=null, dragNote=null;
  svgEl._rgVb = vb;
  function setVb(){svgEl.setAttribute('viewBox',vb.x+' '+vb.y+' '+vb.w+' '+vb.h);}
  function scrollerAt(t){
    var p=t.closest&&t.closest('.rg-pane');
    if(p&&p._rgPane&&p._rgPane.max>0)return {pane:p._rgPane};
    var d=t.closest&&t.closest('.rg-note-body');
    if(d&&d.scrollHeight>d.clientHeight)return {note:d};
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
    // On touch a long note scrolls, so its first line is where it can be picked up, like an occurrence's header.
    var noteScrolls=note&&e.pointerType==='touch'&&scrollerAt(e.target)&&
      e.clientY-note.getBoundingClientRect().top>NOTE_COLLAPSED_H*svgEl.getScreenCTM().d;
    var scroller=e.pointerType==='touch'&&(!note||noteScrolls)?scrollerAt(e.target):null;
    if(scroller){mode='scroll';dragPane=scroller;}
    else if(note){mode='note';dragNote=+note.getAttribute('data-note');}
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
    if((mode==='node'||mode==='note')&&!dragged)return;
    var dx=e.clientX-px, dy=e.clientY-py; px=e.clientX;py=e.clientY;
    if(mode==='scroll'){scrollBy(dragPane,-dy/svgEl.getScreenCTM().d);return;}
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
    vb.x-=dx*(vb.w/r.width); vb.y-=dy*(vb.h/r.height);
    setVb();
  }
  function onUp(){if(mode){mode=null;dragId=null;dragPane=null;dragNote=null;svgEl.style.cursor='grab';}}
  function onWheel(e){
    e.preventDefault();
    hideTip();
    var s=scrollerAt(e.target);
    if(s&&scrollBy(s,e.deltaY))return;
    var f=e.deltaY>0?1.15:1/1.15;
    var r=svgEl.getBoundingClientRect();if(!r.width||!r.height)return;
    var wx=vb.x+(e.clientX-r.left)/r.width*vb.w;
    var wy=vb.y+(e.clientY-r.top)/r.height*vb.h;
    vb.w*=f;vb.h*=f;
    vb.x=wx-(e.clientX-r.left)/r.width*vb.w;
    vb.y=wy-(e.clientY-r.top)/r.height*vb.h;
    setVb();
  }
  svgEl.addEventListener('pointerdown',onDown);
  document.addEventListener('pointermove',onMove);
  document.addEventListener('pointerup',onUp);
  document.addEventListener('pointercancel',onUp);
  svgEl.addEventListener('wheel',onWheel,{passive:false});

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
    if(lines.length>MAX_LINES)lines=lines.slice(0,MAX_LINES-1).concat('+'+(lines.length-MAX_LINES+1)+' more, listed on the card');
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
    hideTip();
  };
};

function _placeNote(svgEl, index) {
  var fo=svgEl._rgNoteEls.children[index], p=svgEl._rgNotePos[index];
  fo.setAttribute('x',p.x); fo.setAttribute('y',p.y);
}

function _placeNode(svgEl, id) {
  var g=svgEl._rgNodeEls.get(id), p=svgEl._rgPos[id];
  g.style.display = p ? '' : 'none';   // no captured position: off the map, never placed by guesswork
  g.setAttribute('tabindex', p ? '0' : '-1');
  if(!p)return;
  g.setAttribute('transform','translate('+p.x+','+p.y+')');
}

// Where a condition meets an occurrence: its displayed field row, or the header when no row can honestly be
// named, since the header can never be mistaken for a field. As Built only; By Table keeps center-to-center lines.
function _attach(svgEl, nodeId, fieldId, other) {
  var p=svgEl._rgPos[nodeId];
  var right = other.x+other.w/2 >= p.x+p.w/2;
  var i = (svgEl._rgRowIndex[nodeId]||{})[fieldId];
  var y = i!==undefined ? p.y+ROWS_TOP+ROW_H*i+ROW_H/2 : p.y+Math.min(HDR_H,p.h)/2;
  return {x:right?p.x+p.w:p.x, y:y};
}
// Whether the XML-left box is the one read second: by box centers, as _attach picks sides; top to bottom if stacked.
function _readsReversed(fp, tp) {
  var a=fp.x+fp.w/2, b=tp.x+tp.w/2;
  return a!==b ? a>b : fp.y>tp.y;
}
var _OP_LABEL={Equal:'=',NotEqual:'≠',Less:'<',Greater:'>',LessOrEqual:'≤',GreaterOrEqual:'≥',CartesianProduct:'×'};
var _OP_MIRROR={Less:'Greater',Greater:'Less',LessOrEqual:'GreaterOrEqual',GreaterOrEqual:'LessOrEqual'};
function _placeEdges(svgEl) {
  var pos=svgEl._rgPos, fm=svgEl._rgMode==='fm', edgeEls=svgEl._rgEdgeEls;
  var geometry={};
  for (var ln of edgeEls) {
    var fid=ln.getAttribute('data-fid'),tid=ln.getAttribute('data-tid');
    var fp=pos[fid],tp=pos[tid],pi=+ln.getAttribute('data-pair');
    var shown = !!(fp&&tp) && (fm || pi===0);
    ln.style.display = shown ? '' : 'none';
    if(!shown)continue;
    var a,b;
    if(fm){a=_attach(svgEl,fid,ln.getAttribute('data-lf'),tp);b=_attach(svgEl,tid,ln.getAttribute('data-rf'),fp);}
    else{a={x:fp.x+fp.w/2,y:fp.y+fp.h/2};b={x:tp.x+tp.w/2,y:tp.y+tp.h/2};}
    ln.setAttribute('x1',a.x); ln.setAttribute('y1',a.y);
    ln.setAttribute('x2',b.x); ln.setAttribute('y2',b.y);
    var dashed = fm ? ln.getAttribute('data-cart') : ln.getAttribute('data-edge-cart');
    if (dashed) ln.setAttribute('stroke-dasharray','5 3'); else ln.removeAttribute('stroke-dasharray');
    geometry[ln.getAttribute('data-item')+'#'+pi]=[a,b];
  }
  for (var op of (svgEl._rgOpEls||[])) {
    var g=geometry[op.getAttribute('data-item')+'#'+op.getAttribute('data-pair')];
    op.style.display = (fm&&g) ? '' : 'none';
    if(!fm||!g)continue;
    op.setAttribute('transform','translate('+((g[0].x+g[1].x)/2)+','+((g[0].y+g[1].y)/2)+')');
    // Read in screen order: a line whose XML-left box comes second shows the mirrored operator.
    var raw=op.getAttribute('data-op'), mirrored=_readsReversed(pos[op.getAttribute('data-fid')],pos[op.getAttribute('data-tid')]);
    op.querySelector('text').textContent=_OP_LABEL[mirrored?(_OP_MIRROR[raw]||raw):raw]||raw;
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
};

// ── Layout: As Built (FM CoordRect), with this session's temporary moves on top ──
window._rgLayoutFM = function(gd, moved) {
  var pos={};
  for (var n of gd.nodes) if (n.x !== null && n.x !== undefined) {
    var m=moved&&moved[n.id];
    pos[n.id]={x:m?m.x:n.x,y:m?m.y:n.y,w:n.w,h:n.h};
  }
  // Copies: a drag writes to these, and appData must keep the captured arrangement.
  var notes=(gd.notes||[]).map(function(n,i){
    var m=moved&&moved['note:'+i];
    return {x:m?m.x:n.x,y:m?m.y:n.y,w:n.w,h:n.h,collapsed:n.collapsed};
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

// ── Center ids in the view by moving the viewBox; widen it only if they don't fit ──
// readable: the view is still the whole-map fit, which on a large file makes every label too small to read.
window._rgCenter = function(svgEl, ids, readable) {
  var pos=svgEl._rgPos, v=svgEl._rgVb; if(!pos||!v) return false;
  if(svgEl._rgHideTip)svgEl._rgHideTip();
  var x0=1e9,y0=1e9,x1=-1e9,y1=-1e9,found=false;
  for (var id of ids) {
    var p=pos[id]; if(!p)continue; found=true;
    if(p.x<x0)x0=p.x; if(p.y<y0)y0=p.y;
    if(p.x+p.w>x1)x1=p.x+p.w; if(p.y+p.h>y1)y1=p.y+p.h;
  }
  if(!found) return false;
  var r=svgEl.getBoundingClientRect();
  if(readable&&r.width&&r.height&&Math.min(r.width/v.w,r.height/v.h)<READABLE){v.w=r.width/READABLE;v.h=r.height/READABLE;}
  var scale=Math.max(1,(x1-x0)*1.25/v.w,(y1-y0)*1.25/v.h);
  v.w*=scale; v.h*=scale;
  v.x=(x0+x1)/2-v.w/2; v.y=(y0+y1)/2-v.h/2;
  svgEl.setAttribute('viewBox',v.x+' '+v.y+' '+v.w+' '+v.h);
  return true;
};
window._rgSetView = function(svgEl, view) {
  var v=svgEl._rgVb; if(!v||!view)return;
  if(svgEl._rgHideTip)svgEl._rgHideTip();
  v.x=view.x; v.y=view.y; v.w=view.w; v.h=view.h;
  svgEl.setAttribute('viewBox',v.x+' '+v.y+' '+v.w+' '+v.h);
};

})(); // end graph module
