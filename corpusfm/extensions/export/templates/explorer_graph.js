(function() {
var NS = 'http://www.w3.org/2000/svg';
var CL_W = 150, CL_H = 28;  // normalized node size for the By Table view
var READABLE = 0.8;  // screen pixels per map unit when first centering; node labels are 9 units high

function _el(tag, attrs) {
  var e = document.createElementNS(NS, tag);
  for (var k in attrs) e.setAttribute(k, attrs[k]);
  return e;
}
function _bounds(posMap) {
  var pad=40, x0=1e9, y0=1e9, x1=-1e9, y1=-1e9;
  for (var id in posMap) {
    var p=posMap[id];
    if(p.x<x0)x0=p.x; if(p.y<y0)y0=p.y;
    if(p.x+p.w>x1)x1=p.x+p.w; if(p.y+p.h>y1)y1=p.y+p.h;
  }
  return {x:x0-pad, y:y0-pad, w:x1-x0+2*pad, h:y1-y0+2*pad};
}

// ── Build SVG structure for one file (positions applied separately) ───────────
window._rgBuild = function(gd, svgEl, navigateFn) {
  if (svgEl._rgCleanup) svgEl._rgCleanup();
  svgEl.innerHTML = '';
  var nodes=gd.nodes, edges=gd.edges;
  var isLight = (document.getElementById('fmc-root')||{}).dataset?.theme === 'light';
  var nodeTxt = isLight ? '#111' : '#fff';
  var cartStroke = isLight ? '#aaa' : '#667';

  var defs = _el('defs',{});
  for (var n of nodes) {
    var cp = _el('clipPath',{id:'rgcp'+n.id});
    var cpr = _el('rect',{id:'rgcpr'+n.id, x:2, y:2,
      width:Math.max(0,(n.w||0)-4), height:Math.max(0,(n.h||0)-4)});
    cp.appendChild(cpr); defs.appendChild(cp);
  }
  svgEl.appendChild(defs);

  // Overlay group — cluster backgrounds sit here, behind edges
  var ov = _el('g',{'class':'rg-ov'});
  svgEl.appendChild(ov);

  // Edges
  var eg = _el('g',{'class':'rg-edges'});
  for (var e of edges) {
    var isCart = e.type==='cartesian';
    var ln = _el('line',{
      'data-fid':e.from_id, 'data-tid':e.to_id,
      stroke:isCart?cartStroke:'#4e9eff', 'stroke-width':'1.5',
      'stroke-opacity':isCart?'0.4':'0.6',
      'data-item':e.item||''
    });
    if (isCart) ln.setAttribute('stroke-dasharray','5 3');
    eg.appendChild(ln);
  }
  svgEl.appendChild(eg);

  // A hairline can't be clicked, focused or tapped, so each relationship gets a wide invisible target.
  var hg = _el('g',{'class':'rg-hits'});
  var nameOf = {}; for (var n of nodes) nameOf[n.id]=n.name;
  for (var e of edges) {
    var hit = _el('line',{'class':'rg-hit','data-fid':e.from_id,'data-tid':e.to_id,'data-item':e.item||'',
      'data-preds':JSON.stringify(e.predicates||[]),tabindex:'0',role:'button',
      'aria-label':'Relationship: '+(nameOf[e.from_id]||'?')+' to '+(nameOf[e.to_id]||'?')});
    hg.appendChild(hit);
  }
  svgEl.appendChild(hg);

  // Nodes
  var ng = _el('g',{'class':'rg-nodes'});
  for (var n of nodes) {
    var deg = n.degree||0, isHub = deg >= 5;  // relational hub: many relationships meet here
    var g = _el('g',{'data-nid':n.id,'data-to-name':n.name,'data-item':n.item||'',
      'data-bt':n.base_table||'','data-ext':n.external?'1':'','data-deg':deg,
      tabindex:'0',role:'button','aria-label':'Occurrence: '+n.name});
    g.style.cursor='pointer';
    var ttl = _el('title',{}); ttl.textContent = n.name + ' · ' + deg + ' relationship' + (deg===1?'':'s');
    g.appendChild(ttl);
    var rect = _el('rect',{'class':'rg-nr', x:0, y:0, width:n.w||0, height:n.h||0,
      fill:n.color,'fill-opacity':'0.9',
      stroke:isHub?'#f0a000':'#888','stroke-width':isHub?'2.5':'1',rx:3});
    var txt = _el('text',{'class':'rg-nt', x:(n.w||0)/2, y:(n.h||0)/2,
      'text-anchor':'middle','dominant-baseline':'middle',fill:nodeTxt,
      'font-size':'9','font-family':'SFMono-Regular,Consolas,monospace',
      'clip-path':'url(#rgcp'+n.id+')','pointer-events':'none'});
    txt.textContent = n.name;
    g.appendChild(rect); g.appendChild(txt);
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
  svgEl._rgOv = ov;

  // ── Pan / zoom ───────────────────────────────────────────────────────────────
  var vb={x:0,y:0,w:1000,h:1000}, pan=false, px=0, py=0, sx=0, sy=0, dragged=false;
  svgEl._rgVb = vb;
  function setVb(){svgEl.setAttribute('viewBox',vb.x+' '+vb.y+' '+vb.w+' '+vb.h);}
  function onDown(e){if(e.button!==0)return;pan=true;dragged=false;px=sx=e.clientX;py=sy=e.clientY;svgEl.style.cursor='grabbing';e.preventDefault();}
  function onMove(e){
    if(!pan)return;
    if(Math.abs(e.clientX-sx)+Math.abs(e.clientY-sy)>4)dragged=true;
    var r=svgEl.getBoundingClientRect();if(!r.width||!r.height)return;
    vb.x-=(e.clientX-px)*(vb.w/r.width); vb.y-=(e.clientY-py)*(vb.h/r.height);
    px=e.clientX;py=e.clientY;setVb();
  }
  function onUp(){if(pan){pan=false;svgEl.style.cursor='grab';}}
  function onWheel(e){
    e.preventDefault();
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
  var tip=document.getElementById('graph-tooltip');
  function showTip(e,h){if(!tip)return;tip.innerHTML=h;tip.style.display='block';
    tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY-8)+'px';}
  function hideTip(){if(tip)tip.style.display='none';}
  function onNMove(e){
    var g=e.target.closest&&e.target.closest('[data-to-name]');if(!g)return;
    var nm=g.getAttribute('data-to-name'),bt=g.getAttribute('data-bt'),ext=g.getAttribute('data-ext');
    showTip(e,'<strong>'+nm+'</strong>'+(bt&&bt!==nm?'<br>'+bt:'')+(ext==='1'?'<br><span style="color:#f0a000">external</span>':''));
  }
  function onEMove(e){
    if(e.target.tagName.toLowerCase()!=='line')return;
    var preds=[];try{preds=JSON.parse(e.target.getAttribute('data-preds')||'[]');}catch(_){}
    showTip(e,preds.length?preds.map(p=>'<div>'+p+'</div>').join(''):'(no predicates)');
  }
  ng.addEventListener('mousemove',onNMove); ng.addEventListener('mouseleave',hideTip);
  hg.addEventListener('mousemove',onEMove); hg.addEventListener('mouseleave',hideTip);
  function targetOf(e){
    var t=e.target.closest&&e.target.closest('[data-item]');
    if(!t||!t.getAttribute('data-item'))return null;
    return {section:t.hasAttribute('data-nid')?'TableOccurrenceCatalog':'RelationshipCatalog',item:t.getAttribute('data-item')};
  }
  function onPick(e){
    if(dragged){dragged=false;return;}
    var t=targetOf(e); if(t){hideTip();navigateFn(t.section,t.item);}
  }
  function onKey(e){
    if(e.key!=='Enter'&&e.key!==' ')return;
    var t=targetOf(e); if(t){e.preventDefault();navigateFn(t.section,t.item);}
  }
  ng.addEventListener('click',onPick); hg.addEventListener('click',onPick);
  ng.addEventListener('keydown',onKey); hg.addEventListener('keydown',onKey);

  svgEl._rgCleanup = function(){
    svgEl.removeEventListener('pointerdown',onDown);
    document.removeEventListener('pointermove',onMove);
    document.removeEventListener('pointerup',onUp);
    document.removeEventListener('pointercancel',onUp);
    svgEl.removeEventListener('wheel',onWheel);
    ng.removeEventListener('mousemove',onNMove); ng.removeEventListener('mouseleave',hideTip);
    hg.removeEventListener('mousemove',onEMove); hg.removeEventListener('mouseleave',hideTip);
  };
};

// ── Apply a posMap {id:{x,y,w,h}} to the live SVG ────────────────────────────
window._rgApply = function(svgEl, posMap) {
  var nodeEls=svgEl._rgNodeEls, edgeEls=svgEl._rgEdgeEls;
  if(!nodeEls||!edgeEls) return;
  svgEl._rgPos = posMap;
  for (var [id,g] of nodeEls) {
    var p=posMap[id];
    g.style.display = p ? '' : 'none';   // no captured position: off the map, never placed by guesswork
    if(g.tabIndex!==undefined) g.setAttribute('tabindex', p ? '0' : '-1');
    if(!p)continue;
    g.setAttribute('transform','translate('+p.x+','+p.y+')');
    var rect=g.querySelector('.rg-nr');
    if(rect){rect.setAttribute('width',p.w);rect.setAttribute('height',p.h);}
    var txt=g.querySelector('.rg-nt');
    if(txt){txt.setAttribute('x',p.w/2);txt.setAttribute('y',p.h/2);}
    var cpr=document.getElementById('rgcpr'+id);
    if(cpr){cpr.setAttribute('width',Math.max(0,p.w-4));cpr.setAttribute('height',Math.max(0,p.h-4));}
    var bk=g.querySelector('.rg-ext'); if(bk) bk.setAttribute('x',p.w-14);
    var bt=g.querySelector('.rg-ext-t'); if(bt) bt.setAttribute('x',p.w-8);
  }
  for (var ln of edgeEls) {
    var fid=ln.getAttribute('data-fid'),tid=ln.getAttribute('data-tid');
    var fp=posMap[fid],tp=posMap[tid];
    ln.style.display = (fp&&tp) ? '' : 'none';
    if(!fp||!tp)continue;
    ln.setAttribute('x1',fp.x+fp.w/2); ln.setAttribute('y1',fp.y+fp.h/2);
    ln.setAttribute('x2',tp.x+tp.w/2); ln.setAttribute('y2',tp.y+tp.h/2);
  }
};

// ── Fit viewBox (also syncs the pan/zoom vb object) ──────────────────────────
window._rgFit = function(svgEl, bounds) {
  svgEl._rgFitVb = bounds;
  var v=svgEl._rgVb; if(!v)return;
  v.x=bounds.x; v.y=bounds.y; v.w=bounds.w; v.h=bounds.h;
  svgEl.setAttribute('viewBox',v.x+' '+v.y+' '+v.w+' '+v.h);
};

// ── Layout: As Built (FM CoordRect) ──────────────────────────────────────────
window._rgLayoutFM = function(gd) {
  var pos={};
  for (var n of gd.nodes) if (n.x !== null && n.x !== undefined) pos[n.id]={x:n.x,y:n.y,w:n.w,h:n.h};
  return {positions:pos, bounds:_bounds(pos)};
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
    g.classList.toggle('rg-dim', !!sel && !sel.main.includes(id) && !sel.near.includes(id));
    if (sel && sel.main.includes(id)) g.setAttribute('aria-current','true'); else g.removeAttribute('aria-current');
  }
  for (var ln of edgeEls) {
    var item=ln.getAttribute('data-item');
    var on=!!sel && sel.edges.includes(item);
    ln.classList.toggle('rg-on', on);
    ln.classList.toggle('rg-picked', !!sel && sel.edge===item);
    ln.classList.toggle('rg-dim', !!sel && !on);
  }
};

// ── Center ids in the view by moving the viewBox; widen it only if they don't fit ──
// readable: the view is still the whole-map fit, which on a large file makes every label too small to read.
window._rgCenter = function(svgEl, ids, readable) {
  var pos=svgEl._rgPos, v=svgEl._rgVb; if(!pos||!v) return false;
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
  v.x=view.x; v.y=view.y; v.w=view.w; v.h=view.h;
  svgEl.setAttribute('viewBox',v.x+' '+v.y+' '+v.w+' '+v.h);
};

})(); // end graph module
