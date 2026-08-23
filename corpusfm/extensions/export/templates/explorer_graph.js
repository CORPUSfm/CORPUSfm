(function() {
var NS = 'http://www.w3.org/2000/svg';
var CL_W = 150, CL_H = 28;  // normalized node size for Cluster / Force views

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
      width:Math.max(0,n.w-4), height:Math.max(0,n.h-4)});
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
      'data-preds':JSON.stringify(e.predicates||[])
    });
    if (isCart) ln.setAttribute('stroke-dasharray','5 3');
    eg.appendChild(ln);
  }
  svgEl.appendChild(eg);

  // Nodes
  var ng = _el('g',{'class':'rg-nodes'});
  for (var n of nodes) {
    var deg = n.degree||0, isHub = deg >= 5;  // relational hub: many relationships meet here
    var g = _el('g',{'data-nid':n.id,'data-to-name':n.name,
      'data-bt':n.base_table||'','data-ext':n.external?'1':'','data-deg':deg});
    g.style.cursor='pointer';
    var ttl = _el('title',{}); ttl.textContent = n.name + ' · ' + deg + ' relationship' + (deg===1?'':'s');
    g.appendChild(ttl);
    var rect = _el('rect',{'class':'rg-nr', x:0, y:0, width:n.w, height:n.h,
      fill:n.color,'fill-opacity':'0.9',
      stroke:isHub?'#f0a000':'#888','stroke-width':isHub?'2.5':'1',rx:3});
    var txt = _el('text',{'class':'rg-nt', x:n.w/2, y:n.h/2,
      'text-anchor':'middle','dominant-baseline':'middle',fill:nodeTxt,
      'font-size':'9','font-family':'SFMono-Regular,Consolas,monospace',
      'clip-path':'url(#rgcp'+n.id+')','pointer-events':'none'});
    txt.textContent = n.name;
    g.appendChild(rect); g.appendChild(txt);
    if (n.external) {
      var bk=_el('rect',{'class':'rg-ext',x:n.w-14,y:2,width:12,height:10,
        fill:'#f0a000',rx:2,'pointer-events':'none'});
      var bt=_el('text',{'class':'rg-ext-t',x:n.w-8,y:7,
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
  svgEl._rgEdgeEls = Array.from(eg.children);
  svgEl._rgOv = ov;

  // ── Pan / zoom ───────────────────────────────────────────────────────────────
  var vb={x:0,y:0,w:1000,h:1000}, pan=false, px=0, py=0;
  svgEl._rgVb = vb;
  function setVb(){svgEl.setAttribute('viewBox',vb.x+' '+vb.y+' '+vb.w+' '+vb.h);}
  function onDown(e){if(e.button!==0)return;pan=true;px=e.clientX;py=e.clientY;svgEl.style.cursor='grabbing';e.preventDefault();}
  function onMove(e){
    if(!pan)return;
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
  svgEl.addEventListener('mousedown',onDown);
  document.addEventListener('mousemove',onMove);
  document.addEventListener('mouseup',onUp);
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
  eg.addEventListener('mousemove',onEMove); eg.addEventListener('mouseleave',hideTip);
  ng.addEventListener('click',function(e){
    var g=e.target.closest&&e.target.closest('[data-to-name]');
    if(g) navigateFn('TableOccurrenceCatalog',g.getAttribute('data-to-name'));
  });

  svgEl._rgCleanup = function(){
    svgEl.removeEventListener('mousedown',onDown);
    document.removeEventListener('mousemove',onMove);
    document.removeEventListener('mouseup',onUp);
    svgEl.removeEventListener('wheel',onWheel);
    ng.removeEventListener('mousemove',onNMove); ng.removeEventListener('mouseleave',hideTip);
    eg.removeEventListener('mousemove',onEMove); eg.removeEventListener('mouseleave',hideTip);
  };
};

// ── Apply a posMap {id:{x,y,w,h}} to the live SVG ────────────────────────────
window._rgApply = function(svgEl, posMap) {
  var nodeEls=svgEl._rgNodeEls, edgeEls=svgEl._rgEdgeEls;
  if(!nodeEls||!edgeEls) return;
  for (var [id,g] of nodeEls) {
    var p=posMap[id]; if(!p)continue;
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
    var fp=posMap[fid],tp=posMap[tid]; if(!fp||!tp)continue;
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
  for (var n of gd.nodes) pos[n.id]={x:n.x,y:n.y,w:n.w,h:n.h};
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

// ── Layout: Discover (force-directed) ────────────────────────────────────────
window._rgLayoutForce = function(gd, startPos, onFrame, onSettle) {
  var REPEL=1400,ATTRACT=0.04,CLUST=0.006,DAMP=0.82,REST=220,MAX=180;
  var sim=gd.nodes.map(n=>{
    var sp=startPos[n.id]||{x:n.x,y:n.y,w:CL_W,h:CL_H};
    // Hub emphasis: node size grows with degree (capped). The free-form Discover
    // layout is where size variation reads cleanly — hubs pull central and large.
    var sc=Math.min(1.9, 1 + 0.1*(n.degree||0));
    return {id:n.id,bt:n.base_table,w:CL_W*sc,h:CL_H*sc,
            x:sp.x+sp.w/2+(Math.random()-.5)*40,
            y:sp.y+sp.h/2+(Math.random()-.5)*40,
            vx:0,vy:0};
  });
  var niMap=new Map(sim.map((n,i)=>[n.id,i]));
  var adj=[];
  for (var e of gd.edges){
    var fi=niMap.get(e.from_id),ti=niMap.get(e.to_id);
    if(fi!==undefined&&ti!==undefined)adj.push([fi,ti]);
  }
  var frame=0,raf=null;
  function tick(){
    for(var n of sim){n.fx=0;n.fy=0;}
    for(var i=0;i<sim.length;i++) for(var j=i+1;j<sim.length;j++){
      var dx=sim[j].x-sim[i].x,dy=sim[j].y-sim[i].y;
      var d2=dx*dx+dy*dy||1,d=Math.sqrt(d2),f=REPEL/d2;
      sim[i].fx-=f*dx/d;sim[i].fy-=f*dy/d;
      sim[j].fx+=f*dx/d;sim[j].fy+=f*dy/d;
    }
    for(var [ai,bi] of adj){
      var dx=sim[bi].x-sim[ai].x,dy=sim[bi].y-sim[ai].y;
      var d=Math.sqrt(dx*dx+dy*dy)||1,f=ATTRACT*(d-REST);
      sim[ai].fx+=f*dx/d;sim[ai].fy+=f*dy/d;
      sim[bi].fx-=f*dx/d;sim[bi].fy-=f*dy/d;
    }
    var cc={};
    for(var n of sim){if(!cc[n.bt])cc[n.bt]={x:0,y:0,c:0};cc[n.bt].x+=n.x;cc[n.bt].y+=n.y;cc[n.bt].c++;}
    for(var bt in cc){cc[bt].x/=cc[bt].c;cc[bt].y/=cc[bt].c;}
    for(var n of sim){var c=cc[n.bt];n.fx+=CLUST*(c.x-n.x);n.fy+=CLUST*(c.y-n.y);}
    var energy=0;
    for(var n of sim){
      n.vx=(n.vx+n.fx)*DAMP;n.vy=(n.vy+n.fy)*DAMP;
      n.x+=n.vx;n.y+=n.vy;energy+=n.vx*n.vx+n.vy*n.vy;
    }
    var pm={};
    for(var n of sim) pm[n.id]={x:n.x-n.w/2,y:n.y-n.h/2,w:n.w,h:n.h};
    onFrame(pm);
    frame++;
    if(energy<0.5||frame>=MAX){raf=null;onSettle({positions:pm,bounds:_bounds(pm)});}
    else raf=requestAnimationFrame(tick);
  }
  raf=requestAnimationFrame(tick);
  return function(){if(raf){cancelAnimationFrame(raf);raf=null;}};
};

})(); // end graph module
