/* UstaCAD oflayn rejim (service worker).
   - CDN kutubxonalari (three.js, jsPDF, xlsx, qrcode) birinchi ochilishda keshlanadi va keyin internetsiz ishlaydi.
   - Ilovaning o‘zi (index.html va boshqa fayllar): avval internet, internet yo‘q/sekin bo‘lsa kesh.
   Yangilash: ilova fayllari o‘zgarmasa ham kerak bo‘lsa V ni oshiring. */
var V='ustacad-v3';
var LIBS=[
 'https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.min.js',
 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js',
 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/exporters/GLTFExporter.js',
 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/environments/RoomEnvironment.js',
 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js',
 'https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js'
];
function put(req,res){if(res&&res.ok){var c=res.clone();caches.open(V).then(function(k){k.put(req,c)})}return res}

self.addEventListener('install',function(e){
 self.skipWaiting();
 e.waitUntil(caches.open(V).then(function(c){
  return Promise.all(LIBS.map(function(u){return c.add(new Request(u,{mode:'cors',credentials:'omit'})).catch(function(){})}))
   .then(function(){return c.add(new Request('./',{cache:'reload'})).catch(function(){})})
 }))});

self.addEventListener('activate',function(e){
 e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k!==V}).map(function(k){return caches.delete(k)}))}).then(function(){return self.clients.claim()}))});

function netFirst(req){
 return new Promise(function(res){
  var done=false,opt={ignoreSearch:true};
  function fin(r){if(!done&&r){done=true;res(r)}}
  var t=setTimeout(function(){caches.match(req,opt).then(fin)},5000);
  fetch(req).then(function(r){clearTimeout(t);fin(put(req,r))}).catch(function(){
   clearTimeout(t);
   caches.match(req,opt).then(function(h){
    if(h)return fin(h);
    if(req.mode==='navigate')return caches.match('./',opt).then(function(d){fin(d||Response.error())});
    fin(Response.error())})})})}

self.addEventListener('fetch',function(e){
 var r=e.request;if(r.method!=='GET')return;
 if(LIBS.indexOf(r.url)>-1){
  e.respondWith(caches.match(r).then(function(h){return h||fetch(r).then(function(x){return put(r,x)})}));return}
 var u=new URL(r.url);
 if(u.origin===self.location.origin)e.respondWith(netFirst(r))});
