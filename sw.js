/* UstaCAD oflayn kesh: ilova va CDN kutubxonalari */
var V='ustacad-v2',CDN=['https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.min.js','https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js','https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/environments/RoomEnvironment.js','https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/exporters/GLTFExporter.js','https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js','https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js','https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js'];
self.addEventListener('install',function(e){self.skipWaiting();e.waitUntil(caches.open(V).then(function(c){return Promise.all(['./'].concat(CDN).map(function(u){return c.add(u).catch(function(){})}))}))});
self.addEventListener('activate',function(e){e.waitUntil(caches.keys().then(function(k){return Promise.all(k.filter(function(x){return x!==V}).map(function(x){return caches.delete(x)}))}).then(function(){return self.clients.claim()}))});
self.addEventListener('fetch',function(e){var r=e.request,u=new URL(r.url);
 if(r.method!=='GET'||/onrender\.com|telegram\.org/.test(u.host))return;
 var cdn=CDN.indexOf(r.url)>=0;
 if(cdn){e.respondWith(caches.match(r).then(function(h){return h||fetch(r).then(function(n){var c=n.clone();caches.open(V).then(function(k){k.put(r,c)});return n})}));return}
 if(u.origin===location.origin){e.respondWith(fetch(r).then(function(n){var c=n.clone();caches.open(V).then(function(k){k.put(r,c)});return n}).catch(function(){return caches.match(r)}))}});
