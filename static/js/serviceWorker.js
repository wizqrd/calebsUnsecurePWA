const assets = [
    "/",
    "static/css/style.css",
    "static/js/app.js",
    "static/images/logo.png",
    "static/images/favicon.jpg",
    "static/icons/icon-128x128.png",
    "static/icons/icon-192x192.png",
    "static/icons/icon-384x384.png",
    "static/icons/icon-512x512.png"
  ];

const CATALOGUE_ASSETS = "catalogue-assets";
const CACHE_VERSION = "v1";
const CURRENT_CACHE = CATALOGUE_ASSETS + "-" + CACHE_VERSION;

self.addEventListener("install", (installEvt) => {
  installEvt.waitUntil(
    caches
      .open(CURRENT_CACHE)
      .then((cache) => {
        cache.addAll(assets);
      })
      .then(self.skipWaiting())
      .catch(() => {})
  );
});

self.addEventListener("activate", function (evt) {
  evt.waitUntil(
    caches
      .keys()
      .then((keyList) => {
        return Promise.all(
          keyList.map((key) => {
            if (key.startsWith(CATALOGUE_ASSETS) && key !== CURRENT_CACHE) {
              return caches.delete(key);
            }
          })
        );
      })
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", function (evt) {
  evt.respondWith(
    fetch(evt.request).catch(() => {
      return caches.open(CURRENT_CACHE).then((cache) => {
        return cache.match(evt.request);
      });
    })
  );
})