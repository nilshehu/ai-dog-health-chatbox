const CACHE_NAME = 'pet-health-assistant-v1';
const ASSETS_TO_CACHE = [
    '/',
    '/index.html',
    '/dist/main.bundle.js',
    '/dist/components.bundle.js',
    '/images/logo.svg',
    'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css',
    'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css'
];

// Install service worker and cache assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(ASSETS_TO_CACHE))
    );
});

// Activate new service worker and clean up old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames
                    .filter((name) => name !== CACHE_NAME)
                    .map((name) => caches.delete(name))
            );
        })
    );
});

// Fetch assets from cache or network
self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request)
            .then((response) => {
                if (response) {
                    return response;
                }

                return fetch(event.request).then((response) => {
                    // Don't cache API calls or external resources
                    if (!event.request.url.includes('/api/') &&
                        event.request.url.startsWith(self.location.origin)) {
                        return caches.open(CACHE_NAME).then((cache) => {
                            cache.put(event.request, response.clone());
                            return response;
                        });
                    }

                    return response;
                });
            })
    );
}); 