/* ============================================================
   AH — Service worker
   ------------------------------------------------------------
   Ne met VOLONTAIREMENT rien en cache : son unique rôle est de
   recevoir les notifications quand l'app est fermée.

   Mettre le HTML en cache casserait le mécanisme de mise à jour
   des apps (qui relit index.html en ligne pour comparer la
   version) : l'app servirait éternellement une version périmée.
   Aucun gestionnaire 'fetch' n'est donc déclaré.
   ============================================================ */

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let data = { title: 'AH', body: 'Notification', tag: 'ah' };
  try {
    if (event.data) data = { ...data, ...event.data.json() };
  } catch (e) {
    try { data.body = event.data.text(); } catch (e2) {}
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: './icon-192.png',
      badge: './icon-192.png',
      tag: data.tag,
      data: { url: data.url || './index.html' },
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || './index.html';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) if ('focus' in c) return c.focus();
      if (self.clients.openWindow) return self.clients.openWindow(target);
    })
  );
});
