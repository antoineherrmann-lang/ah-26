/* ============================================================
   AH — Worker Cloudflare pour les notifications
   ------------------------------------------------------------
   Tout est fait avec les outils cryptographiques intégrés
   (Web Crypto), sans aucune dépendance externe :
     - RFC 8292 : signature VAPID (prouve que l'envoi vient de toi)
     - RFC 8291 : chiffrement de la charge utile (aes128gcm)

   Variables à configurer dans Cloudflare :
     VAPID_PUBLIC   (variable simple)
     VAPID_PRIVATE  (SECRET — jamais en clair)
     VAPID_SUBJECT  (variable simple, ex: mailto:ton@email.fr)
   Stockage à lier :
     PUSH_KV        (espace de stockage KV)
   ============================================================ */

/* ---------- Petits utilitaires d'encodage ---------- */
const enc = new TextEncoder();

function b64urlEncode(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const b64 = (str + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

/* ---------- VAPID : signature du jeton d'authentification ---------- */
async function importVapidPrivateKey(privateB64, publicB64) {
  const d = b64urlDecode(privateB64);
  const pub = b64urlDecode(publicB64); // 65 octets : 0x04 || X(32) || Y(32)
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    d: b64urlEncode(d),
    x: b64urlEncode(pub.slice(1, 33)),
    y: b64urlEncode(pub.slice(33, 65)),
    ext: true,
  };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

async function buildVapidHeader(endpoint, env) {
  const aud = new URL(endpoint).origin;
  const header = b64urlEncode(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64urlEncode(enc.encode(JSON.stringify({
    aud,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT || 'mailto:admin@example.com',
  })));
  const signingInput = `${header}.${payload}`;
  const key = await importVapidPrivateKey(env.VAPID_PRIVATE, env.VAPID_PUBLIC);
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    enc.encode(signingInput)
  );
  return `vapid t=${signingInput}.${b64urlEncode(sig)}, k=${env.VAPID_PUBLIC}`;
}

/* ---------- Chiffrement de la charge utile (aes128gcm) ---------- */
async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

async function encryptPayload(payloadText, p256dhB64, authB64) {
  const clientPub = b64urlDecode(p256dhB64);   // 65 octets
  const authSecret = b64urlDecode(authB64);    // 16 octets

  // Paire de clés éphémère, nouvelle à chaque envoi
  const localKeys = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const localPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', localKeys.publicKey));

  const clientKey = await crypto.subtle.importKey(
    'raw', clientPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: clientKey }, localKeys.privateKey, 256
  );
  const sharedSecret = new Uint8Array(sharedBits);

  // Dérivation en deux temps, comme l'impose la RFC 8291
  const keyInfo = concat(
    enc.encode('WebPush: info\0'),
    clientPub,
    localPubRaw
  );
  const prk = await hkdf(authSecret, sharedSecret, keyInfo, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, prk, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, prk, enc.encode('Content-Encoding: nonce\0'), 12);

  // Le corps est terminé par un octet 0x02 avant chiffrement
  const payload = concat(enc.encode(payloadText), new Uint8Array([0x02]));
  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, aesKey, payload
  ));

  // En-tête : salt(16) + taille d'enregistrement(4) + longueur clé(1) + clé publique(65)
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096);
  return concat(salt, rs, new Uint8Array([localPubRaw.length]), localPubRaw, ciphertext);
}

/* ---------- Envoi à un abonné ---------- */
async function sendPush(subscription, message, env) {
  const body = await encryptPayload(
    JSON.stringify(message),
    subscription.keys.p256dh,
    subscription.keys.auth
  );
  const vapid = await buildVapidHeader(subscription.endpoint, env);

  const res = await fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': vapid,
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400',
      'Urgency': 'normal',
    },
    body,
  });
  return res;
}

/* ---------- Les messages, tirés au hasard ---------- */
const MESSAGES = [
  { title: 'Miarahaba !', body: 'C\'est l\'heure du malgache. Cinq minutes suffisent.' },
  { title: 'Ton malgache t\'attend', body: 'Quelques cartes avant le dîner ?' },
  { title: 'Mila fanazaran-tena', body: 'Un peu d\'entraînement, et la série continue.' },
  { title: 'Diego se rapproche', body: 'Chaque session avance ton parcours sur la carte.' },
  { title: 'Cinq minutes, pas plus', body: 'Juste le temps de quelques mots.' },
  { title: 'Tsy maintsy mianatra', body: 'Le malgache ne s\'apprend pas tout seul.' },
  { title: 'Ta série compte sur toi', body: 'Ne casse pas la chaîne ce soir.' },
  { title: 'Vonona ve ianao ?', body: 'Prêt ? Une petite session t\'attend.' },
];

function pickMessage() {
  return MESSAGES[Math.floor(Math.random() * MESSAGES.length)];
}

/* ---------- Faut-il envoyer maintenant ? ---------- */
// Le déclencheur tourne en temps universel, mais on veut 18h45 à Paris
// quelle que soit l'heure d'été ou d'hiver. On lit donc l'heure locale réelle.
function parisNow() {
  const fmt = new Intl.DateTimeFormat('fr-FR', {
    timeZone: 'Europe/Paris',
    hour: '2-digit', minute: '2-digit',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour12: false,
  });
  const parts = {};
  for (const p of fmt.formatToParts(new Date())) parts[p.type] = p.value;
  return {
    hour: parseInt(parts.hour, 10),
    minute: parseInt(parts.minute, 10),
    date: `${parts.year}-${parts.month}-${parts.day}`,
  };
}

function daysBetween(a, b) {
  return Math.round((Date.parse(b + 'T00:00:00Z') - Date.parse(a + 'T00:00:00Z')) / 86400000);
}

/* ---------- Routage HTTP ---------- */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    // Enregistrer un abonnement
    if (url.pathname === '/subscribe' && request.method === 'POST') {
      const sub = await request.json();
      if (!sub || !sub.endpoint || !sub.keys) {
        return new Response('Abonnement invalide', { status: 400, headers: CORS });
      }
      await env.PUSH_KV.put('sub:' + sub.endpoint, JSON.stringify(sub));
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...CORS, 'Content-Type': 'application/json' },
      });
    }

    // Supprimer un abonnement
    if (url.pathname === '/unsubscribe' && request.method === 'POST') {
      const { endpoint } = await request.json();
      if (endpoint) await env.PUSH_KV.delete('sub:' + endpoint);
      return new Response(JSON.stringify({ ok: true }), {
        headers: { ...CORS, 'Content-Type': 'application/json' },
      });
    }

    // Envoi manuel immédiat, pour tester sans attendre 18h45
    if (url.pathname === '/test') {
      const result = await sendToAll(env, pickMessage(), true);
      return new Response(JSON.stringify(result, null, 2), {
        headers: { ...CORS, 'Content-Type': 'application/json' },
      });
    }

    // État du système
    if (url.pathname === '/status') {
      const list = await env.PUSH_KV.list({ prefix: 'sub:' });
      const last = await env.PUSH_KV.get('lastSent');
      const now = parisNow();
      return new Response(JSON.stringify({
        abonnés: list.keys.length,
        heureParis: `${String(now.hour).padStart(2,'0')}:${String(now.minute).padStart(2,'0')}`,
        dateParis: now.date,
        dernierEnvoi: last || 'jamais',
        clésConfigurées: !!(env.VAPID_PUBLIC && env.VAPID_PRIVATE),
      }, null, 2), { headers: { ...CORS, 'Content-Type': 'application/json' } });
    }

    return new Response('Worker AH — endpoints : /subscribe /unsubscribe /test /status',
      { headers: CORS });
  },

  // Déclencheur programmé
  async scheduled(event, env, ctx) {
    const now = parisNow();

    // On ne garde que le créneau de 18h45 heure de Paris
    if (now.hour !== 18 || now.minute < 40 || now.minute > 50) return;

    // Tous les 2 jours : on compare à la date du dernier envoi réussi
    const last = await env.PUSH_KV.get('lastSent');
    if (last && daysBetween(last, now.date) < 2) return;

    ctx.waitUntil((async () => {
      const result = await sendToAll(env, pickMessage(), false);
      if (result.envoyés > 0) await env.PUSH_KV.put('lastSent', now.date);
    })());
  },
};

/* ---------- Envoi à tous les abonnés ---------- */
async function sendToAll(env, message, isTest) {
  if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE) {
    return { erreur: 'Clés VAPID absentes', envoyés: 0 };
  }

  const list = await env.PUSH_KV.list({ prefix: 'sub:' });
  let sent = 0, removed = 0;
  const errors = [];

  for (const key of list.keys) {
    const raw = await env.PUSH_KV.get(key.name);
    if (!raw) continue;
    try {
      const sub = JSON.parse(raw);
      const res = await sendPush(sub, message, env);
      if (res.status === 404 || res.status === 410) {
        // Abonnement expiré : on nettoie
        await env.PUSH_KV.delete(key.name);
        removed++;
      } else if (res.ok) {
        sent++;
      } else {
        errors.push(`${res.status} ${await res.text().catch(()=> '')}`.slice(0, 120));
      }
    } catch (e) {
      errors.push(e.message);
    }
  }

  return { test: !!isTest, message, envoyés: sent, supprimés: removed, erreurs: errors };
}
