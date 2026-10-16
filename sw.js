/* 解密 Service Worker：唯一持有密钥。game.html、lib/*、res/* 从 enc/ 取密文，解密后返回 */
const scope = self.registration.scope;
const scopePath = new URL(scope).pathname;
const TYPES = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
  json: "application/json",
  png: "image/png",
  jpg: "image/jpeg",
  wav: "audio/wav",
  mp3: "audio/mpeg",
  ogg: "audio/ogg",
  ttf: "font/ttf",
  atlas: "text/plain; charset=utf-8",
};

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("wudidong-lock2", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("k");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
/** 写操作等事务 complete 才返回，之后任何上下文都能读到 */
async function idb(mode, fn) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("k", mode);
    const req = fn(tx.objectStore("k"));
    tx.oncomplete = () => resolve(req.result ?? null);
    tx.onerror = tx.onabort = () => reject(tx.error);
  });
}

const importKey = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
let key = null;
async function loadKey() {
  if (key) return key;
  const raw = await idb("readonly", (s) => s.get("raw")).catch(() => null);
  if (raw) key = await importKey(raw);
  return key;
}
async function forgetKey() {
  key = null;
  await idb("readwrite", (s) => s.delete("raw")).catch(() => null);
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => {
  const port = e.ports[0];
  const d = e.data ?? {};
  e.waitUntil(
    (async () => {
      try {
        if (d.type === "set-key") {
          await idb("readwrite", (s) => s.put(d.raw, "raw"));
          key = await importKey(d.raw);
          port?.postMessage({ ok: true });
        } else if (d.type === "has-key") {
          port?.postMessage({ ok: !!(await loadKey()) });
        }
      } catch (err) {
        port?.postMessage({ ok: false, error: String(err) });
      }
    })(),
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || !url.pathname.startsWith(scopePath)) return;
  const rel = url.pathname.slice(scopePath.length);
  if (rel === "game.html") e.respondWith(serve("index.html", e.request, true));
  else if (rel.startsWith("res/") || rel.startsWith("lib/")) e.respondWith(serve(rel, e.request, false));
});

async function serve(rel, req, isPage) {
  const locked = (reason) => (isPage ? Response.redirect(scope + "?locked=" + reason, 302) : new Response("locked", { status: 403 }));
  const k = await loadKey();
  if (!k) return locked("nokey");
  const decrypt = async (cache) => {
    const res = await fetch(new URL("enc/" + rel, scope), { cache });
    if (!res.ok) return res.status;
    const buf = await res.arrayBuffer();
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, k, buf.slice(12));
  };
  let plain;
  try {
    plain = await decrypt("default");
  } catch {
    // 换密码后 HTTP 缓存里可能还是旧密文：绕过缓存再试一次
    try {
      plain = await decrypt("reload");
    } catch {
      await forgetKey();
      return locked("badkey");
    }
  }
  if (typeof plain === "number") return new Response(null, { status: plain });
  const ext = rel.slice(rel.lastIndexOf(".") + 1).toLowerCase();
  const headers = { "Content-Type": TYPES[ext] ?? "application/octet-stream", "Accept-Ranges": "bytes" };
  const total = plain.byteLength;
  const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.get("range") ?? "");
  if (m && (m[1] || m[2])) {
    const start = m[1] ? Number(m[1]) : Math.max(0, total - Number(m[2]));
    const end = m[1] && m[2] ? Math.min(Number(m[2]), total - 1) : total - 1;
    if (start > end) return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${total}` } });
    return new Response(plain.slice(start, end + 1), {
      status: 206,
      headers: { ...headers, "Content-Range": `bytes ${start}-${end}/${total}`, "Content-Length": String(end - start + 1) },
    });
  }
  return new Response(plain, { headers: { ...headers, "Content-Length": String(total) } });
}
