// ── CDN imports ──────────────────────────────────────────────────────────────
import { generateKeyPair, sharedKey }
  from 'https://esm.run/@stablelib/x25519';
import { ChaCha20Poly1305 }
  from 'https://esm.run/@stablelib/chacha20poly1305';
import { BLAKE2s }
  from 'https://esm.run/@stablelib/blake2s';

// ── Crypto helpers ───────────────────────────────────────────────────────────
const enc = new TextEncoder();
const dec = new TextDecoder();

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function b2s(data) {
  const h = new BLAKE2s(32);
  h.update(data);
  return h.digest();
}

function hmac(key, data) {
  const B = 64;
  let k = key.length > B ? b2s(key) : key;
  const buf = new Uint8Array(B);
  buf.set(k);
  return b2s(concat(buf.map(x => x ^ 0x5c), b2s(concat(buf.map(x => x ^ 0x36), data))));
}

function hkdf2(ck, ikm) {
  const tmp  = hmac(ck, ikm);
  const out1 = hmac(tmp, new Uint8Array([0x01]));
  const out2 = hmac(tmp, concat(out1, new Uint8Array([0x02])));
  return [out1, out2];
}

function toHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function fromHex(s) {
  return new Uint8Array(s.match(/.{2}/g).map(x => parseInt(x, 16)));
}

async function sha256hex(b) {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', b)));
}

// ── Transport cipher state ───────────────────────────────────────────────────
class CipherState {
  constructor(key) { this.aead = new ChaCha20Poly1305(key); this.n = 0; }
  _nonce() {
    const n = new Uint8Array(12);
    new DataView(n.buffer).setUint32(4, this.n++, true);
    return n;
  }
  encrypt(pt) { return this.aead.seal(this._nonce(), pt); }
  decrypt(ct) { return this.aead.open(this._nonce(), ct); }
}

// ── Noise XX handshake (initiator side) ──────────────────────────────────────
//
// Pattern:  → e
//           ← e, ee, s, es
//           → s, se
//
class NoiseXX {
  constructor(staticKey) {
    this.h  = b2s(enc.encode('Noise_XX_25519_ChaChaPoly_BLAKE2s'));
    this.ck = new Uint8Array(this.h);
    this.k  = null;
    this.n  = 0;
    this.staticKey = staticKey;
    this.ephKey    = null;
    this.re = null;
    this.rs = null;
    this._mixHash(new Uint8Array(0)); // MixHash(empty prologue)
  }

  _nonce() {
    const n = new Uint8Array(12);
    new DataView(n.buffer).setUint32(4, this.n++, true);
    return n;
  }

  _mixKey(ikm) {
    const [ck, k] = hkdf2(this.ck, ikm);
    this.ck = ck; this.k = k; this.n = 0;
  }

  _mixHash(data) {
    this.h = b2s(concat(this.h, data));
  }

  _encryptAndHash(pt) {
    if (!this.k) { this._mixHash(pt); return pt; }
    const ct = new ChaCha20Poly1305(this.k).seal(this._nonce(), pt, this.h);
    this._mixHash(ct);
    return ct;
  }

  _decryptAndHash(ct) {
    if (!this.k) { this._mixHash(ct); return ct; }
    const pt = new ChaCha20Poly1305(this.k).open(this._nonce(), ct, this.h);
    if (!pt) throw new Error('authentication failed');
    this._mixHash(ct);
    return pt;
  }

  // → e
  msg1() {
    this.ephKey = generateKeyPair();
    this._mixHash(this.ephKey.publicKey);
    this._mixHash(new Uint8Array(0)); // EncryptAndHash(nil payload) with !hasK → MixHash(nil)
    return this.ephKey.publicKey; // 32 bytes
  }

  // ← e, ee, s, es  (server sends 96 bytes: 32 + 48 + 16)
  msg2(raw) {
    this.re = raw.slice(0, 32);
    this._mixHash(this.re);
    this._mixKey(sharedKey(this.ephKey.secretKey, this.re));    // ee
    this.rs = this._decryptAndHash(raw.slice(32, 80));          // 48 bytes: enc(s_r.public)
    this._mixKey(sharedKey(this.ephKey.secretKey, this.rs));    // es
    this._decryptAndHash(raw.slice(80));                        // 16 bytes: enc(nil payload)
  }

  // → s, se  →  returns 64 bytes (48 + 16)
  msg3() {
    const encS = this._encryptAndHash(this.staticKey.publicKey); // 48 bytes
    this._mixKey(sharedKey(this.staticKey.secretKey, this.re));  // se
    const tag  = this._encryptAndHash(new Uint8Array(0));        // 16 bytes: enc(nil payload)
    return concat(encS, tag);
  }

  split() {
    const [k1, k2] = hkdf2(this.ck, new Uint8Array(0));
    return { send: new CipherState(k1), recv: new CipherState(k2) };
  }
}

// ── Framing (handshake only: 2-byte big-endian length prefix) ────────────────
function frame(payload) {
  const out = new Uint8Array(2 + payload.length);
  out[0] = (payload.length >> 8) & 0xff;
  out[1] = payload.length & 0xff;
  out.set(payload, 2);
  return out;
}

function unframe(data) {
  return data.slice(2, 2 + ((data[0] << 8) | data[1]));
}

// ── Key persistence ──────────────────────────────────────────────────────────
function loadOrGenKey() {
  const p = localStorage.getItem('_np'), s = localStorage.getItem('_ns');
  if (p && s) return { publicKey: fromHex(p), secretKey: fromHex(s) };
  const kp = generateKeyPair();
  localStorage.setItem('_np', toHex(kp.publicKey));
  localStorage.setItem('_ns', toHex(kp.secretKey));
  return kp;
}

// ── App state ────────────────────────────────────────────────────────────────
let cipher = null;
let target = null;
let msgId  = 0;
let ws     = null;

const queue     = [];
const resolvers = [];
function nextMsg() {
  return new Promise(res => {
    if (queue.length) res(queue.shift()); else resolvers.push(res);
  });
}

// ── Identity ─────────────────────────────────────────────────────────────────
const staticKey = loadOrGenKey();
const myFp      = await sha256hex(staticKey.publicKey);
document.getElementById('myFp').textContent = myFp;

// ── Connection & handshake ───────────────────────────────────────────────────
async function connect() {
  queue.length = 0; resolvers.length = 0; cipher = null;
  setStatus(false);

  ws = new WebSocket(`ws://${location.host}/ws`);
  ws.binaryType = 'arraybuffer';

  ws.onmessage = e => {
    const d = new Uint8Array(e.data);
    if (resolvers.length) resolvers.shift()(d); else queue.push(d);
  };
  ws.onclose = () => {
    cipher = null; setStatus(false);
    addSys('Déconnecté — reconnexion dans 3 s…');
    setTimeout(connect, 3000);
  };
  ws.onerror = () => addSys('Erreur WebSocket');

  await new Promise(res => ws.addEventListener('open', res, { once: true }));

  try {
    const noise = new NoiseXX(staticKey);
    ws.send(frame(noise.msg1()));
    noise.msg2(unframe(await nextMsg()));
    ws.send(frame(noise.msg3()));
    cipher = noise.split();
  } catch (e) {
    addSys('Échec du handshake Noise : ' + e.message);
    ws.close(); return;
  }

  ws.onmessage = e => {
    const pt = cipher.recv.decrypt(new Uint8Array(e.data));
    if (!pt) { addSys('Erreur de déchiffrement'); return; }
    handle(JSON.parse(dec.decode(pt)));
  };

  send({ type: 'register', msg_id: 'init', data: { fingerprint: myFp } });
}

function send(env) {
  if (!cipher || ws.readyState !== WebSocket.OPEN) return;
  ws.send(cipher.send.encrypt(enc.encode(JSON.stringify(env))));
}

function handle(env) {
  switch (env.type) {
    case 'ack':
      if (env.msg_id === 'init' && !env.error) {
        setStatus(true);
        addSys('Connecté · partagez votre ID pour recevoir des messages');
      } else if (env.error) {
        addSys('Erreur : ' + env.error);
      }
      break;
    case 'deliver':
      addMsg(String(env.data ?? ''), 'recv');
      break;
    case 'peer_status':
      if (!env.online) addSys(`${String(env.to).slice(0, 12)}… est hors-ligne`);
      break;
    case 'ping':
      send({ type: 'pong', msg_id: env.msg_id });
      break;
  }
}

// ── UI helpers ───────────────────────────────────────────────────────────────
function setStatus(ok) {
  document.getElementById('dot').className      = 'dot' + (ok ? ' on' : '');
  document.getElementById('msgInput').disabled  = !ok || !target;
  document.getElementById('sendBtn').disabled   = !ok || !target;
}

function addMsg(text, dir) {
  const chat = document.getElementById('chat');
  const t    = new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
  const d    = document.createElement('div');
  d.className = 'msg ' + dir;
  d.innerHTML = `<div class="bubble">${esc(text)}</div><span class="time">${t}</span>`;
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
}

function addSys(text) {
  const chat = document.getElementById('chat');
  const d    = document.createElement('div');
  d.className = 'sys'; d.textContent = text;
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ── Button handlers ──────────────────────────────────────────────────────────
document.getElementById('connectBtn').onclick = () => {
  const v = document.getElementById('targetInput').value.trim();
  if (v.length !== 64) { addSys('ID invalide (64 caractères hex attendus)'); return; }
  target = v;
  addSys(`Discussion avec ${v.slice(0, 16)}…`);
  document.getElementById('msgInput').disabled = (cipher === null);
  document.getElementById('sendBtn').disabled  = (cipher === null);
  document.getElementById('msgInput').focus();
};

document.getElementById('sendBtn').onclick =
document.getElementById('msgInput').onkeydown = function(e) {
  if (e.type === 'keydown' && e.key !== 'Enter') return;
  const inp  = document.getElementById('msgInput');
  const text = inp.value.trim();
  if (!text || !target) return;
  inp.value = '';
  send({ type: 'forward', msg_id: String(++msgId), to: target, data: text });
  addMsg(text, 'sent');
};

document.getElementById('copyBtn').onclick = () => {
  navigator.clipboard.writeText(myFp);
  const btn = document.getElementById('copyBtn');
  btn.textContent = 'Copié !';
  setTimeout(() => btn.textContent = 'Copier', 1500);
};

// ── Start ────────────────────────────────────────────────────────────────────
setStatus(false);
connect();
