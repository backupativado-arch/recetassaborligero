'use strict';
// Área de membros Sabor Ligero
// - Login só com o e-mail da compra (precisa estar ativo na tabela members)
// - Painel admin (senha em ADMIN_PASSWORD) para ver, liberar e bloquear e-mails
// - Webhook da 3B Pagamentos: venda paga libera, reembolso/contestação bloqueia

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const WEBHOOK_SECRETS = (process.env.THREEB_WEBHOOK_SECRET || '').split(',').map(s => s.trim()).filter(Boolean);
const PRODUCT_IDS = (process.env.THREEB_PRODUCT_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
const SALES_URL = process.env.SALES_URL || 'https://www.recetassaborligero.com';
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || '';

if (!DATABASE_URL || !SESSION_SECRET || !ADMIN_PASSWORD) {
  console.error('Faltam variáveis: DATABASE_URL, SESSION_SECRET e ADMIN_PASSWORD são obrigatórias.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1|\.railway\.internal/.test(DATABASE_URL) ? false : { rejectUnauthorized: false }
});

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      email        TEXT PRIMARY KEY,
      name         TEXT,
      status       TEXT NOT NULL DEFAULT 'active',
      source       TEXT NOT NULL DEFAULT 'manual',
      order_id     TEXT,
      product_name TEXT,
      note         TEXT,
      last_login   TIMESTAMPTZ,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS webhook_events (
      id          TEXT PRIMARY KEY,
      type        TEXT,
      email       TEXT,
      result      TEXT,
      payload     JSONB,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

// ---------- utilidades ----------
const normEmail = e => String(e || '').trim().toLowerCase();
const isEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hmac = (v) => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('hex');
const safeEq = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setCookie(res, name, value, maxAgeSec) {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSec}`];
  if (process.env.NODE_ENV === 'production') parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}
function makeToken(kind, subject, days) {
  const exp = Math.floor(Date.now() / 1000) + days * 86400;
  const body = Buffer.from(JSON.stringify({ k: kind, s: subject, e: exp })).toString('base64url');
  return body + '.' + hmac(body);
}
function readToken(token, kind) {
  if (!token || token.indexOf('.') < 0) return null;
  const [body, sig] = token.split('.');
  if (!safeEq(sig, hmac(body))) return null;
  try {
    const d = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (d.k !== kind || d.e < Date.now() / 1000) return null;
    return d.s;
  } catch { return null; }
}

// limite simples de tentativas por IP
const hits = new Map();
function tooMany(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  return arr.length > max;
}
const ip = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

// ---------- app ----------
const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'same-origin');
  next();
});

// Webhook precisa do corpo cru para validar a assinatura
app.post('/webhooks/3b', express.raw({ type: '*/*', limit: '1mb' }), async (req, res) => {
  const raw = req.body instanceof Buffer ? req.body.toString('utf8') : '';
  const sigHeader = String(req.headers['x-3b-signature'] || '');
  const parts = Object.fromEntries(sigHeader.split(',').map(p => p.trim().split('=')).filter(x => x.length === 2));
  const t = parts.t, v1 = parts.v1;
  if (!WEBHOOK_SECRETS.length) return res.status(500).send('webhook sem segredo configurado');
  if (!t || !v1) return res.status(400).send('assinatura inválida');
  const ok = WEBHOOK_SECRETS.some(secret => {
    const expected = crypto.createHmac('sha256', secret).update(`${t}.${raw}`).digest('hex');
    return safeEq(expected, v1);
  });
  if (!ok) return res.status(400).send('assinatura inválida');
  if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return res.status(400).send('evento expirado');

  let evt;
  try { evt = JSON.parse(raw); } catch { return res.status(400).send('json inválido'); }
  const eventId = String(req.headers['x-3b-event-id'] || evt.id || '');
  const type = String(evt.type || req.headers['x-3b-event-type'] || '');
  const order = (evt.data && (evt.data.order || evt.data.checkout)) || {};
  const email = normEmail(order.buyer && order.buyer.email);

  const evId = eventId || crypto.randomUUID();
  try {
    const ins = await pool.query(
      'INSERT INTO webhook_events (id, type, email, payload) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO NOTHING RETURNING id',
      [evId, type, email || null, evt]
    );
    if (!ins.rowCount) return res.status(200).send('duplicado');

    let result = 'ignorado';
    if (evt.test === true) {
      result = 'teste recebido (não libera acesso)';
    } else if (PRODUCT_IDS.length && order.product_id && !PRODUCT_IDS.includes(String(order.product_id))) {
      result = 'outro produto (ignorado)';
    } else if (type === 'payment_intent.succeeded' && order.status === 'paid' && isEmail(email)) {
      await pool.query(`
        INSERT INTO members (email, name, status, source, order_id, product_name)
        VALUES ($1,$2,'active','3b',$3,$4)
        ON CONFLICT (email) DO UPDATE SET status='active', source='3b',
          name=COALESCE(EXCLUDED.name, members.name), order_id=EXCLUDED.order_id,
          product_name=EXCLUDED.product_name, note=NULL, updated_at=now()`,
        [email, (order.buyer && order.buyer.name) || null, order.id || null, order.product_name || null]);
      result = 'acesso liberado';
    } else if ((type === 'charge.refunded' || type === 'charge.dispute.created') && isEmail(email)) {
      const reason = type === 'charge.refunded' ? 'reembolso' : 'contestação';
      const up = await pool.query(
        "UPDATE members SET status='blocked', note=$2, updated_at=now() WHERE email=$1", [email, reason]);
      result = up.rowCount ? `acesso bloqueado (${reason})` : `${reason} sem membro cadastrado`;
    }
    await pool.query('UPDATE webhook_events SET result=$2 WHERE id=$1', [evId, result]);
    res.status(200).send('ok');
  } catch (e) {
    console.error('webhook erro', e);
    res.status(500).send('erro');
  }
});

app.use(express.urlencoded({ extended: false, limit: '20kb' }));

// ---------- páginas da cliente (espanhol) ----------
const BRAND_CSS = `
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#FFF8F1;color:#351714;font-family:Poppins,system-ui,sans-serif;display:flex;flex-direction:column}
.top{background:#351714;color:#fff;padding:40px 20px 48px;border-radius:0 0 32px 32px;text-align:center}
.logo{font-family:'Titan One',sans-serif;font-size:34px;line-height:1}.logo small{display:block;font-family:Poppins,sans-serif;font-size:12px;letter-spacing:2px;opacity:.8;margin-top:6px;font-weight:500}
.card{max-width:420px;width:calc(100% - 32px);margin:-24px auto 0;background:#fff;border-radius:24px;padding:28px 22px;box-shadow:0 12px 32px rgba(53,23,20,.12)}
h1{font-family:'Titan One',sans-serif;font-weight:400;font-size:24px;margin:0 0 6px}
p{margin:0 0 18px;line-height:1.5;font-size:15px;color:#5A3A35}
label{display:block;font-weight:600;font-size:14px;margin-bottom:6px}
input{width:100%;height:52px;border:2px solid #E3DBCE;border-radius:14px;padding:0 14px;font:inherit;font-size:16px;color:#351714}
input:focus{outline:none;border-color:#B20404}
button{width:100%;height:54px;margin-top:14px;border:0;border-radius:27px;background:#B20404;color:#fff;font:inherit;font-weight:700;font-size:16px;cursor:pointer;box-shadow:0 5px 0 #7A0202}
.err{background:#FDECEC;color:#8A0A0A;border-radius:12px;padding:12px 14px;font-size:14px;margin-bottom:16px;line-height:1.45}
.err a{color:#8A0A0A;font-weight:700}
.foot{text-align:center;font-size:12px;color:#8C716C;padding:28px 16px}
`;
const FONTS = `<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Titan+One&family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">`;

function loginPage(msg, email) {
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#351714"><title>Sabor Ligero — Acceso</title>${FONTS}<style>${BRAND_CSS}</style></head><body>
<div class="top"><div class="logo">Sabor Ligero<small>ÁREA DE MIEMBROS</small></div></div>
<form class="card" method="post" action="/entrar">
<h1>Accede a tus recetas</h1>
<p>Escribe el mismo e-mail que usaste en la compra.</p>
${msg ? `<div class="err" role="alert">${msg}</div>` : ''}
<label for="email">Tu e-mail</label>
<input id="email" name="email" type="email" inputmode="email" autocomplete="email" required placeholder="tu@email.com" value="${esc(email || '')}">
<button type="submit">Entrar</button>
</form>
<div class="foot">© Sabor Ligero${SUPPORT_EMAIL ? ` · ¿Ayuda? <a href="mailto:${esc(SUPPORT_EMAIL)}" style="color:#B20404">${esc(SUPPORT_EMAIL)}</a>` : ''}</div>
</body></html>`;
}

async function currentMember(req) {
  const email = readToken(parseCookies(req).sl_member, 'm');
  if (!email) return null;
  const r = await pool.query("SELECT email FROM members WHERE email=$1 AND status='active'", [email]);
  return r.rowCount ? email : null;
}

app.get('/', async (req, res) => {
  if (await currentMember(req)) return res.redirect('/recetas/');
  res.send(loginPage());
});

app.post('/entrar', async (req, res) => {
  if (tooMany('login:' + ip(req), 20, 15 * 60 * 1000)) {
    return res.status(429).send(loginPage('Demasiados intentos. Espera unos minutos e inténtalo de nuevo.'));
  }
  const email = normEmail(req.body.email);
  if (!isEmail(email)) return res.status(400).send(loginPage('Escribe un e-mail válido.', email));
  const r = await pool.query('SELECT status FROM members WHERE email=$1', [email]);
  if (!r.rowCount) {
    return res.status(403).send(loginPage(`No encontramos una compra con este e-mail. Revisa si está bien escrito o usa el e-mail de la compra. ¿Aún no compraste? <a href="${esc(SALES_URL)}">Conoce Sabor Ligero</a>.`, email));
  }
  if (r.rows[0].status !== 'active') {
    return res.status(403).send(loginPage('El acceso de este e-mail está desactivado. Si crees que es un error, contáctanos.', email));
  }
  await pool.query('UPDATE members SET last_login=now() WHERE email=$1', [email]);
  setCookie(res, 'sl_member', makeToken('m', email, 180), 180 * 86400);
  res.redirect('/recetas/');
});

app.get('/salir', (req, res) => {
  setCookie(res, 'sl_member', '', 0);
  res.redirect('/');
});

const RECETAS_HTML = fs.readFileSync(path.join(__dirname, 'recetas', 'index.html'), 'utf8');
app.use('/recetas/img', express.static(path.join(__dirname, 'recetas', 'img'), { maxAge: '30d' }));
app.get('/recetas', async (req, res) => {
  if (!req.originalUrl.split('?')[0].endsWith('/')) return res.redirect('/recetas/');
  if (!(await currentMember(req))) return res.redirect('/');
  res.set('Cache-Control', 'private, no-store');
  res.send(RECETAS_HTML);
});

// ---------- admin (português) ----------
const ADMIN_CSS = `
*{box-sizing:border-box}body{margin:0;background:#F6F1EA;color:#2A1412;font-family:Poppins,system-ui,sans-serif;font-size:14px}
a{color:#B20404}
header{background:#351714;color:#fff}header .in{max-width:1100px;margin:0 auto;padding:14px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header b{font-family:'Titan One',sans-serif;font-weight:400;font-size:20px}header span{opacity:.75;font-size:13px}header a{color:#fff;margin-left:auto;font-weight:600}
main{max-width:1100px;margin:0 auto;padding:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.stat{background:#fff;border-radius:16px;padding:14px 16px;border:1px solid #E8DED2}.stat b{display:block;font-size:26px}.stat span{color:#6B4A45;font-size:13px}
.box{background:#fff;border-radius:16px;padding:16px;border:1px solid #E8DED2;margin-bottom:18px}
.box h2{margin:0 0 12px;font-size:16px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input,select{height:42px;border:1.5px solid #D9CCBE;border-radius:10px;padding:0 12px;font:inherit;min-width:0}
input[name=email]{flex:2 1 220px}input[name=name]{flex:1 1 160px}input[name=q]{flex:1 1 240px}
.btn{height:42px;border:0;border-radius:10px;padding:0 16px;font:inherit;font-weight:600;cursor:pointer;background:#B20404;color:#fff}
.btn.s{background:#fff;color:#351714;border:1.5px solid #351714}.btn.sm{height:34px;padding:0 12px;font-size:13px}
.tbl{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:460px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #EFE6DC;vertical-align:middle}th{font-size:12px;color:#6B4A45;text-transform:uppercase;letter-spacing:.5px}
.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}
.on{background:#E3F4E1;color:#1E6B25}.off{background:#FBE3E3;color:#8A0A0A}
.muted{color:#8C716C;font-size:12px}
.flash{background:#E3F4E1;color:#1E6B25;border-radius:10px;padding:10px 14px;margin-bottom:14px}
.flash.e{background:#FBE3E3;color:#8A0A0A}
form.inline{display:inline}
.login{max-width:380px;margin:12vh auto;background:#fff;border-radius:20px;padding:28px;border:1px solid #E8DED2}
.login input{width:100%;margin:8px 0 12px}.login .btn{width:100%}
code{background:#F3ECE3;padding:2px 6px;border-radius:6px;font-size:12.5px;word-break:break-all}
`;
function adminShell(body) {
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Admin — Sabor Ligero</title>${FONTS}<style>${ADMIN_CSS}</style></head><body>${body}</body></html>`;
}
function isAdmin(req) { return readToken(parseCookies(req).sl_admin, 'a') === 'admin'; }

app.get('/admin/login', (req, res) => {
  res.send(adminShell(`<form class="login" method="post" action="/admin/login"><h2 style="margin:0 0 6px">Admin Sabor Ligero</h2><p class="muted" style="margin:0 0 10px">Digite a senha do painel.</p>${req.query.e ? '<div class="flash e">Senha incorreta.</div>' : ''}<label for="p">Senha</label><input id="p" type="password" name="password" autocomplete="current-password" required><button class="btn">Entrar</button></form>`));
});
app.post('/admin/login', (req, res) => {
  if (tooMany('admin:' + ip(req), 10, 15 * 60 * 1000)) return res.status(429).send('Muitas tentativas. Tente em 15 minutos.');
  if (!safeEq(String(req.body.password || ''), ADMIN_PASSWORD)) return res.redirect('/admin/login?e=1');
  setCookie(res, 'sl_admin', makeToken('a', 'admin', 7), 7 * 86400);
  res.redirect('/admin');
});
app.get('/admin/sair', (req, res) => { setCookie(res, 'sl_admin', '', 0); res.redirect('/admin/login'); });
app.use('/admin', (req, res, next) => isAdmin(req) ? next() : res.redirect('/admin/login'));

const fmt = d => d ? new Date(d).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo', dateStyle: 'short', timeStyle: 'short' }) : '—';

app.get('/admin', async (req, res) => {
  const q = normEmail(req.query.q || '');
  const filtro = ['active', 'blocked'].includes(req.query.status) ? req.query.status : '';
  const where = [], args = [];
  if (q) { args.push('%' + q + '%'); where.push(`(email ILIKE $${args.length} OR COALESCE(name,'') ILIKE $${args.length})`); }
  if (filtro) { args.push(filtro); where.push(`status=$${args.length}`); }
  const list = await pool.query(`SELECT * FROM members ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY created_at DESC LIMIT 500`, args);
  const st = (await pool.query(`SELECT
      COUNT(*) FILTER (WHERE status='active') AS ativos,
      COUNT(*) FILTER (WHERE status='blocked') AS bloqueados,
      COUNT(*) FILTER (WHERE source='3b') AS via3b,
      COUNT(*) FILTER (WHERE created_at > now() - interval '24 hours') AS hoje
    FROM members`)).rows[0];
  const evs = await pool.query('SELECT id,type,email,result,received_at FROM webhook_events ORDER BY received_at DESC LIMIT 25');
  const host = `${req.protocol}://${req.get('host')}`;
  const flash = req.query.ok ? `<div class="flash">${esc(req.query.ok)}</div>` : req.query.err ? `<div class="flash e">${esc(req.query.err)}</div>` : '';
  const rows = list.rows.map(m => `<tr>
    <td><b>${esc(m.email)}</b>${m.name ? `<div class="muted">${esc(m.name)}</div>` : ''}</td>
    <td><span class="pill ${m.status === 'active' ? 'on' : 'off'}">${m.status === 'active' ? 'Com acesso' : 'Bloqueado'}</span>${m.note ? `<div class="muted">${esc(m.note)}</div>` : ''}</td>
    <td style="white-space:nowrap">
      <form class="inline" method="post" action="/admin/status"><input type="hidden" name="email" value="${esc(m.email)}"><input type="hidden" name="status" value="${m.status === 'active' ? 'blocked' : 'active'}"><button class="btn s sm">${m.status === 'active' ? 'Bloquear' : 'Liberar'}</button></form>
      <form class="inline" method="post" action="/admin/remover" onsubmit="return confirm('Remover este e-mail da lista?')"><input type="hidden" name="email" value="${esc(m.email)}"><button class="btn s sm">Remover</button></form>
    </td></tr>`).join('');
  const evRows = evs.rows.map(e => `<tr><td>${fmt(e.received_at)}</td><td><code>${esc(e.type)}</code></td><td>${esc(e.email || '—')}</td><td>${esc(e.result || '—')}</td></tr>`).join('');
  res.send(adminShell(`
  <header><div class="in"><b>Sabor Ligero</b><span>Painel de acessos</span><a href="/admin/sair">Sair</a></div></header>
  <main>
    ${flash}
    <div class="stats">
      <div class="stat"><b>${st.ativos}</b><span>com acesso</span></div>
      <div class="stat"><b>${st.bloqueados}</b><span>bloqueados</span></div>
      <div class="stat"><b>${st.via3b}</b><span>vieram da 3B</span></div>
      <div class="stat"><b>${st.hoje}</b><span>novos nas últimas 24h</span></div>
    </div>
    <div class="box"><h2>Liberar acesso manualmente</h2>
      <form class="row" method="post" action="/admin/adicionar">
        <input name="email" type="email" placeholder="email@cliente.com" required aria-label="E-mail">
        <input name="name" placeholder="Nome (opcional)" aria-label="Nome">
        <button class="btn">Liberar acesso</button>
      </form>
    </div>
    <div class="box"><h2>E-mails com acesso ao painel (${list.rowCount}${list.rowCount === 500 ? '+' : ''})</h2>
      <form class="row" method="get" action="/admin" style="margin-bottom:12px">
        <input name="q" placeholder="Buscar por e-mail ou nome" value="${esc(q)}" aria-label="Buscar">
        <select name="status" aria-label="Filtrar status"><option value="">Todos</option><option value="active" ${filtro === 'active' ? 'selected' : ''}>Com acesso</option><option value="blocked" ${filtro === 'blocked' ? 'selected' : ''}>Bloqueados</option></select>
        <button class="btn s">Filtrar</button>
      </form>
      <div class="tbl"><table><thead><tr><th>E-mail</th><th>Status</th><th>Ações</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="3" class="muted">Nenhum e-mail ainda.</td></tr>'}</tbody></table></div>
    </div>
    <div class="box"><h2>Integração 3B</h2>
      <p style="margin:0 0 8px">URL do webhook para colocar na 3B (Integrações → Webhook):</p>
      <p style="margin:0 0 12px"><code>${esc(host)}/webhooks/3b</code></p>
      <p class="muted" style="margin:0 0 12px">Segredo configurado: ${WEBHOOK_SECRETS.length ? 'sim' : '<b style="color:#8A0A0A">não, falta THREEB_WEBHOOK_SECRET</b>'}${PRODUCT_IDS.length ? ` · Produtos filtrados: ${esc(PRODUCT_IDS.join(', '))}` : ' · Aceita todos os produtos do endpoint'}</p>
      <h2 style="margin-top:6px">Últimos eventos recebidos</h2>
      <div class="tbl"><table style="min-width:600px"><thead><tr><th>Quando</th><th>Evento</th><th>E-mail</th><th>Resultado</th></tr></thead><tbody>${evRows || '<tr><td colspan="4" class="muted">Nenhum evento ainda. Use "Enviar teste" na 3B para conferir.</td></tr>'}</tbody></table></div>
    </div>
  </main>`));
});

app.post('/admin/adicionar', async (req, res) => {
  const email = normEmail(req.body.email);
  if (!isEmail(email)) return res.redirect('/admin?err=' + encodeURIComponent('E-mail inválido.'));
  await pool.query(`INSERT INTO members (email, name, status, source) VALUES ($1,$2,'active','manual')
    ON CONFLICT (email) DO UPDATE SET status='active', name=COALESCE(EXCLUDED.name, members.name), note=NULL, updated_at=now()`,
    [email, String(req.body.name || '').trim() || null]);
  res.redirect('/admin?ok=' + encodeURIComponent(`Acesso liberado para ${email}.`));
});
app.post('/admin/status', async (req, res) => {
  const email = normEmail(req.body.email);
  const status = req.body.status === 'blocked' ? 'blocked' : 'active';
  await pool.query("UPDATE members SET status=$2, note=CASE WHEN $2='blocked' THEN 'bloqueado no painel' ELSE NULL END, updated_at=now() WHERE email=$1", [email, status]);
  res.redirect('/admin?ok=' + encodeURIComponent(status === 'active' ? `${email} liberado.` : `${email} bloqueado.`));
});
app.post('/admin/remover', async (req, res) => {
  const email = normEmail(req.body.email);
  await pool.query('DELETE FROM members WHERE email=$1', [email]);
  res.redirect('/admin?ok=' + encodeURIComponent(`${email} removido.`));
});

app.get('/health', (req, res) => res.send('ok'));

migrate().then(() => {
  app.listen(PORT, () => console.log('Área de membros na porta ' + PORT));
}).catch(e => { console.error('Falha ao preparar o banco', e); process.exit(1); });
