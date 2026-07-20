// 手搓笔记本 云同步 API（Cloudflare Pages Functions + D1）
// 路由：POST /api/register  POST /api/login  POST /api/logout
//       GET  /api/data      PUT  /api/data

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } });

const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = s => new Uint8Array(s.match(/.{2}/g).map(h => parseInt(h, 16)));
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));

const PBKDF2_ITER = 25000;
const SESSION_DAYS = 180;
const MAX_BODY = 700000; // ~700KB，个人笔记远用不到

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: PBKDF2_ITER }, key, 256);
  return hex(bits);
}

async function readBody(request) {
  const text = await request.text();
  if (text.length > MAX_BODY) { const e = new Error('too large'); e.status = 413; throw e; }
  return JSON.parse(text || '{}');
}

function validCreds(username, password) {
  if (typeof username !== 'string' || typeof password !== 'string') return '参数不对';
  const u = username.trim();
  if (u.length < 2 || u.length > 32) return '用户名需要 2-32 个字符';
  if (/\s/.test(u)) return '用户名不能包含空格';
  if (password.length < 6 || password.length > 128) return '密码需要 6-128 位';
  return null;
}

async function auth(request, env) {
  const h = request.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  const row = await env.DB.prepare(
    'SELECT s.user_id AS id, s.expires_at, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?'
  ).bind(token).first();
  if (!row || row.expires_at < Date.now()) return null;
  return row;
}

async function newSession(env, userId) {
  const token = randHex(32);
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, userId, Date.now() + SESSION_DAYS * 864e5).run();
  return token;
}

async function register(request, env) {
  const { username, password } = await readBody(request);
  const bad = validCreds(username, password);
  if (bad) return json({ error: bad }, 400);
  const u = username.trim();
  const exists = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(u).first();
  if (exists) return json({ error: '用户名已被注册' }, 409);
  const salt = randHex(16);
  const passHash = await hashPassword(password, salt);
  const r = await env.DB.prepare('INSERT INTO users (username, pass_hash, salt, created_at) VALUES (?, ?, ?, ?)')
    .bind(u, passHash, salt, Date.now()).run();
  const token = await newSession(env, r.meta.last_row_id);
  return json({ token, username: u });
}

async function login(request, env) {
  const { username, password } = await readBody(request);
  if (typeof username !== 'string' || typeof password !== 'string') return json({ error: '参数不对' }, 400);
  const row = await env.DB.prepare('SELECT id, pass_hash, salt FROM users WHERE username = ?')
    .bind(username.trim()).first();
  if (!row) return json({ error: '用户名或密码不对' }, 401);
  const passHash = await hashPassword(password, row.salt);
  if (passHash !== row.pass_hash) return json({ error: '用户名或密码不对' }, 401);
  const token = await newSession(env, row.id);
  return json({ token, username: username.trim() });
}

async function logout(request, env) {
  const h = request.headers.get('Authorization') || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  return json({ ok: true });
}

async function getData(request, env) {
  const user = await auth(request, env);
  if (!user) return json({ error: '未登录或登录已过期' }, 401);
  const row = await env.DB.prepare('SELECT data, updated_at FROM notebooks WHERE user_id = ?').bind(user.id).first();
  if (!row) return json({ data: null, updatedAt: 0 });
  return json({ data: JSON.parse(row.data), updatedAt: row.updated_at });
}

async function putData(request, env) {
  const user = await auth(request, env);
  if (!user) return json({ error: '未登录或登录已过期' }, 401);
  const body = await readBody(request);
  if (!body.data || !body.data.board || !Array.isArray(body.data.board.columns))
    return json({ error: '数据格式不对' }, 400);
  const incoming = body.updatedAt || Date.now();
  const row = await env.DB.prepare('SELECT data, updated_at FROM notebooks WHERE user_id = ?').bind(user.id).first();
  if (row && row.updated_at > incoming)  // 云端更新：不覆盖，把云端数据还给客户端
    return json({ conflict: true, data: JSON.parse(row.data), updatedAt: row.updated_at });
  await env.DB.prepare(
    'INSERT INTO notebooks (user_id, data, updated_at) VALUES (?, ?, ?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
  ).bind(user.id, JSON.stringify(body.data), incoming).run();
  return json({ ok: true, updatedAt: incoming });
}

export async function onRequest(context) {
  const { request, env } = context;
  const path = new URL(request.url).pathname.replace(/^\/api\/?/, '');
  const m = request.method;
  try {
    if (m === 'POST' && path === 'register') return await register(request, env);
    if (m === 'POST' && path === 'login') return await login(request, env);
    if (m === 'POST' && path === 'logout') return await logout(request, env);
    if (m === 'GET' && path === 'data') return await getData(request, env);
    if (m === 'PUT' && path === 'data') return await putData(request, env);
    return json({ error: '接口不存在' }, 404);
  } catch (e) {
    if (e.status === 413) return json({ error: '数据太大了' }, 413);
    if (e instanceof SyntaxError) return json({ error: '请求格式不对' }, 400);
    return json({ error: '服务器开小差了，稍后再试' }, 500);
  }
}
