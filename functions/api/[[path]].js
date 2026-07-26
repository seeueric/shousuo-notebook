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

/* 恢复码：64 位随机数，格式 XXXX-XXXX-XXXX-XXXX。熵足够高，
   用 SHA-256(盐:码) 存储即可，无需慢哈希。一次性使用，用后即换。 */
const newRecoveryCode = () => randHex(8).toUpperCase().match(/.{4}/g).join('-');
const normCode = s => String(s || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
async function sha256Hex(s) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
}
async function setRecovery(env, userId) {
  const code = newRecoveryCode();
  const salt = randHex(16);
  const h = await sha256Hex(salt + ':' + normCode(code));
  await env.DB.prepare('UPDATE users SET recovery_hash = ?, recovery_salt = ? WHERE id = ?')
    .bind(h, salt, userId).run();
  return code;
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
  const userId = r.meta.last_row_id;
  const token = await newSession(env, userId);
  const recoveryCode = await setRecovery(env, userId);
  return json({ token, username: u, recoveryCode });
}

async function recoveryNew(request, env) {
  const user = await auth(request, env);
  if (!user) return json({ error: '未登录或登录已过期' }, 401);
  const recoveryCode = await setRecovery(env, user.id);
  return json({ recoveryCode });
}

async function recoveryReset(request, env) {
  const { username, code, newPassword } = await readBody(request);
  if (typeof username !== 'string' || typeof code !== 'string' || typeof newPassword !== 'string')
    return json({ error: '参数不对' }, 400);
  if (newPassword.length < 6 || newPassword.length > 128) return json({ error: '新密码需要 6-128 位' }, 400);
  const row = await env.DB.prepare('SELECT id, recovery_hash, recovery_salt FROM users WHERE username = ?')
    .bind(username.trim()).first();
  if (!row) return json({ error: '用户名不存在' }, 401);
  if (!row.recovery_hash) return json({ error: '该账号还没有生成过恢复码，无法自助找回' }, 401);
  const h = await sha256Hex(row.recovery_salt + ':' + normCode(code));
  if (h !== row.recovery_hash) return json({ error: '恢复码不对' }, 401);
  const salt = randHex(16);
  const passHash = await hashPassword(newPassword, salt);
  await env.DB.prepare('UPDATE users SET pass_hash = ?, salt = ? WHERE id = ?').bind(passHash, salt, row.id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(row.id).run();  // 踢掉所有旧登录
  const recoveryCode = await setRecovery(env, row.id);  // 旧码作废，换新码
  const token = await newSession(env, row.id);
  return json({ token, username: username.trim(), recoveryCode });
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

/* ================= AI（Cloudflare Workers AI · Qwen3-30B） ================= */
const AI_MODEL = '@cf/qwen/qwen3-30b-a3b-fp8';

function extractJSON(s) {
  if (!s) return null;
  let t = String(s).trim();
  t = t.replace(/```json\s*/gi, '').replace(/```/g, '').trim();
  // 去掉可能的 <think>…</think>
  t = t.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
  try { return JSON.parse(t); } catch (e) {}
  const first = Math.min(...['[', '{'].map(c => { const i = t.indexOf(c); return i < 0 ? Infinity : i; }));
  const lastArr = t.lastIndexOf(']'), lastObj = t.lastIndexOf('}');
  const last = Math.max(lastArr, lastObj);
  if (first === Infinity || last <= first) return null;
  try { return JSON.parse(t.slice(first, last + 1)); } catch (e) { return null; }
}

const AI_RULES = `/no_think
你是资深业务笔记助手。用户是精工工业建筑系统集团（IBS，钢结构/工业建筑系统/精致屋面）代表处负责人兼客户经理，常用系统：红圈CRM、钉钉。
硬性要求：一律简体中文，务实业务口吻，不要空话套话；相对时间（本周/下周等）以“今天”为基准换算成具体日期；不确定的人名/金额/时间标【待确认】，不得编造；人名尽量对应到下方词典的规范称谓。`;

function classifySys(today, dict) {
  return `${AI_RULES}
今天是 ${today}。
${dict ? '【用户业务词典】\n' + dict + '\n' : ''}
任务：我会给你一段随手记的碎片，可能含多件事。拆成相互独立的条目，逐条结构化。
只输出一个 JSON 数组（哪怕一条也用数组），禁止任何解释、禁止思考过程、禁止 markdown 代码块。
每个元素字段：
{"标题":"动词开头,≤12字","类型":"待办|领导交办|客户线索|市场信息|会议要点|素材/想法","归属":"所属战役/项目/客户/内部管理,无法判断填 未归类","相关人":["规范称谓,无法对应填 待确认"],"紧急度":"高|中|低","时限":"YYYY-MM-DD或 本周/本月,无则 null","落地动作":["需进红圈CRM|需进运营周会跟踪表|需上报办公厅|仅存档"],"原文":"对应片段"}
规则：出现董事长/主任/领导要求/让我/交办→类型优先 领导交办 且落地动作含 需上报办公厅；出现客户名/项目/招标/投标/报价/合同→落地动作含 需进红圈CRM；纯想法/资讯/素材→落地动作填 仅存档，不硬造行动项；一件事可多个落地动作。`;
}

function minutesSys(today, dict) {
  return `${AI_RULES}
今天是 ${today}。
${dict ? '【用户业务词典】\n' + dict + '\n' : ''}
任务：把我提供的会议记录/录音转写整理成会议纪要。
只输出一个 JSON 对象，禁止任何解释、禁止思考过程、禁止 markdown 代码块。字段：
{"title":"会议名,≤16字,不含日期","date":"YYYY-MM-DD(依据今天推断,无法确定用今天)","attendees":"参会人,顿号分隔的字符串,规范称谓","body":"正文纯文本"}
body 用纯文本排版（不要 markdown 表格、不要井号标题），按以下结构，没有内容的段落写“无”：
零、一句话结论
一、会议要素
　地点/线上：　主持：　议题：
二、议定事项
　1) 事项 / 责任人 / 时限 / 交付物
三、待决问题
　- 事项（卡在谁那里、需要什么才能决策）
四、承诺对照
　我方：- …
　对方：- …
五、需跟踪·录入去向
　- 事项 / 责任人 / 时限 / 去向(红圈CRM 或 运营周会跟踪表)
要求：责任人用规范称谓；时限尽量转绝对日期；领导口头交办即使没形成决议也列入议定事项并标【口头交办】；金额/工期/承诺条款保留原话不转述。`;
}

async function aiRun(request, env) {
  const user = await auth(request, env);
  if (!user) return json({ error: '请先登录再使用 AI' }, 401);
  if (!env.AI) return json({ error: '本站未启用 AI 能力' }, 501);
  const { kind, text, today, dict } = await readBody(request);
  if (typeof text !== 'string' || !text.trim()) return json({ error: '内容为空' }, 400);
  if (text.length > 16000) return json({ error: '内容过长（上限约 1.6 万字）' }, 413);
  const t = (typeof today === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(today)) ? today : new Date().toISOString().slice(0, 10);
  const d = (typeof dict === 'string' ? dict : '').slice(0, 4000);
  let sys;
  if (kind === 'minutes') sys = minutesSys(t, d);
  else if (kind === 'classify') sys = classifySys(t, d);
  else return json({ error: '未知的 AI 任务' }, 400);
  let resp;
  try {
    const out = await env.AI.run(AI_MODEL, {
      messages: [{ role: 'system', content: sys }, { role: 'user', content: text }],
      max_tokens: 3000,
    });
    resp = out ? out.response : undefined;
  } catch (e) { return json({ error: 'AI 调用失败，请稍后再试' }, 502); }
  // Workers AI 可能直接返回已解析的对象/数组，也可能返回字符串
  const parsed = (resp && typeof resp === 'object') ? resp : extractJSON(resp);
  if (parsed == null) return json({ error: 'AI 返回内容无法解析，请重试或精简输入' }, 502);
  return json({ kind, result: parsed });
}

export async function onRequest(context) {
  const { request, env } = context;
  const path = new URL(request.url).pathname.replace(/^\/api\/?/, '');
  const m = request.method;
  try {
    if (m === 'POST' && path === 'register') return await register(request, env);
    if (m === 'POST' && path === 'login') return await login(request, env);
    if (m === 'POST' && path === 'logout') return await logout(request, env);
    if (m === 'POST' && path === 'recovery/new') return await recoveryNew(request, env);
    if (m === 'POST' && path === 'recovery/reset') return await recoveryReset(request, env);
    if (m === 'GET' && path === 'data') return await getData(request, env);
    if (m === 'PUT' && path === 'data') return await putData(request, env);
    if (m === 'POST' && path === 'ai') return await aiRun(request, env);
    return json({ error: '接口不存在' }, 404);
  } catch (e) {
    if (e.status === 413) return json({ error: '数据太大了' }, 413);
    if (e instanceof SyntaxError) return json({ error: '请求格式不对' }, 400);
    return json({ error: '服务器开小差了，稍后再试' }, 500);
  }
}
