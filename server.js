import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_FILE = path.join(__dirname, 'data.json');
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.VAULT_SECRET || 'dev-only-change-me';

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const defaults = () => ({
  auth: null,
  players: {},
  playerOrder: [],
  leaderboards: {},
  lbOrder: [],
  titleData: { game_version: '1.0.0', maintenance_mode: 'false' },
  catalog: {
    currencies: [{ code: 'GOLD', name: 'Gold' }, { code: 'GEMS', name: 'Gems' }],
    items: [
      { id: 'neon_skin', name: 'Neon Skin', category: 'Skin', price: { currency: 'GOLD', amount: 500 }, repeatable: false },
      { id: 'confetti_emote', name: 'Confetti Burst', category: 'Emote', price: { currency: 'GEMS', amount: 150 }, repeatable: true },
      { id: 'crown_hat', name: 'Golden Crown', category: 'Hat', price: { currency: 'GEMS', amount: 400 }, repeatable: false }
    ]
  },
  apiCalls: 0
});

let data;
let writeQueue = Promise.resolve();
async function load() {
  try { data = JSON.parse(await fs.readFile(DATA_FILE, 'utf8')); }
  catch { data = defaults(); await save(); }
  data.players ||= {}; data.playerOrder ||= []; data.leaderboards ||= {}; data.lbOrder ||= [];
  data.titleData ||= {}; data.catalog ||= { currencies: [], items: [] };
  data.catalog.currencies ||= []; data.catalog.items ||= [];
}
function save() {
  writeQueue = writeQueue.then(() => fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2)));
  return writeQueue;
}
function id(prefix='p') { return `${prefix}_${crypto.randomBytes(7).toString('hex')}`; }
function hashPassword(value, salt = crypto.randomBytes(16).toString('hex')) {
  return `${salt}:${crypto.scryptSync(value, salt, 32).toString('hex')}`;
}
function verifyPassword(value, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const actual = crypto.scryptSync(value, salt, 32).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(hash));
}
function tokenFor(subject) {
  const body = Buffer.from(JSON.stringify({ sub: subject, exp: Date.now() + 1000 * 60 * 60 * 24 * 7 })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [body, sig] = token.split('.');
  if (!body || !sig) return res.status(401).json({ error: 'Unauthorized' });
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig !== expected) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (p.exp < Date.now()) throw new Error('expired');
    req.user = p.sub; next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
}
function call() { data.apiCalls = (data.apiCalls || 0) + 1; }
function safePlayer(p) { return p; }
function getPlayer(pid) { return data.players[pid] || null; }
function requirePlayer(pid, res) { const p = getPlayer(pid); if (!p) { res.status(404).json({ error: 'Player not found' }); return null; } return p; }
function validateName(name) { return typeof name === 'string' && /^[a-zA-Z0-9_.-]{1,32}$/.test(name); }

app.get('/api/health', (req,res) => res.json({ ok:true, service:'vault', time:new Date().toISOString() }));
app.get('/api/auth/status', (req,res) => res.json({ configured: !!data.auth }));
app.post('/api/auth/setup', async (req,res) => {
  if (data.auth) return res.status(409).json({ error:'Passcode already configured' });
  const { passcode } = req.body || {};
  if (typeof passcode !== 'string' || passcode.length < 4) return res.status(400).json({ error:'Passcode must be at least 4 characters' });
  data.auth = { password: hashPassword(passcode), createdAt: Date.now() }; await save();
  res.json({ token: tokenFor('admin') });
});
app.post('/api/auth/login', async (req,res) => {
  const { passcode } = req.body || {};
  if (!data.auth || !verifyPassword(String(passcode || ''), data.auth.password)) return res.status(401).json({ error:'Incorrect passcode' });
  res.json({ token: tokenFor('admin') });
});
app.post('/api/auth/reset', async (req,res) => {
  data.auth = null; await save(); res.json({ ok:true });
});

app.use('/api', auth);
app.get('/api/state', (req,res) => { call(); res.json({ players:data.players, playerOrder:data.playerOrder, leaderboards:data.leaderboards, lbOrder:data.lbOrder, titleData:data.titleData, catalog:data.catalog, apiCalls:data.apiCalls }); });
app.get('/api/stats', (req,res) => res.json({ players:data.playerOrder.length, leaderboards:data.lbOrder.length, titleDataKeys:Object.keys(data.titleData).length, currencies:data.catalog.currencies.length, items:data.catalog.items.length, apiCalls:data.apiCalls }));

app.get('/api/players', (req,res) => res.json(data.playerOrder.map(x=>data.players[x]).filter(Boolean)));
app.post('/api/players', async (req,res) => {
  const { username } = req.body || {};
  if (!validateName(username)) return res.status(400).json({ error:'Username must be 1-32 characters: letters, numbers, _, ., -' });
  const player = { id:id(), username, createdAt:Date.now(), data:{}, currency:{}, inventory:[], banned:false };
  data.players[player.id]=player; data.playerOrder.push(player.id); call(); await save(); res.status(201).json(player);
});
app.get('/api/players/:pid', (req,res) => { const p=requirePlayer(req.params.pid,res); if(p) res.json(p); });
app.put('/api/players/:pid', async (req,res) => { const p=requirePlayer(req.params.pid,res); if(!p)return; const allowed=['username','data','currency','inventory','banned']; for(const k of allowed) if(req.body?.[k]!==undefined) p[k]=req.body[k]; call(); await save(); res.json(p); });
app.delete('/api/players/:pid', async (req,res) => { if(!requirePlayer(req.params.pid,res))return; delete data.players[req.params.pid]; data.playerOrder=data.playerOrder.filter(x=>x!==req.params.pid); call(); await save(); res.json({ok:true}); });
app.post('/api/players/:pid/ban', async (req,res) => { const p=requirePlayer(req.params.pid,res); if(!p)return; p.banned=true; await save(); res.json(p); });
app.post('/api/players/:pid/unban', async (req,res) => { const p=requirePlayer(req.params.pid,res); if(!p)return; p.banned=false; await save(); res.json(p); });
app.post('/api/players/:pid/currency', async (req,res) => {
  const p=requirePlayer(req.params.pid,res); if(!p)return; if(p.banned)return res.status(403).json({error:'Player is banned'});
  const {code, amount, operation='grant'}=req.body||{}; const n=Number(amount);
  if(!code || !Number.isInteger(n) || n<=0)return res.status(400).json({error:'Invalid currency operation'});
  p.currency[code]=(p.currency[code]||0)+(operation==='deduct'?-n:n); if(p.currency[code]<0){p.currency[code]-=(operation==='deduct'?-n:n);return res.status(400).json({error:'Not enough balance'});}
  await save(); res.json(p);
});
app.post('/api/players/:pid/inventory', async (req,res) => {
  const p=requirePlayer(req.params.pid,res); if(!p)return; if(p.banned)return res.status(403).json({error:'Player is banned'});
  const {itemId, mode='give'}=req.body||{}; const item=data.catalog.items.find(x=>x.id===itemId); if(!item)return res.status(404).json({error:'Item not found'});
  const existing=p.inventory.find(x=>x.itemId===item.id);
  if(mode==='sell' && item.price){ const bal=p.currency[item.price.currency]||0; if(bal<item.price.amount)return res.status(400).json({error:`Not enough ${item.price.currency}`}); if(item.repeatable===false&&existing)return res.status(400).json({error:'Player already owns this item'}); p.currency[item.price.currency]=bal-item.price.amount; }
  if(existing) existing.quantity++; else p.inventory.push({itemId:item.id,name:item.name,category:item.category,quantity:1}); await save(); res.json(p);
});
app.delete('/api/players/:pid/inventory/:itemId', async (req,res) => { const p=requirePlayer(req.params.pid,res); if(!p)return; p.inventory=p.inventory.filter(x=>x.itemId!==req.params.itemId); await save(); res.json(p); });

app.get('/api/leaderboards', (req,res)=>res.json(data.lbOrder.map(name=>({name,entries:data.leaderboards[name]||[]}))));
app.post('/api/leaderboards', async (req,res)=>{ const name=String(req.body?.name||'').trim().toLowerCase().replace(/\s+/g,'_'); if(!/^[a-z0-9_-]{1,64}$/.test(name))return res.status(400).json({error:'Invalid leaderboard name'}); if(data.lbOrder.includes(name))return res.status(409).json({error:'Leaderboard already exists'}); data.lbOrder.push(name);data.leaderboards[name]=[];await save();res.status(201).json({name,entries:[]}); });
app.put('/api/leaderboards/:name', async (req,res)=>{ if(!data.lbOrder.includes(req.params.name))return res.status(404).json({error:'Leaderboard not found'}); if(!Array.isArray(req.body))return res.status(400).json({error:'Array required'}); data.leaderboards[req.params.name]=req.body; await save(); res.json({name:req.params.name,entries:data.leaderboards[req.params.name]}); });
app.post('/api/leaderboards/:name/scores', async (req,res)=>{ if(!data.lbOrder.includes(req.params.name))return res.status(404).json({error:'Leaderboard not found'}); const username=String(req.body?.username||'').trim(); const score=Number(req.body?.score); if(!username||!Number.isFinite(score))return res.status(400).json({error:'Invalid score'}); const entry={username,score,timestamp:Date.now()}; data.leaderboards[req.params.name].push(entry);data.leaderboards[req.params.name].sort((a,b)=>b.score-a.score);await save();res.status(201).json(entry); });

app.get('/api/title-data', (req,res)=>res.json(data.titleData));
app.put('/api/title-data', async (req,res)=>{ if(!req.body||typeof req.body!=='object'||Array.isArray(req.body))return res.status(400).json({error:'Object required'}); data.titleData=req.body;await save();res.json(data.titleData); });
app.get('/api/catalog', (req,res)=>res.json(data.catalog));
app.put('/api/catalog', async (req,res)=>{ const {currencies,items}=req.body||{}; if(!Array.isArray(currencies)||!Array.isArray(items))return res.status(400).json({error:'currencies and items arrays required'}); data.catalog={currencies,items};await save();res.json(data.catalog); });

app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({error:'Internal server error'}); });
app.use((req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

await load();
app.listen(PORT,()=>console.log(`VAULT running at http://localhost:${PORT}`));
