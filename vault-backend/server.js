import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { Pool } from 'pg';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.VAULT_SECRET || 'dev-only-change-me';
const GAME_API_KEY = process.env.GAME_API_KEY || '';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required. Create a PostgreSQL database and set DATABASE_URL.');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
const app = express();

const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin(origin, cb) { if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return cb(null, true); return cb(new Error('CORS origin not allowed')); } }));
app.use(express.json({ limit: '1mb' }));

const DEFAULT_CATALOG = {
  currencies: [{ code: 'GOLD', name: 'Gold' }, { code: 'GEMS', name: 'Gems' }],
  items: [
    { id: 'neon_skin', name: 'Neon Skin', category: 'Skin', price: { currency: 'GOLD', amount: 500 }, repeatable: false },
    { id: 'confetti_emote', name: 'Confetti Burst', category: 'Emote', price: { currency: 'GEMS', amount: 150 }, repeatable: true },
    { id: 'crown_hat', name: 'Golden Crown', category: 'Hat', price: { currency: 'GEMS', amount: 400 }, repeatable: false }
  ]
};

async function dbInit() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS vault_settings (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS players (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      currency JSONB NOT NULL DEFAULT '{}'::jsonb,
      inventory JSONB NOT NULL DEFAULT '[]'::jsonb,
      banned BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE TABLE IF NOT EXISTS leaderboards (
      name TEXT PRIMARY KEY,
      entries JSONB NOT NULL DEFAULT '[]'::jsonb
    );
    CREATE INDEX IF NOT EXISTS players_username_idx ON players(username);
  `);
  await pool.query(`INSERT INTO vault_settings(key,value) VALUES ('titleData',$1) ON CONFLICT (key) DO NOTHING`, [{ game_version:'1.0.0', maintenance_mode:'false' }]);
  await pool.query(`INSERT INTO vault_settings(key,value) VALUES ('catalog',$1) ON CONFLICT (key) DO NOTHING`, [DEFAULT_CATALOG]);
  await pool.query(`INSERT INTO vault_settings(key,value) VALUES ('apiCalls','0') ON CONFLICT (key) DO NOTHING`);
}

function id(prefix='p') { return `${prefix}_${crypto.randomBytes(7).toString('hex')}`; }
function hashPassword(value, salt = crypto.randomBytes(16).toString('hex')) { return `${salt}:${crypto.scryptSync(value, salt, 32).toString('hex')}`; }
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
function adminAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  const [body, sig] = token.split('.');
  if (!body || !sig) return res.status(401).json({ error:'Unauthorized' });
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return res.status(401).json({ error:'Unauthorized' });
  try { const p = JSON.parse(Buffer.from(body,'base64url').toString()); if (p.exp < Date.now()) throw new Error(); req.user=p.sub; next(); } catch { res.status(401).json({ error:'Unauthorized' }); }
}
function gameAuth(req,res,next) {
  if (!GAME_API_KEY || req.headers['x-vault-game-key'] !== GAME_API_KEY) return res.status(401).json({ error:'Invalid game API key' });
  next();
}
function validateName(name) { return typeof name === 'string' && /^[a-zA-Z0-9_.-]{1,32}$/.test(name); }
async function setting(key, fallback=null) { const r=await pool.query('SELECT value FROM vault_settings WHERE key=$1',[key]); return r.rowCount ? r.rows[0].value : fallback; }
async function setSetting(key,value) { await pool.query(`INSERT INTO vault_settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`,[key,value]); }
async function incrementCalls() { await pool.query(`UPDATE vault_settings SET value = (COALESCE(value::text,'0')::bigint + 1)::text::jsonb WHERE key='apiCalls'`); }
async function playerObject(row) { if (!row) return null; return { id:row.id, username:row.username, createdAt:Number(row.created_at), data:row.data || {}, currency:row.currency || {}, inventory:row.inventory || [], banned:row.banned }; }
async function requirePlayer(pid,res) { const r=await pool.query('SELECT * FROM players WHERE id=$1',[pid]); if(!r.rowCount){res.status(404).json({error:'Player not found'});return null;} return r.rows[0]; }

app.get('/api/health', async (req,res)=>{ try { await pool.query('SELECT 1'); res.json({ok:true,service:'vault',database:'postgresql',time:new Date().toISOString()}); } catch { res.status(503).json({ok:false,error:'Database unavailable'}); } });
app.get('/api/auth/status', async (req,res)=>res.json({configured:!!(await setting('auth'))}));
app.post('/api/auth/setup', async (req,res)=>{ if(await setting('auth')) return res.status(409).json({error:'Passcode already configured'}); const {passcode}=req.body||{}; if(typeof passcode!=='string'||passcode.length<4)return res.status(400).json({error:'Passcode must be at least 4 characters'}); await setSetting('auth',{password:hashPassword(passcode),createdAt:Date.now()}); res.json({token:tokenFor('admin')}); });
app.post('/api/auth/login', async (req,res)=>{ const {passcode}=req.body||{}; const auth=await setting('auth'); if(!auth||!verifyPassword(String(passcode||''),auth.password))return res.status(401).json({error:'Incorrect passcode'}); res.json({token:tokenFor('admin')}); });

app.use('/api', adminAuth);
app.get('/api/state', async (req,res)=>{ const [players,lbs,titleData,catalog,apiCalls]=await Promise.all([pool.query('SELECT * FROM players ORDER BY created_at ASC'),pool.query('SELECT * FROM leaderboards ORDER BY name ASC'),setting('titleData',{}),setting('catalog',DEFAULT_CATALOG),setting('apiCalls',0)]); await incrementCalls(); const ps={}; const po=[]; for(const row of players.rows){const p=await playerObject(row);ps[p.id]=p;po.push(p.id);} const ls={}; const lo=[]; for(const row of lbs.rows){ls[row.name]=row.entries||[];lo.push(row.name);} res.json({players:ps,playerOrder:po,leaderboards:ls,lbOrder:lo,titleData,catalog,apiCalls:Number(apiCalls||0)+1}); });
app.get('/api/stats', async (req,res)=>{ const [p,l,t,c,a]=await Promise.all([pool.query('SELECT count(*)::int n FROM players'),pool.query('SELECT count(*)::int n FROM leaderboards'),setting('titleData',{}),setting('catalog',DEFAULT_CATALOG),setting('apiCalls',0)]); res.json({players:p.rows[0].n,leaderboards:l.rows[0].n,titleDataKeys:Object.keys(t||{}).length,currencies:(c.currencies||[]).length,items:(c.items||[]).length,apiCalls:Number(a||0)}); });
app.get('/api/players', async (req,res)=>{const r=await pool.query('SELECT * FROM players ORDER BY created_at ASC');await incrementCalls();res.json(await Promise.all(r.rows.map(playerObject)));});
app.post('/api/players', async (req,res)=>{const {username}=req.body||{};if(!validateName(username))return res.status(400).json({error:'Username must be 1-32 characters: letters, numbers, _, ., -'});const p={id:id(),username,createdAt:Date.now(),data:{},currency:{},inventory:[],banned:false};await pool.query('INSERT INTO players(id,username,created_at,data,currency,inventory,banned) VALUES($1,$2,$3,$4,$5,$6,$7)',[p.id,p.username,p.createdAt,p.data,p.currency,p.inventory,false]);await incrementCalls();res.status(201).json(p);});
app.get('/api/players/:pid', async (req,res)=>{const p=await requirePlayer(req.params.pid,res);if(p)res.json(await playerObject(p));});
app.put('/api/players/:pid', async (req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;const b=req.body||{};const username=b.username===undefined?p.username:b.username; if(!validateName(username))return res.status(400).json({error:'Invalid username'}); const data=b.data===undefined?p.data:b.data,currency=b.currency===undefined?p.currency:b.currency,inventory=b.inventory===undefined?p.inventory:b.inventory,banned=b.banned===undefined?p.banned:!!b.banned;await pool.query('UPDATE players SET username=$1,data=$2,currency=$3,inventory=$4,banned=$5 WHERE id=$6',[username,data,currency,inventory,banned,p.id]);await incrementCalls();res.json({id:p.id,username,createdAt:Number(p.created_at),data,currency,inventory,banned});});
app.delete('/api/players/:pid', async (req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;await pool.query('DELETE FROM players WHERE id=$1',[p.id]);await incrementCalls();res.json({ok:true});});
app.post('/api/players/:pid/ban', async(req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;await pool.query('UPDATE players SET banned=true WHERE id=$1',[p.id]);res.json({...await playerObject(p),banned:true});});
app.post('/api/players/:pid/unban', async(req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;await pool.query('UPDATE players SET banned=false WHERE id=$1',[p.id]);res.json({...await playerObject(p),banned:false});});
app.post('/api/players/:pid/currency', async(req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;if(p.banned)return res.status(403).json({error:'Player is banned'});const {code,amount,operation='grant'}=req.body||{};const n=Number(amount);if(!code||!Number.isInteger(n)||n<=0||!['grant','deduct'].includes(operation))return res.status(400).json({error:'Invalid currency operation'});const currency={...(p.currency||{})};currency[code]=(currency[code]||0)+(operation==='deduct'?-n:n);if(currency[code]<0)return res.status(400).json({error:'Not enough balance'});await pool.query('UPDATE players SET currency=$1 WHERE id=$2',[currency,p.id]);res.json({...await playerObject(p),currency});});
app.post('/api/players/:pid/inventory', async(req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;if(p.banned)return res.status(403).json({error:'Player is banned'});const catalog=await setting('catalog',DEFAULT_CATALOG);const {itemId,mode='give'}=req.body||{};const item=(catalog.items||[]).find(x=>x.id===itemId);if(!item)return res.status(404).json({error:'Item not found'});const inventory=[...(p.inventory||[])].map(x=>({...x}));const currency={...(p.currency||{})};const existing=inventory.find(x=>x.itemId===item.id);if(mode==='sell'&&item.price){const bal=currency[item.price.currency]||0;if(bal<item.price.amount)return res.status(400).json({error:`Not enough ${item.price.currency}`});if(item.repeatable===false&&existing)return res.status(400).json({error:'Player already owns this item'});currency[item.price.currency]=bal-item.price.amount;}if(existing)existing.quantity++;else inventory.push({itemId:item.id,name:item.name,category:item.category,quantity:1});await pool.query('UPDATE players SET currency=$1,inventory=$2 WHERE id=$3',[currency,inventory,p.id]);res.json({...await playerObject(p),currency,inventory});});
app.delete('/api/players/:pid/inventory/:itemId',async(req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;const inventory=(p.inventory||[]).filter(x=>x.itemId!==req.params.itemId);await pool.query('UPDATE players SET inventory=$1 WHERE id=$2',[inventory,p.id]);res.json({...await playerObject(p),inventory});});

app.get('/api/leaderboards',async(req,res)=>{const r=await pool.query('SELECT name,entries FROM leaderboards ORDER BY name ASC');res.json(r.rows.map(x=>({name:x.name,entries:x.entries||[]})));});
app.post('/api/leaderboards',async(req,res)=>{const name=String(req.body?.name||'').trim().toLowerCase().replace(/\s+/g,'_');if(!/^[a-z0-9_-]{1,64}$/.test(name))return res.status(400).json({error:'Invalid leaderboard name'});try{await pool.query('INSERT INTO leaderboards(name,entries) VALUES($1,$2)',[name,[]]);res.status(201).json({name,entries:[]});}catch(e){if(e.code==='23505')return res.status(409).json({error:'Leaderboard already exists'});throw e;}});
app.put('/api/leaderboards/:name',async(req,res)=>{if(!Array.isArray(req.body))return res.status(400).json({error:'Array required'});const r=await pool.query('UPDATE leaderboards SET entries=$1 WHERE name=$2 RETURNING name,entries',[req.body,req.params.name]);if(!r.rowCount)return res.status(404).json({error:'Leaderboard not found'});res.json(r.rows[0]);});
app.post('/api/leaderboards/:name/scores',async(req,res)=>{const r=await pool.query('SELECT entries FROM leaderboards WHERE name=$1',[req.params.name]);if(!r.rowCount)return res.status(404).json({error:'Leaderboard not found'});const username=String(req.body?.username||'').trim(),score=Number(req.body?.score);if(!username||!Number.isFinite(score))return res.status(400).json({error:'Invalid score'});const entries=[...(r.rows[0].entries||[]),{username,score,timestamp:Date.now()}].sort((a,b)=>b.score-a.score);await pool.query('UPDATE leaderboards SET entries=$1 WHERE name=$2',[entries,req.params.name]);res.status(201).json(entries[entries.findIndex(x=>x.timestamp===entries[entries.length-1]?.timestamp)]||entries[0]);});

app.get('/api/title-data',async(req,res)=>res.json(await setting('titleData',{})));
app.put('/api/title-data',async(req,res)=>{if(!req.body||typeof req.body!=='object'||Array.isArray(req.body))return res.status(400).json({error:'Object required'});await setSetting('titleData',req.body);res.json(req.body);});
app.get('/api/catalog',async(req,res)=>res.json(await setting('catalog',DEFAULT_CATALOG)));
app.put('/api/catalog',async(req,res)=>{const {currencies,items}=req.body||{};if(!Array.isArray(currencies)||!Array.isArray(items))return res.status(400).json({error:'currencies and items arrays required'});const catalog={currencies,items};await setSetting('catalog',catalog);res.json(catalog);});

app.post('/api/auth/reset',async(req,res)=>{await setSetting('auth',null);res.json({ok:true});});

// Game API: use X-Vault-Game-Key. Do not ship this secret in an untrusted client for a production game.
app.use('/game', gameAuth);
app.post('/game/players',async(req,res)=>{const {username}=req.body||{};if(!validateName(username))return res.status(400).json({error:'Invalid username'});const p={id:id(),username,createdAt:Date.now(),data:{},currency:{},inventory:[],banned:false};await pool.query('INSERT INTO players(id,username,created_at,data,currency,inventory,banned) VALUES($1,$2,$3,$4,$5,$6,$7)',[p.id,p.username,p.createdAt,p.data,p.currency,p.inventory,false]);res.status(201).json(p);});
app.get('/game/players/:pid',async(req,res)=>{const p=await requirePlayer(req.params.pid,res);if(p)res.json(await playerObject(p));});
app.put('/game/players/:pid',async(req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;const b=req.body||{};const data=b.data===undefined?p.data:b.data;await pool.query('UPDATE players SET data=$1 WHERE id=$2',[data,p.id]);res.json({...await playerObject(p),data});});
app.post('/game/players/:pid/currency',async(req,res)=>{const p=await requirePlayer(req.params.pid,res);if(!p)return;if(p.banned)return res.status(403).json({error:'Player is banned'});const {code,amount,operation='grant'}=req.body||{};const n=Number(amount);if(!code||!Number.isInteger(n)||n<=0||!['grant','deduct'].includes(operation))return res.status(400).json({error:'Invalid currency operation'});const currency={...(p.currency||{})};currency[code]=(currency[code]||0)+(operation==='deduct'?-n:n);if(currency[code]<0)return res.status(400).json({error:'Not enough balance'});await pool.query('UPDATE players SET currency=$1 WHERE id=$2',[currency,p.id]);res.json({...await playerObject(p),currency});});
app.get('/game/title-data',async(req,res)=>res.json(await setting('titleData',{})));
app.get('/game/catalog',async(req,res)=>res.json(await setting('catalog',DEFAULT_CATALOG)));
app.get('/game/leaderboards/:name',async(req,res)=>{const r=await pool.query('SELECT entries FROM leaderboards WHERE name=$1',[req.params.name]);if(!r.rowCount)return res.status(404).json({error:'Leaderboard not found'});res.json({name:req.params.name,entries:r.rows[0].entries||[]});});
app.post('/game/leaderboards/:name/scores',async(req,res)=>{const r=await pool.query('SELECT entries FROM leaderboards WHERE name=$1',[req.params.name]);if(!r.rowCount)return res.status(404).json({error:'Leaderboard not found'});const username=String(req.body?.username||'').trim(),score=Number(req.body?.score);if(!username||!Number.isFinite(score))return res.status(400).json({error:'Invalid score'});const entries=[...(r.rows[0].entries||[]),{username,score,timestamp:Date.now()}].sort((a,b)=>b.score-a.score);await pool.query('UPDATE leaderboards SET entries=$1 WHERE name=$2',[entries,req.params.name]);res.status(201).json({username,score,timestamp:entries.find(x=>x.username===username&&x.score===score)?.timestamp||Date.now()});});

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Internal server error'});});

await dbInit();
app.listen(PORT,'0.0.0.0',()=>console.log(`VAULT API running on port ${PORT}`));
