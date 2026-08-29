import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { Pool } from 'pg';

const app = express();

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const SECRET = process.env.VAULT_SECRET || 'change-this-secret';
const GAME_API_KEY = process.env.GAME_API_KEY || '';

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors());
app.use(express.json({ limit: '1mb' }));

function createId(prefix = 'p') {
  return prefix + '_' + crypto.randomBytes(7).toString('hex');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 32).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;

  const parts = stored.split(':');
  const salt = parts[0];
  const hash = parts[1];

  try {
    const actual = crypto.scryptSync(password, salt, 32).toString('hex');

    if (actual.length !== hash.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      Buffer.from(actual),
      Buffer.from(hash)
    );
  } catch {
    return false;
  }
}

function createToken(subject) {
  const payload = {
    sub: subject,
    exp: Date.now() + 604800000
  };

  const body = Buffer
    .from(JSON.stringify(payload))
    .toString('base64url');

  const signature = crypto
    .createHmac('sha256', SECRET)
    .update(body)
    .digest('base64url');

  return body + '.' + signature;
}

function adminAuth(req, res, next) {
  const auth = req.headers.authorization || '';

  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  const token = auth.substring(7);
  const parts = token.split('.');

  if (parts.length !== 2) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  const body = parts[0];
  const signature = parts[1];

  const expected = crypto
    .createHmac('sha256', SECRET)
    .update(body)
    .digest('base64url');

  if (signature !== expected) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  try {
    const payload = JSON.parse(
      Buffer.from(body, 'base64url').toString()
    );

    if (!payload.exp || payload.exp < Date.now()) {
      return res.status(401).json({
        error: 'Token expired'
      });
    }

    req.user = payload.sub;
    next();
  } catch {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }
}

function gameAuth(req, res, next) {
  if (!GAME_API_KEY) {
    return res.status(500).json({
      error: 'GAME_API_KEY is not configured'
    });
  }

  if (req.headers['x-vault-game-key'] !== GAME_API_KEY) {
    return res.status(401).json({
      error: 'Invalid game API key'
    });
  }

  next();
}

function validUsername(username) {
  return (
    typeof username === 'string' &&
    /^[a-zA-Z0-9_.-]{1,32}$/.test(username)
  );
}

function playerObject(row) {
  return {
    id: row.id,
    username: row.username,
    createdAt: Number(row.created_at),
    data: row.data || {},
    currency: row.currency || {},
    inventory: row.inventory || [],
    banned: row.banned
  };
}

async function getSetting(key, fallback = null) {
  const result = await pool.query(
    'SELECT value FROM vault_settings WHERE key = $1',
    [key]
  );

  if (!result.rowCount) {
    return fallback;
  }

  return result.rows[0].value;
}

async function setSetting(key, value) {
  await pool.query(
    'INSERT INTO vault_settings(key, value) VALUES($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value',
    [key, value]
  );
}

async function incrementCalls() {
  await pool.query(
    "UPDATE vault_settings SET value = to_jsonb((COALESCE(value #>> '{}', '0')::bigint + 1)::text) WHERE key = 'apiCalls'"
  );
}

async function getPlayer(id) {
  const result = await pool.query(
    'SELECT * FROM players WHERE id = $1',
    [id]
  );

  return result.rowCount ? result.rows[0] : null;
}

async function initializeDatabase() {
  await pool.query(
    'CREATE TABLE IF NOT EXISTS vault_settings (key TEXT PRIMARY KEY, value JSONB NOT NULL)'
  );

  await pool.query(
    'CREATE TABLE IF NOT EXISTS players (id TEXT PRIMARY KEY, username TEXT NOT NULL, created_at BIGINT NOT NULL, data JSONB NOT NULL DEFAULT \'{}\'::jsonb, currency JSONB NOT NULL DEFAULT \'{}\'::jsonb, inventory JSONB NOT NULL DEFAULT \'[]\'::jsonb, banned BOOLEAN NOT NULL DEFAULT FALSE)'
  );

  await pool.query(
    'CREATE TABLE IF NOT EXISTS leaderboards (name TEXT PRIMARY KEY, entries JSONB NOT NULL DEFAULT \'[]\'::jsonb)'
  );

  await pool.query(
    'CREATE INDEX IF NOT EXISTS players_username_idx ON players(username)'
  );

  const titleData = await getSetting('titleData');

  if (titleData === null) {
    await setSetting('titleData', {
      game_version: '1.0.0',
      maintenance_mode: false
    });
  }

  const catalog = await getSetting('catalog');

  if (catalog === null) {
    await setSetting('catalog', {
      currencies: [
        {
          code: 'GOLD',
          name: 'Gold'
        },
        {
          code: 'GEMS',
          name: 'Gems'
        }
      ],
      items: [
        {
          id: 'neon_skin',
          name: 'Neon Skin',
          category: 'Skin',
          price: {
            currency: 'GOLD',
            amount: 500
          },
          repeatable: false
        },
        {
          id: 'confetti_emote',
          name: 'Confetti Burst',
          category: 'Emote',
          price: {
            currency: 'GEMS',
            amount: 150
          },
          repeatable: true
        },
        {
          id: 'crown_hat',
          name: 'Golden Crown',
          category: 'Hat',
          price: {
            currency: 'GEMS',
            amount: 400
          },
          repeatable: false
        }
      ]
    });
  }

  const apiCalls = await getSetting('apiCalls');

  if (apiCalls === null) {
    await setSetting('apiCalls', '0');
  }

  console.log('Database initialized.');
}

app.get('/', (req, res) => {
  res.status(200).json({
    ok: true,
    service: 'Snakes Games Vault API',
    status: 'online',
    version: '2.0.0',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth/status',
      catalog: '/api/catalog'
    }
  });
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      service: 'vault',
      database: 'postgresql',
      time: new Date().toISOString()
    });
  } catch (error) {
    console.error(error);

    res.status(503).json({
      ok: false,
      error: 'Database unavailable'
    });
  }
});

app.get('/api/auth/status', async (req, res) => {
  const auth = await getSetting('auth');

  res.json({
    configured: !!auth
  });
});

app.post('/api/auth/setup', async (req, res) => {
  const existing = await getSetting('auth');

  if (existing) {
    return res.status(409).json({
      error: 'Passcode already configured'
    });
  }

  const passcode = req.body?.passcode;

  if (
    typeof passcode !== 'string' ||
    passcode.length < 4
  ) {
    return res.status(400).json({
      error: 'Passcode must be at least 4 characters'
    });
  }

  await setSetting('auth', {
    password: hashPassword(passcode),
    createdAt: Date.now()
  });

  res.json({
    token: createToken('admin')
  });
});

app.post('/api/auth/login', async (req, res) => {
  const passcode = String(req.body?.passcode || '');
  const auth = await getSetting('auth');

  if (!auth || !verifyPassword(passcode, auth.password)) {
    return res.status(401).json({
      error: 'Incorrect passcode'
    });
  }

  res.json({
    token: createToken('admin')
  });
});

app.use('/api/admin', adminAuth);

app.get('/api/admin/state', async (req, res) => {
  const players = await pool.query(
    'SELECT * FROM players ORDER BY created_at ASC'
  );

  const leaderboards = await pool.query(
    'SELECT * FROM leaderboards ORDER BY name ASC'
  );

  const titleData = await getSetting('titleData', {});
  const catalog = await getSetting('catalog', {});
  const apiCalls = await getSetting('apiCalls', '0');

  await incrementCalls();

  const playerMap = {};
  const playerOrder = [];

  for (const row of players.rows) {
    const player = playerObject(row);
    playerMap[player.id] = player;
    playerOrder.push(player.id);
  }

  const leaderboardMap = {};
  const leaderboardOrder = [];

  for (const row of leaderboards.rows) {
    leaderboardMap[row.name] = row.entries || [];
    leaderboardOrder.push(row.name);
  }

  res.json({
    players: playerMap,
    playerOrder,
    leaderboards: leaderboardMap,
    lbOrder: leaderboardOrder,
    titleData,
    catalog,
    apiCalls: Number(apiCalls) + 1
  });
});

app.get('/api/admin/stats', async (req, res) => {
  const players = await pool.query(
    'SELECT COUNT(*)::int AS count FROM players'
  );

  const leaderboards = await pool.query(
    'SELECT COUNT(*)::int AS count FROM leaderboards'
  );

  const titleData = await getSetting('titleData', {});
  const catalog = await getSetting('catalog', {});
  const apiCalls = await getSetting('apiCalls', '0');

  res.json({
    players: players.rows[0].count,
    leaderboards: leaderboards.rows[0].count,
    titleDataKeys: Object.keys(titleData).length,
    currencies: (catalog.currencies || []).length,
    items: (catalog.items || []).length,
    apiCalls: Number(apiCalls)
  });
});

app.get('/api/admin/players', async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM players ORDER BY created_at ASC'
  );

  await incrementCalls();

  res.json(
    result.rows.map(playerObject)
  );
});

app.post('/api/admin/players', async (req, res) => {
  const username = req.body?.username;

  if (!validUsername(username)) {
    return res.status(400).json({
      error: 'Invalid username'
    });
  }

  const player = {
    id: createId(),
    username,
    createdAt: Date.now(),
    data: {},
    currency: {},
    inventory: [],
    banned: false
  };

  await pool.query(
    'INSERT INTO players(id, username, created_at, data, currency, inventory, banned) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [
      player.id,
      player.username,
      player.createdAt,
      player.data,
      player.currency,
      player.inventory,
      false
    ]
  );

  await incrementCalls();

  res.status(201).json(player);
});

app.get('/api/admin/players/:id', async (req, res) => {
  const player = await getPlayer(req.params.id);

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  res.json(playerObject(player));
});

app.delete('/api/admin/players/:id', async (req, res) => {
  const player = await getPlayer(req.params.id);

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  await pool.query(
    'DELETE FROM players WHERE id = $1',
    [player.id]
  );

  await incrementCalls();

  res.json({
    ok: true
  });
});

app.post('/api/admin/players/:id/ban', async (req, res) => {
  const player = await getPlayer(req.params.id);

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  await pool.query(
    'UPDATE players SET banned = true WHERE id = $1',
    [player.id]
  );

  res.json({
    ok: true,
    banned: true
  });
});

app.post('/api/admin/players/:id/unban', async (req, res) => {
  const player = await getPlayer(req.params.id);

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  await pool.query(
    'UPDATE players SET banned = false WHERE id = $1',
    [player.id]
  );

  res.json({
    ok: true,
    banned: false
  });
});

app.get('/api/admin/title-data', async (req, res) => {
  res.json(
    await getSetting('titleData', {})
  );
});

app.put('/api/admin/title-data', async (req, res) => {
  if (
    !req.body ||
    typeof req.body !== 'object' ||
    Array.isArray(req.body)
  ) {
    return res.status(400).json({
      error: 'Object required'
    });
  }

  await setSetting('titleData', req.body);

  res.json(req.body);
});

app.get('/api/admin/catalog', async (req, res) => {
  res.json(
    await getSetting('catalog', {})
  );
});

app.put('/api/admin/catalog', async (req, res) => {
  const currencies = req.body?.currencies;
  const items = req.body?.items;

  if (
    !Array.isArray(currencies) ||
    !Array.isArray(items)
  ) {
    return res.status(400).json({
      error: 'currencies and items arrays required'
    });
  }

  const catalog = {
    currencies,
    items
  };

  await setSetting('catalog', catalog);

  res.json(catalog);
});

app.get('/api/admin/leaderboards', async (req, res) => {
  const result = await pool.query(
    'SELECT name, entries FROM leaderboards ORDER BY name ASC'
  );

  res.json(
    result.rows.map(row => ({
      name: row.name,
      entries: row.entries || []
    }))
  );
});

app.post('/api/admin/leaderboards', async (req, res) => {
  const name = String(req.body?.name || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_');

  if (!/^[a-z0-9_-]{1,64}$/.test(name)) {
    return res.status(400).json({
      error: 'Invalid leaderboard name'
    });
  }

  try {
    await pool.query(
      'INSERT INTO leaderboards(name, entries) VALUES($1,$2)',
      [name, []]
    );

    res.status(201).json({
      name,
      entries: []
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Leaderboard already exists'
      });
    }

    throw error;
  }
});

app.post('/api/admin/leaderboards/:name/scores', async (req, res) => {
  const result = await pool.query(
    'SELECT entries FROM leaderboards WHERE name = $1',
    [req.params.name]
  );

  if (!result.rowCount) {
    return res.status(404).json({
      error: 'Leaderboard not found'
    });
  }

  const username = String(
    req.body?.username || ''
  ).trim();

  const score = Number(req.body?.score);

  if (!username || !Number.isFinite(score)) {
    return res.status(400).json({
      error: 'Invalid score'
    });
  }

  const entry = {
    username,
    score,
    timestamp: Date.now()
  };

  const entries = [
    ...(result.rows[0].entries || []),
    entry
  ].sort((a, b) => b.score - a.score);

  await pool.query(
    'UPDATE leaderboards SET entries = $1 WHERE name = $2',
    [entries, req.params.name]
  );

  res.status(201).json(entry);
});

app.use('/game', gameAuth);

app.get('/game/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      service: 'vault-game-api'
    });
  } catch {
    res.status(503).json({
      ok: false
    });
  }
});

app.post('/game/players', async (req, res) => {
  const username = req.body?.username;

  if (!validUsername(username)) {
    return res.status(400).json({
      error: 'Invalid username'
    });
  }

  const player = {
    id: createId(),
    username,
    createdAt: Date.now(),
    data: {},
    currency: {},
    inventory: [],
    banned: false
  };

  await pool.query(
    'INSERT INTO players(id, username, created_at, data, currency, inventory, banned) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [
      player.id,
      player.username,
      player.createdAt,
      player.data,
      player.currency,
      player.inventory,
      false
    ]
  );

  res.status(201).json(player);
});

app.get('/game/players/:id', async (req, res) => {
  const player = await getPlayer(req.params.id);

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  res.json(playerObject(player));
});

app.put('/game/players/:id', async (req, res) => {
  const player = await getPlayer(req.params.id);

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  const data =
    req.body?.data === undefined
      ? player.data
      : req.body.data;

  await pool.query(
    'UPDATE players SET data = $1 WHERE id = $2',
    [data, player.id]
  );

  res.json({
    ...playerObject(player),
    data
  });
});

app.post('/game/players/:id/currency', async (req, res) => {
  const player = await getPlayer(req.params.id);

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  if (player.banned) {
    return res.status(403).json({
      error: 'Player is banned'
    });
  }

  const code = req.body?.code;
  const amount = Number(req.body?.amount);
  const operation = req.body?.operation || 'grant';

  if (
    !code ||
    !Number.isInteger(amount) ||
    amount <= 0 ||
    !['grant', 'deduct'].includes(operation)
  ) {
    return res.status(400).json({
      error: 'Invalid currency operation'
    });
  }

  const currency = {
    ...(player.currency || {})
  };

  currency[code] =
    (currency[code] || 0) +
    (operation === 'deduct' ? -amount : amount);

  if (currency[code] < 0) {
    return res.status(400).json({
      error: 'Not enough balance'
    });
  }

  await pool.query(
    'UPDATE players SET currency = $1 WHERE id = $2',
    [currency, player.id]
  );

  res.json({
    ...playerObject(player),
    currency
  });
});

app.get('/game/catalog', async (req, res) => {
  res.json(
    await getSetting('catalog', {})
  );
});

app.get('/game/title-data', async (req, res) => {
  res.json(
    await getSetting('titleData', {})
  );
});

app.get('/game/leaderboards/:name', async (req, res) => {
  const result = await pool.query(
    'SELECT entries FROM leaderboards WHERE name = $1',
    [req.params.name]
  );

  if (!result.rowCount) {
    return res.status(404).json({
      error: 'Leaderboard not found'
    });
  }

  res.json({
    name: req.params.name,
    entries: result.rows[0].entries || []
  });
});

app.post('/game/leaderboards/:name/scores', async (req, res) => {
  const result = await pool.query(
    'SELECT entries FROM leaderboards WHERE name = $1',
    [req.params.name]
  );

  if (!result.rowCount) {
    return res.status(404).json({
      error: 'Leaderboard not found'
    });
  }

  const username = String(
    req.body?.username || ''
  ).trim();

  const score = Number(req.body?.score);

  if (!username || !Number.isFinite(score)) {
    return res.status(400).json({
      error: 'Invalid score'
    });
  }

  const entry = {
    username,
    score,
    timestamp: Date.now()
  };

  const entries = [
    ...(result.rows[0].entries || []),
    entry
  ].sort((a, b) => b.score - a.score);

  await pool.query(
    'UPDATE leaderboards SET entries = $1 WHERE name = $2',
    [entries, req.params.name]
  );

  res.status(201).json(entry);
});

app.use((error, req, res, next) => {
  console.error('Server error:', error);

  res.status(500).json({
    error: 'Internal server error'
  });
});

async function start() {
  try {
    console.log('Connecting to PostgreSQL...');

    await pool.query('SELECT 1');

    console.log('PostgreSQL connected.');

    await initializeDatabase();

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          'VAULT API running on port ' + PORT
        );
      }
    );
  } catch (error) {
    console.error(
      'Failed to start server:',
      error
    );

    process.exit(1);
  }
}

start();
