import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { Pool } from 'pg';

const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.VAULT_SECRET || 'change-this-secret';
const GAME_API_KEY = process.env.GAME_API_KEY || '';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('DATABASE_URL is required.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));

const DEFAULT_CATALOG = {
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
};

function createId(prefix = 'p') {
  return prefix + '_' + crypto.randomBytes(7).toString('hex');
}

function hashPassword(value) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(value, salt, 32).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(value, stored) {
  if (!stored || !stored.includes(':')) {
    return false;
  }

  const parts = stored.split(':');
  const salt = parts[0];
  const hash = parts[1];

  try {
    const actual = crypto.scryptSync(value, salt, 32).toString('hex');

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
  const authorization = req.headers.authorization || '';

  if (!authorization.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  const token = authorization.slice(7);
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

  if (signature.length !== expected.length) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  if (!crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  )) {
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
        error: 'Unauthorized'
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

function validateName(name) {
  return (
    typeof name === 'string' &&
    /^[a-zA-Z0-9_.-]{1,32}$/.test(name)
  );
}

async function setting(key, fallback = null) {
  const result = await pool.query(
    'SELECT value FROM vault_settings WHERE key = $1',
    [key]
  );

  if (result.rowCount > 0) {
    return result.rows[0].value;
  }

  return fallback;
}

async function setSetting(key, value) {
  await pool.query(
    'INSERT INTO vault_settings(key, value) VALUES($1, $2) ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value',
    [key, value]
  );
}

async function incrementCalls() {
  await pool.query(
    "UPDATE vault_settings SET value = ((COALESCE(value::text, '0')::bigint + 1)::text)::jsonb WHERE key = 'apiCalls'"
  );
}

function playerObject(row) {
  if (!row) {
    return null;
  }

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

async function getPlayer(pid) {
  const result = await pool.query(
    'SELECT * FROM players WHERE id = $1',
    [pid]
  );

  if (!result.rowCount) {
    return null;
  }

  return result.rows[0];
}

async function dbInit() {
  const createSettings =
    'CREATE TABLE IF NOT EXISTS vault_settings (' +
    'key TEXT PRIMARY KEY,' +
    'value JSONB NOT NULL' +
    ')';

  const createPlayers =
    'CREATE TABLE IF NOT EXISTS players (' +
    'id TEXT PRIMARY KEY,' +
    'username TEXT NOT NULL,' +
    'created_at BIGINT NOT NULL,' +
    "data JSONB NOT NULL DEFAULT '{}'::jsonb," +
    "currency JSONB NOT NULL DEFAULT '{}'::jsonb," +
    "inventory JSONB NOT NULL DEFAULT '[]'::jsonb," +
    'banned BOOLEAN NOT NULL DEFAULT FALSE' +
    ')';

  const createLeaderboards =
    'CREATE TABLE IF NOT EXISTS leaderboards (' +
    'name TEXT PRIMARY KEY,' +
    "entries JSONB NOT NULL DEFAULT '[]'::jsonb" +
    ')';

  await pool.query(createSettings);
  await pool.query(createPlayers);
  await pool.query(createLeaderboards);

  await pool.query(
    'CREATE INDEX IF NOT EXISTS players_username_idx ON players(username)'
  );

  await pool.query(
    'INSERT INTO vault_settings(key, value) VALUES($1, $2) ON CONFLICT(key) DO NOTHING',
    [
      'titleData',
      {
        game_version: '1.0.0',
        maintenance_mode: 'false'
      }
    ]
  );

  await pool.query(
    'INSERT INTO vault_settings(key, value) VALUES($1, $2) ON CONFLICT(key) DO NOTHING',
    [
      'catalog',
      DEFAULT_CATALOG
    ]
  );

  await pool.query(
    'INSERT INTO vault_settings(key, value) VALUES($1, $2) ON CONFLICT(key) DO NOTHING',
    [
      'apiCalls',
      0
    ]
  );

  console.log('Database initialized successfully.');
}

app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'Snakes Games Vault API',
    status: 'online',
    version: '2.0.0'
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
  try {
    const auth = await setting('auth');

    res.json({
      configured: !!auth
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/api/auth/setup', async (req, res) => {
  try {
    const existing = await setting('auth');

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
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const passcode = String(
      req.body?.passcode || ''
    );

    const auth = await setting('auth');

    if (
      !auth ||
      !verifyPassword(passcode, auth.password)
    ) {
      return res.status(401).json({
        error: 'Incorrect passcode'
      });
    }

    res.json({
      token: createToken('admin')
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.use('/api', adminAuth);

app.get('/api/state', async (req, res) => {
  try {
    const playersResult = await pool.query(
      'SELECT * FROM players ORDER BY created_at ASC'
    );

    const leaderboardResult = await pool.query(
      'SELECT * FROM leaderboards ORDER BY name ASC'
    );

    const titleData = await setting(
      'titleData',
      {}
    );

    const catalog = await setting(
      'catalog',
      DEFAULT_CATALOG
    );

    const apiCalls = await setting(
      'apiCalls',
      0
    );

    await incrementCalls();

    const players = {};
    const playerOrder = [];

    for (const row of playersResult.rows) {
      const player = playerObject(row);
      players[player.id] = player;
      playerOrder.push(player.id);
    }

    const leaderboards = {};
    const lbOrder = [];

    for (const row of leaderboardResult.rows) {
      leaderboards[row.name] = row.entries || [];
      lbOrder.push(row.name);
    }

    res.json({
      players,
      playerOrder,
      leaderboards,
      lbOrder,
      titleData,
      catalog,
      apiCalls: Number(apiCalls || 0) + 1
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const players = await pool.query(
      'SELECT COUNT(*)::int AS count FROM players'
    );

    const leaderboards = await pool.query(
      'SELECT COUNT(*)::int AS count FROM leaderboards'
    );

    const titleData = await setting(
      'titleData',
      {}
    );

    const catalog = await setting(
      'catalog',
      DEFAULT_CATALOG
    );

    const apiCalls = await setting(
      'apiCalls',
      0
    );

    res.json({
      players: players.rows[0].count,
      leaderboards: leaderboards.rows[0].count,
      titleDataKeys: Object.keys(titleData || {}).length,
      currencies: (catalog.currencies || []).length,
      items: (catalog.items || []).length,
      apiCalls: Number(apiCalls || 0)
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/api/players', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM players ORDER BY created_at ASC'
    );

    await incrementCalls();

    res.json(
      result.rows.map(playerObject)
    );
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/api/players', async (req, res) => {
  try {
    const username = req.body?.username;

    if (!validateName(username)) {
      return res.status(400).json({
        error: 'Username must be 1-32 characters'
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
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/api/players/:pid', async (req, res) => {
  try {
    const player = await getPlayer(
      req.params.pid
    );

    if (!player) {
      return res.status(404).json({
        error: 'Player not found'
      });
    }

    res.json(playerObject(player));
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.put('/api/players/:pid', async (req, res) => {
  try {
    const player = await getPlayer(
      req.params.pid
    );

    if (!player) {
      return res.status(404).json({
        error: 'Player not found'
      });
    }

    const body = req.body || {};

    const username =
      body.username === undefined
        ? player.username
        : body.username;

    if (!validateName(username)) {
      return res.status(400).json({
        error: 'Invalid username'
      });
    }

    const data =
      body.data === undefined
        ? player.data
        : body.data;

    const currency =
      body.currency === undefined
        ? player.currency
        : body.currency;

    const inventory =
      body.inventory === undefined
        ? player.inventory
        : body.inventory;

    const banned =
      body.banned === undefined
        ? player.banned
        : !!body.banned;

    await pool.query(
      'UPDATE players SET username=$1,data=$2,currency=$3,inventory=$4,banned=$5 WHERE id=$6',
      [
        username,
        data,
        currency,
        inventory,
        banned,
        player.id
      ]
    );

    await incrementCalls();

    res.json({
      id: player.id,
      username,
      createdAt: Number(player.created_at),
      data,
      currency,
      inventory,
      banned
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.delete('/api/players/:pid', async (req, res) => {
  try {
    const player = await getPlayer(
      req.params.pid
    );

    if (!player) {
      return res.status(404).json({
        error: 'Player not found'
      });
    }

    await pool.query(
      'DELETE FROM players WHERE id=$1',
      [player.id]
    );

    await incrementCalls();

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/api/players/:pid/ban', async (req, res) => {
  try {
    const player = await getPlayer(
      req.params.pid
    );

    if (!player) {
      return res.status(404).json({
        error: 'Player not found'
      });
    }

    await pool.query(
      'UPDATE players SET banned=true WHERE id=$1',
      [player.id]
    );

    res.json({
      ...playerObject(player),
      banned: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/api/players/:pid/unban', async (req, res) => {
  try {
    const player = await getPlayer(
      req.params.pid
    );

    if (!player) {
      return res.status(404).json({
        error: 'Player not found'
      });
    }

    await pool.query(
      'UPDATE players SET banned=false WHERE id=$1',
      [player.id]
    );

    res.json({
      ...playerObject(player),
      banned: false
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/api/players/:pid/currency', async (req, res) => {
  try {
    const player = await getPlayer(
      req.params.pid
    );

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
    const amount = Number(
      req.body?.amount
    );
    const operation =
      req.body?.operation || 'grant';

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
      (
        operation === 'deduct'
          ? -amount
          : amount
      );

    if (currency[code] < 0) {
      return res.status(400).json({
        error: 'Not enough balance'
      });
    }

    await pool.query(
      'UPDATE players SET currency=$1 WHERE id=$2',
      [
        currency,
        player.id
      ]
    );

    res.json({
      ...playerObject(player),
      currency
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/api/leaderboards', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT name,entries FROM leaderboards ORDER BY name ASC'
    );

    res.json(
      result.rows.map(row => ({
        name: row.name,
        entries: row.entries || []
      }))
    );
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.post('/api/leaderboards', async (req, res) => {
  try {
    const name = String(
      req.body?.name || ''
    )
      .trim()
      .toLowerCase()
      .replace(/\s+/g, '_');

    if (!/^[a-z0-9_-]{1,64}$/.test(name)) {
      return res.status(400).json({
        error: 'Invalid leaderboard name'
      });
    }

    await pool.query(
      'INSERT INTO leaderboards(name,entries) VALUES($1,$2)',
      [
        name,
        []
      ]
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

    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/api/title-data', async (req, res) => {
  try {
    res.json(
      await setting(
        'titleData',
        {}
      )
    );
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/api/catalog', async (req, res) => {
  try {
    res.json(
      await setting(
        'catalog',
        DEFAULT_CATALOG
      )
    );
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.use('/game', gameAuth);

app.get('/game/health', async (req, res) => {
  res.json({
    ok: true,
    service: 'game-api',
    status: 'online'
  });
});

app.post('/game/players', async (req, res) => {
  try {
    const username = req.body?.username;

    if (!validateName(username)) {
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
      'INSERT INTO players(id,username,created_at,data,currency,inventory,banned) VALUES($1,$2,$3,$4,$5,$6,$7)',
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
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/game/players/:pid', async (req, res) => {
  try {
    const player = await getPlayer(
      req.params.pid
    );

    if (!player) {
      return res.status(404).json({
        error: 'Player not found'
      });
    }

    res.json(playerObject(player));
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.put('/game/players/:pid', async (req, res) => {
  try {
    const player = await getPlayer(
      req.params.pid
    );

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
      'UPDATE players SET data=$1 WHERE id=$2',
      [
        data,
        player.id
      ]
    );

    res.json({
      ...playerObject(player),
      data
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/game/title-data', async (req, res) => {
  try {
    res.json(
      await setting(
        'titleData',
        {}
      )
    );
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/game/catalog', async (req, res) => {
  try {
    res.json(
      await setting(
        'catalog',
        DEFAULT_CATALOG
      )
    );
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.get('/game/leaderboards/:name', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT entries FROM leaderboards WHERE name=$1',
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
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);

  res.status(500).json({
    error: 'Internal server error'
  });
});

async function start() {
  try {
    console.log('Connecting to PostgreSQL...');

    await pool.query('SELECT 1');

    console.log('PostgreSQL connection successful.');

    await dbInit();

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
