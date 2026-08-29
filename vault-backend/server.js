```js
import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { Pool } from 'pg';

const app = express();

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

app.use(express.json({ limit: '1mb' }));

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(function (x) {
    return x.trim();
  })
  .filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (
      !origin ||
      allowedOrigins.length === 0 ||
      allowedOrigins.includes(origin)
    ) {
      callback(null, true);
      return;
    }

    callback(new Error('CORS origin not allowed'));
  }
}));

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

function createId(prefix) {
  prefix = prefix || 'p';

  return prefix + '_' + crypto
    .randomBytes(7)
    .toString('hex');
}

function hashPassword(value, salt) {
  salt = salt || crypto
    .randomBytes(16)
    .toString('hex');

  const hash = crypto
    .scryptSync(value, salt, 32)
    .toString('hex');

  return salt + ':' + hash;
}

function verifyPassword(value, stored) {
  if (!stored || !stored.includes(':')) {
    return false;
  }

  const parts = stored.split(':');

  if (parts.length !== 2) {
    return false;
  }

  const salt = parts[0];
  const hash = parts[1];

  try {
    const actual = crypto
      .scryptSync(value, salt, 32)
      .toString('hex');

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
    exp: Date.now() + (1000 * 60 * 60 * 24 * 7)
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

  const token = authorization.substring(7);
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

  if (
    !crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    )
  ) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  try {
    const payload = JSON.parse(
      Buffer
        .from(body, 'base64url')
        .toString()
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

async function getSetting(key, fallback) {
  const result = await pool.query(
    'SELECT value FROM vault_settings WHERE key = $1',
    [key]
  );

  if (result.rowCount) {
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

async function getPlayer(id) {
  const result = await pool.query(
    'SELECT * FROM players WHERE id = $1',
    [id]
  );

  if (!result.rowCount) {
    return null;
  }

  return result.rows[0];
}

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

    CREATE INDEX IF NOT EXISTS players_username_idx
    ON players(username);
  `);

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
      '0'
    ]
  );
}

/*
|--------------------------------------------------------------------------
| ROOT
|--------------------------------------------------------------------------
*/

app.get('/', function (req, res) {
  res.status(200).json({
    ok: true,
    service: 'Snakes Games Vault API',
    status: 'online',
    version: '2.0.0',
    endpoints: {
      health: '/api/health',
      authStatus: '/api/auth/status',
      stats: '/api/stats',
      catalog: '/api/catalog'
    }
  });
});

/*
|--------------------------------------------------------------------------
| HEALTH
|--------------------------------------------------------------------------
*/

app.get('/api/health', async function (req, res) {
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

/*
|--------------------------------------------------------------------------
| AUTH
|--------------------------------------------------------------------------
*/

app.get('/api/auth/status', async function (req, res) {
  const auth = await getSetting('auth', null);

  res.json({
    configured: !!auth
  });
});

app.post('/api/auth/setup', async function (req, res) {
  const existing = await getSetting('auth', null);

  if (existing) {
    return res.status(409).json({
      error: 'Passcode already configured'
    });
  }

  const passcode = req.body && req.body.passcode;

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

app.post('/api/auth/login', async function (req, res) {
  const passcode = String(
    (req.body && req.body.passcode) || ''
  );

  const auth = await getSetting('auth', null);

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
});

/*
|--------------------------------------------------------------------------
| ADMIN API
|--------------------------------------------------------------------------
*/

app.use('/api', adminAuth);

app.get('/api/stats', async function (req, res) {
  const players = await pool.query(
    'SELECT count(*)::int AS count FROM players'
  );

  const leaderboards = await pool.query(
    'SELECT count(*)::int AS count FROM leaderboards'
  );

  const titleData = await getSetting(
    'titleData',
    {}
  );

  const catalog = await getSetting(
    'catalog',
    DEFAULT_CATALOG
  );

  const apiCalls = await getSetting(
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
});

app.get('/api/state', async function (req, res) {
  const players = await pool.query(
    'SELECT * FROM players ORDER BY created_at ASC'
  );

  const leaderboards = await pool.query(
    'SELECT * FROM leaderboards ORDER BY name ASC'
  );

  const titleData = await getSetting(
    'titleData',
    {}
  );

  const catalog = await getSetting(
    'catalog',
    DEFAULT_CATALOG
  );

  const apiCalls = await getSetting(
    'apiCalls',
    0
  );

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
    playerOrder: playerOrder,
    leaderboards: leaderboardMap,
    lbOrder: leaderboardOrder,
    titleData: titleData,
    catalog: catalog,
    apiCalls: Number(apiCalls || 0) + 1
  });
});

/*
|--------------------------------------------------------------------------
| PLAYERS
|--------------------------------------------------------------------------
*/

app.get('/api/players', async function (req, res) {
  const result = await pool.query(
    'SELECT * FROM players ORDER BY created_at ASC'
  );

  await incrementCalls();

  res.json(
    result.rows.map(playerObject)
  );
});

app.post('/api/players', async function (req, res) {
  const username = req.body && req.body.username;

  if (!validateName(username)) {
    return res.status(400).json({
      error: 'Username must be 1-32 characters'
    });
  }

  const player = {
    id: createId(),
    username: username,
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

app.get('/api/players/:pid', async function (req, res) {
  const player = await getPlayer(
    req.params.pid
  );

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  res.json(
    playerObject(player)
  );
});

app.put('/api/players/:pid', async function (req, res) {
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
      : Boolean(body.banned);

  await pool.query(
    'UPDATE players SET username=$1, data=$2, currency=$3, inventory=$4, banned=$5 WHERE id=$6',
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
    username: username,
    createdAt: Number(player.created_at),
    data: data,
    currency: currency,
    inventory: inventory,
    banned: banned
  });
});

app.delete('/api/players/:pid', async function (req, res) {
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
});

app.post('/api/players/:pid/ban', async function (req, res) {
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
});

app.post('/api/players/:pid/unban', async function (req, res) {
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
});

/*
|--------------------------------------------------------------------------
| CURRENCY
|--------------------------------------------------------------------------
*/

async function changeCurrency(req, res) {
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

  const body = req.body || {};

  const code = body.code;
  const amount = Number(body.amount);
  const operation = body.operation || 'grant';

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
    (operation === 'deduct'
      ? -amount
      : amount);

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
    currency: currency
  });
}

app.post(
  '/api/players/:pid/currency',
  changeCurrency
);

/*
|--------------------------------------------------------------------------
| INVENTORY
|--------------------------------------------------------------------------
*/

app.post('/api/players/:pid/inventory', async function (req, res) {
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

  const catalog = await getSetting(
    'catalog',
    DEFAULT_CATALOG
  );

  const body = req.body || {};

  const itemId = body.itemId;
  const mode = body.mode || 'give';

  const item = (catalog.items || [])
    .find(function (x) {
      return x.id === itemId;
    });

  if (!item) {
    return res.status(404).json({
      error: 'Item not found'
    });
  }

  const inventory = [
    ...(player.inventory || [])
  ].map(function (x) {
    return {
      ...x
    };
  });

  const currency = {
    ...(player.currency || {})
  };

  const existing = inventory.find(function (x) {
    return x.itemId === item.id;
  });

  if (
    mode === 'sell' &&
    item.price
  ) {
    const balance =
      currency[item.price.currency] || 0;

    if (balance < item.price.amount) {
      return res.status(400).json({
        error:
          'Not enough ' +
          item.price.currency
      });
    }

    if (
      item.repeatable === false &&
      existing
    ) {
      return res.status(400).json({
        error: 'Player already owns this item'
      });
    }

    currency[item.price.currency] =
      balance - item.price.amount;
  }

  if (existing) {
    existing.quantity++;
  } else {
    inventory.push({
      itemId: item.id,
      name: item.name,
      category: item.category,
      quantity: 1
    });
  }

  await pool.query(
    'UPDATE players SET currency=$1, inventory=$2 WHERE id=$3',
    [
      currency,
      inventory,
      player.id
    ]
  );

  res.json({
    ...playerObject(player),
    currency: currency,
    inventory: inventory
  });
});

app.delete(
  '/api/players/:pid/inventory/:itemId',
  async function (req, res) {
    const player = await getPlayer(
      req.params.pid
    );

    if (!player) {
      return res.status(404).json({
        error: 'Player not found'
      });
    }

    const inventory = (
      player.inventory || []
    ).filter(function (x) {
      return x.itemId !== req.params.itemId;
    });

    await pool.query(
      'UPDATE players SET inventory=$1 WHERE id=$2',
      [
        inventory,
        player.id
      ]
    );

    res.json({
      ...playerObject(player),
      inventory: inventory
    });
  }
);

/*
|--------------------------------------------------------------------------
| LEADERBOARDS
|--------------------------------------------------------------------------
*/

app.get('/api/leaderboards', async function (req, res) {
  const result = await pool.query(
    'SELECT name, entries FROM leaderboards ORDER BY name ASC'
  );

  res.json(
    result.rows.map(function (row) {
      return {
        name: row.name,
        entries: row.entries || []
      };
    })
  );
});

app.post('/api/leaderboards', async function (req, res) {
  const name = String(
    (req.body && req.body.name) || ''
  )
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
      [
        name,
        []
      ]
    );

    res.status(201).json({
      name: name,
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

app.get(
  '/api/leaderboards/:name',
  async function (req, res) {
    const result = await pool.query(
      'SELECT name, entries FROM leaderboards WHERE name=$1',
      [
        req.params.name
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Leaderboard not found'
      });
    }

    res.json({
      name: result.rows[0].name,
      entries: result.rows[0].entries || []
    });
  }
);

app.post(
  '/api/leaderboards/:name/scores',
  async function (req, res) {
    const result = await pool.query(
      'SELECT entries FROM leaderboards WHERE name=$1',
      [
        req.params.name
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Leaderboard not found'
      });
    }

    const username = String(
      (req.body && req.body.username) || ''
    ).trim();

    const score = Number(
      req.body && req.body.score
    );

    if (
      !username ||
      !Number.isFinite(score)
    ) {
      return res.status(400).json({
        error: 'Invalid score'
      });
    }

    const entry = {
      username: username,
      score: score,
      timestamp: Date.now()
    };

    const entries = [
      ...(result.rows[0].entries || []),
      entry
    ].sort(function (a, b) {
      return b.score - a.score;
    });

    await pool.query(
      'UPDATE leaderboards SET entries=$1 WHERE name=$2',
      [
        entries,
        req.params.name
      ]
    );

    res.status(201).json(entry);
  }
);

/*
|--------------------------------------------------------------------------
| TITLE DATA
|--------------------------------------------------------------------------
*/

app.get('/api/title-data', async function (req, res) {
  res.json(
    await getSetting(
      'titleData',
      {}
    )
  );
});

app.put('/api/title-data', async function (req, res) {
  if (
    !req.body ||
    typeof req.body !== 'object' ||
    Array.isArray(req.body)
  ) {
    return res.status(400).json({
      error: 'Object required'
    });
  }

  await setSetting(
    'titleData',
    req.body
  );

  res.json(req.body);
});

/*
|--------------------------------------------------------------------------
| CATALOG
|--------------------------------------------------------------------------
*/

app.get('/api/catalog', async function (req, res) {
  res.json(
    await getSetting(
      'catalog',
      DEFAULT_CATALOG
    )
  );
});

app.put('/api/catalog', async function (req, res) {
  const body = req.body || {};

  if (
    !Array.isArray(body.currencies) ||
    !Array.isArray(body.items)
  ) {
    return res.status(400).json({
      error: 'currencies and items arrays required'
    });
  }

  const catalog = {
    currencies: body.currencies,
    items: body.items
  };

  await setSetting(
    'catalog',
    catalog
  );

  res.json(catalog);
});

/*
|--------------------------------------------------------------------------
| GAME API
|--------------------------------------------------------------------------
*/

app.use('/game', gameAuth);

app.get('/game/health', function (req, res) {
  res.json({
    ok: true,
    service: 'vault-game-api'
  });
});

app.post('/game/players', async function (req, res) {
  const username =
    req.body && req.body.username;

  if (!validateName(username)) {
    return res.status(400).json({
      error: 'Invalid username'
    });
  }

  const player = {
    id: createId(),
    username: username,
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
});

app.get('/game/players/:pid', async function (req, res) {
  const player = await getPlayer(
    req.params.pid
  );

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  res.json(
    playerObject(player)
  );
});

app.put('/game/players/:pid', async function (req, res) {
  const player = await getPlayer(
    req.params.pid
  );

  if (!player) {
    return res.status(404).json({
      error: 'Player not found'
    });
  }

  const data =
    req.body && req.body.data !== undefined
      ? req.body.data
      : player.data;

  await pool.query(
    'UPDATE players SET data=$1 WHERE id=$2',
    [
      data,
      player.id
    ]
  );

  res.json({
    ...playerObject(player),
    data: data
  });
});

app.post(
  '/game/players/:pid/currency',
  changeCurrency
);

app.get('/game/title-data', async function (req, res) {
  res.json(
    await getSetting(
      'titleData',
      {}
    )
  );
});

app.get('/game/catalog', async function (req, res) {
  res.json(
    await getSetting(
      'catalog',
      DEFAULT_CATALOG
    )
  );
});

app.get(
  '/game/leaderboards/:name',
  async function (req, res) {
    const result = await pool.query(
      'SELECT entries FROM leaderboards WHERE name=$1',
      [
        req.params.name
      ]
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
  }
);

app.post(
  '/game/leaderboards/:name/scores',
  async function (req, res) {
    const result = await pool.query(
      'SELECT entries FROM leaderboards WHERE name=$1',
      [
        req.params.name
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Leaderboard not found'
      });
    }

    const username = String(
      (req.body && req.body.username) || ''
    ).trim();

    const score = Number(
      req.body && req.body.score
    );

    if (
      !username ||
      !Number.isFinite(score)
    ) {
      return res.status(400).json({
        error: 'Invalid score'
      });
    }

    const entry = {
      username: username,
      score: score,
      timestamp: Date.now()
    };

    const entries = [
      ...(result.rows[0].entries || []),
      entry
    ].sort(function (a, b) {
      return b.score - a.score;
    });

    await pool.query(
      'UPDATE leaderboards SET entries=$1 WHERE name=$2',
      [
        entries,
        req.params.name
      ]
    );

    res.status(201).json(entry);
  }
);

/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/

app.use(function (err, req, res, next) {
  console.error('Server error:', err);

  res.status(500).json({
    error: 'Internal server error'
  });
});

/*
|--------------------------------------------------------------------------
| START
|--------------------------------------------------------------------------
*/

async function start() {
  try {
    await dbInit();
    await pool.query('SELECT 1');

    app.listen(
      PORT,
      '0.0.0.0',
      function () {
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
```
