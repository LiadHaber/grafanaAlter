import express from 'express';
import session from 'express-session';
import { readFileSync, writeFileSync, existsSync, chmodSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { scryptSync, randomBytes, timingSafeEqual } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const config = JSON.parse(readFileSync(join(__dirname, 'metrics.json'), 'utf8'));

const PROMETHEUS_URL = process.env.PROMETHEUS_URL || config.prometheusUrl;

const USERS_FILE = join(__dirname, 'users.json');
const PASSWORDS_FILE = join(__dirname, 'passwords.txt');

// ── Password utilities ──────────────────────────────────────────
function generatePassword(len = 14) {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#%';
  return Array.from(randomBytes(len)).map(b => chars[b % chars.length]).join('');
}
function hashPassword(pw) {
  const salt = randomBytes(16).toString('hex');
  return salt + ':' + scryptSync(pw, salt, 64).toString('hex');
}
function verifyPassword(pw, stored) {
  try {
    const [salt, hash] = stored.split(':');
    return timingSafeEqual(Buffer.from(hash, 'hex'), scryptSync(pw, salt, 64));
  } catch { return false; }
}

// ── User store ─────────────────────────────────────────────────
function loadUsers() {
  return JSON.parse(readFileSync(USERS_FILE, 'utf8'));
}
function saveUsers(users) {
  writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}
function updatePasswordInFile(email, password) {
  let lines = [];
  if (existsSync(PASSWORDS_FILE)) {
    lines = readFileSync(PASSWORDS_FILE, 'utf8').split('\n');
    // Remove existing entry for this email (non-comment lines)
    lines = lines.filter(l => !l.startsWith(email + ':'));
  }
  // Remove trailing empty lines for cleanliness
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();
  // Find and remove old header if present, rebuild it
  lines = lines.filter(l => !l.startsWith('# Last modified:'));
  lines.unshift(`# Last modified: ${new Date().toISOString()}`);
  lines.push(`${email}:${password}`);
  writeFileSync(PASSWORDS_FILE, lines.join('\n') + '\n', 'utf8');
  chmodSync(PASSWORDS_FILE, 0o600);
}

// ── Bootstrap on first run ─────────────────────────────────────
if (!existsSync(USERS_FILE)) {
  const initialUsers = [
    { id: 'admin',  email: 'admin',           name: 'Admin', role: 'admin', jobFilter: { type: 'all' } },
    { id: 'lenny',  email: 'lenny@markito.tv', name: 'Lenny', role: 'user',  jobFilter: { type: 'all' } },
    { id: 'ido',    email: 'ido@markito.tv',   name: 'Ido',   role: 'user',  jobFilter: { type: 'exclude', pattern: 'shtz' } },
    { id: 'maya',   email: 'maya@markito.tv',  name: 'Maya',  role: 'user',  jobFilter: { type: 'exclude', pattern: 'shtz' } },
    { id: 'elad',   email: 'elad@shortiz.tv',  name: 'Elad',  role: 'user',  jobFilter: { type: 'only',    pattern: 'shtz' } },
  ];

  const passwords = [];
  const users = initialUsers.map(u => {
    const pw = generatePassword();
    passwords.push({ email: u.email, password: pw });
    return { ...u, passwordHash: hashPassword(pw) };
  });

  saveUsers(users);

  const now = new Date().toISOString();
  const pwLines = [
    `# MetricsDash initial passwords — generated ${now}`,
    `# Keep this file secret (chmod 600). Change passwords after first login.`,
    '',
    ...passwords.map(p => `${p.email}:${p.password}`),
    '',
  ];
  writeFileSync(PASSWORDS_FILE, pwLines.join('\n'), 'utf8');
  chmodSync(PASSWORDS_FILE, 0o600);

  console.log('✓ Initial users created. See passwords.txt for credentials.');
}

// ── Job filter ─────────────────────────────────────────────────
function applyJobFilter(promResults, user) {
  if (!user || user.jobFilter.type === 'all') return promResults;
  const { type, pattern } = user.jobFilter;
  const pat = pattern.toLowerCase();
  return promResults.filter(r => {
    const job = (r.metric?.job ?? '').toLowerCase();
    return type === 'only' ? job.includes(pat) : !job.includes(pat);
  });
}

// ── Existing utilities ─────────────────────────────────────────
function safeFloat(v) {
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : null;
}

function dims(metric) {
  return Array.isArray(metric.labelDimension)
    ? metric.labelDimension
    : [metric.labelDimension];
}

function isRawExpression(rule) {
  return /[\s(]/.test(rule);
}

const DURATION_MULTIPLIERS = { s: 1, m: 60, h: 3600, d: 86400 };

function parseDuration(str) {
  const m = str.match(/^(\d+)([smhd])$/i);
  if (!m) return null;
  return parseInt(m[1], 10) * (DURATION_MULTIPLIERS[m[2].toLowerCase()] ?? 60);
}

function parseRuleWindowSeconds(metric) {
  if (metric.window) {
    const secs = parseDuration(metric.window);
    if (secs) return secs;
  }
  const suffixMatch = metric.rule.match(/:(\d+)([smhd])$/i);
  if (suffixMatch) {
    return parseInt(suffixMatch[1], 10) * (DURATION_MULTIPLIERS[suffixMatch[2].toLowerCase()] ?? 60);
  }
  const windowMatches = [...metric.rule.matchAll(/\[(\d+)([smhd])\]/gi)];
  if (windowMatches.length) {
    return Math.max(...windowMatches.map(m => parseInt(m[1], 10) * (DURATION_MULTIPLIERS[m[2].toLowerCase()] ?? 60)));
  }
  return 60;
}

// ── Middleware ─────────────────────────────────────────────────
app.use(express.json());

app.use(session({
  secret: randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 8 * 60 * 60 * 1000 },
}));

function requireAuth(req, res, next) {
  const userId = req.session?.userId;
  if (!userId) {
    return req.path.startsWith('/api/') ? res.status(401).json({ error: 'Unauthorized' }) : res.redirect('/login');
  }
  const user = loadUsers().find(u => u.id === userId && !u.disabled);
  if (!user) {
    req.session.destroy(() => {});
    return req.path.startsWith('/api/') ? res.status(401).json({ error: 'Unauthorized' }) : res.redirect('/login');
  }
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user?.role !== 'admin') {
      return req.path.startsWith('/api/') ? res.status(403).json({ error: 'Forbidden' }) : res.redirect('/');
    }
    next();
  });
}

// ── HTML routes ────────────────────────────────────────────────
app.get('/login', (req, res) => res.sendFile(join(__dirname, 'public/login.html')));
app.get('/', requireAuth, (req, res) => res.sendFile(join(__dirname, 'public/index.html')));
app.get('/admin', requireAdmin, (req, res) => res.sendFile(join(__dirname, 'public/admin.html')));

// ── Auth API routes ────────────────────────────────────────────
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const users = loadUsers();
  const user = users.find(u => u.email === email && !u.disabled);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.userId = user.id;
  res.json({ role: user.role });
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {});
  res.json({ ok: true });
});

app.get('/auth/me', requireAuth, (req, res) => {
  const { id, email, name, role, jobFilter } = req.user;
  res.json({ id, email, name, role, jobFilter });
});

// ── Metrics API routes ─────────────────────────────────────────

// List all configured metrics
app.get('/api/metrics', requireAuth, (_req, res) => {
  res.json(config.metrics.map(({ id, name, unit, description, labelDimension }) => ({ id, name, unit, description, labelDimension })));
});

// Query a metric's current value across all label values
app.get('/api/metrics/:id/current', requireAuth, async (req, res) => {
  const metric = config.metrics.find(m => m.id === req.params.id);
  if (!metric) return res.status(404).json({ error: 'Metric not found' });

  try {
    const url = `${PROMETHEUS_URL}/api/v1/query?query=${encodeURIComponent(metric.rule)}`;
    const response = await fetch(url);
    const data = await response.json();

    if (data.status !== 'success') {
      return res.status(502).json({ error: 'Prometheus error', detail: data.error });
    }

    const filtered = applyJobFilter(data.data.result, req.user);
    const dimensions = dims(metric);
    const results = filtered.map(r => {
      const labelMap = Object.fromEntries(dimensions.map(d => [d, r.metric[d] ?? '?']));
      return {
        label: dimensions.map(d => r.metric[d] ?? '?').join(' / '),
        labelMap,
        value: safeFloat(r.value[1]),
        unit: metric.unit,
      };
    });

    results.sort((a, b) => b.value - a.value);
    res.json({ metric, results });
  } catch (err) {
    res.status(502).json({ error: 'Failed to reach Prometheus', detail: err.message });
  }
});

// Query a metric's range over time (for a single label value)
app.get('/api/metrics/:id/range', requireAuth, async (req, res) => {
  const metric = config.metrics.find(m => m.id === req.params.id);
  if (!metric) return res.status(404).json({ error: 'Metric not found' });

  const { labels: labelsParam, hours, start: startParam, end: endParam } = req.query;
  const windowSecs = parseRuleWindowSeconds(metric);
  let end, start;
  if (startParam && endParam) {
    end = Math.floor(parseInt(endParam, 10) / windowSecs) * windowSecs;
    start = parseInt(startParam, 10);
  } else {
    end = Math.floor(Date.now() / 1000 / windowSecs) * windowSecs;
    start = end - parseInt(hours || 24, 10) * 3600;
  }
  const step = windowSecs;

  let query = metric.rule;
  let inMemoryFilter = null;
  if (labelsParam) {
    const labelMap = JSON.parse(labelsParam);
    if (isRawExpression(metric.rule)) {
      inMemoryFilter = labelMap;
    } else {
      const selector = Object.entries(labelMap).map(([k, v]) => `${k}="${v}"`).join(',');
      if (selector) query = `${metric.rule}{${selector}}`;
    }
  }

  try {
    const url = `${PROMETHEUS_URL}/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${step}`;
    const response = await fetch(url);
    const data = await response.json();

    if (data.status !== 'success') {
      return res.status(502).json({ error: 'Prometheus error', detail: data.error ?? 'unknown error' });
    }

    const dimensions = dims(metric);
    const allSeries = data.data.result
      .filter(r => !inMemoryFilter || Object.entries(inMemoryFilter).every(([k, v]) => r.metric[k] === v))
      .filter(r => applyJobFilter([r], req.user).length > 0)
      .map(r => ({
        label: dimensions.map(d => r.metric[d] ?? '?').join(' / '),
        points: r.values.map(([ts, val]) => ({ ts: ts * 1000, value: safeFloat(val) })),
      }));
    const series = allSeries;

    res.json({ metric, series, stepMs: step * 1000, startMs: start * 1000, endMs: end * 1000 });
  } catch (err) {
    res.status(502).json({ error: 'Failed to reach Prometheus', detail: err.message });
  }
});

// ── Jobs API ───────────────────────────────────────────────────

app.get('/api/jobs', requireAuth, async (req, res) => {
  try {
    const url = `${PROMETHEUS_URL}/api/v1/status/config`;
    const response = await fetch(url);
    const data = await response.json();
    if (data.status !== 'success') {
      return res.status(502).json({ error: 'Prometheus error', detail: data.error });
    }
    // Extract all job_name entries from the YAML config
    const yaml = data.data?.yaml ?? '';
    const jobs = [...yaml.matchAll(/^\s*-?\s*job_name\s*:\s*["']?([^"'\n]+?)["']?\s*$/gm)]
      .map(m => m[1].trim())
      .filter(Boolean);

    // Apply user job filter
    const user = req.user;
    const filtered = user.jobFilter.type === 'all'
      ? jobs
      : jobs.filter(job => {
          const j = job.toLowerCase();
          const pat = user.jobFilter.pattern.toLowerCase();
          return user.jobFilter.type === 'only' ? j.includes(pat) : !j.includes(pat);
        });

    res.json([...new Set(filtered)].sort());
  } catch (err) {
    res.status(502).json({ error: 'Failed to reach Prometheus', detail: err.message });
  }
});

// ── Admin API routes ───────────────────────────────────────────

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers().map(({ passwordHash, ...u }) => u);
  res.json(users);
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { email, password, name, role, jobFilter } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const users = loadUsers();
  const id = 'u_' + randomBytes(6).toString('hex');
  const newUser = {
    id,
    email,
    name: name || email,
    role: role || 'user',
    jobFilter: jobFilter || { type: 'all' },
    passwordHash: hashPassword(password),
  };
  users.push(newUser);
  saveUsers(users);
  updatePasswordInFile(email, password);
  const { passwordHash, ...safe } = newUser;
  res.json(safe);
});

app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const users = loadUsers();
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });

  const { name, role, jobFilter, disabled, password } = req.body;
  const isSelf = req.user.id === id;

  // Guard: cannot disable or demote own account
  if (isSelf && disabled) return res.status(400).json({ error: 'Cannot disable your own account' });
  if (isSelf && role && role !== 'admin') return res.status(400).json({ error: 'Cannot demote your own account' });

  if (name !== undefined) users[idx].name = name;
  if (role !== undefined) users[idx].role = role;
  if (jobFilter !== undefined) users[idx].jobFilter = jobFilter;
  if (disabled !== undefined) users[idx].disabled = disabled;
  if (password) {
    users[idx].passwordHash = hashPassword(password);
    updatePasswordInFile(users[idx].email, password);
  }

  saveUsers(users);
  const { passwordHash, ...safe } = users[idx];
  res.json(safe);
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  if (req.user.id === id) return res.status(400).json({ error: 'Cannot delete your own account' });
  const users = loadUsers();
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  users.splice(idx, 1);
  saveUsers(users);
  res.json({ ok: true });
});

app.post('/api/admin/reload-metrics', requireAdmin, (req, res) => {
  try {
    const fresh = JSON.parse(readFileSync(join(__dirname, 'metrics.json'), 'utf8'));
    config.metrics = fresh.metrics;
    if (fresh.prometheusUrl) config.prometheusUrl = fresh.prometheusUrl;
    console.log('metrics.json reloaded');
    res.json({ ok: true, count: config.metrics.length });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reload metrics.json', detail: err.message });
  }
});

const PORT = process.env.PORT || 8082;
app.listen(PORT, () => console.log(`GrafnaAlter running at http://localhost:${PORT}`));
