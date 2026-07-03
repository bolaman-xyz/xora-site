const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const app = express();
const PORT = process.env.PORT || 3000;

// ── KeyAuth (seller API) ──
// Seller keys are read-only here: we only look up a key's subscription, never bind HWID.
// Multiple seller keys are supported so products from different KeyAuth accounts can
// live on the same site. Configure them via env:
//   KEYAUTH_SELLER_KEY        + optional KEYAUTH_SELLER_LABEL   (default label "Main")
//   KEYAUTH_SELLER_KEY_2..10  + optional KEYAUTH_SELLER_LABEL_2..10
function buildSellers() {
    const list = [];
    const push = (key, label, fallback) => {
        if (key && String(key).trim()) list.push({ key: String(key).trim(), label: (label && label.trim()) || fallback });
    };
    push(process.env.KEYAUTH_SELLER_KEY, process.env.KEYAUTH_SELLER_LABEL, 'Main');
    for (let i = 2; i <= 10; i++) {
        push(process.env['KEYAUTH_SELLER_KEY_' + i], process.env['KEYAUTH_SELLER_LABEL_' + i], 'Seller ' + i);
    }
    return list;
}
const SELLERS = buildSellers();
// Back-compat alias (first seller key)
const KEYAUTH_SELLER_KEY = SELLERS[0] && SELLERS[0].key;
function sellerByLabel(label) {
    if (!label) return null;
    return SELLERS.find(s => s.label.toLowerCase() === String(label).toLowerCase()) || null;
}

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SITE_URL = process.env.SITE_URL || '';

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DATA_FILE = path.join(DATA_DIR, 'config.json');

function loadData() { try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return { products: {}, guides: {} }; } }
function saveData(data) { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }

const USERS_FILE = path.join(DATA_DIR, 'users.json');
function loadUsers() { try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return {}; } }
function saveUsers(users) { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }

// HWID reset cooldown tracking (per license key)
const RESETS_FILE = path.join(DATA_DIR, 'hwid_resets.json');
function loadResets() { try { return JSON.parse(fs.readFileSync(RESETS_FILE, 'utf8')); } catch { return {}; } }
function saveResets(r) { fs.writeFileSync(RESETS_FILE, JSON.stringify(r, null, 2)); }
const HWID_RESET_DAYS = 30;
const HWID_RESET_MS = HWID_RESET_DAYS * 24 * 60 * 60 * 1000;
// KeyAuth seller op used to reset a key's HWID. Adjust if your KeyAuth setup differs.
const KEYAUTH_RESET_TYPE = process.env.KEYAUTH_RESET_TYPE || 'resetuser';

// Uploaded loader files live on the volume so they persist across deploys
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            const dir = path.join(UPLOADS_DIR, req.params.id);
            fs.mkdirSync(dir, { recursive: true });
            cb(null, dir);
        },
        filename: (req, file, cb) => cb(null, (file.originalname || 'file').replace(/[^\w.\-]+/g, '_'))
    }),
    limits: { fileSize: 500 * 1024 * 1024 } // 500 MB
});

const sessions = new Map();

// ── Discord logging ──
// Set LOG_CHANNEL_ID to a Discord channel ID; the bot posts site events there.
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
let logChannel = null;
function logEvent(title, fields, color = 0xe11d2a) {
    if (!logChannel) return;
    try {
        logChannel.send({ embeds: [{
            title, color,
            fields: (fields || []).map(f => ({
                name: f.name,
                value: (f.value == null || f.value === '') ? '—' : String(f.value).slice(0, 1024),
                inline: f.inline !== false
            })),
            timestamp: new Date().toISOString()
        }] }).catch(() => {});
    } catch {}
}
function sessionName(s) {
    if (!s) return 'Unknown';
    if (s.type === 'admin') return 'Admin Panel';
    return (s.global_name || s.username || s.discord_id || 'User') + (s.discord_id ? ` (<@${s.discord_id}>)` : '');
}

function authMiddleware(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Unauthorized' });
    req.session = sessions.get(token);
    next();
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── KeyAuth key verification ──
// Looks up a license key via the KeyAuth Seller API and returns the
// subscription name(s) attached to it. Read-only — does not bind HWID.
async function verifyKeyAuthKey(key) {
    if (!SELLERS.length) return { valid: false, subs: [], error: 'KeyAuth not configured (missing KEYAUTH_SELLER_KEY)' };

    // A license key only validates against the seller account it belongs to, so we
    // try each configured seller key until one recognizes it.
    let lastError = 'Invalid or expired key';
    for (const seller of SELLERS) {
        const attempt = await verifyKeyWithSeller(key, seller);
        if (attempt.valid) return attempt;
        if (attempt.error) lastError = attempt.error;
    }
    return { valid: false, subs: [], error: lastError };
}

async function verifyKeyWithSeller(key, seller) {
    try {
        const url = `https://keyauth.win/api/seller/?sellerkey=${encodeURIComponent(seller.key)}&type=info&key=${encodeURIComponent(key)}`;
        const r = await fetch(url);
        const text = await r.text();
        let data;
        try { data = JSON.parse(text); } catch { return { valid: false, subs: [], error: 'Unexpected response from KeyAuth', raw: text }; }
        console.log(`KeyAuth info response [${seller.label}]:`, JSON.stringify(data).substring(0, 600));
        if (!data.success) return { valid: false, subs: [], error: data.message || 'Invalid or expired key', raw: data };

        // Collect every candidate subscription identifier KeyAuth might return,
        // so matching works whether the field is `subscription`, `level`, etc.
        const subs = new Set();
        const add = v => { if (v != null && String(v).trim()) subs.add(String(v).trim()); };
        add(data.subscription);
        add(data.level);
        add(data.subscription_name);
        if (Array.isArray(data.subscriptions)) data.subscriptions.forEach(s => add(s && (s.subscription || s.name || s)));

        // Pick the first meaningful (non-empty, non-zero) value
        const pick = (...vals) => {
            for (const v of vals) {
                if (v === undefined || v === null || v === '' || v === 0 || v === '0') continue;
                return v;
            }
            return null;
        };
        let subExpiry = null, subTimeLeft = null;
        if (Array.isArray(data.subscriptions) && data.subscriptions.length) {
            subExpiry = data.subscriptions[0].expiry;
            subTimeLeft = data.subscriptions[0].timeleft;
        }
        const expiry = pick(data.expiry, data.expires, data.expire, subExpiry, data.duration);
        const timeleft = pick(data.timeleft, subTimeLeft);

        // Is the key already activated (used in the loader)?
        const usedOn = pick(data.usedon, data.used_on, data.usedOn);
        const statusStr = String(data.status || '').toLowerCase();
        const hwid = pick(data.hwid, data.HWID);
        const used = !!(hwid || (usedOn && String(usedOn) !== '0') || (statusStr.includes('used') && !statusStr.includes('not')));
        console.log('KeyAuth time → expiry:', expiry, '| timeleft:', timeleft, '| usedon:', usedOn, '| status:', data.status, '| used:', used);

        return {
            valid: true,
            subs: [...subs],
            expiry,
            timeleft,
            used,
            status: data.status || null,
            hwid: hwid || null,
            seller_label: seller.label,
            seller_key: seller.key,
            raw: data
        };
    } catch (err) {
        console.error('KeyAuth verify error:', err);
        return { valid: false, subs: [], error: 'Could not reach KeyAuth' };
    }
}

// Returns catalog products whose `sub` matches any of the given subscription names.
// If a product is tagged with a specific `seller`, it only matches when the key was
// verified against that same seller — this prevents a level "1" on one KeyAuth account
// from unlocking a different product that also uses level "1" on another account.
function productsForSubs(subs, sellerLabel) {
    const config = loadData();
    const catalog = config.products || {};
    const wanted = (subs || []).map(s => String(s).toLowerCase());
    const sl = sellerLabel ? String(sellerLabel).toLowerCase() : '';
    const out = [];
    for (const [id, p] of Object.entries(catalog)) {
        if (!p || typeof p !== 'object') continue;
        const pSeller = String(p.seller || '').trim().toLowerCase();
        if (pSeller && sl && pSeller !== sl) continue; // product locked to a different seller
        const psubs = String(p.sub || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
        if (psubs.length && psubs.some(ps => wanted.includes(ps))) {
            out.push({ ...p, id, _id: id, variants: p.variants || [] });
        }
    }
    return out;
}

// ── Discord OAuth ──
app.get('/auth/discord', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify%20email`;
    res.redirect(url);
});

app.get('/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.redirect('/?error=no_code');

    try {
        const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: DISCORD_CLIENT_ID,
                client_secret: DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: DISCORD_REDIRECT_URI
            })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) return res.redirect('/?error=auth_failed');

        const userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
        });
        const user = await userRes.json();

        const sessionToken = crypto.randomBytes(32).toString('hex');
        const savedUsers = loadUsers();
        const savedKey = savedUsers[user.id] || null;
        sessions.set(sessionToken, {
            type: 'user',
            discord_id: user.id,
            username: user.username,
            global_name: user.global_name || user.username,
            avatar: user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : null,
            key: savedKey,
            saved_key: savedKey,
            created: Date.now()
        });

        res.redirect(`/dashboard#token=${sessionToken}`);
    } catch (err) {
        console.error('Discord OAuth error:', err);
        res.redirect('/?error=server_error');
    }
});

// Current user session
app.get('/api/me', authMiddleware, (req, res) => {
    res.json(req.session);
});

// Redeem / look up products by license key (KeyAuth)
app.post('/api/lookup', authMiddleware, async (req, res) => {
    const key = (req.body.key || '').trim();
    if (!key) return res.status(400).json({ error: 'License key required' });

    const result = await verifyKeyAuthKey(key);
    if (!result.valid) {
        logEvent('❌ Invalid key attempt', [
            { name: 'User', value: sessionName(req.session), inline: false },
            { name: 'Key', value: key },
            { name: 'Reason', value: result.error || 'Invalid' }
        ], 0x888888);
        return res.json({ products: [], valid: false, error: result.error || 'Invalid key' });
    }

    // Save the key on the session and remember it per Discord user
    const token = req.headers['authorization']?.replace('Bearer ', '');
    const session = sessions.get(token);
    if (session) {
        session.key = key;
        session.saved_key = key;
        session.seller_key = result.seller_key || null;
        session.seller_label = result.seller_label || null;
        if (session.discord_id) {
            const users = loadUsers();
            users[session.discord_id] = key;
            saveUsers(users);
        }
    }

    const products = productsForSubs(result.subs, result.seller_label);
    console.log(`Key verified [${result.seller_label}]. Subs: ${result.subs.join(', ') || '(none)'} → ${products.length} product(s)`);

    const resets = loadResets();
    const lastReset = resets[key] ? new Date(resets[key]).getTime() : 0;
    const resetNext = lastReset ? new Date(lastReset + HWID_RESET_MS).toISOString() : null;

    res.json({
        products, valid: true, subs: result.subs,
        expiry: result.expiry, timeleft: result.timeleft, used: result.used, hwid: result.hwid, key,
        hwid_reset_next: resetNext, hwid_reset_days: HWID_RESET_DAYS
    });
});

// Forget the caller's saved key so they can enter a different one
app.post('/api/clear-key', authMiddleware, (req, res) => {
    const session = req.session || {};
    session.key = null;
    session.saved_key = null;
    if (session.discord_id) {
        const users = loadUsers();
        delete users[session.discord_id];
        saveUsers(users);
    }
    logEvent('🔁 Key removed', [{ name: 'User', value: sessionName(session), inline: false }], 0x888888);
    res.json({ ok: true });
});

// Log a loader download (called by the dashboard download button)
app.post('/api/log-download', authMiddleware, (req, res) => {
    const data = loadData();
    const p = data.products && data.products[req.body.id];
    logEvent('⬇️ Loader downloaded', [
        { name: 'User', value: sessionName(req.session), inline: false },
        { name: 'Product', value: (p && p.name) || req.body.id || '—' }
    ], 0x22c55e);
    res.json({ ok: true });
});

// Reset the HWID on the caller's license key (max once per HWID_RESET_DAYS)
app.post('/api/reset-hwid', authMiddleware, async (req, res) => {
    const session = req.session || {};
    const key = (session.key || session.saved_key || (req.body.key || '')).trim();
    if (!key) return res.status(400).json({ ok: false, error: 'No license key on this session' });

    const resets = loadResets();
    const last = resets[key] ? new Date(resets[key]).getTime() : 0;
    const now = Date.now();
    if (last && now - last < HWID_RESET_MS) {
        return res.json({ ok: false, rate_limited: true, next: new Date(last + HWID_RESET_MS).toISOString(),
            error: `HWID can only be reset once every ${HWID_RESET_DAYS} days.` });
    }
    if (!SELLERS.length) return res.json({ ok: false, error: 'KeyAuth not configured' });

    // Reset must target the same seller account the key belongs to. Use the one saved
    // on the session; if missing (e.g. after a restart), re-discover it by verifying.
    let sellerKey = session.seller_key;
    if (!sellerKey) {
        const check = await verifyKeyAuthKey(key);
        if (check.valid && check.seller_key) {
            sellerKey = check.seller_key;
            session.seller_key = check.seller_key;
            session.seller_label = check.seller_label;
        }
    }
    if (!sellerKey) sellerKey = SELLERS[0].key; // last-resort fallback

    try {
        const url = `https://keyauth.win/api/seller/?sellerkey=${encodeURIComponent(sellerKey)}&type=${encodeURIComponent(KEYAUTH_RESET_TYPE)}&user=${encodeURIComponent(key)}`;
        const r = await fetch(url);
        const text = await r.text();
        let data; try { data = JSON.parse(text); } catch { data = { success: false, message: text }; }
        console.log('KeyAuth reset response:', JSON.stringify(data).substring(0, 400));
        if (data.success) {
            resets[key] = new Date().toISOString();
            saveResets(resets);
            logEvent('🔄 HWID reset', [
                { name: 'User', value: sessionName(req.session), inline: false },
                { name: 'Key', value: key }
            ], 0xf59e0b);
            return res.json({ ok: true, message: data.message || 'HWID reset', next: new Date(now + HWID_RESET_MS).toISOString() });
        }
        let msg = data.message || 'KeyAuth could not reset the HWID';
        if (/find user|not found|no user|doesn'?t exist/i.test(msg)) {
            msg = "This key hasn't been activated in the loader yet, so there's no HWID to reset. Run the loader once with it, then try again.";
        }
        return res.json({ ok: false, error: msg });
    } catch (e) {
        console.error('Reset HWID error:', e);
        return res.json({ ok: false, error: 'Could not reach KeyAuth' });
    }
});

// Public catalog (admin-defined products)
app.get('/api/products', (req, res) => {
    const config = loadData();
    const catalog = config.products || {};
    const data = Object.entries(catalog)
        .filter(([id, p]) => p && typeof p === 'object')
        .map(([id, p]) => ({ ...p, id, _id: id }));
    res.json({ data });
});

// ── Admin endpoints ──
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong password' });
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { type: 'admin', created: Date.now() });
    res.json({ token });
});

app.get('/api/admin/config', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    res.json(loadData());
});

// List configured KeyAuth seller accounts (labels only — never expose the keys)
app.get('/api/admin/sellers', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    res.json({ sellers: SELLERS.map(s => s.label) });
});

// Create a new catalog product
app.post('/api/admin/product', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    const data = loadData();
    if (!data.products) data.products = {};
    const id = 'p_' + crypto.randomBytes(5).toString('hex');
    data.products[id] = { ...req.body, created_at: new Date().toISOString() };
    saveData(data);
    res.json({ ok: true, id });
});

app.put('/api/admin/product/:id', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    const data = loadData();
    if (!data.products) data.products = {};
    const merged = { ...data.products[req.params.id], ...req.body };
    if (Object.prototype.hasOwnProperty.call(req.body, 'download_link')) {
        merged.link_source = 'admin';
        merged.link_updated_at = new Date().toISOString();
        merged.link_updated_by = 'Admin Panel';
    }
    data.products[req.params.id] = merged;
    saveData(data);
    res.json({ ok: true });
});

app.delete('/api/admin/product/:id', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    const data = loadData();
    if (data.products) delete data.products[req.params.id];
    saveData(data);
    try { fs.rmSync(path.join(UPLOADS_DIR, req.params.id), { recursive: true, force: true }); } catch {}
    res.json({ ok: true });
});

// Upload a loader file for a product (becomes its download)
app.post('/api/admin/upload/:id', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    const data = loadData();
    if (!data.products || !data.products[req.params.id]) return res.status(404).json({ error: 'Product not found — save it first' });
    upload.single('file')(req, res, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        if (!req.file) return res.status(400).json({ error: 'No file received' });
        const dir = path.join(UPLOADS_DIR, req.params.id);
        // keep only the newest file
        for (const f of fs.readdirSync(dir)) {
            if (f !== req.file.filename) { try { fs.unlinkSync(path.join(dir, f)); } catch {} }
        }
        const d = loadData();
        d.products[req.params.id] = {
            ...d.products[req.params.id],
            download_file: req.file.filename,
            download_link: '/download/' + req.params.id,
            link_source: 'admin',
            link_updated_at: new Date().toISOString(),
            link_updated_by: 'Admin Upload'
        };
        saveData(d);
        res.json({ ok: true, file: req.file.filename });
    });
});

// Public download of an uploaded loader file
app.get('/download/:id', (req, res) => {
    const data = loadData();
    const p = data.products && data.products[req.params.id];
    if (!p || !p.download_file) return res.status(404).send('File not found');
    const filePath = path.join(UPLOADS_DIR, req.params.id, p.download_file);
    if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
    res.download(filePath, p.download_file);
});

app.put('/api/admin/guide/:slug', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    const data = loadData();
    if (!data.guides) data.guides = {};
    data.guides[req.params.slug] = req.body;
    saveData(data);
    res.json({ ok: true });
});

app.delete('/api/admin/guide/:slug', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    const data = loadData();
    if (data.guides) delete data.guides[req.params.slug];
    saveData(data);
    res.json({ ok: true });
});

app.put('/api/admin/template/:slug', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    const data = loadData();
    if (!data.templates) data.templates = {};
    data.templates[req.params.slug] = req.body;
    saveData(data);
    res.json({ ok: true });
});

app.delete('/api/admin/template/:slug', authMiddleware, (req, res) => {
    if (req.session.type !== 'admin') return res.status(403).json({ error: 'Not admin' });
    const data = loadData();
    if (data.templates) delete data.templates[req.params.slug];
    saveData(data);
    res.json({ ok: true });
});

app.get('/api/guides', (req, res) => {
    const guides = loadData().guides || {};
    const clean = {};
    for (const [k, v] of Object.entries(guides)) { if (v && typeof v === 'object') clean[k] = v; }
    res.json(clean);
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/downloads', (req, res) => res.sendFile(path.join(__dirname, 'public', 'downloads.html')));
app.get('/guides', (req, res) => res.sendFile(path.join(__dirname, 'public', 'guides.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Running on port ${PORT}`);
    const onVolume = process.env.DATA_DIR ? 'set' : 'NOT SET (data will be wiped on redeploy — set DATA_DIR + attach a volume)';
    console.log(`DATA_DIR = ${DATA_DIR}  | DATA_DIR env: ${onVolume}`);
    console.log(`KeyAuth sellers (${SELLERS.length}): ${SELLERS.map(s => s.label).join(', ') || '(none configured)'}`);
});

// ── Discord Bot ──
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
if (DISCORD_BOT_TOKEN) {
    const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, EmbedBuilder } = require('discord.js');

    const bot = new Client({ intents: [GatewayIntentBits.Guilds] });

    const commands = [
        new SlashCommandBuilder()
            .setName('setlink')
            .setDescription('Set a download link for a product')
            .addStringOption(o => o.setName('product').setDescription('Select a product').setRequired(true).setAutocomplete(true))
            .addStringOption(o => o.setName('url').setDescription('Download URL').setRequired(true)),
        new SlashCommandBuilder()
            .setName('setstatus')
            .setDescription('Set product status text')
            .addStringOption(o => o.setName('product').setDescription('Select a product').setRequired(true).setAutocomplete(true))
            .addStringOption(o => o.setName('status').setDescription('Status text').setRequired(true)
                .addChoices(
                    { name: 'Available', value: 'Available' },
                    { name: 'Updating', value: 'Updating' },
                    { name: 'Offline', value: 'Offline' },
                    { name: 'Maintenance', value: 'Maintenance' }
                )),
        new SlashCommandBuilder()
            .setName('products')
            .setDescription('List all products and their download links'),
        new SlashCommandBuilder()
            .setName('updatelink')
            .setDescription('Update an existing download link for a product')
            .addStringOption(o => o.setName('product').setDescription('Select a product').setRequired(true).setAutocomplete(true))
            .addStringOption(o => o.setName('url').setDescription('New download URL').setRequired(true)),
    ].map(c => c.toJSON());

    bot.once('ready', async () => {
        console.log(`Bot logged in as ${bot.user.tag}`);
        const rest = new REST({ version: '10' }).setToken(DISCORD_BOT_TOKEN);
        try {
            await rest.put(Routes.applicationCommands(bot.user.id), { body: commands });
            console.log('Slash commands registered');
        } catch (err) {
            console.error('Failed to register commands:', err);
        }
        if (LOG_CHANNEL_ID) {
            try {
                logChannel = await bot.channels.fetch(LOG_CHANNEL_ID);
                console.log('Log channel ready:', logChannel?.name || LOG_CHANNEL_ID);
                logEvent('📡 Xora logging online', [{ name: 'Status', value: 'Connected' }], 0x22c55e);
            } catch (e) {
                console.error('Could not fetch LOG_CHANNEL_ID:', e.message);
            }
        }
    });

    // Products now come from the local catalog (config.products), not SellAuth.
    function fetchProducts() {
        const catalog = loadData().products || {};
        return Object.entries(catalog)
            .filter(([id, p]) => p && typeof p === 'object')
            .map(([id, p]) => ({ ...p, id }));
    }

    function findProduct(query) {
        const products = fetchProducts();
        const q = (query || '').toLowerCase();
        return products.find(p => String(p.id) === query) ||
               products.find(p => (p.name || '').toLowerCase() === q) ||
               products.find(p => (p.name || '').toLowerCase().includes(q));
    }

    bot.on('interactionCreate', async interaction => {
        if (interaction.isAutocomplete()) {
            const focused = interaction.options.getFocused();
            const products = fetchProducts();
            const q = focused.toLowerCase();
            const filtered = products
                .filter(p => (p.name || '').toLowerCase().includes(q) || String(p.id).includes(q))
                .slice(0, 25)
                .map(p => ({ name: p.name || `Product ${p.id}`, value: String(p.id) }));
            return interaction.respond(filtered);
        }

        if (!interaction.isChatInputCommand()) return;

        const { commandName } = interaction;

        if (commandName === 'setlink' || commandName === 'updatelink') {
            const query = interaction.options.getString('product');
            const url = interaction.options.getString('url');
            const product = findProduct(query);
            if (!product) return interaction.reply({ content: `Product "${query}" not found.`, ephemeral: true });

            const data = loadData();
            if (!data.products) data.products = {};
            const editor = interaction.user ? (interaction.user.username || interaction.user.tag || 'Discord') : 'Discord';
            data.products[String(product.id)] = {
                ...data.products[String(product.id)],
                download_link: url,
                link_source: 'discord',
                link_updated_at: new Date().toISOString(),
                link_updated_by: editor
            };
            saveData(data);

            const embed = new EmbedBuilder()
                .setColor(0xe11d2a)
                .setTitle(commandName === 'updatelink' ? 'Download Link Updated' : 'Download Link Set')
                .addFields(
                    { name: 'Product', value: product.name || String(product.id), inline: true },
                    { name: 'Link', value: url, inline: false }
                )
                .setTimestamp();
            return interaction.reply({ embeds: [embed] });
        }

        if (commandName === 'setstatus') {
            const query = interaction.options.getString('product');
            const status = interaction.options.getString('status');
            const product = findProduct(query);
            if (!product) return interaction.reply({ content: `Product "${query}" not found.`, ephemeral: true });

            const data = loadData();
            if (!data.products) data.products = {};
            data.products[String(product.id)] = { ...data.products[String(product.id)], status_text: status };
            saveData(data);

            const embed = new EmbedBuilder()
                .setColor(0xe11d2a)
                .setTitle('Status Updated')
                .addFields(
                    { name: 'Product', value: product.name || String(product.id), inline: true },
                    { name: 'Status', value: status, inline: true }
                )
                .setTimestamp();
            return interaction.reply({ embeds: [embed] });
        }

        if (commandName === 'products') {
            const products = fetchProducts();
            if (!products.length) {
                return interaction.reply({ content: 'No products in the catalog yet. Add some in the admin panel.', ephemeral: true });
            }

            const embed = new EmbedBuilder()
                .setColor(0xe11d2a)
                .setTitle('All Products')
                .setTimestamp();

            for (const p of products.slice(0, 25)) {
                const status = p.status_text || 'Available';
                const link = p.download_link || 'Not set';
                const sub = p.sub ? ` · sub: ${p.sub}` : '';
                embed.addFields({
                    name: (p.name || `Product ${p.id}`) + sub,
                    value: `Status: ${status}\nLink: ${link}`,
                    inline: false
                });
            }

            return interaction.reply({ embeds: [embed] });
        }
    });

    bot.login(DISCORD_BOT_TOKEN).catch(err => console.error('Bot login failed:', err));
} else {
    console.log('No DISCORD_BOT_TOKEN set, bot disabled');
}
