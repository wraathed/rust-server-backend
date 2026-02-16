const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const { Pool } = require('pg');
const { GameDig } = require('gamedig');
const path = require('path');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 3000;

// --- DATABASE CONNECTION ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// --- ROBUST DB SCHEMA INITIALIZATION ---
const initDb = async () => {
    const client = await pool.connect();
    try {
        console.log("Initializing Database Schema...");
        
        // 1. Users Table
        await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS ranks TEXT[] DEFAULT '{}'");
        
        // 2. Tickets Table (Ensure steam_id exists)
        await client.query(`
            CREATE TABLE IF NOT EXISTS tickets (
                id SERIAL PRIMARY KEY,
                steam_id TEXT NOT NULL,
                username TEXT,
                avatar TEXT,
                category TEXT,
                subject TEXT,
                status TEXT DEFAULT 'Open',
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // 3. Messages Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER REFERENCES tickets(id),
                sender_steam_id TEXT,
                sender_name TEXT,
                sender_avatar TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // 4. FIX: If tables existed from previous attempt with wrong column name 'steamid', add 'steam_id'
        try {
            await client.query("ALTER TABLE tickets ADD COLUMN IF NOT EXISTS steam_id TEXT");
            // If the old column exists, migrate data (optional, ensures safety)
            await client.query("UPDATE tickets SET steam_id = steamid WHERE steam_id IS NULL AND steamid IS NOT NULL").catch(()=>{});
        } catch (e) {}

        console.log("Database tables verified.");
    } catch (err) {
        console.error("DB Init Error:", err);
    } finally {
        client.release();
    }
};
initDb();

// --- CONFIGURATION ---
app.set('trust proxy', 1);

const ADMIN_IDS = ['76561198871950726', '76561198839698805']; 
const DOMAIN = 'https://classic-rust-api.onrender.com'; 

const STEAM_API_KEY = process.env.STEAM_API_KEY;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;

const STEAM_GROUP_ID = '103582791475507840'; 
const STEAM_GROUP_URL_NAME = 'classicrustservers'; 

const SERVERS = [
    { name: "Classic Rust Test Server", ip: "75.76.68.155", port: 28016, type: 'rust' }
];

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Helper: Safely get Avatar
const getAvatar = (user) => {
    if (user.photos && user.photos.length > 2) return user.photos[2].value;
    if (user.photos && user.photos.length > 0) return user.photos[0].value;
    return 'assets/logo.png'; // Fallback
};

// Secure Cookies Logic
const isProduction = process.env.NODE_ENV === 'production';
app.use(session({
    secret: 'super_secret_rust_key_12345',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction, 
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- GROUP CHECK ---
async function checkGroupMembership(userSteamId) {
    try {
        const apiRes = await axios.get(`http://api.steampowered.com/ISteamUser/GetUserGroupList/v1/?key=${STEAM_API_KEY}&steamid=${userSteamId}`);
        const groups = apiRes.data.response.groups || [];
        if (groups.some(g => g.gid === STEAM_GROUP_ID)) return true;
    } catch (e) {}
    try {
        const xmlUrl = `https://steamcommunity.com/groups/${STEAM_GROUP_URL_NAME}/memberslistxml/?xml=1`;
        const xmlRes = await axios.get(xmlUrl);
        if (xmlRes.data.includes(`<steamID64>${userSteamId}</steamID64>`)) return true;
    } catch (e) {}
    return false;
}

// --- AUTH ---
passport.use(new SteamStrategy({
    returnURL: `${DOMAIN}/auth/steam/return`,
    realm: `${DOMAIN}/`,
    apiKey: STEAM_API_KEY
  },
  async (identifier, profile, done) => {
      try {
          await pool.query(
              `INSERT INTO users (steam_id, gems, ranks) VALUES (\\$1, 0, '{}') ON CONFLICT (steam_id) DO NOTHING`,
              [profile.id]
          );
      } catch (err) { console.error("DB Save Error:", err); }
      return done(null, profile);
  }
));

passport.use(new DiscordStrategy({
    clientID: DISCORD_CLIENT_ID,
    clientSecret: DISCORD_CLIENT_SECRET,
    callbackURL: `${DOMAIN}/auth/discord/callback`,
    scope: ['identify', 'guilds.join'],
    passReqToCallback: true 
}, async (req, accessToken, refreshToken, profile, done) => {
    if (!req.user) return done(new Error("You must be logged into Steam first!"));
    try {
        const existingCheck = await pool.query(`SELECT steam_id FROM users WHERE discord_id = \\$1`, [profile.id]);
        if (existingCheck.rows.length > 0 && existingCheck.rows[0].steam_id !== req.user.id) {
            return done(null, false, { message: 'duplicate' });
        }
        await pool.query(`UPDATE users SET discord_id = \\$1, discord_username = \\$2 WHERE steam_id = \\$3`, [profile.id, profile.username, req.user.id]);
        try { await axios.put(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${profile.id}`, { access_token: accessToken }, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }); } catch (e) { }
        return done(null, req.user);
    } catch (err) { return done(err, null); }
}));

app.get('/auth/steam', passport.authenticate('steam'));
app.get('/auth/steam/return', passport.authenticate('steam', { failureRedirect: '/' }), (req, res) => res.redirect('/index.html'));
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', (req, res, next) => {
    passport.authenticate('discord', (err, user, info) => {
        if (err) return next(err);
        if (!user && info?.message === 'duplicate') return res.redirect('/profile.html?error=discord_in_use');
        if (!user) return res.redirect('/profile.html?error=unknown');
        req.logIn(user, (err) => res.redirect('/profile.html'));
    })(req, res, next);
});

app.post('/auth/discord/unlink', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Not logged in" });
    try { await pool.query(`UPDATE users SET discord_id = NULL, discord_username = NULL WHERE steam_id = \\$1`, [req.user.id]); res.json({ success: true }); } catch (err) { res.status(500).json({ error: "Database error" }); }
});

app.get('/user', async (req, res) => {
    if(!req.user) return res.json(null);
    const isAdmin = ADMIN_IDS.includes(req.user.id);
    let discordInfo = null, gemBalance = 0, ranks = [];
    try {
        const dbRes = await pool.query('SELECT discord_username, gems, ranks FROM users WHERE steam_id = \\$1', [req.user.id]);
        if (dbRes.rows.length > 0) { discordInfo = dbRes.rows[0].discord_username; gemBalance = dbRes.rows[0].gems || 0; ranks = dbRes.rows[0].ranks || []; }
    } catch(e) {}
    const inSteamGroup = await checkGroupMembership(req.user.id);
    res.json({ ...req.user, isAdmin, discord: discordInfo, gems: gemBalance, ranks: ranks, inSteamGroup: inSteamGroup });
});

app.get('/logout', (req, res) => { req.logout(() => { req.session.destroy(() => res.redirect('/index.html')); }); });

// --- STORE API ---
app.post('/api/store/buy-rank', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { rank } = req.body;
    try {
        const check = await pool.query('SELECT ranks FROM users WHERE steam_id = \\$1', [req.user.id]);
        const currentRanks = check.rows[0].ranks || [];
        if(currentRanks.includes(rank)) return res.json({ success: false, error: "Already owned" });
        await pool.query("UPDATE users SET ranks = array_append(COALESCE(ranks, '{}'), \\$1) WHERE steam_id = \\$2", [rank, req.user.id]);
        res.json({ success: true, message: `Purchased ${rank.toUpperCase()}!` });
    } catch (err) { res.status(500).json({ error: "DB Error" }); }
});

app.post('/api/store/buy-gems', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { amount } = req.body;
    try { await pool.query('UPDATE users SET gems = gems + \\$1 WHERE steam_id = \$2', [amount, req.user.id]); res.json({ success: true, message: `Added ${amount} gems!` }); } catch (err) { res.status(500).json({ error: "DB Error" }); }
});

// --- SERVER API ---
app.post('/api/server/redeem', async (req, res) => {
    try {
        const { steamId, kit } = req.query;
        if (!steamId || !kit) return res.status(400).send("Missing Params");
        const rankKits = ['vip', 'elite', 'soldier', 'juggernaut', 'overlord'];
        if (rankKits.includes(kit)) {
            const userRes = await pool.query('SELECT ranks FROM users WHERE steam_id = \\$1', [steamId]);
            const userRanks = (userRes.rows[0]?.ranks) ? userRes.rows[0].ranks : [];
            return userRanks.includes(kit) ? res.status(200).send("OK") : res.status(403).send("LOCKED");
        }
        if (kit === 'discord' || kit === 'discordbuild') {
            const userRes = await pool.query('SELECT discord_id FROM users WHERE steam_id = \\$1', [steamId]);
            if (!userRes.rows[0]?.discord_id) return res.status(403).send("FAIL_LINK"); 
            try { await axios.get(`https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userRes.rows[0].discord_id}`, { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }); return res.status(200).send("OK"); } catch (discordErr) { return res.status(403).send("FAIL_GUILD"); }
        }
        if (kit === 'steam') { return (await checkGroupMembership(steamId)) ? res.status(200).send("OK") : res.status(403).send("FAIL_STEAM_GROUP"); }
        res.status(200).send("OK");
    } catch (err) { res.status(500).send("ERROR"); }
});

app.get('/api/server/balance', async (req, res) => {
    const { steamId } = req.query;
    try { const result = await pool.query('SELECT gems FROM users WHERE steam_id = \\$1', [steamId]); return res.send(result.rows.length > 0 ? result.rows[0].gems.toString() : "0"); } catch (err) { return res.send("0"); }
});

app.post('/api/server/spend', async (req, res) => {
    const { steamId, cost } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const resCheck = await client.query('SELECT gems FROM users WHERE steam_id = \\$1 FOR UPDATE', [steamId]);
        if (resCheck.rows.length === 0) { await client.query('ROLLBACK'); return res.send("NO_USER"); }
        if (resCheck.rows[0].gems < cost) { await client.query('ROLLBACK'); return res.send("INSUFFICIENT_FUNDS"); }
        await client.query('UPDATE users SET gems = gems - \\$1 WHERE steam_id = \\$2', [cost, steamId]);
        await client.query('COMMIT'); 
        return res.send("SUCCESS");
    } catch (err) { await client.query('ROLLBACK'); return res.send("ERROR"); } finally { client.release(); }
});

// --- TICKET API (FIXED) ---
app.post('/api/tickets', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Login required' });
    const { category, subject, description } = req.body;
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 1. Get avatar safely
        const avatar = getAvatar(req.user);

        // 2. Insert with correct 'steam_id' column
        const ticketRes = await client.query(
            'INSERT INTO tickets (steam_id, username, avatar, category, subject) VALUES (\\$1, \\$2, \\$3, \\$4, \\$5) RETURNING id',
            [req.user.id, req.user.displayName, avatar, category, subject]
        );
        const ticketId = ticketRes.rows[0].id;
        
        // 3. Insert Message
        await client.query(
            'INSERT INTO messages (ticket_id, sender_steam_id, sender_name, sender_avatar, content) VALUES (\\$1, \\$2, \\$3, \\$4, \\$5)',
            [ticketId, req.user.id, req.user.displayName, avatar, description]
        );
        await client.query('COMMIT');
        res.json({ success: true });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("Ticket Create Error:", e); // Check this in Render logs if it fails
        res.status(500).json({ error: 'Database error', details: e.message });
    } finally {
        client.release();
    }
});

app.get('/api/my-tickets', async (req, res) => {
    if (!req.user) return res.status(401).json([]);
    try {
        // Use steam_id (snake_case)
        const result = await pool.query('SELECT * FROM tickets WHERE steam_id = \\$1 ORDER BY id DESC', [req.user.id]);
        res.json(result.rows);
    } catch (err) { console.error("My Tickets Error:", err); res.json([]); }
});

// --- ADMIN API ---
app.get('/api/admin/tickets', async (req, res) => {
    if (!req.user || !ADMIN_IDS.includes(req.user.id)) return res.status(403).json({ error: "Unauthorized access" });
    try {
        const query = `SELECT * FROM tickets ORDER BY CASE WHEN status = 'Open' THEN 1 WHEN status = 'Answered' THEN 2 ELSE 3 END, id DESC`;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error("Admin Fetch Error:", err);
        res.status(500).json({ error: "Database error" });
    }
});

app.get('/api/ticket/:id', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    const ticketId = req.params.id;
    try {
        const ticketRes = await pool.query('SELECT * FROM tickets WHERE id = \\$1', [ticketId]);
        const ticket = ticketRes.rows[0];
        if (!ticket) return res.status(404).json({ error: "Ticket not found" });
        
        const isAdminUser = ADMIN_IDS.includes(req.user.id);
        // Compare steam_id
        if (ticket.steam_id !== req.user.id && !isAdminUser) return res.status(403).json({ error: "Forbidden" });

        const msgRes = await pool.query('SELECT * FROM messages WHERE ticket_id = \\$1 ORDER BY created_at ASC', [ticketId]);
        const enrichedMessages = msgRes.rows.map(msg => ({
            ...msg,
            isAdminSender: ADMIN_IDS.includes(msg.sender_steam_id)
        }));
        res.json({ ticket, messages: enrichedMessages, currentUserSteamId: req.user.id, isAdmin: isAdminUser });
    } catch (err) { 
        console.error("Get Ticket Error:", err);
        res.status(500).json({ error: "DB Error", details: err.message }); 
    }
});

app.post('/api/ticket/:id/reply', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    const ticketId = req.params.id;
    const isAdminUser = ADMIN_IDS.includes(req.user.id);
    try {
        const ticketCheck = await pool.query('SELECT status FROM tickets WHERE id = \\$1', [ticketId]);
        if (ticketCheck.rows.length === 0) return res.status(404).json({ error: "Not found" });
        if (ticketCheck.rows[0].status === 'Closed') return res.status(400).json({ error: "Ticket is closed." });

        const avatar = getAvatar(req.user);

        await pool.query(
            'INSERT INTO messages (ticket_id, sender_steam_id, sender_name, sender_avatar, content) VALUES (\\$1, \\$2, \\$3, \\$4, \\$5)',
            [ticketId, req.user.id, req.user.displayName, avatar, req.body.content]
        );
        const newStatus = isAdminUser ? 'Answered' : 'Open';
        await pool.query('UPDATE tickets SET status = \\$1 WHERE id = \\$2', [newStatus, ticketId]);
        res.json({ success: true });
    } catch (err) { 
        console.error("Reply Error:", err);
        res.status(500).json({ error: "Error", details: err.message }); 
    }
});

// --- SERVER INFO API ---
app.get('/api/servers', async (req, res) => {
    try {
        const promises = SERVERS.map(server =>
            GameDig.query({ type: server.type, host: server.ip, port: server.port, maxAttempts: 2 })
            .then((state) => ({ name: server.name, ip: server.ip, port: server.port, map: state.map, players: state.players.length, maxPlayers: state.maxplayers, status: 'Online' }))
            .catch(() => ({ name: server.name, ip: server.ip, port: server.port, map: "N/A", players: 0, maxPlayers: 0, status: 'Offline' }))
        );
        res.json(await Promise.all(promises));
    } catch (err) { res.json([]); }
});

app.listen(port, () => console.log(`Server running on port ${port}`));