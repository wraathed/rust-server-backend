const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session); // <--- ADD THIS
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

// --- DB SCHEMA CHECK ---
// Ensure the 'ranks' column exists to prevent errors on old users
pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS ranks TEXT[] DEFAULT '{}'")
    .then(() => console.log("Database schema checked: ranks column ready."))
    .catch(err => console.error("DB Schema Error:", err));

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

app.use(session({
    store: new pgSession({
        pool : pool,                // Use your existing Postgres connection
        tableName : 'session',      // We will create this table automatically
        createTableIfMissing: true  // This ensures the table exists
    }),
    secret: 'super_secret_rust_key_12345',
    resave: false,
    saveUninitialized: false,
    cookie: {
        // FIX: Only require HTTPS if we are in production (Render). 
        // This makes it work on Localhost AND Render.
        secure: process.env.NODE_ENV === 'production', 
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 Days
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- HELPER: ROBUST GROUP CHECK ---
async function checkGroupMembership(userSteamId) {
    try {
        const apiRes = await axios.get(`http://api.steampowered.com/ISteamUser/GetUserGroupList/v1/?key=${STEAM_API_KEY}&steamid=${userSteamId}`);
        const groups = apiRes.data.response.groups || [];
        const isMember = groups.some(g => g.gid === STEAM_GROUP_ID);
        if (isMember) return true;
    } catch (e) {}

    try {
        const xmlUrl = `https://steamcommunity.com/groups/${STEAM_GROUP_URL_NAME}/memberslistxml/?xml=1`;
        const xmlRes = await axios.get(xmlUrl);
        if (xmlRes.data.includes(`<steamID64>${userSteamId}</steamID64>`)) {
            return true;
        }
    } catch (e) {
        console.error("Group Check Error:", e.message);
    }
    return false;
}

// --- 1. STEAM AUTH ---
passport.use(new SteamStrategy({
    returnURL: `${DOMAIN}/auth/steam/return`,
    realm: `${DOMAIN}/`,
    apiKey: STEAM_API_KEY
  },
  async (identifier, profile, done) => {
      try {
          // Initialize user with empty ranks array if new
          await pool.query(
              `INSERT INTO users (steam_id, gems, ranks) VALUES (\$1, 0, '{}') ON CONFLICT (steam_id) DO NOTHING`,
              [profile.id]
          );
      } catch (err) { console.error("DB Save Error:", err); }
      return done(null, profile);
  }
));

// --- 2. DISCORD AUTH ---
passport.use(new DiscordStrategy({
    clientID: DISCORD_CLIENT_ID,
    clientSecret: DISCORD_CLIENT_SECRET,
    callbackURL: `${DOMAIN}/auth/discord/callback`,
    scope: ['identify', 'guilds.join'],
    passReqToCallback: true 
}, async (req, accessToken, refreshToken, profile, done) => {
    
    if (!req.user) return done(new Error("You must be logged into Steam first!"));

    try {
        const existingCheck = await pool.query(
            `SELECT steam_id FROM users WHERE discord_id = \$1`,
            [profile.id]
        );

        if (existingCheck.rows.length > 0) {
            const existingSteamId = existingCheck.rows[0].steam_id;
            if (existingSteamId !== req.user.id) {
                return done(null, false, { message: 'duplicate' });
            }
        }

        await pool.query(
            `UPDATE users SET discord_id = \$1, discord_username = \$2 WHERE steam_id = \$3`,
            [profile.id, profile.username, req.user.id]
        );
        
        try {
            await axios.put(
                `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${profile.id}`,
                { access_token: accessToken },
                { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
            );
        } catch (e) { }

        return done(null, req.user);
    } catch (err) {
        return done(err, null);
    }
}));

// --- AUTH ROUTES ---
app.get('/auth/steam', passport.authenticate('steam'));
app.get('/auth/steam/return', passport.authenticate('steam', { failureRedirect: '/' }), (req, res) => res.redirect('/index.html'));

app.get('/auth/discord', passport.authenticate('discord'));

app.get('/auth/discord/callback', (req, res, next) => {
    passport.authenticate('discord', (err, user, info) => {
        if (err) return next(err);
        if (!user && info && info.message === 'duplicate') {
            return res.redirect('/profile.html?error=discord_in_use');
        }
        if (!user) return res.redirect('/profile.html?error=unknown');

        req.logIn(user, (err) => {
            if (err) return next(err);
            return res.redirect('/profile.html');
        });
    })(req, res, next);
});

app.post('/auth/discord/unlink', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Not logged in" });
    try {
        await pool.query(
            `UPDATE users SET discord_id = NULL, discord_username = NULL WHERE steam_id = \$1`,
            [req.user.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Database error" });
    }
});

// --- USER DATA ---
app.get('/user', async (req, res) => {
    if(!req.user) return res.json(null);
    const isAdmin = ADMIN_IDS.includes(req.user.id);

    let discordInfo = null;
    let gemBalance = 0;
    let ranks = [];

    try {
        const dbRes = await pool.query('SELECT discord_username, gems, ranks FROM users WHERE steam_id = \$1', [req.user.id]);
        if (dbRes.rows.length > 0) {
            discordInfo = dbRes.rows[0].discord_username;
            gemBalance = dbRes.rows[0].gems || 0;
            ranks = dbRes.rows[0].ranks || [];
        }
    } catch(e) { console.error("DB Error:", e); }

    const inSteamGroup = await checkGroupMembership(req.user.id);

    res.json({ 
        ...req.user, 
        isAdmin, 
        discord: discordInfo,
        gems: gemBalance, 
        ranks: ranks,
        inSteamGroup: inSteamGroup 
    });
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        req.session.destroy(() => res.redirect('/index.html'));
    });
});

// --- STORE API (WEBSITE) ---

// 1. Buy Rank (FIXED: Handles NULL arrays)
app.post('/api/store/buy-rank', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { rank } = req.body;
    if(!rank) return res.status(400).json({error: "No rank specified"});

    try {
        const check = await pool.query('SELECT ranks FROM users WHERE steam_id = \$1', [req.user.id]);
        const currentRanks = check.rows[0].ranks || [];

        if(currentRanks.includes(rank)) return res.json({ success: false, error: "Already owned" });

        // IMPORTANT: COALESCE ensures we don't try to append to a NULL value
        await pool.query(
            "UPDATE users SET ranks = array_append(COALESCE(ranks, '{}'), \$1) WHERE steam_id = \$2",
            [rank, req.user.id]
        );
        res.json({ success: true, message: `Purchased ${rank.toUpperCase()}!` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "DB Error" });
    }
});

// 2. Buy Gems
app.post('/api/store/buy-gems', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { amount } = req.body;
    if(!amount || isNaN(amount)) return res.status(400).json({error: "Invalid amount"});

    try {
        await pool.query('UPDATE users SET gems = gems + \$1 WHERE steam_id = \$2', [amount, req.user.id]);
        res.json({ success: true, message: `Added ${amount} gems!` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "DB Error" });
    }
});

// --- SERVER INTERACTION API (OXIDE) ---

// 1. Redeem Kit
app.post('/api/server/redeem', async (req, res) => {
    try {
        const { steamId, kit } = req.query;
        if (!steamId || !kit) return res.status(400).send("Missing Params");

        // CHECK 1: Rank Kits (DB Check)
        const rankKits = ['vip', 'elite', 'soldier', 'juggernaut', 'overlord'];
        if (rankKits.includes(kit)) {
            const userRes = await pool.query('SELECT ranks FROM users WHERE steam_id = \$1', [steamId]);
            const userRanks = (userRes.rows[0] && userRes.rows[0].ranks) ? userRes.rows[0].ranks : [];
            
            if (userRanks.includes(kit)) return res.status(200).send("OK");
            else return res.status(403).send("LOCKED");
        }

        // CHECK 2: Discord
        if (kit === 'discord' || kit === 'discordbuild') {
            const userRes = await pool.query('SELECT discord_id FROM users WHERE steam_id = \$1', [steamId]);
            if (!userRes.rows[0]?.discord_id) return res.status(403).send("FAIL_LINK"); 
            try {
                await axios.get(
                    `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${userRes.rows[0].discord_id}`,
                    { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
                );
                return res.status(200).send("OK");
            } catch (discordErr) {
                return res.status(403).send("FAIL_GUILD");
            }
        }

        // CHECK 3: Steam Group
        if (kit === 'steam') {
            const inGroup = await checkGroupMembership(steamId);
            return inGroup ? res.status(200).send("OK") : res.status(403).send("FAIL_STEAM_GROUP");
        }

        res.status(200).send("OK");
    } catch (err) { res.status(500).send("ERROR"); }
});

// 2. Get Balance
app.get('/api/server/balance', async (req, res) => {
    const { steamId } = req.query;
    if (!steamId) return res.send("0");

    try {
        const result = await pool.query('SELECT gems FROM users WHERE steam_id = \$1', [steamId]);
        if (result.rows.length > 0) {
            return res.send(result.rows[0].gems.toString());
        }
        return res.send("0");
    } catch (err) {
        console.error(err);
        return res.send("0");
    }
});

// 3. Spend Gems (Transaction)
app.post('/api/server/spend', async (req, res) => {
    const { steamId, cost } = req.body;
    if (!steamId || !cost) return res.status(400).send("ERROR");

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Start Transaction

        const resCheck = await client.query('SELECT gems FROM users WHERE steam_id = \$1 FOR UPDATE', [steamId]);
        
        if (resCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.send("NO_USER");
        }

        const currentBalance = resCheck.rows[0].gems;
        if (currentBalance < cost) {
            await client.query('ROLLBACK');
            return res.send("INSUFFICIENT_FUNDS");
        }

        await client.query('UPDATE users SET gems = gems - \$1 WHERE steam_id = \$2', [cost, steamId]);
        await client.query('COMMIT'); 
        return res.send("SUCCESS");

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(err);
        return res.send("ERROR");
    } finally {
        client.release();
    }
});

// --- TICKET API ---

app.get('/api/admin/tickets', async (req, res) => {
    // 1. Check if user is logged in AND is an admin
    if (!req.user || !ADMIN_IDS.includes(req.user.id)) {
        return res.status(403).json({ error: "Access Denied" });
    }

    try {
        // 2. Fetch all tickets. 
        // Logic: specific sorting (Open tickets first, then Answered, then Closed)
        const query = `
            SELECT * FROM tickets 
            ORDER BY 
            CASE 
                WHEN status = 'Open' THEN 1 
                WHEN status = 'Answered' THEN 2 
                WHEN status = 'Resolved' THEN 3
                ELSE 4 
            END, 
            id DESC
        `;
        
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (err) {
        console.error("Admin Ticket Load Error:", err);
        res.status(500).json({ error: "Database error" });
    }
});

app.post('/api/tickets', async (req, res) => {
    // DEBUG LOG: See if the server recognizes the user
    console.log("Ticket Attempt. User:", req.user ? req.user.id : "Not Logged In");

    if (!req.user) return res.status(401).json({ error: 'Login required' });
    const { category, subject, description } = req.body;
    
    // Safety check for avatar
    const avatar = (req.user.photos && req.user.photos[2]) ? req.user.photos[2].value : 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_full.jpg';

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const ticketRes = await client.query(
            'INSERT INTO tickets (steamId, username, avatar, category, subject) VALUES (\$1, \$2, \$3, \$4, \$5) RETURNING id',
            [req.user.id, req.user.displayName, avatar, category, subject]
        );
        const ticketId = ticketRes.rows[0].id;
        
        await client.query(
            'INSERT INTO messages (ticket_id, sender_steamId, sender_name, sender_avatar, content) VALUES (\$1, \$2, \$3, \$4, \$5)',
            [ticketId, req.user.id, req.user.displayName, avatar, description]
        );
        await client.query('COMMIT');
        res.json({ success: true });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error("Ticket Create Error:", e); // Log the actual error
        res.status(500).json({ error: 'Database error' });
    } finally {
        client.release();
    }
});

app.get('/api/my-tickets', async (req, res) => {
    if (!req.user) return res.status(401).json([]);
    try {
        const result = await pool.query('SELECT * FROM tickets WHERE steamId = \$1 ORDER BY id DESC', [req.user.id]);
        res.json(result.rows);
    } catch (err) { res.json([]); }
});

app.get('/api/ticket/:id', async (req, res) => {
    if (!req.user) return res.status(401).send("Unauthorized");
    const ticketId = req.params.id;
    try {
        const ticketRes = await pool.query('SELECT * FROM tickets WHERE id = \$1', [ticketId]);
        const ticket = ticketRes.rows[0];
        if (!ticket) return res.status(404).send("Ticket not found");
        
        const isAdminUser = ADMIN_IDS.includes(req.user.id);
        if (ticket.steamid !== req.user.id && !isAdminUser) return res.status(403).send("Forbidden");

        const msgRes = await pool.query('SELECT * FROM messages WHERE ticket_id = \$1 ORDER BY created_at ASC', [ticketId]);
        const enrichedMessages = msgRes.rows.map(msg => ({
            ...msg,
            isAdminSender: ADMIN_IDS.includes(msg.sender_steamid)
        }));
        res.json({ ticket, messages: enrichedMessages, currentUserSteamId: req.user.id, isAdmin: isAdminUser });
    } catch (err) { res.status(500).send("DB Error"); }
});

app.post('/api/ticket/:id/reply', async (req, res) => {
    if (!req.user) return res.status(401).send("Unauthorized");
    const ticketId = req.params.id;
    const isAdminUser = ADMIN_IDS.includes(req.user.id);
    try {
        const ticketCheck = await pool.query('SELECT status FROM tickets WHERE id = \$1', [ticketId]);
        if (ticketCheck.rows.length === 0) return res.status(404).send("Not found");
        if (ticketCheck.rows[0].status === 'Closed') return res.status(400).json({ error: "Ticket is closed." });

        await pool.query(
            'INSERT INTO messages (ticket_id, sender_steamId, sender_name, sender_avatar, content) VALUES (\$1, \$2, \$3, \$4, \$5)',
            [ticketId, req.user.id, req.user.displayName, req.user.photos[2].value, req.body.content]
        );
        const newStatus = isAdminUser ? 'Answered' : 'Open';
        await pool.query('UPDATE tickets SET status = \$1 WHERE id = \$2', [newStatus, ticketId]);
        res.json({ success: true });
    } catch (err) { res.status(500).send("Error"); }
});

// --- SERVER INFO API ---
app.get('/api/servers', async (req, res) => {
    try {
        const promises = SERVERS.map(server =>
            GameDig.query({ type: server.type, host: server.ip, port: server.port, maxAttempts: 2 })
            .then((state) => ({
                name: server.name, ip: server.ip, port: server.port, map: state.map, players: state.players.length, maxPlayers: state.maxplayers, status: 'Online'
            })).catch((error) => ({
                name: server.name, ip: server.ip, port: server.port, map: "N/A", players: 0, maxPlayers: 0, status: 'Offline'
            }))
        );
        res.json(await Promise.all(promises));
    } catch (err) { res.json([]); }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});