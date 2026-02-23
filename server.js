const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const { Pool } = require('pg');
const { GameDig } = require('gamedig');
const path = require('path');
const axios = require('axios');
const pgSession = require('connect-pg-simple')(session);

const app = express();
const port = process.env.PORT || 3000;

// --- DATABASE CONNECTION ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// --- RENDER CONFIG ---
app.set('trust proxy', 1);

// --- CONFIGURATION ---
const ADMIN_IDS = ['76561198871950726', '76561198839698805']; 
const DOMAIN = 'https://classic-rust-api.onrender.com'; 

const STEAM_API_KEY = process.env.STEAM_API_KEY;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;

// --- STEAM GROUP DETAILS ---
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
        pool: pool,                // Use your existing database connection
        tableName: 'session',      // Matches the table in your screenshot
        createTableIfMissing: false // Since you already created it manually
    }),
    secret: 'super_secret_rust_key_12345',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true, 
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 Days (standard for persistent logins)
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
        // XML Fallback for Private Profiles
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
          await pool.query(
              `INSERT INTO users (steam_id) VALUES (\$1) ON CONFLICT (steam_id) DO NOTHING`,
              [profile.id]
          );
      } catch (err) { console.error("DB Save Error:", err); }
      return done(null, profile);
  }
));

// --- 2. DISCORD AUTH (UPDATED FOR DUPLICATE CHECK) ---
passport.use(new DiscordStrategy({
    clientID: DISCORD_CLIENT_ID,
    clientSecret: DISCORD_CLIENT_SECRET,
    callbackURL: `${DOMAIN}/auth/discord/callback`,
    scope: ['identify', 'guilds.join'],
    passReqToCallback: true 
}, async (req, accessToken, refreshToken, profile, done) => {
    
    if (!req.user) return done(new Error("You must be logged into Steam first!"));

    try {
        // 1. Check if this Discord ID is already linked to a DIFFERENT Steam ID
        const existingCheck = await pool.query(
            `SELECT steam_id FROM users WHERE discord_id = \$1`,
            [profile.id]
        );

        if (existingCheck.rows.length > 0) {
            const existingSteamId = existingCheck.rows[0].steam_id;
            // If linked to someone else, reject
            if (existingSteamId !== req.user.id) {
                return done(null, false, { message: 'duplicate' });
            }
        }

        // 2. Link account
        await pool.query(
            `UPDATE users SET discord_id = \$1, discord_username = \$2 WHERE steam_id = \$3`,
            [profile.id, profile.username, req.user.id]
        );
        
        // 3. Join Guild
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

// Updated Callback to handle duplicates
app.get('/auth/discord/callback', (req, res, next) => {
    passport.authenticate('discord', (err, user, info) => {
        if (err) return next(err);
        
        // If "info" contains message duplicate, redirect with error param
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
        console.error("Unlink Error:", err);
        res.status(500).json({ error: "Database error" });
    }
});

// --- USER DATA ---
app.get('/user', async (req, res) => {
    if(!req.user) return res.json(null);
    const isAdmin = ADMIN_IDS.includes(req.user.id);

    let discordInfo = null;
    try {
        const dbRes = await pool.query('SELECT discord_username FROM users WHERE steam_id = \$1', [req.user.id]);
        if (dbRes.rows.length > 0 && dbRes.rows[0].discord_username) {
            discordInfo = dbRes.rows[0].discord_username;
        }
    } catch(e) { console.error("DB Error:", e); }

    const inSteamGroup = await checkGroupMembership(req.user.id);

    res.json({ 
        ...req.user, 
        isAdmin, 
        discord: discordInfo,
        inSteamGroup: inSteamGroup 
    });
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        req.session.destroy(() => res.redirect('/index.html'));
    });
});

// --- API ROUTES (Tickets/Servers/Redeem) remain unchanged ---
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

app.post('/api/tickets', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Login required' });
    const { category, subject, description } = req.body;
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const ticketRes = await client.query(
            'INSERT INTO tickets (steam_id, username, avatar, category, subject) VALUES (\$1, \$2, \$3, \$4, \$5) RETURNING id',
            [req.user.id, req.user.displayName, req.user.photos[2].value, category, subject]
        );
        const ticketId = ticketRes.rows[0].id;
        await client.query(
            'INSERT INTO messages (ticket_id, sender_steam_id, sender_name, sender_avatar, content) VALUES (\$1, \$2, \$3, \$4, \$5)',
            [ticketId, req.user.id, req.user.displayName, req.user.photos[2].value, description]
        );
        await client.query('COMMIT');
        res.json({ success: true });
    } catch (e) {
        await client.query('ROLLBACK');
        res.status(500).json({ error: 'Database error' });
    } finally {
        client.release();
    }
});

app.get('/api/my-tickets', async (req, res) => {
    if (!req.user) return res.status(401).json([]);
    try {
        const result = await pool.query('SELECT * FROM tickets WHERE steam_id = \$1 ORDER BY id DESC', [req.user.id]);
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

// FIX: Change ticket.steamid to ticket.steam_id
if (ticket.steam_id !== req.user.id && !isAdminUser) return res.status(403).send("Forbidden");

        const msgRes = await pool.query('SELECT * FROM messages WHERE ticket_id = \$1 ORDER BY created_at ASC', [ticketId]);
        
        const enrichedMessages = msgRes.rows.map(msg => ({
    ...msg,
    // Check both just in case, but sender_steam_id is the new standard
    isAdminSender: ADMIN_IDS.includes(msg.sender_steam_id) 
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
        
        if (ticketCheck.rows[0].status === 'Closed') {
            return res.status(400).json({ error: "Ticket is closed." });
        }

        await pool.query(
            'INSERT INTO messages (ticket_id, sender_steam_id, sender_name, sender_avatar, content) VALUES (\$1, \$2, \$3, \$4, \$5)',
            [ticketId, req.user.id, req.user.displayName, req.user.photos[2].value, req.body.content]
        );
        
        const newStatus = isAdminUser ? 'Answered' : 'Open';
        await pool.query('UPDATE tickets SET status = \$1 WHERE id = \$2', [newStatus, ticketId]);
        res.json({ success: true });
    } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/admin/tickets', async (req, res) => {
    if (!ADMIN_IDS.includes(req.user?.id)) return res.status(403).json([]);
    try {
        const result = await pool.query('SELECT * FROM tickets ORDER BY status DESC, created_at DESC');
        res.json(result.rows);
    } catch (err) { res.json([]); }
});

app.post('/api/ticket/:id/status', async (req, res) => {
    if (!ADMIN_IDS.includes(req.user?.id)) return res.status(403).send("Admins only");
    try {
        await pool.query('UPDATE tickets SET status = \$1 WHERE id = \$2', [req.body.status, req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).send("Error"); }
});

// --- GAME SERVER API (RUST PLUGIN CONNECTIVITY) ---

// 1. Get Gem Balance (Called by plugin "FetchGemBalance")
app.get('/api/server/balance', async (req, res) => {
    const { steamId } = req.query;
    try {
        const result = await pool.query('SELECT gems FROM users WHERE steam_id = \$1', [steamId]);
        if (result.rows.length > 0) {
            // Plugin expects raw text number (e.g., "500")
            res.send(result.rows[0].gems.toString());
        } else {
            res.send("0");
        }
    } catch (err) {
        res.send("0");
    }
});

// 2. Spend Gems (Called by plugin "CmdShopBuy")
app.post('/api/server/spend', async (req, res) => {
    const { steamId, cost } = req.body;
    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            
            // Check Balance
            const userRes = await client.query('SELECT gems FROM users WHERE steam_id = \$1 FOR UPDATE', [steamId]);
            if (userRes.rows.length === 0) throw new Error("User not found");
            
            const currentGems = userRes.rows[0].gems;

            if (currentGems >= cost) {
                await client.query('UPDATE users SET gems = gems - \$1 WHERE steam_id = \$2', [cost, steamId]);
                await client.query('COMMIT');
                // Plugin expects exact string "SUCCESS"
                res.send("SUCCESS"); 
            } else {
                await client.query('ROLLBACK');
                // Plugin expects exact string "INSUFFICIENT_FUNDS"
                res.send("INSUFFICIENT_FUNDS");
            }
        } catch (e) {
            await client.query('ROLLBACK');
            res.send("ERROR");
        } finally {
            client.release();
        }
    } catch (err) {
        res.send("ERROR");
    }
});

// --- NEW: SHOP POINTS SYSTEM ---

// 1. Grant Shop Points (Called by Rust Plugin every 20 mins)
app.post('/api/server/grant-points', async (req, res) => {
    const { steamId, amount } = req.body;
    
    // Basic validation
    if (!steamId || !amount) return res.status(400).send("MISSING_DATA");

    try {
        // Increment shop_points. If user doesn't exist, ignore (or could insert).
        // Assuming user exists because they are online playing.
        await pool.query(
            'UPDATE users SET shop_points = shop_points + \$1 WHERE steam_id = \$2',
            [amount, steamId]
        );
        console.log(`[Points System] Granted ${amount} points to ${steamId}`);
        res.status(200).send("OK");
    } catch (err) {
        console.error("Grant Points Error:", err);
        res.status(500).send("ERROR");
    }
});

// 2. Buy Shop Points (Website Test Panel)
app.post('/api/store/buy-points', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const amount = 500; // Fixed test amount

    try {
        await pool.query(
            'UPDATE users SET shop_points = shop_points + \$1 WHERE steam_id = \$2',
            [amount, req.user.id]
        );
        res.json({ success: true, message: `Added ${amount} Shop Points!` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "DB Error" });
    }
});

// 3. Redeem Kit (Updated to include Ranks)
app.post('/api/server/redeem', async (req, res) => {
    try {
        const { steamId, kit } = req.query;
        console.log(`[Game Server] Request from ${steamId} for kit: ${kit}`);

        if (!steamId || !kit) return res.status(400).send("Missing Params");

        // -- LOGIC FOR RANKS (VIP, ELITE, ETC) --
        const RANK_KITS = ['vip', 'elite', 'soldier', 'juggernaut', 'overlord'];
        if (RANK_KITS.includes(kit)) {
            const dbRes = await pool.query('SELECT ranks FROM users WHERE steam_id = \$1', [steamId]);
            // Check if user has the rank in their array
            if (dbRes.rows.length > 0 && dbRes.rows[0].ranks && dbRes.rows[0].ranks.includes(kit)) {
                return res.status(200).send("OK");
            } else {
                return res.status(403).send("LOCKED");
            }
        }

        // -- LOGIC FOR DISCORD --
        if (kit === 'discord' || kit === 'discordbuild') {
            const userRes = await pool.query('SELECT discord_id FROM users WHERE steam_id = \$1', [steamId]);
            if (userRes.rows.length === 0 || !userRes.rows[0].discord_id) {
                return res.status(403).send("FAIL_LINK"); 
            }
            // Optional: Double check if they are still in the guild via Discord API here
            return res.status(200).send("OK");
        }

        // -- LOGIC FOR STEAM GROUP --
        if (kit === 'steam') {
            const inGroup = await checkGroupMembership(steamId);
            if (inGroup) {
                return res.status(200).send("OK");
            } else {
                return res.status(403).send("FAIL_STEAM_GROUP");
            }
        }

        res.status(200).send("OK");

    } catch (err) {
        console.error("Redeem Error:", err);
        res.status(500).send("ERROR");
    }
});

// --- NEW: Shop Points Logic ---

// 1. Get User Data (Combined Balance) - used by the new Shop UI
// --- GET USER DATA (GEMS & POINTS) ---
app.get('/api/server/user-data', async (req, res) => {
    const { steamId } = req.query;
    try {
        const result = await pool.query('SELECT gems, shop_points FROM users WHERE steam_id = \$1', [steamId]);
        
        if (result.rows.length > 0) {
            // We map 'shop_points' from DB to 'points' for the JSON
            res.json({ 
                gems: result.rows[0].gems || 0, 
                points: result.rows[0].shop_points || 0 
            });
        } else {
            res.json({ gems: 0, points: 0 });
        }
    } catch (err) {
        console.error("User Data Error:", err);
        res.json({ gems: 0, points: 0 });
    }
});

// 2. Spend Shop Points
app.post('/api/server/spend-points', async (req, res) => {
    const { steamId, cost } = req.body;
    try {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const userRes = await client.query('SELECT shop_points FROM users WHERE steam_id = \$1 FOR UPDATE', [steamId]);
            if (userRes.rows.length === 0) throw new Error("User not found");
            
            const currentPoints = userRes.rows[0].shop_points || 0;

            if (currentPoints >= cost) {
                await client.query('UPDATE users SET shop_points = shop_points - \$1 WHERE steam_id = \$2', [cost, steamId]);
                await client.query('COMMIT');
                res.send("SUCCESS"); 
            } else {
                await client.query('ROLLBACK');
                res.send("INSUFFICIENT_FUNDS");
            }
        } catch (e) {
            await client.query('ROLLBACK');
            res.send("ERROR");
        } finally {
            client.release();
        }
    } catch (err) {
        res.send("ERROR");
    }
});

// --- STORE API (WEBSITE PURCHASES) ---

// 1. Buy Gems (Simulated Test)
app.post('/api/store/buy-gems', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const amount = 20000; // Fixed test amount

    try {
        await pool.query(
            'UPDATE users SET gems = gems + \$1 WHERE steam_id = \$2',
            [amount, req.user.id]
        );
        res.json({ success: true, message: `Added ${amount} Gems!` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "DB Error" });
    }
});

// 2. Buy Rank (Simulated Test)
app.post('/api/store/buy-rank', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { rank } = req.body; // e.g., "vip"

    try {
        // Add rank to the array if it doesn't exist
        await pool.query(
            `UPDATE users SET ranks = array_append(ranks, \$1) 
             WHERE steam_id = \$2 AND NOT (\$1 = ANY(ranks))`,
            [rank, req.user.id]
        );
        res.json({ success: true, message: `Purchased ${rank} Rank!` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "DB Error" });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});