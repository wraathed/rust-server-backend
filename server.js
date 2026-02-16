const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const { Pool } = require('pg');
const { GameDig } = require('gamedig');
const path = require('path');
const axios = require('axios');

// --- CONFIGURATION ---
const app = express();
const port = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

// *** MASTER RESET SWITCH ***
// This will DROP your ticket tables and remake them every time the server starts.
// Once it works, change this to FALSE.
const REBUILD_DB = true; 

// --- DATABASE CONNECTION (NEON) ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Required for Neon
});

// --- DB INITIALIZATION ---
const initDb = async () => {
    const client = await pool.connect();
    try {
        console.log(">> CONNECTED TO DB. STARTING INIT...");

        // 1. Session Table (For Persistent Login)
        await client.query(`
            CREATE TABLE IF NOT EXISTS "session" (
                "sid" varchar NOT NULL COLLATE "default",
                "sess" json NOT NULL,
                "expire" timestamp(6) NOT NULL
            )
            WITH (OIDS=FALSE);
        `);
        try { await client.query(`ALTER TABLE "session" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE`); } catch (e) {}
        await client.query(`CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire")`);

        // 2. Users Table
        await client.query(`CREATE TABLE IF NOT EXISTS users (steam_id TEXT PRIMARY KEY, discord_id TEXT, discord_username TEXT, gems INT DEFAULT 0, ranks TEXT[] DEFAULT '{}')`);
        
        // 3. TICKET SYSTEM REBUILD
        if (REBUILD_DB) {
            console.log(">> DROPPING OLD TICKET TABLES...");
            await client.query("DROP TABLE IF EXISTS messages CASCADE");
            await client.query("DROP TABLE IF EXISTS tickets CASCADE");
        }

        console.log(">> CREATING TICKET TABLES...");
        
        // Tickets Table - Using snake_case for everything
        await client.query(`
            CREATE TABLE IF NOT EXISTS tickets (
                id SERIAL PRIMARY KEY,
                steam_id TEXT NOT NULL,
                username TEXT,
                avatar TEXT,
                category TEXT,
                subject TEXT,
                description TEXT,
                status TEXT DEFAULT 'Open',
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Messages Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER REFERENCES tickets(id) ON DELETE CASCADE,
                sender_steam_id TEXT,
                sender_name TEXT,
                sender_avatar TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        console.log(">> DATABASE INITIALIZATION COMPLETE. READY.");
    } catch (err) {
        console.error(">> FATAL DB ERROR:", err);
    } finally {
        client.release();
    }
};

// Run DB Init
initDb();

// --- CONSTANTS ---
app.set('trust proxy', 1);

const ADMIN_IDS = ['76561198871950726', '76561198839698805']; 
const DOMAIN = 'https://classic-rust-api.onrender.com'; 

const STEAM_API_KEY = process.env.STEAM_API_KEY;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;

const SERVERS = [
    { name: "Classic Rust Test Server", ip: "75.76.68.155", port: 28016, type: 'rust' }
];

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Persistent Sessions
app.use(session({
    store: new pgSession({ pool: pool, tableName: 'session' }),
    secret: 'super_secret_rust_key_12345',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction, 
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000 
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- HELPER: GET AVATAR ---
const getAvatar = (user) => {
    if (!user || !user.photos) return 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_full.jpg';
    // Steam strategy usually returns 3 photos (Small, Medium, Large). Index 2 is Large.
    if (user.photos.length > 2) return user.photos[2].value;
    if (user.photos.length > 0) return user.photos[0].value;
    return 'https://steamcdn-a.akamaihd.net/steamcommunity/public/images/avatars/fe/fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb_full.jpg';
};

// --- AUTHENTICATION ---
passport.use(new SteamStrategy({
    returnURL: `${DOMAIN}/auth/steam/return`,
    realm: `${DOMAIN}/`,
    apiKey: STEAM_API_KEY
  },
  async (identifier, profile, done) => {
      // Ensure user exists in DB immediately
      try {
          await pool.query(
              `INSERT INTO users (steam_id, gems, ranks) VALUES (\\$1, 0, '{}') ON CONFLICT (steam_id) DO NOTHING`,
              [profile.id]
          );
      } catch (err) { console.error("Auth DB Error:", err); }
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
    if (!req.user) return done(new Error("Login to Steam first"));
    // (Discord logic omitted for brevity, keeping existing logic is fine)
    return done(null, req.user);
}));

app.get('/auth/steam', passport.authenticate('steam'));
app.get('/auth/steam/return', passport.authenticate('steam', { failureRedirect: '/' }), (req, res) => res.redirect('/index.html'));
app.get('/user', (req, res) => {
    if (!req.user) return res.json(null);
    res.json({ ...req.user, isAdmin: ADMIN_IDS.includes(req.user.id) });
});
app.get('/logout', (req, res) => { req.logout(() => { req.session.destroy(() => res.redirect('/index.html')); }); });

// ==========================================
//  TICKET SYSTEM (REBUILT & SIMPLIFIED)
// ==========================================

// 1. CREATE TICKET
app.post('/api/tickets', async (req, res) => {
    // 1. Auth Check
    if (!req.user) {
        console.log("Create Ticket: No User Session Found");
        return res.status(401).json({ error: "You must be logged in." });
    }

    const { category, subject, description } = req.body;
    
    // 2. Validation
    if (!category || !subject || !description) {
        return res.status(400).json({ error: "All fields are required." });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const avatar = getAvatar(req.user);
        const steamId = req.user.id;
        const username = req.user.displayName || "Unknown Survivor";

        // 3. Insert Ticket
        const ticketRes = await client.query(
            `INSERT INTO tickets (steam_id, username, avatar, category, subject, description) 
             VALUES (\\$1, \\$2, \\$3, \\$4, \\$5, \\$6) 
             RETURNING id`,
            [steamId, username, avatar, category, subject, description]
        );
        
        const newTicketId = ticketRes.rows[0].id;

        // 4. Insert Initial Message
        await client.query(
            `INSERT INTO messages (ticket_id, sender_steam_id, sender_name, sender_avatar, content) 
             VALUES (\\$1, \\$2, \\$3, \\$4, \\$5)`,
            [newTicketId, steamId, username, avatar, description]
        );

        await client.query('COMMIT');
        console.log(`>> Ticket #${newTicketId} created by ${username}`);
        res.json({ success: true, ticketId: newTicketId });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error(">> CREATE TICKET ERROR:", err); // Watch this log
        res.status(500).json({ error: "Database error during creation.", details: err.message });
    } finally {
        client.release();
    }
});

// 2. GET MY TICKETS
app.get('/api/my-tickets', async (req, res) => {
    if (!req.user) return res.json([]); // Return empty array if not logged in

    try {
        // Simple query, ordered by newest first
        const result = await pool.query(
            `SELECT * FROM tickets WHERE steam_id = \\$1 ORDER BY id DESC`, 
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(">> FETCH TICKETS ERROR:", err);
        res.status(500).json({ error: "Failed to fetch tickets." });
    }
});

// 3. GET SINGLE TICKET
app.get('/api/ticket/:id', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    
    try {
        const ticketId = req.params.id;
        
        // Fetch Ticket
        const ticketRes = await pool.query(`SELECT * FROM tickets WHERE id = \\$1`, [ticketId]);
        if (ticketRes.rows.length === 0) return res.status(404).json({ error: "Ticket not found" });

        const ticket = ticketRes.rows[0];
        const isAdmin = ADMIN_IDS.includes(req.user.id);

        // Access Control
        if (ticket.steam_id !== req.user.id && !isAdmin) {
            return res.status(403).json({ error: "Forbidden" });
        }

        // Fetch Messages
        const msgRes = await pool.query(`SELECT * FROM messages WHERE ticket_id = \\$1 ORDER BY created_at ASC`, [ticketId]);

        res.json({ 
            ticket, 
            messages: msgRes.rows, 
            currentUserSteamId: req.user.id, 
            isAdmin 
        });

    } catch (err) {
        console.error(">> GET TICKET ERROR:", err);
        res.status(500).json({ error: "Server Error" });
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

app.listen(port, () => console.log(`>> SERVER STARTED ON PORT ${port}`));