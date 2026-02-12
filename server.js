const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const { Pool } = require('pg');
const { GameDig } = require('gamedig');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// --- DATABASE CONNECTION (NEON/POSTGRES) ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// --- RENDER CONFIGURATION ---
// Critical: Tells Express it's behind Render's Load Balancer (for secure cookies)
app.set('trust proxy', 1);

// --- MAIN CONFIGURATION ---
const ADMIN_IDS = ['76561198871950726', '76561198839698805']; // Replace with your IDs
const DOMAIN = 'https://classic-rust-api.onrender.com'; 

// Ensure you set STEAM_API_KEY in your Render Environment Variables!
const STEAM_API_KEY = process.env.STEAM_API_KEY || 'YOUR_API_KEY_HERE_IF_TESTING_LOCALLY';

const SERVERS = [
    { name: "Classic Rust Test Server", ip: "75.76.68.155", port: 28016, type: 'rust' }
];

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 1. SERVE STATIC FILES
app.use(express.static(path.join(__dirname, 'public')));

// 2. SESSION COOKIES
app.use(session({
    secret: 'super_secret_rust_key_12345',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true, // Required for HTTPS (Render)
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 1 Day
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- AUTHENTICATION ---
passport.use(new SteamStrategy({
    returnURL: `${DOMAIN}/auth/steam/return`,
    realm: `${DOMAIN}/`,
    apiKey: STEAM_API_KEY
  },
  (identifier, profile, done) => done(null, profile)
));

app.get('/auth/steam', passport.authenticate('steam'));

app.get('/auth/steam/return',
  passport.authenticate('steam', { failureRedirect: '/' }),
  (req, res) => {
      res.redirect('/index.html');
  }
);

app.get('/user', (req, res) => {
    if(!req.user) return res.json(null);
    const isAdmin = ADMIN_IDS.includes(req.user.id);
    res.json({ ...req.user, isAdmin });
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        req.session.destroy(() => {
            res.redirect('/index.html');
        });
    });
});

// --- API ROUTES ---

// 1. Server Status
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

// 2. Create Ticket
app.post('/api/tickets', async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Login required' });
    const { category, subject, description } = req.body;
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const ticketRes = await client.query(
            'INSERT INTO tickets (steamId, username, avatar, category, subject) VALUES (\$1, \$2, \$3, \$4, \$5) RETURNING id',
            [req.user.id, req.user.displayName, req.user.photos[2].value, category, subject]
        );
        const ticketId = ticketRes.rows[0].id;
        await client.query(
            'INSERT INTO messages (ticket_id, sender_steamId, sender_name, sender_avatar, content) VALUES (\$1, \$2, \$3, \$4, \$5)',
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

// 3. Get My Tickets
app.get('/api/my-tickets', async (req, res) => {
    if (!req.user) return res.status(401).json([]);
    try {
        const result = await pool.query('SELECT * FROM tickets WHERE steamId = \$1 ORDER BY id DESC', [req.user.id]);
        res.json(result.rows);
    } catch (err) { res.json([]); }
});

// 4. Get Single Ticket (Chat)
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

// 5. Reply to Ticket
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
            'INSERT INTO messages (ticket_id, sender_steamId, sender_name, sender_avatar, content) VALUES (\$1, \$2, \$3, \$4, \$5)',
            [ticketId, req.user.id, req.user.displayName, req.user.photos[2].value, req.body.content]
        );
        
        const newStatus = isAdminUser ? 'Answered' : 'Open';
        await pool.query('UPDATE tickets SET status = \$1 WHERE id = \$2', [newStatus, ticketId]);
        res.json({ success: true });
    } catch (err) { res.status(500).send("Error"); }
});

// 6. Admin: Get All Tickets
app.get('/api/admin/tickets', async (req, res) => {
    if (!ADMIN_IDS.includes(req.user?.id)) return res.status(403).json([]);
    try {
        const result = await pool.query('SELECT * FROM tickets ORDER BY status DESC, created_at DESC');
        res.json(result.rows);
    } catch (err) { res.json([]); }
});

// 7. Admin: Change Status
app.post('/api/ticket/:id/status', async (req, res) => {
    if (!ADMIN_IDS.includes(req.user?.id)) return res.status(403).send("Admins only");
    try {
        await pool.query('UPDATE tickets SET status = \$1 WHERE id = \$2', [req.body.status, req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).send("Error"); }
});

// --- NEW SECTION: GAME SERVER INTERACTION ---

// 8. Game Server: Redeem Kit
// This is called by your C# Oxide Plugin when a player clicks "Redeem"
app.post('/api/server/redeem', async (req, res) => {
    try {
        // The C# plugin sends data in the URL Query String: ?steamId=123&kit=starter
        const { steamId, kit } = req.query;

        console.log(`[Game Server] Request from ${steamId} to redeem kit: ${kit}`);

        if (!steamId || !kit) {
            return res.status(400).send("Missing Parameters");
        }

        // --- FUTURE LOGIC GOES HERE ---
        // 1. Query your database to see if this user has "credits" or is authorized.
        // const userCheck = await pool.query('SELECT credits FROM users WHERE steamid = \$1', [steamId]);
        
        // For now, we are in "Test Mode", so we just approve everything.
        const isAuthorized = true; 

        if (isAuthorized) {
            // Return "OK" to tell the Rust server to give the items
            res.status(200).send("OK");
        } else {
            // Return "FAIL" to tell Rust server to show an error message
            res.status(403).send("FAIL");
        }

    } catch (err) {
        console.error("Redeem Error:", err);
        res.status(500).send("ERROR");
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});