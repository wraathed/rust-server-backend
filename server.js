const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const { Pool } = require('pg'); // NEW: Postgres Library
const { GameDig } = require('gamedig');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// --- DATABASE CONNECTION ---
// We use a Connection Pool for better performance
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // We will set this in Render later
    ssl: {
        rejectUnauthorized: false // Required for Neon/Render connection
    }
});

// --- TRUST PROXY ---
app.set('trust proxy', 1);

// --- CONFIGURATION ---
const ADMIN_IDS = ['76561198871950726']; // REPLACE WITH YOUR STEAM ID

const CORS_ORIGIN = 'https://wraathed.github.io';
const FRONTEND_URL = 'https://wraathed.github.io/Classic-Rust-Website';
const BACKEND_URL = 'https://classic-rust-api.onrender.com'; 

const SERVERS = [
    { name: "Classic Rust Test Server", ip: "75.76.68.155", port: 28016, type: 'rust' }
];

// --- MIDDLEWARE ---
app.use(cors({
    origin: CORS_ORIGIN,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'super_secret_rust_key_12345',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        sameSite: 'none',
        secure: true,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- INITIALIZE TABLES (Postgres Syntax) ---
const initDB = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS tickets (
                id SERIAL PRIMARY KEY,
                steamId TEXT,
                username TEXT,
                avatar TEXT,
                category TEXT,
                subject TEXT,
                status TEXT DEFAULT 'Open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER,
                sender_steamId TEXT,
                sender_name TEXT,
                sender_avatar TEXT,
                content TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("Database Tables Checked/Created");
    } catch (err) {
        console.error("Error creating tables:", err);
    }
};
initDB();

// --- AUTH ---
passport.use(new SteamStrategy({
    returnURL: `${BACKEND_URL}/auth/steam/return`,
    realm: `${BACKEND_URL}/`,
    apiKey: 'ED6078E97DF207E71FC65CD3BD24DB38'
  },
  (identifier, profile, done) => done(null, profile)
));

app.get('/auth/steam', passport.authenticate('steam'));

app.get('/auth/steam/return',
  passport.authenticate('steam', { failureRedirect: '/' }),
  (req, res) => {
      req.session.save((err) => {
          res.redirect(`${FRONTEND_URL}/index.html`);
      });
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
            res.redirect(`${FRONTEND_URL}/index.html`);
        });
    });
});

function isAdmin(req) { return req.user && ADMIN_IDS.includes(req.user.id); }

// --- API ROUTES (Updated for Postgre) ---

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
    
    // Postgres Transaction
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // Insert Ticket and return the new ID
        const ticketRes = await client.query(
            'INSERT INTO tickets (steamId, username, avatar, category, subject) VALUES (\$1, \$2, \$3, \$4, \$5) RETURNING id',
            [req.user.id, req.user.displayName, req.user.photos[2].value, category, subject]
        );
        const ticketId = ticketRes.rows[0].id;

        // Insert First Message
        await client.query(
            'INSERT INTO messages (ticket_id, sender_steamId, sender_name, sender_avatar, content) VALUES (\$1, \$2, \$3, \$4, \$5)',
            [ticketId, req.user.id, req.user.displayName, req.user.photos[2].value, description]
        );

        await client.query('COMMIT');
        res.json({ success: true });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error(e);
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
        if (ticket.steamid !== req.user.id && !isAdmin(req)) return res.status(403).send("Forbidden");

        const msgRes = await pool.query('SELECT * FROM messages WHERE ticket_id = \$1 ORDER BY created_at ASC', [ticketId]);
        
        res.json({ ticket, messages: msgRes.rows, currentUserSteamId: req.user.id, isAdmin: isAdmin(req) });
    } catch (err) { console.error(err); res.status(500).send("DB Error"); }
});

app.post('/api/ticket/:id/reply', async (req, res) => {
    if (!req.user) return res.status(401).send("Unauthorized");
    const ticketId = req.params.id;
    
    try {
        await pool.query(
            'INSERT INTO messages (ticket_id, sender_steamId, sender_name, sender_avatar, content) VALUES (\$1, \$2, \$3, \$4, \$5)',
            [ticketId, req.user.id, req.user.displayName, req.user.photos[2].value, req.body.content]
        );
        
        const newStatus = isAdmin(req) ? 'Answered' : 'Open';
        await pool.query('UPDATE tickets SET status = \$1 WHERE id = \$2', [newStatus, ticketId]);
        
        res.json({ success: true });
    } catch (err) { res.status(500).send("Error"); }
});

app.get('/api/admin/tickets', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).json([]);
    try {
        const result = await pool.query('SELECT * FROM tickets ORDER BY status DESC, created_at DESC');
        res.json(result.rows);
    } catch (err) { res.json([]); }
});

app.post('/api/ticket/:id/status', async (req, res) => {
    if (!isAdmin(req)) return res.status(403).send("Admins only");
    try {
        await pool.query('UPDATE tickets SET status = \$1 WHERE id = \$2', [req.body.status, req.params.id]);
        res.json({ success: true });
    } catch (err) { res.status(500).send("Error"); }
});

app.listen(port, () => {
    console.log(`Backend running on port ${port}`);
});