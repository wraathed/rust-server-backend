const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const Database = require('better-sqlite3');
const { GameDig } = require('gamedig');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;
const db = new Database('tickets.db');

// --- CRITICAL FOR RENDER ---
// This tells Express to trust that Render is handling HTTPS
app.set('trust proxy', 1); 

// --- CONFIGURATION ---
const ADMIN_IDS = ['76561198871950726']; // REPLACE WITH YOUR STEAM ID

// URLs
const FRONTEND_URL = 'https://wraathed.github.io'; // No trailing slash
const FRONTEND_FULL_URL = 'https://wraathed.github.io/Classic-Rust-Website';
const BACKEND_URL = 'https://classic-rust-api.onrender.com'; 

const SERVERS = [
    { name: "Classic Rust Test Server", ip: "75.76.68.155", port: 28015, type: 'rust' }
];

// --- MIDDLEWARE ---
app.use(cors({
    origin: FRONTEND_URL, // Must match exactly
    credentials: true,    // Required to accept the cookie
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- SESSION SETTINGS (The Fix) ---
app.use(session({
    secret: 'super_secret_rust_key_12345',
    resave: false,
    saveUninitialized: false, // Don't create cookies until logged in
    proxy: true,              // Required for Render
    cookie: {
        sameSite: 'none',     // Required for Cross-Site (GitHub <-> Render)
        secure: true,         // Required for SameSite: none
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 1 Day
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- DATABASE SETUP ---
db.prepare(`CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, steamId TEXT, username TEXT, avatar TEXT, category TEXT, subject TEXT, status TEXT DEFAULT 'Open', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
db.prepare(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, sender_steamId TEXT, sender_name TEXT, sender_avatar TEXT, content TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();

// --- AUTH ---
passport.use(new SteamStrategy({
    returnURL: `${BACKEND_URL}/auth/steam/return`,
    realm: `${BACKEND_URL}/`,
    apiKey: 'ED6078E97DF207E71FC65CD3BD24DB38' // YOUR NEW KEY
  },
  (identifier, profile, done) => done(null, profile)
));

app.get('/auth/steam', passport.authenticate('steam'));

app.get('/auth/steam/return',
  passport.authenticate('steam', { failureRedirect: '/' }),
  (req, res) => {
      // SUCCESS: Save session explicitly before redirecting
      req.session.save((err) => {
          res.redirect(`${FRONTEND_FULL_URL}/index.html`);
      });
  }
);

app.get('/user', (req, res) => {
    // If cookie is missing, req.user will be undefined
    if(!req.user) return res.json(null);
    const isAdmin = ADMIN_IDS.includes(req.user.id);
    res.json({ ...req.user, isAdmin });
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        req.session.destroy(() => {
            res.redirect(`${FRONTEND_FULL_URL}/index.html`);
        });
    });
});

// --- HELPER ---
function isAdmin(req) { return req.user && ADMIN_IDS.includes(req.user.id); }

// --- API ROUTES ---
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

app.post('/api/tickets', (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Login required' });
    const { category, subject, description } = req.body;
    const createTx = db.transaction(() => {
        const info = db.prepare('INSERT INTO tickets (steamId, username, avatar, category, subject) VALUES (?, ?, ?, ?, ?)').run(req.user.id, req.user.displayName, req.user.photos[2].value, category, subject);
        db.prepare('INSERT INTO messages (ticket_id, sender_steamId, sender_name, sender_avatar, content) VALUES (?, ?, ?, ?, ?)').run(info.lastInsertRowid, req.user.id, req.user.displayName, req.user.photos[2].value, description);
    });
    createTx();
    res.json({ success: true });
});

app.get('/api/my-tickets', (req, res) => {
    if (!req.user) return res.status(401).json([]);
    res.json(db.prepare('SELECT * FROM tickets WHERE steamId = ? ORDER BY id DESC').all(req.user.id));
});

app.get('/api/ticket/:id', (req, res) => {
    if (!req.user) return res.status(401).send("Unauthorized");
    const ticketId = req.params.id;
    const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
    if (!ticket) return res.status(404).send("Ticket not found");
    if (ticket.steamId !== req.user.id && !isAdmin(req)) return res.status(403).send("Forbidden");
    const messages = db.prepare('SELECT * FROM messages WHERE ticket_id = ? ORDER BY created_at ASC').all(ticketId);
    res.json({ ticket, messages, currentUserSteamId: req.user.id, isAdmin: isAdmin(req) });
});

app.post('/api/ticket/:id/reply', (req, res) => {
    if (!req.user) return res.status(401).send("Unauthorized");
    const ticketId = req.params.id;
    db.prepare('INSERT INTO messages (ticket_id, sender_steamId, sender_name, sender_avatar, content) VALUES (?, ?, ?, ?, ?)').run(ticketId, req.user.id, req.user.displayName, req.user.photos[2].value, req.body.content);
    const newStatus = isAdmin(req) ? 'Answered' : 'Open';
    db.prepare('UPDATE tickets SET status = ? WHERE id = ?').run(newStatus, ticketId);
    res.json({ success: true });
});

app.get('/api/admin/tickets', (req, res) => {
    if (!isAdmin(req)) return res.status(403).json([]);
    res.json(db.prepare('SELECT * FROM tickets ORDER BY status DESC, created_at DESC').all());
});

app.post('/api/ticket/:id/status', (req, res) => {
    if (!isAdmin(req)) return res.status(403).send("Admins only");
    db.prepare('UPDATE tickets SET status = ? WHERE id = ?').run(req.body.status, req.params.id);
    res.json({ success: true });
});

app.listen(port, () => {
    console.log(`Backend running on port ${port}`);
});