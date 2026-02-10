const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const path = require('path');
const Database = require('better-sqlite3');
const { GameDig } = require('gamedig');
const cors = require('cors'); // NEW: Required for GitHub Pages

const app = express();
const port = process.env.PORT || 3000;
const db = new Database('tickets.db');

// --- CONFIGURATION ---
const ADMIN_IDS = ['76561198000000000']; 

// YOUR SERVER LIST
const SERVERS = [
    { name: "Classic Rust Test Server", ip: "75.76.68.155", port: 28015, type: 'rust' }
];

// --- MIDDLEWARE ---
// 1. Allow GitHub Pages to talk to this server
app.use(cors({
    origin: 'https://wraathed.github.io', 
    credentials: true 
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 2. Cookie Settings (Must be tweaked for cross-site)
app.use(session({ 
    secret: 'rust_server_secret', 
    resave: true, 
    saveUninitialized: true,
    cookie: { 
        sameSite: 'none', // Required for different domains
        secure: true      // Required if using sameSite: none
    } 
}));

// Note: For 'secure: true' to work on localhost, you usually need https. 
// If login fails, you might need to host this backend on Render/Heroku instead of localhost.

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- STEAM AUTH CONFIGURATION ---
passport.use(new SteamStrategy({
    // The "returnURL" must point to THIS running server (Your PC or VPS)
    returnURL: 'http://localhost:3000/auth/steam/return', 
    
    // The "realm" is the website sending the user (Your GitHub Page)
    realm: 'https://wraathed.github.io/Classic-Rust-Website/',
    
    // YOUR NEW API KEY
    apiKey: '4C59B011483176A0E56AF7E6C49F13CA' 
  },
  (identifier, profile, done) => done(null, profile)
));

// --- ROUTES ---

// 1. Start Login (Redirects to Steam)
app.get('/auth/steam', passport.authenticate('steam'));

// 2. Return from Steam (Redirects back to GitHub Pages)
app.get('/auth/steam/return', 
  passport.authenticate('steam', { failureRedirect: '/' }), 
  (req, res) => {
      // SUCCESS! Send them back to the GitHub website
      res.redirect('https://wraathed.github.io/Classic-Rust-Website/index.html');
  }
);

app.get('/user', (req, res) => {
    if(!req.user) return res.json(null);
    const isAdmin = ADMIN_IDS.includes(req.user.id);
    res.json({ ...req.user, isAdmin });
});

app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('https://wraathed.github.io/Classic-Rust-Website/index.html'));
});

// --- API ROUTES (Servers/Tickets) ---
// (Your existing routes for tickets/servers go here - kept short for brevity)
app.get('/api/servers', async (req, res) => {
    /* ... Your GameDig code ... */
    res.json([]); // Placeholder
});

app.listen(port, () => {
    console.log(`Backend running at http://localhost:${port}`);
});