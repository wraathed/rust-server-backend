const { GameDig } = require('gamedig');

console.log("Scanning Public IP: 75.76.68.155...");

// Test 1: Game Port (28015)
GameDig.query({
    type: 'rust',
    host: '75.76.68.155', // Your Public IP
    port: 28015
}).then((state) => {
    console.log("✅ FOUND ON PORT 28015!");
    console.log("Name:", state.name);
    console.log("Players:", state.players.length);
}).catch((e) => {
    console.log("❌ Failed on 28015 (Public IP)");
});

// Test 2: Query Port (28016) - Most likely the correct one
GameDig.query({
    type: 'rust',
    host: '75.76.68.155', // Your Public IP
    port: 28016 
}).then((state) => {
    console.log("✅ FOUND ON PORT 28016!");
    console.log("Name:", state.name);
    console.log("Players:", state.players.length);
}).catch((e) => {
    console.log("❌ Failed on 28016 (Public IP)");
});