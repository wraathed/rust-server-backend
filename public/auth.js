// Leave this empty because the API is on the same domain
const API_URL = ''; 

document.addEventListener("DOMContentLoaded", () => {
    // 1. Update Login Button
    const loginBtn = document.querySelector('.steam-login');
    if (loginBtn) {
        // Points to /auth/steam on the current site
        loginBtn.href = `/auth/steam`; 
    }

    // 2. Check User Status
    fetch(`/user`, {
        credentials: 'include' // Still good practice to keep
    })
    .then(response => response.json())
    .then(user => {
        const authSection = document.getElementById('auth-section');

        if (user) {
            // User IS logged in
            authSection.innerHTML = `
                <div style="display: flex; align-items: center; gap: 10px;">
                    <a href="profile.html" style="text-decoration: none; color: white; display: flex; align-items: center; gap: 10px;">
                        <img src="${user.photos[2].value}" style="width: 32px; height: 32px; border-radius: 50%; border: 2px solid #ff9100;">
                        <span>${user.displayName}</span>
                    </a>
                    <a href="/logout" style="color: #aaa; font-size: 12px; margin-left: 10px; text-decoration: none;">(Logout)</a>
                </div>
            `;
            
            // Update Profile Page elements if they exist
            if (document.getElementById('profile-name')) {
                document.getElementById('profile-avatar').src = user.photos[2].value;
                document.getElementById('profile-name').innerText = user.displayName;
                document.getElementById('profile-steamid').innerText = `Steam ID: ${user.id}`;
            }
        }
    })
    .catch(err => {
        // Not logged in - do nothing (default is "Sign in")
    });
});