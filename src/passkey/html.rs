//! Inline HTML templates for passkey setup and login pages

/// Setup page for first-user passkey registration
pub fn setup_page() -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup Passkey - Obsidian Memory</title>
    <style>{}</style>
</head>
<body>
    <div class="container">
        <h1>Setup Passkey</h1>
        <p>Register a passkey to secure your Obsidian Memory server.</p>

        <form id="setup-form">
            <div class="field">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required placeholder="Choose a username">
            </div>
            <button type="submit" id="submit-btn">Register Passkey</button>
        </form>

        <div id="status" class="status hidden"></div>
    </div>

    <script>
    {}
    </script>
</body>
</html>"#,
        CSS_STYLES,
        setup_js()
    )
}

/// "Already setup" page shown when a user already exists
pub fn already_setup_page() -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Already Configured - Obsidian Memory</title>
    <style>{}</style>
</head>
<body>
    <div class="container">
        <h1>Already Configured</h1>
        <p>A passkey has already been registered for this server.</p>
        <p>If you need to reset, use: <code>docker exec auth-service auth-service reset</code></p>
        <a href="/login" class="button">Go to Login</a>
    </div>
</body>
</html>"#,
        CSS_STYLES
    )
}

/// Login page for passkey authentication
pub fn login_page(return_to: Option<&str>) -> String {
    let return_input = return_to
        .map(|r| format!(r#"<input type="hidden" id="return_to" value="{}">"#, html_escape(r)))
        .unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Obsidian Memory</title>
    <style>{}</style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <p>Authenticate with your passkey to continue.</p>

        <form id="login-form">
            {}
            <button type="submit" id="submit-btn">Login with Passkey</button>
        </form>

        <div id="status" class="status hidden"></div>
    </div>

    <script>
    {}
    </script>
</body>
</html>"#,
        CSS_STYLES,
        return_input,
        login_js()
    )
}

/// Redirect page shown after successful login
pub fn redirect_page(url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0;url={}">
    <title>Redirecting...</title>
    <style>{}</style>
</head>
<body>
    <div class="container">
        <h1>Success!</h1>
        <p>Redirecting...</p>
        <p><a href="{}">Click here if not redirected</a></p>
    </div>
</body>
</html>"#,
        html_escape(url),
        CSS_STYLES,
        html_escape(url)
    )
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

const CSS_STYLES: &str = r#"
* {
    box-sizing: border-box;
}
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #1a1a2e;
    color: #eee;
    margin: 0;
    padding: 20px;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}
.container {
    background: #16213e;
    padding: 40px;
    border-radius: 12px;
    max-width: 400px;
    width: 100%;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}
h1 {
    margin: 0 0 10px 0;
    color: #fff;
    font-size: 24px;
}
p {
    color: #aaa;
    margin: 0 0 20px 0;
    line-height: 1.5;
}
.field {
    margin-bottom: 20px;
}
label {
    display: block;
    margin-bottom: 8px;
    color: #ddd;
    font-size: 14px;
}
input {
    width: 100%;
    padding: 12px;
    border: 1px solid #333;
    border-radius: 6px;
    background: #0f0f23;
    color: #fff;
    font-size: 16px;
}
input:focus {
    outline: none;
    border-color: #4f46e5;
}
button, .button {
    display: block;
    width: 100%;
    padding: 14px;
    background: #4f46e5;
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 16px;
    cursor: pointer;
    text-decoration: none;
    text-align: center;
}
button:hover, .button:hover {
    background: #4338ca;
}
button:disabled {
    background: #333;
    cursor: not-allowed;
}
.status {
    margin-top: 20px;
    padding: 12px;
    border-radius: 6px;
    font-size: 14px;
}
.status.hidden {
    display: none;
}
.status.error {
    background: #7f1d1d;
    color: #fca5a5;
}
.status.success {
    background: #14532d;
    color: #86efac;
}
.status.info {
    background: #1e3a5f;
    color: #93c5fd;
}
code {
    background: #0f0f23;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
}
"#;

fn setup_js() -> &'static str {
    r#"
const form = document.getElementById('setup-form');
const status = document.getElementById('status');
const submitBtn = document.getElementById('submit-btn');

function showStatus(message, type) {
    status.textContent = message;
    status.className = 'status ' + type;
}

function base64UrlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (let i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;

    submitBtn.disabled = true;
    showStatus('Starting registration...', 'info');

    try {
        // Start registration
        const startRes = await fetch('/setup/register/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!startRes.ok) {
            const err = await startRes.text();
            throw new Error(err);
        }

        const { challenge_id, options } = await startRes.json();

        // Decode challenge and user.id for WebAuthn
        options.publicKey.challenge = base64UrlDecode(options.publicKey.challenge);
        options.publicKey.user.id = base64UrlDecode(options.publicKey.user.id);
        if (options.publicKey.excludeCredentials) {
            options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(c => ({
                ...c,
                id: base64UrlDecode(c.id)
            }));
        }

        showStatus('Touch your security key or use biometrics...', 'info');

        // Create credential
        const credential = await navigator.credentials.create(options);

        // Encode response for server
        const response = {
            id: credential.id,
            rawId: base64UrlEncode(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: base64UrlEncode(credential.response.attestationObject),
                clientDataJSON: base64UrlEncode(credential.response.clientDataJSON)
            }
        };

        showStatus('Verifying credential...', 'info');

        // Finish registration
        const finishRes = await fetch('/setup/register/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ challenge_id, credential: response })
        });

        if (!finishRes.ok) {
            const err = await finishRes.text();
            throw new Error(err);
        }

        showStatus('Passkey registered successfully! Redirecting...', 'success');
        setTimeout(() => window.location.href = '/login', 1500);

    } catch (err) {
        console.error('Registration error:', err);
        showStatus('Error: ' + err.message, 'error');
        submitBtn.disabled = false;
    }
});
"#
}

fn login_js() -> &'static str {
    r#"
const form = document.getElementById('login-form');
const status = document.getElementById('status');
const submitBtn = document.getElementById('submit-btn');
const returnToEl = document.getElementById('return_to');

function showStatus(message, type) {
    status.textContent = message;
    status.className = 'status ' + type;
}

function base64UrlEncode(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (let i = 0; i < bytes.length; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

form.addEventListener('submit', async (e) => {
    e.preventDefault();

    submitBtn.disabled = true;
    showStatus('Starting authentication...', 'info');

    try {
        // Start authentication
        const startRes = await fetch('/login/auth/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!startRes.ok) {
            const err = await startRes.text();
            throw new Error(err);
        }

        const { challenge_id, options } = await startRes.json();

        // Decode challenge for WebAuthn
        options.publicKey.challenge = base64UrlDecode(options.publicKey.challenge);
        if (options.publicKey.allowCredentials) {
            options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(c => ({
                ...c,
                id: base64UrlDecode(c.id)
            }));
        }

        showStatus('Touch your security key or use biometrics...', 'info');

        // Get assertion
        const credential = await navigator.credentials.get(options);

        // Encode response for server
        const response = {
            id: credential.id,
            rawId: base64UrlEncode(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: base64UrlEncode(credential.response.authenticatorData),
                clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
                signature: base64UrlEncode(credential.response.signature),
                userHandle: credential.response.userHandle ? base64UrlEncode(credential.response.userHandle) : null
            }
        };

        showStatus('Verifying...', 'info');

        // Finish authentication
        const returnTo = returnToEl ? returnToEl.value : null;
        const finishRes = await fetch('/login/auth/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ challenge_id, credential: response, return_to: returnTo })
        });

        if (!finishRes.ok) {
            const err = await finishRes.text();
            throw new Error(err);
        }

        const result = await finishRes.json();
        showStatus('Login successful! Redirecting...', 'success');

        // Redirect to return_to or default
        window.location.href = result.redirect_to || '/';

    } catch (err) {
        console.error('Authentication error:', err);
        showStatus('Error: ' + err.message, 'error');
        submitBtn.disabled = false;
    }
});
"#
}
