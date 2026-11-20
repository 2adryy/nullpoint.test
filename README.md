# SecureChat — End-to-End Encrypted Chat in Python

NULLPOINT · Introduction to Cybersecurity (CCY2001)

A chat app with a web (HTML/CSS/JS) interface where messages are encrypted on the
sender's computer and can only be decrypted by the recipient. The server relays
messages but cannot read them.

```
Browser (HTML/CSS/JS)  <-- HTTP, 127.0.0.1 only -->  python client.py  <-- encrypted TCP -->  python server.py
   user interface only                                all crypto (Python)                      relays ciphertext
```

The browser does **no** cryptography and never sees a private key. It only shows what
the Python client decided, for example "Signature verified".

Assignment requirements covered:

| Requirement | How SecureChat does it |
|---|---|
| Message encryption | Fresh AES-256-GCM key per message, wrapped with the recipient's RSA-2048 key (RSA-OAEP) |
| User authentication | bcrypt password hashes, password policy, 5-attempt lockout, RSA-PSS signature on every message |
| Secure key exchange | Client generates its key pair locally; server key pinned on first use; encrypted client↔server channel; fingerprint verification between contacts |
| Cryptographic library | [`cryptography`](https://cryptography.io) (plus `bcrypt` for password hashing) |

## Run it

Needs Python 3.10+ and any modern browser.

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Terminal 1 — server:
```bash
python server.py --host 127.0.0.1
```

Terminal 2 and 3 — two clients:
```bash
python client.py
```

Each client opens its own browser tab: the first at `http://127.0.0.1:8080/`, the
second at `:8081` (the next free port). In each tab click **Create account** and register
a different user (for example `Ahmed` and `Omar`, password like `Str0ng!pass`). Then
**add each other as friends**: type the other username under *Friends* and press **Add**.
The other user clicks **Accept**, and now you can chat.

Options: `python client.py --web-port 9000 --no-browser --data other_folder`.

### Admin page

Create an admin account once (on the server computer):
```bash
python server.py --create-admin
```
Start the server as usual and open **http://127.0.0.1:8090/** on the server computer.
Use `--admin-port` to change the port, or `--no-admin` to turn the page off.

Two computers on the same network: run `python server.py --host 0.0.0.0`, and in the
client type the server computer's LAN IP (e.g. `192.168.1.20`) in the Connection box.

## Sending files

Click **File** next to the message box (maximum 10 MiB). A file goes through exactly the
same end-to-end path as a text message, with `kind = "file"`:

- The file name and bytes are packed together, then encrypted with a fresh AES-256-GCM key,
  that key is wrapped for the recipient, and the whole packet is signed.
- Only the **base name** is sent (`report.pdf`), never the folder path on your computer.
- The receiver checks the signature and replay protection before saving anything.
- **Safe saving:** the name is cleaned (`../../etc/evil.sh` becomes `evil.sh`) and the file
  is saved only inside `client_data/downloads/<user>/`. It never overwrites an existing file
  (the second copy becomes `report (1).txt`).
- **Safe download:** received files are always served as a download
  (`Content-Disposition: attachment`, `application/octet-stream`, sandbox CSP). A received
  `.html` file can't run scripts inside the chat page.
- **Size limits:** 10 MiB per file. Before login the server accepts only small frames
  (64 KiB), so strangers can't flood it with huge data.

## Presentation demos (attacks)

These options are **off by default** and are only for showing the defenses live. Use test
accounts only.

| Command | What it does |
|---|---|
| `python server.py --allow-plain` | lets clients choose **Plain demo (unencrypted)** on the login screen |
| `python mitm_proxy.py` | a "hacker on the Wi-Fi" between the clients and the server, printing what it can see |
| `python mitm_proxy.py --tamper` | the same, but it also tries to change traffic |
| `python server.py --attack tamper` | acts like a **hacked server** that changes messages and files it relays |
| `python server.py --attack replay` | acts like a hacked server that **re-sends** every message twice |

### Demo script

**Demo 1: why encryption matters (Plain vs Secure)**
1. `python server.py --allow-plain`
2. `python mitm_proxy.py` (listens on port 6000 and forwards to 5000)
3. Start two clients (`python client.py`). On the login screen set the port to **6000**.
4. Choose **Plain demo**, register two users, make them friends, and send a message and a file.
   The proxy prints their **passwords**, the message and the file contents in red.
   The chat shows a red **PLAIN MODE — NOT ENCRYPTED** badge.
5. Log out, log in again with **Secure mode** (still port 6000), and send the same message.
   The proxy now shows only `ENCRYPTED … bytes` of random-looking data. No password, no text.

**Demo 2: an attacker changing traffic on the network**
1. Restart the proxy with `python mitm_proxy.py --tamper`.
2. In **Plain** mode the receiver sees *"[CHANGED BY ATTACKER ON THE NETWORK] Meet me at 3am"*
   with no warning. Plain mode has no integrity check.
3. In **Secure** mode the proxy flips one bit, AES-GCM detects it, and the server drops the
   connection instead of accepting a changed message.

**Demo 3: a hacked server changes a message**
1. `python server.py --attack tamper` (connect clients directly to port 5000).
2. Send a message in Secure mode. The receiver shows the red warning
   **"Message rejected: Invalid signature - possible tampering / man-in-the-middle"**.
   The same happens for a file, and nothing is saved.
3. Add `--allow-plain` and repeat in Plain mode: the text is silently replaced. That's
   the difference a signature makes.

**Demo 4: replay attack**
1. `python server.py --attack replay`
2. Send *"Transfer 100 EGP"*. The first copy arrives, and the second shows
   **"Message rejected: duplicate message id (replay attack)"**.

While a demo mode is on, the admin page shows it under *Server → Demo modes*, and users
connected in Plain mode get a red tag in the Users table.

## Project structure

```
client.py / server.py / mitm_proxy.py   short launchers
securechat/
  crypto_utils.py   RSA keys, OAEP, PSS signatures, AES-GCM, fingerprints, hybrid encrypt/decrypt
  protocol.py       length-prefixed frames over TCP; encrypted channel with frame counters
  policy.py         username + password rules (checked on client AND server)
  database.py       SQLite: users, admins, friends, security events, audit log, settings
  server.py         handshake, register/login, lockout, bans, friends, relay, admin operations
  admin_web.py      admin page server (127.0.0.1 only): sessions, CSRF protection, admin API
  mitm_proxy.py     DEMO man-in-the-middle proxy: shows what an attacker sees, optional --tamper
  client_core.py    connect, key pinning, login, friends, password change, send, verify + decrypt
  web_client.py     local web server (127.0.0.1) that connects the user page to client_core
  web/
    index.html      user page: Login, Register, Chat, Profile + dialogs
    app.css / app.js   user page styling and logic (no crypto)
    theme.js        dark / light mode toggle shared by both pages (remembers your choice)
    admin.html      admin page: login, Overview, Users, Security monitor, Announcements & settings
    admin.css / admin.js   admin page styling and logic
tests/              112 automated tests (unit, integration, web security, demos, files)
```

## Roles and permissions

| | User | Admin | Server (anyone who hacks it) |
|---|---|---|---|
| Chat with friends | ✅ | ❌ (admins have no chat account) | ❌ |
| Read message content | Own chats only | ❌ never | ❌ only ciphertext |
| See passwords | ❌ | ❌ (bcrypt hashes only) | ❌ hashes only |
| See private keys | Own key only | ❌ | ❌ never uploaded |
| Send messages as someone else | ❌ | ❌ (signature check fails) | ❌ (signature check fails) |
| Add / accept / remove friends | ✅ | ❌ | — |
| Change own password | ✅ (also re-encrypts the local key) | — | — |
| See own security events | ✅ | ✅ all users | — |
| See users, online status, friend counts, fingerprints | Friends only | ✅ (metadata) | ✅ |
| Kick, ban/unban, unlock, delete accounts | ❌ | ✅ (written to audit log) | — |
| Send announcements | ❌ | ✅ | — |
| Open/close registration, change lockout limits | ❌ | ✅ | — |

### User page
- **Chat**: friends list (online and offline), friend requests with Accept and Decline,
  encrypted chat, and an announcement banner.
- **Dark / light mode**: the moon/sun button in the top bar (and on the login screen) switches
  themes. The first visit follows your computer's setting; after that your choice is remembered.
- **Profile**: account and session info, your key and the server key fingerprints,
  friends with their pinned keys (Verify, Remove), password change, your own security
  events, and past announcements.

### Admin page
- **Overview**: registered/online/banned/locked users, messages relayed (a count only),
  blocked packets, friendships, uptime, server fingerprint, who is online.
- **Users**: a table with status, created date, last login, friend count and key
  fingerprint, plus actions: **Kick**, **Ban/Unban**, **Unlock**, **Delete** (with confirmation).
- **Security monitor**: failed logins, lockouts, banned login attempts, spoofed packets,
  failed admin logins, and the **audit log** of every admin action.
- **Announcements & settings**: send an announcement to all online users, open or close
  registration, and change the lockout limits.

### How the admin page is protected
| Threat | Defense |
|---|---|
| Someone on the network opens the admin page | Listens on `127.0.0.1` only, so only the server computer can reach it |
| Password guessing | bcrypt hashes; locked for 60 s after 5 failures; failures are logged |
| Stealing the session with JavaScript (XSS) | Session cookie is `HttpOnly`; all text is inserted with `textContent`; strict CSP |
| A malicious website clicks "Ban" for you (CSRF) | Cookie is `SameSite=Strict`, and every action needs the `X-SecureChat-Admin` header |
| A forgotten open session | Expires after 30 minutes of inactivity; Logout destroys it |
| An admin abusing their power | Every action goes to the audit log; admins still can't read messages |

## Securing the local web page

The page talks to `client.py` over HTTP on your own computer, and that link needs
protecting too:

| Threat | Defense |
|---|---|
| Another computer connects to your client | Listens on `127.0.0.1` only |
| A malicious website you visit sends "send message" requests to localhost (CSRF) | Every API call needs a random token created at startup. Other sites can't read it (same-origin policy) |
| DNS rebinding tricks | The `Host` header must be `127.0.0.1:<port>` or `localhost:<port>` |
| A message containing `<script>` (XSS) | JS inserts text only with `textContent`, and a strict Content-Security-Policy blocks inline scripts |
| Clickjacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'` |
| Path traversal (`/static/../../keys`) | Static files are served only by plain file name from `securechat/web/` |

## How a message travels

```
Ahmed's client                         Server                       Omar's client
--------------                         ------                       -------------
header = {from, to, ts, id, kind}
K = random AES-256 key
ct = AES-GCM(K, text, aad=header)
ek = RSA-OAEP(Omar_public, K)
sig = RSA-PSS(Ahmed_private, header+ek+nonce+ct)
     -- encrypted channel -->   checks header.from == Ahmed
                                 (cannot decrypt ek/ct)
                                       -- encrypted channel -->   verify sig with Ahmed's pinned key
                                                                  K = RSA-OAEP-decrypt(Omar_private, ek)
                                                                  text = AES-GCM-decrypt(K, ct)
                                                                  reject if id seen / ts > 5 min off
```

### Two layers of encryption

1. **Channel layer (client ↔ server).** On connect the server sends its public key. The
   client checks it against the fingerprint saved last time (`client_data/known_servers.json`)
   and warns loudly if it changed. The client then sends a random AES key wrapped with the
   server's key. Every later frame is AES-GCM encrypted, with a direction tag and a counter as
   associated data, so frames cannot be replayed, reordered or modified. This hides passwords
   and the user list from anyone on the network.
2. **End-to-end layer (client ↔ client).** Described above. Even the server, or someone
   who breaks into it, only sees ciphertext.

### Authentication

- **Users → server:** password checked against a bcrypt hash (salted, cost 12). After 5 wrong
  attempts the account is locked for 60 seconds. Unknown usernames take the same time as wrong
  passwords, so attackers can't tell which accounts exist.
- **Messages → recipient:** every packet is signed with the sender's private key. A modified
  or forged packet fails verification and shows a red warning instead of the text.
- **Contacts' keys:** the first key seen for a contact is pinned (`known_keys_<user>.json`).
  If it changes, sending is blocked and a warning appears until you compare fingerprints with
  **Verify contact key** and accept the new key.

## What is stored where

| File | Contents | Protection |
|---|---|---|
| `server_data/users.db` | users (bcrypt hash, public key, created, last login, banned), admins, friendships, security events, audit log, settings | no plain passwords, no messages |
| `server_data/server_private.pem` | server private key | file mode 600 (owner only) |
| `client_data/keys/<user>_private.pem` | your private key | encrypted with your password |
| `client_data/known_servers.json` | pinned server fingerprints | public data, but decides trust |
| `client_data/known_keys_<user>.json` | pinned contact fingerprints | public data, but decides trust |
| `client_data/downloads/<user>/` | files you received | already decrypted, so protect this folder |

Messages are kept **in memory only** and are cleared on logout.

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

The 112 tests run in about 20 seconds. They use a real server on a random port with real
clients and temporary folders, so they never touch your `client_data` or `server_data`.

| File | What it proves |
|---|---|
| `test_crypto.py` | encrypt/decrypt round trip; fresh key and nonce per message; a changed ciphertext or header is rejected; a forged signature is rejected; only the recipient can decrypt; private keys are encrypted with the password; RSA keys under 2048 bits are refused |
| `test_policy_db.py` | password policy (including the bcrypt 72-byte limit); passwords stored only as salted bcrypt hashes; SQL injection does nothing; friend lifecycle; a database from the old version still opens |
| `test_protocol.py` | encrypted frames hide content; replayed, reordered, modified or reflected frames are rejected; plain frames after encryption are rejected; bad lengths and bad JSON are rejected |
| `test_server.py` | login, lockout and admin unlock; duplicate sessions refused; server key change detected; password change re-encrypts the key; strangers can't message (even with a modified client); tamper, replay, old-timestamp and spoofed-sender attacks rejected; a contact key change blocks sending; kick, ban, delete, announcements and settings work; the admin dashboard contains no message text |
| `test_demos_files.py` | Plain mode refused unless `--allow-plain`; Secure users refuse plain messages; the proxy reads passwords and messages in Plain mode but sees none of them in Secure mode; proxy tampering goes unnoticed in Plain but is detected in Secure; hacked-server tampering and replay are rejected; files arrive intact up to 10 MiB; folder names are stripped; `../` path traversal is neutralized; names never overwrite; oversized/empty files are refused; big frames before login are refused; downloads are forced attachments |
| `test_web.py` | user page: token required (CSRF), DNS rebinding blocked, path traversal blocked, CSP headers present, private key never sent to the browser. Admin page: login required, `HttpOnly` + `SameSite` cookie, lockout, normal users can't log in as admin, CSRF header required, actions are audited, logout ends the session |

## Limitations (honest list)

- Custom protocol for learning. It has not been audited, and it is not a replacement for Signal.
- No forward secrecy: if a long-term private key leaks, old recorded messages could be decrypted.
- Trust on first use: the first connection to a server or contact is trusted automatically.
  Compare fingerprints out of band to be sure.
- Only online friends can chat. There's no offline delivery, history or group chats. Files go
  only to online friends (max 10 MiB) and are sent in one piece, so the page waits until the whole file is sent.
- Lockout counters and admin sessions live in server memory and reset when the server restarts.
- The server, and so the admin, can see metadata: friendships, who is online, when people
  log in, and how many messages were relayed. It can't see what the messages say.
- The admin page uses plain HTTP, which is acceptable only because it's limited to
  `127.0.0.1`. Remote admin access would need HTTPS.
- Your private key exists only on the computer where you registered. If you lose it, the
  account can't be recovered.
