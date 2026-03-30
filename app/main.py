from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Request
from fastapi.responses import FileResponse, Response, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import os, secrets, bcrypt
from datetime import datetime, timedelta
from app.crypto import (
    generate_keys, derive_key, encrypt_file, decrypt_file,
    serialize_public_key, serialize_private_key,
    load_public_key, load_private_key
)
from app.supabase_client import (
    upload_file, download_file,
    save_metadata, get_metadata, get_user_files,
    save_share_token, get_metadata_by_token,
    verify_token
)
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from urllib.parse import quote

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")



def get_server_keys():
    pem = os.getenv("SERVER_PRIVATE_KEY")
    if pem:
        private_key = load_private_key(pem.encode("utf-8"))
        # print("Server key loaded from environment variable")
    else:
        key_path = "storage/keys/server_private.pem"
        os.makedirs("storage/keys", exist_ok=True)
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                private_key = load_private_key(f.read())
            print("Server key loaded from file (dev mode)")
        else:
            private_key, _ = generate_keys()
            with open(key_path, "wb") as f:
                f.write(serialize_private_key(private_key))
            print("New server key generated and saved (dev mode)")
    return private_key, private_key.public_key()

server_private, server_public = get_server_keys()



def get_current_user(authorization: str = None):
    # Extract and verify Bearer token, return user or raise 401
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    user = verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user



def _decrypt_file_bytes(meta: dict) -> tuple[bytes, str]:
    original_filename = meta["original_filename"]
    client_public_key = load_public_key(meta["client_public_key"].encode("utf-8"))
    aes_key = derive_key(server_private, client_public_key)

    enc_path = f"storage/encrypted/{meta['enc_filename']}"
    if not os.path.exists(enc_path):
        os.makedirs("storage/encrypted", exist_ok=True)
        download_file(meta["enc_filename"], enc_path)

    with open(enc_path, "rb") as f:
        raw = f.read()

    nonce, ciphertext = raw[:12], raw[12:]
    plaintext = decrypt_file(nonce, ciphertext, aes_key)
    return plaintext, original_filename



@app.get("/")
def root():
    return RedirectResponse(url="/static/login.html")


@app.post("/encrypt")
async def encrypt(file: UploadFile = File(...), authorization: str = Header(default=None)):
    user = get_current_user(authorization)
    data = await file.read()

    os.makedirs("storage/encrypted", exist_ok=True)

    client_private, client_public = generate_keys()
    aes_key = derive_key(server_private, client_public)
    nonce, ciphertext = encrypt_file(data, aes_key)

    enc_filename = file.filename + ".enc"
    file_path = f"storage/encrypted/{enc_filename}"
    with open(file_path, "wb") as f:
        f.write(nonce + ciphertext)

    upload_file(file_path, enc_filename)
    save_metadata(
        enc_filename=enc_filename,
        original_filename=file.filename,
        client_public_key=serialize_public_key(client_public).decode("utf-8"),
        user_id=user.id
    )

    return {"message": "Encrypted & uploaded successfully"}


@app.get("/files")
def list_files(authorization: str = Header(default=None)):
    user = get_current_user(authorization)
    return get_user_files(user.id)


@app.get("/download/{filename}")
def download_encrypted(filename: str, authorization: str = Header(default=None)):
    user = get_current_user(authorization)

    # Verify file belongs to this user
    meta = get_metadata(filename)
    if not meta or meta.get("user_id") != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    path = f"storage/encrypted/{filename}"
    if not os.path.exists(path):
        os.makedirs("storage/encrypted", exist_ok=True)
        download_file(filename, path)
    return FileResponse(path, filename=filename)


@app.get("/decrypt/{filename}")
def decrypt_and_download(filename: str, authorization: str = Header(default=None)):
    user = get_current_user(authorization)

    meta = get_metadata(filename)
    if not meta:
        raise HTTPException(status_code=404, detail="Metadata not found")
    if meta.get("user_id") != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        plaintext, original_filename = _decrypt_file_bytes(meta)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(original_filename)}"}
    )



@app.post("/share/create/{filename}")
async def create_share_link(filename: str, request: Request, authorization: str = Header(default=None)):
    user = get_current_user(authorization)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    meta = get_metadata(filename)
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")
    if meta.get("user_id") != user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    password = body.get("password", "")
    expires_hours = int(body.get("expires_hours", 24))

    if not password:
        raise HTTPException(status_code=400, detail="Password is required")

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    share_token = secrets.token_urlsafe(16)
    expires_at = (datetime.utcnow() + timedelta(hours=expires_hours)).isoformat()

    save_share_token(filename, share_token, password_hash, expires_at)

    server_url = os.getenv("SERVER_URL", "http://127.0.0.1:8000")
    return {
        "share_token": share_token,
        "share_url": f"{server_url}/share/{share_token}"
    }


@app.get("/share/{token}", response_class=HTMLResponse)
def share_page(token: str):
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureFS — Download File</title>
    <link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
        :root{{
            --black:#0a0a0a;--white:#fafafa;--grey-100:#f0f0f0;
            --grey-200:#e0e0e0;--grey-400:#999;--grey-600:#555;
            --mono:'DM Mono',monospace;--sans:'DM Sans',sans-serif;
        }}
        body{{font-family:var(--sans);background:var(--white);color:var(--black);
              min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}}
        .card{{width:100%;max-width:420px;border:1px solid var(--grey-200);padding:48px 40px;}}
        .page-label{{font-family:var(--mono);font-size:10px;letter-spacing:0.2em;
                     text-transform:uppercase;color:var(--grey-400);margin-bottom:8px;}}
        h1{{font-size:22px;font-weight:500;letter-spacing:-0.02em;margin-bottom:32px;}}
        .divider{{height:1px;background:var(--grey-200);margin:24px 0;}}
        label{{font-family:var(--mono);font-size:10px;letter-spacing:0.15em;text-transform:uppercase;
               color:var(--grey-600);display:block;margin-bottom:6px;}}
        input[type=password]{{width:100%;padding:10px 12px;border:1px solid var(--grey-200);
                              font-family:var(--mono);font-size:12px;outline:none;
                              background:var(--white);margin-bottom:16px;}}
        input[type=password]:focus{{border-color:var(--black);}}
        .btn{{font-family:var(--mono);font-size:11px;letter-spacing:0.12em;text-transform:uppercase;
              cursor:pointer;border:none;padding:12px 24px;width:100%;
              display:flex;align-items:center;justify-content:center;gap:8px;}}
        .btn-primary{{background:var(--black);color:var(--white);}}
        .btn-primary:hover{{background:#222;}}
        .btn-primary:disabled{{background:var(--grey-200);color:var(--grey-400);cursor:not-allowed;}}
        #status{{font-family:var(--mono);font-size:11px;color:var(--grey-600);
                 text-align:center;margin-top:16px;min-height:20px;}}
    </style>
</head>
<body>
    <div class="card">
        <p class="page-label">Shared File</p>
        <h1>Enter Password</h1>
        <div class="divider"></div>
        <label>Password</label>
        <input type="password" id="pwd" placeholder="Enter the password you were given" autofocus>
        <button class="btn btn-primary" id="dlBtn" onclick="download()">Download File</button>
        <p id="status"></p>
    </div>
    <script>
        async function download() {{
            const pwd = document.getElementById('pwd').value;
            const status = document.getElementById('status');
            const btn = document.getElementById('dlBtn');
            if (!pwd) {{ status.innerText = 'Please enter a password.'; return; }}
            btn.disabled = true;
            btn.innerText = 'Verifying...';
            status.innerText = '';
            try {{
                const res = await fetch('/share/{token}', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{password: pwd}})
                }});
                if (res.ok) {{
                    const blob = await res.blob();
                    const disposition = res.headers.get('Content-Disposition') || '';
                    const match = disposition.match(/filename\*=UTF-8''(.+)/i)
                               || disposition.match(/filename="?([^";\\n]+)"?/i);
                    const fname = match ? decodeURIComponent(match[1].trim()) : 'download';
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url; a.download = fname; a.click();
                    URL.revokeObjectURL(url);
                    status.innerText = '✓ Download started';
                }} else {{
                    const err = await res.json();
                    status.innerText = err.detail || 'Incorrect password';
                }}
            }} catch(e) {{
                status.innerText = 'Network error: ' + e.message;
            }} finally {{
                btn.disabled = false;
                btn.innerText = 'Download File';
            }}
        }}
        document.getElementById('pwd').addEventListener('keydown', e => {{
            if (e.key === 'Enter') download();
        }});
    </script>
</body>
</html>""")


@app.post("/share/{token}")
async def download_shared_file(token: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    meta = get_metadata_by_token(token)
    if not meta:
        raise HTTPException(status_code=404, detail="Invalid or expired link")

    if meta.get("expires_at"):
        expires_at = datetime.fromisoformat(meta["expires_at"])
        if datetime.utcnow() > expires_at:
            raise HTTPException(status_code=410, detail="This link has expired")

    password = body.get("password", "")
    stored_hash = meta.get("password_hash", "").strip()

    if not stored_hash:
        raise HTTPException(status_code=500, detail="No password hash stored for this link")

    try:
        match = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Password check error: {str(e)}")

    if not match:
        raise HTTPException(status_code=401, detail="Incorrect password")

    try:
        plaintext, original_filename = _decrypt_file_bytes(meta)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(original_filename)}"}
    )

@app.get("/config")
def get_config():
    return {
        "supabase_url": os.getenv("SUPABASE_URL"),
        "supabase_anon_key": os.getenv("SUPABASE_KEY")
    }