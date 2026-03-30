# SecureFS

A secure file storage system built with FastAPI. Files are encrypted before storage and decrypted only when accessed by an authenticated user.

---

## Features

- Token-based user authentication
- Server-side file encryption on upload
- In-memory decryption on download (no plaintext written to disk)
- File listing and deletion
- Minimal web interface

---

## Tech Stack

- **Backend:** FastAPI (Python 3.10+)
- **Encryption:** `cryptography` library — Fernet (AES-128-CBC + HMAC-SHA256)
- **Frontend:** HTML, CSS, JavaScript
- **Server:** Uvicorn

---

## Project Structure

```
SecureFS/
├── app/
│   ├── crypto.py
│   ├── main.py
│   └── supabase_client.py
├── static/
│   ├── dashboard.html
|   ├── index.html
│   ├── login.html
|   ├── script.js
│   ├── signup.html
│   └── style.css
├── requirements.txt
└── README.md
```

---

## Installation

```bash
git clone https://github.com/CodeTitan7/SecureFS.git
cd SecureFS

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000` in your browser.

---

## API Reference

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/auth/login` | Get access token | No |
| `POST` | `/files/upload` | Upload and encrypt a file | Yes |
| `GET` | `/files/list` | List uploaded files | Yes |
| `GET` | `/files/download/{filename}` | Download and decrypt a file | Yes |
| `DELETE` | `/files/delete/{filename}` | Delete a file | Yes |

Authenticated endpoints require `Authorization: Bearer <token>`.
