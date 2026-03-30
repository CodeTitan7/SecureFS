const API_URL = "http://127.0.0.1:8000";

function getToken() {
    return localStorage.getItem("sb_token") || "";
}

function authHeaders() {
    return { "Authorization": `Bearer ${getToken()}` };
}

function requireAuth() {
    if (!getToken()) window.location.href = "login.html";
}

function logout() {
    localStorage.removeItem("sb_token");
    localStorage.removeItem("sb_refresh");
    localStorage.removeItem("sb_email");
    window.location.href = "login.html";
}

function showUserEmail() {
    const el = document.getElementById("userEmail");
    if (el) el.innerText = localStorage.getItem("sb_email") || "";
}

function onFileChange(input) {
    const label = document.getElementById("fileName");
    if (label) label.innerText = input.files[0] ? input.files[0].name : "";
}

async function uploadFile() {
    requireAuth();
    const fileInput = document.getElementById("fileInput");
    const status = document.getElementById("status");
    const btn = document.getElementById("uploadBtn");

    if (!fileInput || !status) return;

    const file = fileInput.files[0];
    if (!file) { status.innerText = "No file selected."; return; }

    const formData = new FormData();
    formData.append("file", file);

    status.innerText = "";
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span> Encrypting...`;

    try {
        const res = await fetch(`${API_URL}/encrypt`, {
            method: "POST",
            headers: authHeaders(),
            body: formData
        });

        const text = await res.text();

        if (res.status === 401) {
            logout();
            return;
        }

        if (!res.ok) { status.innerText = `Error ${res.status}: ${text}`; return; }

        let data;
        try { data = JSON.parse(text); } catch (e) {
            status.innerText = "Unexpected response: " + text; return;
        }

        status.innerText = "✓ " + (data.message ?? "Done");
        fileInput.value = "";
        document.getElementById("fileName").innerText = "";

    } catch (error) {
        status.innerText = error.message.includes("Failed to fetch")
            ? "Cannot reach server. Is FastAPI running?"
            : "Error: " + error.message;
    } finally {
        btn.disabled = false;
        btn.innerHTML = "Encrypt & Upload";
    }
}

async function fetchAndDownload(url, fallbackName) {
    const res = await fetch(url, { headers: authHeaders() });

    if (res.status === 401) { logout(); return; }

    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Unknown error" }));
        alert("Failed: " + (err.detail || res.status));
        return;
    }

    const blob = await res.blob();
    const disposition = res.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename\*=UTF-8''(.+)/i)
                || disposition.match(/filename="?([^";\n]+)"?/i);
    const filename = match ? decodeURIComponent(match[1].trim()) : fallbackName;

    const url2 = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url2;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url2);
}

function downloadDecrypted(filename) {
    fetchAndDownload(`${API_URL}/decrypt/${filename}`, filename.replace(".enc", ""));
}

function downloadEncrypted(filename) {
    fetchAndDownload(`${API_URL}/download/${filename}`, filename);
}

async function loadFiles() {
    requireAuth();
    const list = document.getElementById("fileList");
    if (!list) return;

    list.innerHTML = `<li style="padding:16px 0;text-align:center;font-family:var(--mono);
                                  font-size:11px;color:var(--grey-400);">Loading...</li>`;

    try {
        const res = await fetch(`${API_URL}/files`, { headers: authHeaders() });

        if (res.status === 401) { logout(); return; }

        const files = await res.json();
        list.innerHTML = "";

        if (!files.length) {
            list.innerHTML = `<li class="empty-state">No files found</li>`;
            return;
        }

        files.forEach(file => {
            const li = document.createElement("li");
            li.innerHTML = `
                <span class="file-name" title="${file}">${file}</span>
                <div class="file-actions">
                    <button class="btn btn-ghost btn-sm" onclick="downloadDecrypted('${file}')">↓ Decrypt</button>
                    <button class="btn btn-ghost btn-sm" onclick="openShareModal('${file}')">⤴ Share</button>
                    <button class="btn btn-ghost btn-sm" onclick="downloadEncrypted('${file}')">Raw</button>
                </div>
            `;
            list.appendChild(li);
        });

    } catch (error) {
        list.innerHTML = `<li class="empty-state">Cannot reach server</li>`;
    }
}