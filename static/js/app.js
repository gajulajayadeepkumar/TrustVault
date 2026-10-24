/**
 * TrustVault Client Application Logic
 * Zero-Trust Document Security & Real-Time Tamper-Evident Ledger
 */

// Application State
let currentUser = null;
let currentDocuments = [];
let selectedUploadFile = null;
let searchDebounceTimer = null;

// ==========================================================================
// API Client Helper
// ==========================================================================
function getCsrfCookie() {
  const match = document.cookie.match(/(?:^|;\s*)tv_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function api(endpoint, options = {}) {
  const token = localStorage.getItem("tv_token");
  const csrf = getCsrfCookie();
  const headers = {
    ...options.headers
  };

  if (csrf && !headers["X-CSRF-Token"]) {
    headers["X-CSRF-Token"] = csrf;
  }

  if (token && !headers["Authorization"]) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  // Auto set JSON header if body is an object and not FormData
  if (options.body && !(options.body instanceof FormData) && typeof options.body === "object") {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }

  try {
    const res = await fetch(endpoint, { ...options, headers });
    
    // Auto logout on 401
    if (res.status === 401 && !endpoint.includes("/api/auth/login")) {
      localStorage.removeItem("tv_token");
      currentUser = null;
      renderAuthState();
      showToast("Session expired or invalid. Please sign in.", "error");
      throw new Error("Unauthorized");
    }

    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || data.message || "Request failed");
      }
      return data;
    } else {
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || "Request failed");
      }
      return res;
    }
  } catch (err) {
    console.error(`API Error [${endpoint}]:`, err);
    throw err;
  }
}

// ==========================================================================
// Authentication & Lifecycle
// ==========================================================================
async function checkAuth() {
  const token = localStorage.getItem("tv_token");
  if (!token) {
    currentUser = null;
    renderAuthState();
    return;
  }

  try {
    const me = await api("/api/auth/me");
    currentUser = me;
    renderAuthState();
    loadDocuments();
  } catch (err) {
    localStorage.removeItem("tv_token");
    currentUser = null;
    renderAuthState();
  }
}


function renderAuthState() {
  const loginSec = document.getElementById("loginSection");
  const appSec = document.getElementById("appSection");
  const userMenu = document.getElementById("userMenu");
  const navAuthLinks = document.getElementById("navAuthLinks");
  const tabBtnAdmin = document.getElementById("tabBtnAdmin");
  const adminPrivacyBanner = document.getElementById("adminPrivacyBanner");
  const viewerUploadWarning = document.getElementById("viewerUploadWarning");

  if (currentUser) {
    if (loginSec) loginSec.style.display = "none";
    if (appSec) appSec.style.display = "block";
    if (userMenu) userMenu.style.display = "flex";
    if (navAuthLinks) navAuthLinks.style.display = "none";

    const displayName = currentUser.full_name || currentUser.username;
    const nameEl = document.getElementById("navUsername");
    if (nameEl) nameEl.textContent = displayName;

    const badge = document.getElementById("navRoleBadge");
    if (badge) {
      badge.textContent = currentUser.role;
      badge.className = `role-badge role-${currentUser.role}`;
    }

    // Role-based dashboard routing
    const storedRoleTarget = sessionStorage.getItem("tv_current_role");
    if (storedRoleTarget === "ADMIN" || currentUser.role === "ADMIN") {
      if (storedRoleTarget) {
        sessionStorage.removeItem("tv_current_role");
        switchTab("admin");
      }
    } else {
      if (storedRoleTarget) {
        sessionStorage.removeItem("tv_current_role");
        switchTab("vault");
      }
    }

    // Admin-specific UI elements
    if (currentUser.role === "ADMIN") {
      if (tabBtnAdmin) tabBtnAdmin.style.display = "flex";
      if (adminPrivacyBanner) adminPrivacyBanner.style.display = "block";
      if (viewerUploadWarning) viewerUploadWarning.style.display = "none";
      loadAdminMetrics();
    } else {
      if (tabBtnAdmin) tabBtnAdmin.style.display = "none";
      if (adminPrivacyBanner) adminPrivacyBanner.style.display = "none";
    }

    // Viewer-specific restrictions
    const uploadBtn = document.getElementById("uploadSubmitBtn");
    if (currentUser.role === "VIEWER") {
      if (viewerUploadWarning) viewerUploadWarning.style.display = "block";
      if (uploadBtn) {
        uploadBtn.disabled = true;
        uploadBtn.style.opacity = "0.5";
      }
    } else {
      if (viewerUploadWarning) viewerUploadWarning.style.display = "none";
      if (uploadBtn) {
        uploadBtn.disabled = false;
        uploadBtn.style.opacity = "1";
      }
    }
  } else {
    if (loginSec) loginSec.style.display = "block";
    if (appSec) appSec.style.display = "none";
    if (userMenu) userMenu.style.display = "none";
    if (navAuthLinks) navAuthLinks.style.display = "flex";
  }
}

async function handleLogin(e) {
  e.preventDefault();
  const emailInput = document.getElementById("loginEmail");
  const email = emailInput ? emailInput.value.trim() : "";
  const password = document.getElementById("loginPassword").value;
  const loginBtn = document.getElementById("indexLoginBtn");

  if (!email || !password) {
    showToast("Please enter both email address and password.", "error");
    return;
  }

  if (loginBtn) {
    loginBtn.disabled = true;
    loginBtn.textContent = "Verifying...";
  }

  try {
    const csrfToken = getCsrfCookie();
    const data = await api("/api/auth/login", {
      method: "POST",
      headers: {
        "X-CSRF-Token": csrfToken
      },
      body: { email, password, csrf_token: csrfToken }
    });
    localStorage.setItem("tv_token", data.token);
    currentUser = data.user;
    
    // Store role target for dashboard routing
    sessionStorage.setItem("tv_current_role", currentUser.role);

    renderAuthState();
    loadDocuments();
    showToast(`Welcome to TrustVault, ${currentUser.full_name || currentUser.username}!`, "success");
  } catch (err) {
    showToast(err.message, "error");
  } finally {
    if (loginBtn) {
      loginBtn.disabled = false;
      loginBtn.textContent = "Authenticate to Vault";
    }
  }
}

async function handleLogout() {
  try {
    const csrfToken = getCsrfCookie();
    await api("/api/auth/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken }
    });
  } catch (e) {
    // ignore
  }
  localStorage.removeItem("tv_token");
  currentUser = null;
  window.location.href = "/auth/login";
}

// ==========================================================================
// Tabs Navigation
// ==========================================================================
function switchTab(tabId) {
  const tabs = ["vault", "upload", "audit", "admin"];
  tabs.forEach(t => {
    const btn = document.getElementById(`tabBtn${t.charAt(0).toUpperCase() + t.slice(1)}`);
    const content = document.getElementById(`tab${t.charAt(0).toUpperCase() + t.slice(1)}`);
    if (btn && content) {
      btn.classList.toggle("active", t === tabId);
      content.classList.toggle("active", t === tabId);
    }
  });

  if (tabId === "vault") loadDocuments();
  if (tabId === "audit") {
    loadAuditLedger();
    verifyAuditLedger();
  }
  if (tabId === "admin" && currentUser && currentUser.role === "ADMIN") {
    loadAdminMetrics();
    loadAdminUsers();
  }
}

// ==========================================================================
// Documents Management
// ==========================================================================
async function loadDocuments() {
  const search = document.getElementById("searchInput").value.trim();
  const category = document.getElementById("categoryFilter").value;

  const params = new URLSearchParams();
  if (search) params.append("search", search);
  if (category) params.append("category", category);

  try {
    const docs = await api(`/api/documents?${params.toString()}`);
    currentDocuments = docs;
    renderDocumentCards(docs);
  } catch (err) {
    showToast(`Failed to load documents: ${err.message}`, "error");
  }
}

function renderDocumentCards(docs) {
  const grid = document.getElementById("documentsGrid");
  grid.innerHTML = "";

  if (!docs || docs.length === 0) {
    grid.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 4rem 1rem; color: var(--text-dim);">
        <div style="font-size: 3rem; margin-bottom: 0.75rem;">📂</div>
        <div style="font-size: 1.15rem; font-weight: 600; color: var(--text-muted);">No Accessible Documents Found</div>
        <div style="font-size: 0.85rem; margin-top: 0.25rem;">Zero unauthorized documents are ever visible. Only documents owned or explicitly shared with you appear here.</div>
      </div>
    `;
    return;
  }

  docs.forEach(doc => {
    const card = document.createElement("div");
    card.className = "doc-card";

    // Format file size
    const sizeKb = (doc.file_size / 1024).toFixed(1);
    const sizeStr = doc.file_size > 1024 * 1024 ? `${(doc.file_size / (1024 * 1024)).toFixed(2)} MB` : `${sizeKb} KB`;

    // File type icon
    let icon = "📄";
    if (doc.mime_type.includes("pdf")) icon = "📕";
    else if (doc.mime_type.includes("word")) icon = "📘";
    else if (doc.mime_type.includes("sheet")) icon = "📗";
    else if (doc.mime_type.includes("image")) icon = "🖼️";

    const isOwner = doc.user_permission === "OWNER";
    const canEdit = isOwner || doc.user_permission === "EDIT";

    card.innerHTML = `
      <div>
        <div class="doc-header">
          <div class="doc-icon">${icon}</div>
          <div style="flex: 1;">
            <div class="doc-title">${escapeHtml(doc.title)}</div>
            <div class="doc-meta">
              <span class="category-tag">${escapeHtml(doc.category)}</span>
              <span>•</span>
              <span>Owner: <strong>${escapeHtml(doc.owner_username)}</strong></span>
              <span>•</span>
              <span>${sizeStr}</span>
            </div>
          </div>
          <div>
            <span class="role-badge role-${doc.user_permission === 'OWNER' ? 'OWNER' : (doc.user_permission === 'EDIT' ? 'ADMIN' : 'VIEWER')}">
              ${doc.user_permission}
            </span>
          </div>
        </div>

        <div class="doc-desc">${escapeHtml(doc.description || "No description provided.")}</div>

        <div class="doc-fingerprint" title="Cryptographic SHA-256 Checksum">
          <span>🔒 SHA-256:</span>
          <span>${doc.file_hash_sha256.substring(0, 18)}...</span>
        </div>
      </div>

      <div class="doc-actions">
        <button class="btn-action" onclick="handlePreview(${doc.id})">👁️ Preview</button>
        <button class="btn-action primary" onclick="handleDownload(${doc.id})">⬇️ Download</button>
        ${canEdit ? `<button class="btn-action" onclick="openEditModal(${doc.id})">✏️ Edit</button>` : ''}
        ${isOwner ? `<button class="btn-action" onclick="openShareModal(${doc.id})">👥 Permissions</button>` : ''}
        ${isOwner ? `<button class="btn-action danger" onclick="handleDelete(${doc.id})">🗑️ Delete</button>` : ''}
      </div>
    `;
    grid.appendChild(card);
  });
}

function handleSearch() {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => {
    loadDocuments();
  }, 250);
}

// File Drag & Drop Handlers
function handleFileSelected(e) {
  const file = e.target.files[0];
  if (file) {
    selectedUploadFile = file;
    document.getElementById("dropzoneLabel").textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    if (!document.getElementById("uploadTitle").value) {
      document.getElementById("uploadTitle").value = file.name.replace(/\.[^/.]+$/, "");
    }
  }
}

// Drag & Drop events
document.addEventListener("DOMContentLoaded", () => {
  const dropzone = document.getElementById("dropzone");
  if (dropzone) {
    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("dragover");
    });
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length) {
        document.getElementById("fileInput").files = e.dataTransfer.files;
        handleFileSelected({ target: { files: e.dataTransfer.files } });
      }
    });
  }
});

async function handleUpload(e) {
  e.preventDefault();
  if (!selectedUploadFile) {
    showToast("Please select a file to upload.", "error");
    return;
  }

  const formData = new FormData();
  formData.append("file", selectedUploadFile);
  formData.append("title", document.getElementById("uploadTitle").value.trim());
  formData.append("category", document.getElementById("uploadCategory").value);
  formData.append("description", document.getElementById("uploadDescription").value.trim());

  try {
    const res = await api("/api/documents/upload", {
      method: "POST",
      body: formData
    });
    showToast(`Document "${res.title}" successfully encrypted & stored in private vault!`, "success");
    document.getElementById("uploadForm").reset();
    document.getElementById("dropzoneLabel").textContent = "Click to browse or drag and drop file here";
    selectedUploadFile = null;
    switchTab("vault");
  } catch (err) {
    showToast(`Upload failed: ${err.message}`, "error");
  }
}

async function handleDownload(docId) {
  const token = localStorage.getItem("tv_token");
  try {
    const res = await fetch(`/api/documents/${docId}/download`, {
      headers: { "Authorization": `Bearer ${token}` }
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Download failed");
    }

    const disposition = res.headers.get("content-disposition");
    let filename = `document_${docId}.dat`;
    if (disposition && disposition.indexOf("filename=") !== -1) {
      filename = disposition.split("filename=")[1].replace(/['"]/g, "").trim();
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    a.remove();
    showToast(`Securely downloaded "${filename}"`, "success");
  } catch (err) {
    showToast(`Download blocked: ${err.message}`, "error");
  }
}

async function handlePreview(docId) {
  try {
    const doc = await api(`/api/documents/${docId}`);
    const modal = document.getElementById("previewModal");
    document.getElementById("previewTitle").textContent = doc.title;

    const sizeKb = (doc.file_size / 1024).toFixed(1);
    const body = document.getElementById("previewBody");
    body.innerHTML = `
      <div style="background: rgba(255,255,255,0.03); padding: 1.25rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); margin-bottom: 1.25rem;">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; font-size: 0.88rem;">
          <div><strong style="color: var(--text-dim);">Original Filename:</strong> ${escapeHtml(doc.original_filename)}</div>
          <div><strong style="color: var(--text-dim);">Category:</strong> <span class="category-tag">${escapeHtml(doc.category)}</span></div>
          <div><strong style="color: var(--text-dim);">Document Owner:</strong> ${escapeHtml(doc.owner_username)}</div>
          <div><strong style="color: var(--text-dim);">Your Permission:</strong> <span class="role-badge role-${doc.user_permission === 'OWNER' ? 'OWNER' : (doc.user_permission === 'EDIT' ? 'ADMIN' : 'VIEWER')}">${doc.user_permission}</span></div>
          <div><strong style="color: var(--text-dim);">File Size:</strong> ${sizeKb} KB (${doc.file_size} bytes)</div>
          <div><strong style="color: var(--text-dim);">MIME Type:</strong> ${escapeHtml(doc.mime_type)}</div>
        </div>
        <div style="margin-top: 0.85rem; padding-top: 0.85rem; border-top: 1px solid var(--border-subtle);">
          <strong style="color: var(--text-dim);">Description:</strong>
          <p style="margin-top: 0.25rem; color: var(--text-muted); font-size: 0.9rem;">${escapeHtml(doc.description || "No description provided.")}</p>
        </div>
        <div style="margin-top: 0.85rem; padding-top: 0.85rem; border-top: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 0.75rem; color: var(--primary-cyan);">
          <strong>SHA-256 Checksum:</strong> ${doc.file_hash_sha256}
        </div>
      </div>
      <div style="text-align: center; padding: 1.5rem; background: rgba(0,0,0,0.3); border-radius: var(--radius-sm); border: 1px dashed var(--border-subtle);">
        <div style="font-size: 2.2rem; margin-bottom: 0.5rem;">🔒</div>
        <div style="font-weight: 600; font-size: 0.95rem;">Private Storage Vault Isolation Verified</div>
        <div style="font-size: 0.8rem; color: var(--text-dim); margin-top: 0.2rem;">Files are stored outside web directory with randomized UUID tokens. Click below to stream download.</div>
      </div>
    `;

    document.getElementById("previewDownloadBtn").onclick = () => handleDownload(docId);
    openModal("previewModal");
  } catch (err) {
    showToast(`Access blocked: ${err.message}`, "error");
  }
}

function openEditModal(docId) {
  const doc = currentDocuments.find(d => d.id === docId);
  if (!doc) return;

  document.getElementById("editDocId").value = doc.id;
  document.getElementById("editTitle").value = doc.title;
  document.getElementById("editCategory").value = doc.category;
  document.getElementById("editDescription").value = doc.description || "";
  openModal("editModal");
}

async function handleSaveEdit(e) {
  e.preventDefault();
  const docId = document.getElementById("editDocId").value;
  const title = document.getElementById("editTitle").value.trim();
  const category = document.getElementById("editCategory").value;
  const description = document.getElementById("editDescription").value.trim();

  try {
    await api(`/api/documents/${docId}`, {
      method: "PUT",
      body: { title, category, description }
    });
    closeModal("editModal");
    showToast("Document updated successfully.", "success");
    loadDocuments();
  } catch (err) {
    showToast(`Update failed: ${err.message}`, "error");
  }
}

async function handleDelete(docId) {
  const doc = currentDocuments.find(d => d.id === docId);
  const title = doc ? doc.title : `Doc #${docId}`;

  if (!confirm(`Are you sure you want to delete "${title}"? This cannot be undone.`)) {
    return;
  }

  try {
    await api(`/api/documents/${docId}`, { method: "DELETE" });
    showToast(`Document "${title}" permanently deleted from vault.`, "success");
    loadDocuments();
  } catch (err) {
    showToast(`Delete failed: ${err.message}`, "error");
  }
}

// ==========================================================================
// Permissions Management
// ==========================================================================
async function openShareModal(docId) {
  document.getElementById("shareDocId").value = docId;
  const doc = currentDocuments.find(d => d.id === docId);
  document.getElementById("shareDocTitle").textContent = `Manage Access: ${doc ? doc.title : ''}`;

  // Populate user dropdown
  try {
    const users = await api("/api/auth/users");
    const select = document.getElementById("shareUserSelect");
    select.innerHTML = '<option value="">Select User to Grant...</option>';
    users
      .filter(u => u.username !== currentUser.username)
      .forEach(u => {
        select.innerHTML += `<option value="${escapeHtml(u.username)}">${escapeHtml(u.username)} (${u.role})</option>`;
      });

    await loadDocPermissions(docId);
    openModal("shareModal");
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function loadDocPermissions(docId) {
  const container = document.getElementById("permissionsListContainer");
  container.innerHTML = '<div style="color: var(--text-dim); font-size: 0.85rem;">Loading permissions...</div>';

  try {
    const perms = await api(`/api/documents/${docId}/permissions`);
    if (!perms || perms.length === 0) {
      container.innerHTML = '<div style="color: var(--text-dim); font-size: 0.85rem;">No user permissions currently granted. Only you (the owner) have access.</div>';
      return;
    }

    let html = '<div style="display: flex; flex-direction: column; gap: 0.5rem;">';
    perms.forEach(p => {
      html += `
        <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(255,255,255,0.03); padding: 0.65rem 0.95rem; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
          <div>
            <strong style="color: var(--text-main); font-size: 0.9rem;">${escapeHtml(p.username)}</strong>
            <span class="role-badge role-${p.permission_level === 'EDIT' ? 'ADMIN' : 'VIEWER'}" style="margin-left: 0.5rem;">${p.permission_level}</span>
          </div>
          <button class="btn-action danger" style="padding: 0.3rem 0.65rem; font-size: 0.75rem;" onclick="handleRevokePermission(${docId}, ${p.user_id}, '${escapeHtml(p.username)}')">
            Revoke Access
          </button>
        </div>
      `;
    });
    html += '</div>';
    container.innerHTML = html;
  } catch (err) {
    container.innerHTML = `<div style="color: var(--accent-rose); font-size: 0.85rem;">Failed to load permissions: ${err.message}</div>`;
  }
}

async function handleGrantPermission() {
  const docId = document.getElementById("shareDocId").value;
  const username = document.getElementById("shareUserSelect").value;
  const level = document.getElementById("shareLevelSelect").value;

  if (!username) {
    showToast("Please select a target user.", "error");
    return;
  }

  try {
    await api(`/api/documents/${docId}/permissions`, {
      method: "POST",
      body: { target_username: username, permission_level: level }
    });
    showToast(`Granted ${level} permission to ${username}`, "success");
    loadDocPermissions(docId);
  } catch (err) {
    showToast(`Failed to grant: ${err.message}`, "error");
  }
}

async function handleRevokePermission(docId, userId, username) {
  try {
    await api(`/api/documents/${docId}/permissions/${userId}`, {
      method: "DELETE"
    });
    showToast(`Immediately revoked access for ${username}. Subsequent requests will be denied.`, "success");
    loadDocPermissions(docId);
  } catch (err) {
    showToast(`Revocation failed: ${err.message}`, "error");
  }
}

// ==========================================================================
// Audit & Tamper Detection Center
// ==========================================================================
async function loadAuditLedger() {
  const tbody = document.getElementById("auditTableBody");
  tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-dim); padding: 2rem;">Loading audit trail...</td></tr>';

  try {
    const data = await api("/api/audit/events?limit=100");
    tbody.innerHTML = "";

    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-dim); padding: 2rem;">No audit events recorded.</td></tr>';
      return;
    }

    data.events.forEach(ev => {
      const tr = document.createElement("tr");
      tr.id = `auditRow_${ev.id}`;
      tr.innerHTML = `
        <td style="font-weight: 700; color: var(--text-dim);">${ev.id}</td>
        <td style="font-size: 0.78rem; color: var(--text-muted); font-family: var(--font-mono);">${ev.timestamp.replace('T', ' ').substring(0, 19)}</td>
        <td><strong>${escapeHtml(ev.actor_username || 'SYSTEM')}</strong></td>
        <td><span style="font-size: 0.78rem; font-weight: 600; color: var(--primary-cyan);">${escapeHtml(ev.action_type)}</span></td>
        <td><span class="category-tag">${escapeHtml(ev.target_type)} ${ev.target_id ? '#' + ev.target_id : ''}</span></td>
        <td><span class="badge-status badge-${ev.outcome}">${ev.outcome}</span></td>
        <td style="font-size: 0.82rem; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(ev.details || '')}">${escapeHtml(ev.details || '')}</td>
        <td class="hash-cell" title="Prev: ${ev.prev_hash}\nHash: ${ev.record_hash}">
          🔗 ${ev.record_hash.substring(0, 12)}...
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--accent-rose); padding: 2rem;">Error: ${err.message}</td></tr>`;
  }
}

async function verifyAuditLedger() {
  const banner = document.getElementById("auditStatusBanner");
  const icon = document.getElementById("auditStatusIcon");
  const title = document.getElementById("auditStatusTitle");
  const desc = document.getElementById("auditStatusDesc");

  try {
    const result = await api("/api/audit/verify");
    if (result.is_valid) {
      banner.className = "security-banner verified";
      icon.textContent = "✓";
      title.textContent = `Cryptographic Audit Chain Integrity: VERIFIED (${result.total_events} blocks)`;
      desc.textContent = `All SHA-256 block hashes, chronological timestamps, and sequence numbers match cryptographic ground truth. (Verified in ${result.verification_time_ms} ms)`;
      showToast(`Audit ledger cryptographically verified in ${result.verification_time_ms} ms!`, "success");
    } else {
      banner.className = "security-banner tampered";
      icon.textContent = "⚠️";
      title.textContent = `ALERT: TAMPERING DETECTED AT BLOCK #${result.broken_event_id}`;
      desc.textContent = `Tamper Discrepancy: ${result.error_message}`;
      showToast(`TAMPER ALARM: Discrepancy detected at Block #${result.broken_event_id}!`, "error");

      // Highlight the corrupted row if visible
      const row = document.getElementById(`auditRow_${result.broken_event_id}`);
      if (row) {
        row.style.background = "rgba(244, 63, 94, 0.25)";
        row.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }
  } catch (err) {
    showToast(`Verification query failed: ${err.message}`, "error");
  }
}

async function simulateTamper() {
  try {
    const res = await api("/api/audit/tamper-test", { method: "POST" });
    showToast(`Injected simulated unauthorized database edit into Block #${res.modified_record_id}. Verifying chain...`, "error");
    await loadAuditLedger();
    await verifyAuditLedger();
  } catch (err) {
    showToast(`Simulation failed: ${err.message}`, "error");
  }
}

async function restoreLedger() {
  try {
    await api("/api/audit/repair", { method: "POST" });
    showToast("Audit ledger restored to valid cryptographic state.", "success");
    await loadAuditLedger();
    await verifyAuditLedger();
  } catch (err) {
    showToast(`Restore failed: ${err.message}`, "error");
  }
}

// ==========================================================================
// Admin Console
// ==========================================================================
async function loadAdminMetrics() {
  try {
    const metrics = await api("/api/admin/metrics");
    document.getElementById("statTotalDocs").textContent = metrics.total_documents;
    document.getElementById("statTotalUsers").textContent = metrics.total_users;
    document.getElementById("statTotalAudit").textContent = metrics.total_audit_events;
    document.getElementById("statAccessDenied").textContent = metrics.access_denied_24h;

    // Render alerts
    const alertsBody = document.getElementById("adminAlertsTableBody");
    alertsBody.innerHTML = "";
    if (metrics.recent_alerts && metrics.recent_alerts.length > 0) {
      metrics.recent_alerts.forEach(a => {
        alertsBody.innerHTML += `
          <tr>
            <td>${a.id}</td>
            <td style="font-size: 0.78rem; font-family: var(--font-mono);">${a.timestamp.substring(11, 19)}</td>
            <td><strong>${escapeHtml(a.actor || 'ANON')}</strong></td>
            <td><span style="color: var(--accent-rose); font-weight: 600; font-size: 0.8rem;">${escapeHtml(a.action)}</span></td>
            <td>${escapeHtml(a.target)}</td>
            <td style="font-size: 0.82rem;">${escapeHtml(a.details)}</td>
            <td style="font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(a.ip)}</td>
          </tr>
        `;
      });
    } else {
      alertsBody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No recent security alerts recorded.</td></tr>';
    }
  } catch (err) {
    console.error("Failed to load admin metrics:", err);
  }
}

async function loadAdminUsers() {
  try {
    const users = await api("/api/admin/users");
    const tbody = document.getElementById("adminUsersTableBody");
    tbody.innerHTML = "";

    users.forEach(u => {
      tbody.innerHTML += `
        <tr>
          <td>${u.id}</td>
          <td><strong>${escapeHtml(u.username)}</strong></td>
          <td>${escapeHtml(u.email)}</td>
          <td><span class="role-badge role-${u.role}">${u.role}</span></td>
          <td>
            <span class="badge-status ${u.is_active ? 'badge-SUCCESS' : 'badge-FAILURE'}">
              ${u.is_active ? 'ACTIVE' : 'DISABLED'}
            </span>
          </td>
          <td>${u.failed_attempts}</td>
          <td>
            ${u.id !== currentUser.id ? `
              <button class="btn-action ${u.is_active ? 'danger' : 'primary'}" style="padding: 0.3rem 0.75rem; font-size: 0.78rem;" onclick="handleToggleUserStatus(${u.id}, ${u.is_active})">
                ${u.is_active ? 'Disable' : 'Enable'}
              </button>
            ` : '<span style="color: var(--text-dim); font-size: 0.8rem;">Current Account</span>'}
          </td>
        </tr>
      `;
    });
  } catch (err) {
    console.error("Failed to load admin users:", err);
  }
}

async function handleToggleUserStatus(userId, currentlyActive) {
  try {
    await api(`/api/admin/users/${userId}/toggle-status`, { method: "POST" });
    showToast(`User account status updated.`, "success");
    loadAdminUsers();
  } catch (err) {
    showToast(`Failed to update user: ${err.message}`, "error");
  }
}

// ==========================================================================
// Modals & UI Utilities
// ==========================================================================
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.add("active");
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove("active");
}

function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;

  let icon = "ℹ️";
  if (type === "success") icon = "✅";
  if (type === "error") icon = "⚠️";

  toast.innerHTML = `
    <span style="font-size: 1.1rem;">${icon}</span>
    <span style="font-size: 0.88rem; font-weight: 500;">${escapeHtml(message)}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(100%)";
    toast.style.transition = "all 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Initialize Application on page load
window.addEventListener("DOMContentLoaded", () => {
  checkAuth();
});
