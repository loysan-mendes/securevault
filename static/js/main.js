// ============================================================
// SecureVault — Main JS
// ============================================================

// ─── Toggle password visibility ──────────────────────────────
function togglePw(inputId) {
    const input = document.getElementById(inputId);
    if (!input) return;
    input.type = input.type === 'password' ? 'text' : 'password';
}
function togglePwId(id) { togglePw(id); }

// ─── Download button delegation ───────────────────────────────
document.addEventListener('click', e => {
    const btn = e.target.closest('.download-btn');
    if (!btn) return;
    const fileId = btn.getAttribute('data-file-id');
    const fileName = btn.getAttribute('data-file-name');
    showDownload(fileId, fileName);
});

// ─── Upload panel toggle ──────────────────────────────────────
function toggleUpload() {
    const panel = document.getElementById('upload-panel');
    if (!panel) return;
    const visible = panel.style.display !== 'none';
    panel.style.display = visible ? 'none' : 'block';
    if (!visible) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── File select handler ──────────────────────────────────────
function handleFileSelect(input) {
    const label = document.getElementById('file-name-label');
    if (label && input.files.length > 0) {
        const f = input.files[0];
        const size = (f.size / 1024).toFixed(1);
        label.textContent = `Selected: ${f.name} (${size} KB)`;
    }
}

// Drag-and-drop
document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('dragover', e => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--primary)';
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.style.borderColor = '';
    });
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.style.borderColor = '';
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            handleFileSelect(fileInput);
        }
    });
});

// ─── Download modal ──────────────────────────────────────────
function showDownload(fileId, filename) {
    const modal = document.getElementById('download-modal');
    const form = document.getElementById('download-form');
    const label = document.getElementById('download-filename');
    if (!modal || !form) return;
    form.action = `/vault/download/${fileId}`;
    if (label) label.textContent = filename;
    modal.style.display = 'flex';
    document.getElementById('dl-password').focus();
}
function closeDownload() {
    const modal = document.getElementById('download-modal');
    if (modal) modal.style.display = 'none';
    const pw = document.getElementById('dl-password');
    if (pw) pw.value = '';
}
// Close modal on backdrop click
document.addEventListener('DOMContentLoaded', () => {
    const overlay = document.getElementById('download-modal');
    if (overlay) {
        overlay.addEventListener('click', e => {
            if (e.target === overlay) closeDownload();
        });
    }
});

// ─── Password strength meter ─────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const pwInput = document.getElementById('password');
    const meter = document.getElementById('pw-strength');
    if (!pwInput || !meter) return;

    pwInput.addEventListener('input', () => {
        const pw = pwInput.value;
        let score = 0;
        if (pw.length >= 10) score++;
        if (pw.length >= 14) score++;
        if (/[A-Z]/.test(pw)) score++;
        if (/[0-9]/.test(pw)) score++;
        if (/[^A-Za-z0-9]/.test(pw)) score++;

        const widths = ['0%', '20%', '40%', '60%', '80%', '100%'];
        const colors = ['', '#f87171', '#fbbf24', '#fbbf24', '#4ade80', '#22c55e'];
        meter.style.setProperty('--pw-width', widths[score]);
        meter.style.setProperty('--pw-color', colors[score] || '#f87171');
    });
});

// ─── Upload button loading state ─────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('upload-form');
    const btn = document.getElementById('upload-btn');
    if (!form || !btn) return;
    form.addEventListener('submit', () => {
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Encrypting…';
        btn.disabled = true;
    });
});
