// ============================================================
// SecureVault — Main JS  (Premium Edition)
// ============================================================

// ─── Generate hero particles ────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('hero-particles');
    if (!container) return;
    const count = 28;
    const colors = ['#06b6d4', '#8b5cf6', '#22d3ee', '#a78bfa', '#ec4899'];
    for (let i = 0; i < count; i++) {
        const p = document.createElement('span');
        p.className = 'particle';
        const size = Math.random() * 3 + 1.5;
        p.style.cssText = `
            left: ${Math.random() * 100}%;
            width: ${size}px; height: ${size}px;
            background: ${colors[Math.floor(Math.random() * colors.length)]};
            animation-duration: ${Math.random() * 12 + 8}s;
            animation-delay: ${Math.random() * 10}s;
            opacity: ${Math.random() * 0.6 + 0.2};
            border-radius: 50%;
            box-shadow: 0 0 ${size * 3}px currentColor;
        `;
        container.appendChild(p);
    }
});

// ─── Toggle password visibility ──────────────────────────────
function togglePw(inputId) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const btn = input.closest('.input-wrapper')?.querySelector('.toggle-pw i');
    input.type = input.type === 'password' ? 'text' : 'password';
    if (btn) {
        btn.className = input.type === 'text' ? 'fas fa-eye-slash' : 'fas fa-eye';
    }
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

// ─── Confirm delete ──────────────────────────────────────────
function confirmDelete(filename) {
    return confirm(`⚠️ Permanently delete "${filename}"?\n\nThis action cannot be undone.`);
}

// ─── Upload panel toggle ──────────────────────────────────────
function toggleUpload() {
    const panel = document.getElementById('upload-panel');
    const btn = document.getElementById('upload-toggle-btn');
    if (!panel) return;
    const visible = panel.style.display !== 'none';
    panel.style.display = visible ? 'none' : 'block';
    if (btn) {
        btn.innerHTML = visible
            ? '<i class="fas fa-upload"></i> Upload File'
            : '<i class="fas fa-xmark"></i> Close';
    }
    if (!visible) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── File select handler ──────────────────────────────────────
function handleFileSelect(input) {
    const label = document.getElementById('file-name-label');
    const dropZone = document.getElementById('drop-zone');
    if (label && input.files.length > 0) {
        const f = input.files[0];
        const size = f.size > 1024 * 1024
            ? (f.size / 1024 / 1024).toFixed(2) + ' MB'
            : (f.size / 1024).toFixed(1) + ' KB';
        label.innerHTML = `<i class="fas fa-circle-check"></i> ${f.name} (${size})`;
        if (dropZone) {
            dropZone.style.borderColor = 'var(--cyan)';
            dropZone.style.background = 'rgba(6,182,212,0.06)';
        }
    }
}

// Drag-and-drop
document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    if (!dropZone || !fileInput) return;

    dropZone.addEventListener('dragover', e => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
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
    setTimeout(() => document.getElementById('dl-password')?.focus(), 100);
}
function closeDownload() {
    const modal = document.getElementById('download-modal');
    if (modal) modal.style.display = 'none';
    const pw = document.getElementById('dl-password');
    if (pw) pw.value = '';
}
// Close modal on backdrop click / Escape
document.addEventListener('DOMContentLoaded', () => {
    const overlay = document.getElementById('download-modal');
    if (overlay) {
        overlay.addEventListener('click', e => {
            if (e.target === overlay) closeDownload();
        });
    }
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeDownload();
});

// ─── Password strength meter (register page) ──────────────────
document.addEventListener('DOMContentLoaded', () => {
    const pwInput = document.getElementById('password');
    const bar = document.getElementById('pw-strength-bar');
    const lbl = document.getElementById('pw-strength-label');
    if (!pwInput || !bar) return;

    const levels = [
        { label: '', color: '', pct: '0%' },
        { label: 'Very weak', color: '#f87171', pct: '20%' },
        { label: 'Weak', color: '#fb923c', pct: '40%' },
        { label: 'Fair', color: '#fbbf24', pct: '60%' },
        { label: 'Strong', color: '#4ade80', pct: '80%' },
        { label: 'Very strong', color: '#10b981', pct: '100%' },
    ];

    pwInput.addEventListener('input', () => {
        const pw = pwInput.value;
        let score = 0;
        if (pw.length >= 10) score++;
        if (pw.length >= 14) score++;
        if (/[A-Z]/.test(pw)) score++;
        if (/[0-9]/.test(pw)) score++;
        if (/[^A-Za-z0-9]/.test(pw)) score++;

        const lvl = levels[score] || levels[1];
        bar.style.setProperty('--pw-width', lvl.pct);
        bar.style.setProperty('--pw-color', lvl.color);
        bar.style.width = lvl.pct;
        bar.style.background = lvl.color;
        bar.style.boxShadow = lvl.color ? `0 0 8px ${lvl.color}60` : '';
        if (lbl) {
            lbl.textContent = lvl.label;
            lbl.style.color = lvl.color || 'var(--text-muted)';
        }
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
        btn.style.opacity = '0.75';
    });
});

// ─── Staggered file card animations ─────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.file-card').forEach((card, i) => {
        card.style.animationDelay = `${i * 0.06}s`;
    });
});

// ─── Auto-dismiss alerts ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.5s ease, transform 0.5s ease, max-height 0.5s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-8px)';
            setTimeout(() => alert.remove(), 500);
        }, 5000);
    });
});

