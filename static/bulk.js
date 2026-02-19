// State
let csvHeaders = [];
let csvRows = [];
let emailColumnKey = '';
let previewMode = 'light';

// ───── CSV Handling ─────

const csvZone = document.getElementById('csvZone');
const csvFileInput = document.getElementById('csvFile');

csvZone.addEventListener('click', () => csvFileInput.click());
csvZone.addEventListener('dragover', e => { e.preventDefault(); csvZone.classList.add('dragover'); });
csvZone.addEventListener('dragleave', () => csvZone.classList.remove('dragover'));
csvZone.addEventListener('drop', e => {
    e.preventDefault();
    csvZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith('.csv')) handleCsvFile(file);
});
csvFileInput.addEventListener('change', () => {
    if (csvFileInput.files[0]) handleCsvFile(csvFileInput.files[0]);
});

function parseCsv(text) {
    const rows = [];
    let current = '';
    let inQuotes = false;
    const lines = [];

    // Split into lines respecting quoted newlines
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (ch === '"') {
            inQuotes = !inQuotes;
            current += ch;
        } else if ((ch === '\n' || ch === '\r') && !inQuotes) {
            if (current.trim()) lines.push(current);
            current = '';
            if (ch === '\r' && text[i + 1] === '\n') i++;
        } else {
            current += ch;
        }
    }
    if (current.trim()) lines.push(current);

    // Parse each line into fields
    for (const line of lines) {
        const fields = [];
        let field = '';
        let q = false;
        for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            if (ch === '"') {
                if (q && line[i + 1] === '"') { field += '"'; i++; }
                else q = !q;
            } else if (ch === ',' && !q) {
                fields.push(field.trim());
                field = '';
            } else {
                field += ch;
            }
        }
        fields.push(field.trim());
        rows.push(fields);
    }
    return rows;
}

function handleCsvFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        const parsed = parseCsv(e.target.result);
        if (parsed.length < 2) {
            alert('CSV needs at least a header row and one data row.');
            return;
        }

        csvHeaders = parsed[0].map(h => h.trim());
        csvRows = parsed.slice(1).map(row => {
            const obj = {};
            csvHeaders.forEach((h, i) => { obj[h] = (row[i] || '').trim(); });
            return obj;
        });

        // Update UI
        csvZone.classList.add('loaded');
        csvZone.innerHTML = `<i class="ri-checkbox-circle-line" style="font-size: 2rem; color: var(--success);"></i>
            <p style="margin: 8px 0 0; color: var(--success);">${file.name} loaded</p>`;

        document.getElementById('csvFileName').textContent = file.name;
        document.getElementById('recipientCount').textContent = csvRows.length;

        // Email column selector
        const sel = document.getElementById('emailColumnSelect');
        sel.innerHTML = '';
        csvHeaders.forEach(h => {
            const opt = document.createElement('option');
            opt.value = h;
            opt.textContent = h;
            // Auto-select if the header looks like an email column
            if (h.toLowerCase().includes('email') || h.toLowerCase().includes('mail')) opt.selected = true;
            sel.appendChild(opt);
        });
        emailColumnKey = sel.value;
        sel.onchange = () => { emailColumnKey = sel.value; updatePreview(); };

        // Variable chips
        const chips = document.getElementById('varChips');
        chips.innerHTML = '';
        csvHeaders.forEach(h => {
            const chip = document.createElement('span');
            chip.className = 'var-chip';
            chip.textContent = `{{${h}}}`;
            chip.onclick = () => insertVariable(h);
            chips.appendChild(chip);
        });

        document.getElementById('csvMappingSection').style.display = 'block';
        updatePreview();
    };
    reader.readAsText(file);
}

function clearCsv() {
    csvHeaders = [];
    csvRows = [];
    emailColumnKey = '';
    csvFileInput.value = '';
    csvZone.classList.remove('loaded');
    csvZone.innerHTML = `<i class="ri-upload-cloud-2-line" style="font-size: 2rem; color: var(--accent-color);"></i>
        <p style="margin: 8px 0 0; color: var(--text-secondary);">Click or drag a CSV file here</p>`;
    document.getElementById('csvMappingSection').style.display = 'none';
    updatePreview();
}

function insertVariable(header) {
    const editor = document.getElementById('richEditor');
    editor.focus();
    document.execCommand('insertText', false, `{{${header}}}`);
    updatePreview();
}

// ───── Rich Text Editor ─────

function execCmd(cmd) {
    document.execCommand(cmd, false, null);
    document.getElementById('richEditor').focus();
    syncHtmlEditor();
    updatePreview();
}

function execFormat(cmd, value) {
    document.execCommand(cmd, false, value);
    document.getElementById('richEditor').focus();
    syncHtmlEditor();
    updatePreview();
}

function execFontSize(size) {
    document.execCommand('fontSize', false, size);
    document.getElementById('richEditor').focus();
    syncHtmlEditor();
    updatePreview();
}

function insertLink() {
    const url = prompt('Enter URL:');
    if (url) {
        document.execCommand('createLink', false, url);
        document.getElementById('richEditor').focus();
        syncHtmlEditor();
        updatePreview();
    }
}

function insertImage() {
    const url = prompt('Enter image URL:');
    if (url) {
        document.execCommand('insertImage', false, url);
        document.getElementById('richEditor').focus();
        syncHtmlEditor();
        updatePreview();
    }
}

// Pull: copy rich editor HTML into the raw HTML textarea
function syncHtmlEditor() {
    document.getElementById('htmlEditor').value = document.getElementById('richEditor').innerHTML;
}

function pullHtmlFromEditor() {
    syncHtmlEditor();
}

// Push: apply raw HTML textarea content back into the visual editor
function applyHtmlToEditor() {
    document.getElementById('richEditor').innerHTML = document.getElementById('htmlEditor').value;
    updatePreview();
}

// Listen for typing in rich editor
document.getElementById('richEditor').addEventListener('input', () => {
    syncHtmlEditor();
    updatePreview();
});

document.getElementById('subjectInput').addEventListener('input', () => updatePreview());

// Advanced toggle
document.getElementById('advancedToggle').addEventListener('click', () => {
    const toggle = document.getElementById('advancedToggle');
    const body = document.getElementById('advancedBody');
    toggle.classList.toggle('open');
    body.classList.toggle('open');
    if (body.classList.contains('open')) syncHtmlEditor();
});

// ───── Gmail Preview ─────

function setPreviewMode(mode, btn) {
    previewMode = mode;
    document.querySelectorAll('.preview-tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    updatePreview();
}

function substituteVars(template, data) {
    if (!data || !template) return template || '';
    let result = template;
    for (const [key, value] of Object.entries(data)) {
        result = result.split('{{' + key + '}}').join(value || '');
    }
    return result;
}

function updatePreview() {
    const subject = document.getElementById('subjectInput').value || '(No subject)';
    const bodyHtml = document.getElementById('richEditor').innerHTML;
    const sampleData = csvRows.length > 0 ? csvRows[0] : {};
    const filledSubject = substituteVars(subject, sampleData);
    const filledBody = substituteVars(bodyHtml, sampleData);

    const isDark = previewMode === 'dark';

    const gmailHtml = `<!DOCTYPE html>
<html>
<head>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: 'Google Sans', Roboto, Arial, sans-serif;
        background: ${isDark ? '#1f1f1f' : '#f6f8fc'};
        padding: 0;
    }
    .gmail-top-bar {
        background: ${isDark ? '#2d2d2d' : '#f2f6fc'};
        padding: 8px 16px;
        display: flex;
        align-items: center;
        gap: 12px;
        border-bottom: 1px solid ${isDark ? '#3c3c3c' : '#e0e0e0'};
    }
    .gmail-top-bar svg { fill: ${isDark ? '#e8eaed' : '#5f6368'}; }
    .gmail-logo {
        font-size: 22px;
        font-weight: 500;
        color: ${isDark ? '#e8eaed' : '#202124'};
        display: flex;
        align-items: center;
        gap: 4px;
    }
    .gmail-logo span { color: ${isDark ? '#8ab4f8' : '#1a73e8'}; font-weight: normal; font-size: 10px; }
    .email-container {
        max-width: 680px;
        margin: 0 auto;
        padding: 20px 16px;
    }
    .email-subject {
        font-size: 20px;
        font-weight: 400;
        color: ${isDark ? '#e8eaed' : '#202124'};
        padding: 10px 0 16px;
        line-height: 1.3;
    }
    .email-meta {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 0;
        border-bottom: 1px solid ${isDark ? '#3c3c3c' : '#e8eaed'};
        margin-bottom: 16px;
    }
    .email-avatar {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background: ${isDark ? '#8ab4f8' : '#1a73e8'};
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 18px;
        font-weight: 500;
        flex-shrink: 0;
    }
    .email-sender-info {
        flex: 1;
    }
    .email-sender-name {
        font-size: 14px;
        font-weight: 500;
        color: ${isDark ? '#e8eaed' : '#202124'};
    }
    .email-sender-addr {
        font-size: 12px;
        color: ${isDark ? '#9aa0a6' : '#5f6368'};
    }
    .email-date {
        font-size: 12px;
        color: ${isDark ? '#9aa0a6' : '#5f6368'};
    }
    .email-body {
        color: ${isDark ? '#e8eaed' : '#202124'};
        font-size: 14px;
        line-height: 1.6;
    }
    .email-body a { color: ${isDark ? '#8ab4f8' : '#1a73e8'}; }
    .email-body img { max-width: 100%; height: auto; border-radius: 4px; }
    .email-body h1 { font-size: 24px; margin: 16px 0 8px; font-weight: 500; }
    .email-body h2 { font-size: 20px; margin: 14px 0 6px; font-weight: 500; }
    .email-body h3 { font-size: 16px; margin: 12px 0 4px; font-weight: 500; }
    .email-body p { margin: 0 0 10px; }
    .email-body ul, .email-body ol { padding-left: 24px; margin: 8px 0; }
    .email-body li { margin: 4px 0; }
    .email-body hr { border: none; border-top: 1px solid ${isDark ? '#3c3c3c' : '#dadce0'}; margin: 16px 0; }
</style>
</head>
<body>
    <div class="gmail-top-bar">
        <div class="gmail-logo">
            <svg width="20" height="20" viewBox="0 0 24 24"><path d="M20 18h-2V9.25L12 13 6 9.25V18H4V6h1.2l6.8 4.25L18.8 6H20m0-2H4c-1.11 0-2 .89-2 2v12a2 2 0 002 2h16a2 2 0 002-2V6a2 2 0 00-2-2z"/></svg>
            Gmail
        </div>
    </div>
    <div class="email-container">
        <div class="email-subject">${escHtml(filledSubject)}</div>
        <div class="email-meta">
            <div class="email-avatar">Y</div>
            <div class="email-sender-info">
                <div class="email-sender-name">You</div>
                <div class="email-sender-addr">to ${escHtml(sampleData[emailColumnKey] || 'recipient@example.com')}</div>
            </div>
            <div class="email-date">${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</div>
        </div>
        <div class="email-body">${filledBody || '<span style="color:#999">Start typing to see preview...</span>'}</div>
    </div>
</body>
</html>`;

    const frame = document.getElementById('previewFrame');
    frame.srcdoc = gmailHtml;
}

function escHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ───── Bulk Send ─────

async function startBulkSend() {
    if (csvRows.length === 0) {
        alert('Upload a CSV file first.');
        return;
    }
    if (!emailColumnKey) {
        alert('Select the email column.');
        return;
    }

    const subject = document.getElementById('subjectInput').value;
    const htmlBody = document.getElementById('richEditor').innerHTML;

    if (!subject.trim()) { alert('Enter a subject.'); return; }
    if (!htmlBody.trim()) { alert('Write an email body.'); return; }

    // Build recipient list with all fields
    const recipients = csvRows.map(row => {
        const obj = { ...row };
        obj.email = row[emailColumnKey] || '';
        return obj;
    });

    const btn = document.getElementById('sendBulkBtn');
    btn.disabled = true;
    btn.innerHTML = '<div class="loading"></div> Sending...';

    const progressDiv = document.getElementById('sendProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const logDiv = document.getElementById('sendLog');
    progressDiv.style.display = 'block';
    logDiv.style.display = 'block';
    logDiv.innerHTML = '';

    try {
        const response = await fetch('/api/bulk-send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                subject: subject,
                html_body: htmlBody,
                recipients: recipients
            })
        });

        const data = await response.json();

        if (data.results) {
            data.results.forEach((r, i) => {
                const pct = Math.round(((i + 1) / data.results.length) * 100);
                progressFill.style.width = pct + '%';
                progressText.textContent = `${i + 1}/${data.results.length} processed`;

                const entry = document.createElement('div');
                entry.className = `log-entry log-${r.status}`;
                entry.innerHTML = `<i class="ri-${r.status === 'sent' ? 'check-line' : r.status === 'failed' ? 'close-line' : 'skip-forward-line'}"></i> ${escHtml(r.email)} - ${r.status}${r.message ? ': ' + escHtml(r.message) : ''}`;
                logDiv.appendChild(entry);
            });
        }

        progressFill.style.width = '100%';
        progressText.textContent = data.message || 'Done!';

        if (data.success) {
            btn.innerHTML = '<i class="ri-check-line"></i> Sent!';
            btn.style.borderColor = 'var(--success)';
        } else {
            btn.innerHTML = '<i class="ri-error-warning-line"></i> ' + (data.message || 'Error');
            btn.style.borderColor = 'var(--error)';
        }
    } catch (err) {
        progressText.textContent = 'Network error: ' + err.message;
        btn.innerHTML = '<i class="ri-error-warning-line"></i> Failed';
    }

    setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = '<i class="ri-send-plane-fill"></i> Send to All Recipients';
        btn.style.borderColor = '';
    }, 4000);
}

// ───── Docs ─────

function openDocs() {
    document.getElementById('docsPanel').classList.add('open');
    document.getElementById('docsBackdrop').classList.add('open');
}

function closeDocs() {
    document.getElementById('docsPanel').classList.remove('open');
    document.getElementById('docsBackdrop').classList.remove('open');
}

// ───── Init ─────

updatePreview();
