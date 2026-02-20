let currentFolder = 'inbox';
let offset = 0;
const limit = 20;
let isLoading = false;
let allLoaded = false;

document.addEventListener('DOMContentLoaded', () => {
    loadEmails(true);
    setupModal();
    setupCompose();
    setupInfiniteScroll();
    startJobPolling();
});

function startJobPolling() {
    fetchJobs();
    setInterval(fetchJobs, 5000); // Poll every 5 seconds
}

async function fetchJobs() {
    try {
        const response = await fetch('/api/jobs');
        const data = await response.json();
        const list = document.getElementById('jobsList');

        if (!data.jobs || data.jobs.length === 0) {
            list.innerHTML = '<div style="color:var(--text-secondary);font-size:0.8rem;text-align:center;padding:10px;">No active sending jobs.</div>';
            return;
        }

        list.innerHTML = '';
        data.jobs.forEach(job => {
            const item = document.createElement('div');
            item.style.background = 'rgba(0,0,0,0.25)';
            item.style.borderRadius = 'var(--radius-sm)';
            item.style.padding = '8px 12px';
            item.style.fontSize = '0.8rem';

            const isRunning = job.status === 'running' || job.status.startsWith('Wait');
            const isPaused = job.status === 'paused' || job.status.startsWith('Paused');
            const isActive = isRunning || isPaused;
            const statusColor = isActive ? (isPaused ? 'var(--warning)' : 'var(--primary-color)') : (job.status === 'completed' ? 'var(--success)' : 'var(--error)');

            const pct = job.percent || 0;

            let actions = '';
            if (isActive) {
                actions = `
                    <div style="display:flex; justify-content: flex-end; gap:6px; margin-top:6px; pt-1; border-top:1px solid rgba(255,255,255,0.05);">
                        ${isPaused ?
                        `<button onclick="controlJob('${job.id}', 'resume')" class="glass-btn glass-btn-xs" title="Resume"><i class="ri-play-fill"></i></button>` :
                        `<button onclick="controlJob('${job.id}', 'pause')" class="glass-btn glass-btn-xs" title="Pause"><i class="ri-pause-circle-line"></i></button>`
                    }
                        <button onclick="controlJob('${job.id}', 'cancel')" class="glass-btn glass-btn-xs" title="Cancel" style="color:var(--error);"><i class="ri-stop-circle-line"></i></button>
                    </div>
                `;
            }

            item.innerHTML = `
                <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                    <span style="font-weight:600;color:var(--text-secondary);">${job.type}</span>
                    <span style="color:${statusColor};font-size:0.75rem;">${job.status}</span>
                </div>
                <div style="margin-bottom:4px;color:var(--text-secondary);font-size:0.75rem;display:flex;justify-content:space-between;">
                   <span>${job.sent}/${job.total} sent</span>
                   <span>${pct}%</span>
                </div>
                <div style="height:4px;background:rgba(255,255,255,0.1);border-radius:2px;overflow:hidden;margin-bottom:6px;">
                    <div style="width:${pct}%;height:100%;background:${statusColor};transition:width 0.5s;"></div>
                </div>
                <div style="font-size:0.7rem;color:var(--text-secondary);opacity:0.8;">
                   <i class="ri-timer-line"></i> ETA: ${job.estimated_completion || '?'}
                </div>
                ${actions}
            `;
            list.appendChild(item);
        });

    } catch (e) {
        console.error("Job poll error", e);
    }
}

async function controlJob(id, action) {
    if (!confirm(`Are you sure you want to ${action} this job?`)) return;
    try {
        await fetch(`/api/jobs/${id}/action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action })
        });
        fetchJobs();
    } catch (e) {
        alert('Action failed');
    }
}

function setupInfiniteScroll() {
    const trigger = document.getElementById('loadMoreTrigger');
    const observer = new IntersectionObserver((entries) => {
        if (entries[0].isIntersecting && !isLoading && !allLoaded) {
            loadEmails(false);
        }
    }, { threshold: 0.1 });
    observer.observe(trigger);
}

function switchFolder(folder, element) {
    document.querySelectorAll('.menu-item').forEach(el => el.classList.remove('active'));
    element.classList.add('active');
    document.getElementById('folderTitle').innerText = folder.charAt(0).toUpperCase() + folder.slice(1);

    currentFolder = folder;
    offset = 0;
    allLoaded = false;
    document.getElementById('emailList').innerHTML = '';

    // Reset detail
    const detail = document.getElementById('emailDetailView');
    detail.innerHTML = `<div class="detail-panel-inner"><div class="detail-placeholder">
        <i class="ri-mail-open-line"></i><p>Select an email to read</p>
    </div></div>`;

    loadEmails(true);
}

function refreshEmails() {
    offset = 0;
    allLoaded = false;
    document.getElementById('emailList').innerHTML = '';
    loadEmails(true);
}

async function loadEmails(isInitial) {
    if (isLoading) return;
    isLoading = true;

    const list = document.getElementById('emailList');
    const trigger = document.getElementById('loadMoreTrigger');

    if (isInitial) {
        list.innerHTML = '<div class="sync-msg">Loading emails... <div class="loading"></div></div>';
    } else {
        trigger.innerHTML = '<div class="loading"></div>';
    }

    try {
        const response = await fetch(`/api/emails/${currentFolder}?offset=${offset}&limit=${limit}`);
        if (response.status === 401) { window.location.href = '/'; return; }

        const data = await response.json();

        if (!response.ok || data.error) {
            throw new Error(data.error || 'Failed to load emails');
        }

        const emails = Array.isArray(data) ? data : [];

        if (isInitial) list.innerHTML = '';

        if (emails.length < limit) {
            allLoaded = true;
            trigger.innerHTML = emails.length === 0 && offset === 0 ? '' : 'End of list';
        } else {
            trigger.innerHTML = 'Scroll for more';
        }

        if (emails.length === 0 && isInitial) {
            list.innerHTML = '<div class="empty-msg"><i class="ri-inbox-line" style="font-size:2rem;opacity:0.4;"></i>No emails found</div>';
        } else {
            emails.forEach(em => {
                const item = document.createElement('div');
                item.className = 'email-item';
                item.onclick = () => loadEmailDetail(em.id, item);
                item.innerHTML = `
                    <div class="email-sender">
                        <span class="email-sender-name">${escapeHtml(em.sender)}</span>
                        <span class="email-date">${formatDate(em.date)}</span>
                    </div>
                    <div class="email-subject">${escapeHtml(em.subject)}</div>
                    <div class="email-snippet">${escapeHtml(em.snippet)}</div>
                `;
                list.appendChild(item);
            });
            offset += emails.length;
        }

    } catch (error) {
        console.error(error);
        if (isInitial) list.innerHTML = `<div class="error-msg"><i class="ri-error-warning-line"></i> ${escapeHtml(error.message)}</div>`;
    } finally {
        isLoading = false;
    }
}

async function loadEmailDetail(id, itemElement) {
    document.querySelectorAll('.email-item').forEach(el => el.classList.remove('selected'));
    itemElement.classList.add('selected');

    const detailView = document.getElementById('emailDetailView');
    detailView.innerHTML = '<div class="detail-panel-inner"><div class="sync-msg">Loading... <div class="loading"></div></div></div>';

    try {
        const response = await fetch(`/api/email/${currentFolder}/${id}`);
        const email = await response.json();

        let attachmentsHtml = '';
        if (email.attachments && email.attachments.length > 0) {
            attachmentsHtml = '<div style="margin-top:12px; padding-top:10px; border-top:1px solid var(--glass-border);">';
            email.attachments.forEach(att => {
                attachmentsHtml += `<span class="attachment-chip">
                    <i class="ri-attachment-line"></i> ${escapeHtml(att.filename)}
                    <span style="opacity:0.5;font-size:0.7em;">(${formatBytes(att.size)})</span>
                </span>`;
            });
            attachmentsHtml += '</div>';
        }

        detailView.innerHTML = `
            <div class="detail-panel-inner">
                <div class="detail-header">
                    <div class="detail-subject">${escapeHtml(email.subject)}</div>
                    <div class="detail-meta">
                        <span>From: <strong>${escapeHtml(email.sender)}</strong></span>
                        <span>${formatDate(email.date)}</span>
                    </div>
                    ${attachmentsHtml}
                </div>
                <div class="detail-body">
                    <iframe class="detail-content-frame" srcdoc="${escapeHtmlAttribute(email.body_html || email.body_text)}"></iframe>
                </div>
            </div>
        `;
    } catch (e) {
        detailView.innerHTML = '<div class="detail-panel-inner"><div class="error-msg">Failed to load email content.</div></div>';
    }
}

function setupModal() {
    const modal = document.getElementById('composeModal');
    const btn = document.getElementById('composeBtn');
    const close = document.getElementById('closeModal');

    btn.onclick = () => { modal.style.display = 'flex'; };
    close.onclick = () => { modal.style.display = 'none'; document.getElementById('composeForm').reset(); };
    window.onclick = (event) => { if (event.target === modal) modal.style.display = 'none'; };
}

function setupCompose() {
    const form = document.getElementById('composeForm');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = 'Sending... <div class="loading"></div>';
        submitBtn.disabled = true;

        try {
            const response = await fetch('/send', { method: 'POST', body: new FormData(form) });
            const result = await response.json();

            if (result.success) {
                alert('Email sent successfully!');
                document.getElementById('composeModal').style.display = 'none';
                form.reset();
                if (currentFolder === 'sent') refreshEmails();
            } else {
                alert('Error: ' + result.message);
            }
        } catch (error) {
            alert('Network error.');
        } finally {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    };
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function escapeHtmlAttribute(text) {
    if (!text) return '';
    return text.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

function formatDate(dateStr) {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    const now = new Date();
    const isToday = d.toDateString() === now.toDateString();
    if (isToday) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const isThisYear = d.getFullYear() === now.getFullYear();
    if (isThisYear) return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatBytes(bytes, decimals = 1) {
    if (!+bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}
