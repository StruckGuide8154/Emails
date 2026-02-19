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
});

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
    // Update UI
    document.querySelectorAll('.menu-item').forEach(el => el.classList.remove('active'));
    element.classList.add('active');
    document.getElementById('folderTitle').innerText = folder.charAt(0).toUpperCase() + folder.slice(1);

    // Reset state
    currentFolder = folder;
    offset = 0;
    allLoaded = false;
    document.getElementById('emailList').innerHTML = '';

    // Clear detail view
    document.getElementById('emailDetailView').innerHTML = `
        <div style="text-align: center; margin-top: 100px; opacity: 0.5;">
            <i class="ri-mail-open-line" style="font-size: 3rem;"></i>
            <p>Select an email to read</p>
        </div>
    `;

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
        list.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">Syncing secure cache... <div class="loading"></div></div>';
    } else {
        trigger.innerHTML = 'Loading... <div class="loading"></div>';
    }

    try {
        const response = await fetch(`/api/emails/${currentFolder}?offset=${offset}&limit=${limit}`);
        if (response.status === 401) {
            window.location.href = '/';
            return;
        }

        const data = await response.json();

        if (!response.ok || data.error) {
            throw new Error(data.error || 'Failed to load emails');
        }

        const emails = Array.isArray(data) ? data : [];

        if (isInitial) list.innerHTML = '';

        if (emails.length < limit) {
            allLoaded = true;
            trigger.innerHTML = '<span style="font-size: 0.8rem; opacity: 0.5;">No more emails</span>';
        } else {
            trigger.innerHTML = '<span style="font-size: 0.8rem; opacity: 0.5;">Scroll for more</span>';
        }

        if (emails.length === 0 && isInitial) {
            list.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">No emails found.</div>';
        } else {
            emails.forEach(email => {
                const item = document.createElement('div');
                item.className = 'email-item';
                item.onclick = () => loadEmailDetail(email.id, item);
                item.innerHTML = `
                    <div class="email-sender">
                        <span style="font-weight: bold; color: white;">${escapeHtml(email.sender)}</span>
                        <span style="font-size: 0.75rem; opacity: 0.7;">${formatDate(email.date)}</span>
                    </div>
                    <div class="email-subject">${escapeHtml(email.subject)}</div>
                    <div style="color: var(--text-secondary); font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        ${escapeHtml(email.snippet)}
                    </div>
                `;
                list.appendChild(item);
            });
            offset += emails.length;
        }

    } catch (error) {
        console.error(error);
        if (isInitial) list.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--error);">Failed to load emails. Check connection.</div>';
    } finally {
        isLoading = false;
    }
}

async function loadEmailDetail(id, itemElement) {
    // Highlight selected
    document.querySelectorAll('.email-item').forEach(el => el.classList.remove('selected'));
    itemElement.classList.add('selected');

    const detailView = document.getElementById('emailDetailView');
    detailView.style.display = 'block';
    detailView.innerHTML = '<div style="text-align: center; margin-top: 50px;">Loading content... <div class="loading"></div></div>';

    try {
        const response = await fetch(`/api/email/${currentFolder}/${id}`);
        const email = await response.json();

        // Format Attachments
        let attachmentsHtml = '';
        if (email.attachments && email.attachments.length > 0) {
            attachmentsHtml = '<div style="margin-top: 15px; padding-top: 10px; border-top: 1px solid var(--glass-border);">';
            email.attachments.forEach(att => {
                attachmentsHtml += `
                    <span class="attachment-chip">
                        <i class="ri-attachment-line"></i> ${escapeHtml(att.filename)} 
                        <span style="opacity: 0.6; font-size: 0.7em;">(${formatBytes(att.size)})</span>
                    </span>`;
            });
            attachmentsHtml += '</div>';
        }

        detailView.innerHTML = `
            <div class="detail-header">
                <div class="detail-subject">${escapeHtml(email.subject)}</div>
                <div class="detail-meta">
                    <span>From: <strong>${escapeHtml(email.sender)}</strong></span>
                    <span>${formatDate(email.date)}</span>
                </div>
                ${attachmentsHtml}
            </div>
            <div class="detail-body">
                 <!-- Sandboxed iframe for security -->
                 <iframe class="detail-content-frame" srcdoc="${escapeHtmlAttribute(email.body_html || email.body_text)}"></iframe>
            </div>
        `;
    } catch (e) {
        detailView.innerHTML = '<div style="color: var(--error);">Failed to load email content.</div>';
    }
}

function setupModal() {
    const modal = document.getElementById('composeModal');
    const btn = document.getElementById('composeBtn');
    const close = document.getElementById('closeModal');

    btn.onclick = () => {
        modal.style.display = 'flex';
    }

    close.onclick = () => {
        modal.style.display = 'none';
        document.getElementById('composeForm').reset();
    }

    window.onclick = (event) => {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    }
}

function setupCompose() {
    const form = document.getElementById('composeForm');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const submitBtn = form.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = 'Sending... <div class="loading"></div>';
        submitBtn.disabled = true;

        const formData = new FormData(form);

        try {
            const response = await fetch('/send', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (result.success) {
                alert('Email sent successfully!');
                document.getElementById('composeModal').style.display = 'none';
                form.reset();
                if (currentFolder === 'sent') refreshEmails();
            } else {
                alert('Error sending email: ' + result.message);
            }
        } catch (error) {
            alert('Network error occurred.');
        } finally {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }
    };
}

function escapeHtml(text) {
    if (!text) return '';
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function escapeHtmlAttribute(text) {
    if (!text) return '';
    return text.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

function formatDate(dateStr) {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}
