document.addEventListener('DOMContentLoaded', () => {
    loadEmails();
    setupModal();
    setupCompose();
});

function setupModal() {
    const modal = document.getElementById('composeModal');
    const btn = document.getElementById('composeBtn');
    const close = document.getElementById('closeModal');

    btn.onclick = () => {
        modal.style.display = 'flex';
    }

    close.onclick = () => {
        modal.style.display = 'none';
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

        const data = {
            to: document.getElementById('toEmail').value,
            subject: document.getElementById('subject').value,
            body: document.getElementById('body').value
        };

        try {
            const response = await fetch('/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (result.success) {
                alert('Email sent successfully!');
                document.getElementById('composeModal').style.display = 'none';
                form.reset();
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

async function loadEmails() {
    const list = document.getElementById('emailList');
    list.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">Syncing with Gmail... <div class="loading"></div></div>';

    try {
        const response = await fetch('/api/emails');
        if (response.status === 401) {
            window.location.href = '/';
            return;
        }
        
        const emails = await response.json();
        
        if (emails.length === 0) {
            list.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">No emails found.</div>';
            return;
        }

        list.innerHTML = '';
        emails.forEach(email => {
            const item = document.createElement('div');
            item.className = 'email-item';
            item.innerHTML = `
                <div class="email-sender">
                    <span>${escapeHtml(email.sender)}</span>
                    <span style="font-size: 0.8rem; opacity: 0.7;">${email.date ? email.date.substring(0, 16) : ''}</span>
                </div>
                <div class="email-subject">${escapeHtml(email.subject)}</div>
                <div style="color: var(--text-secondary); font-size: 0.9rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    ${escapeHtml(email.snippet)}
                </div>
            `;
            list.appendChild(item);
        });

    } catch (error) {
        list.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--error);">Failed to load emails. Check connection.</div>';
    }
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
