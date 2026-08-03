const API_URL = 'https://best-remaining-reply-referring.trycloudflare.com/api';
let trendChart = null;
let idToken = null;

// Navigation Logic
const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');
const pageTitle = document.getElementById('page-title');
const navTriggers = document.querySelectorAll('.nav-trigger');

function switchView(targetId) {
    views.forEach(v => v.classList.remove('active'));
    document.getElementById(targetId).classList.add('active');
    
    navItems.forEach(n => {
        n.classList.remove('active');
        if (n.dataset.target === targetId) {
            n.classList.add('active');
            pageTitle.textContent = n.textContent.trim();
        }
    });

    if(targetId === 'dashboard-view') {
        fetchStats();
        fetchHistoryForChart();
    }
    if(targetId === 'history-view') fetchHistory();
}

navItems.forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        switchView(item.dataset.target);
    });
});

navTriggers.forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.target));
});

// Scanner Logic
const form = document.getElementById('analyze-form');
const analyzeBtn = document.getElementById('analyze-btn');
const emptyState = document.getElementById('empty-state');
const resultContent = document.getElementById('result-content');

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const sender = document.getElementById('sender').value;
    const subject = document.getElementById('subject').value;
    const body = document.getElementById('body').value;
    if (!body) return;

    analyzeBtn.disabled = true;
    analyzeBtn.querySelector('.btn-text').classList.add('hidden');
    analyzeBtn.querySelector('.spinner').classList.remove('hidden');

    try {
        const web3Enabled = localStorage.getItem('web3_defense_enabled') === 'true';
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${idToken}`
            },
            body: JSON.stringify({ sender, subject, body, web3_enabled: web3Enabled })
        });
        const data = await response.json();
        if (data.status === 'success') {
            renderResult(data, body);
        }
    } catch (err) {
        alert("Failed to connect to backend server.");
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.querySelector('.btn-text').classList.remove('hidden');
        analyzeBtn.querySelector('.spinner').classList.add('hidden');
    }
});

function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag]));
}

function renderResult(data, originalBody) {
    emptyState.classList.add('hidden');
    resultContent.classList.remove('hidden');
    
    const isPhishing = data.prediction === 'phishing';
    const isDrainer = data.prediction === 'drainer';
    const confPercent = (data.confidence * 100).toFixed(1);
    
    const banner = document.getElementById('verdict-banner');
    const icon = document.getElementById('verdict-icon');
    const text = document.getElementById('verdict-text');
    const contentBox = document.getElementById('result-content');
    const web3Block = document.getElementById('web3-block-state');
    const scoreSection = document.getElementById('score-section');
    const xaiBox = document.getElementById('xai-box');
    const indicatorsBox = document.getElementById('indicators-box');
    
    // Reset displays
    banner.classList.remove('hidden');
    scoreSection.classList.remove('hidden');
    xaiBox.classList.remove('hidden');
    indicatorsBox.classList.remove('hidden');
    web3Block.classList.add('hidden');
    
    if (isDrainer) {
        banner.classList.add('hidden');
        scoreSection.classList.add('hidden');
        indicatorsBox.classList.add('hidden');
        
        web3Block.classList.remove('hidden');
        contentBox.className = 'result-content verdict-danger';
        
        document.getElementById('xai-text').innerHTML = `<span style="color:#ef4444; font-weight:bold;">🚨 CRITICAL: The system simulated the transaction and detected malicious smart contract opcodes (e.g., setApprovalForAll) attempting to transfer assets.</span><br><br><span style="color:#94a3b8; word-break: break-all;">Target payload blocked: ${escapeHTML(originalBody)}</span>`;
        return;
    }
    
    banner.className = `verdict-banner ${isPhishing ? 'verdict-danger' : 'verdict-safe'}`;
    contentBox.className = `result-content ${isPhishing ? 'verdict-danger' : 'verdict-safe'}`;
    
    icon.className = isPhishing ? 'fa-solid fa-shield-xmark' : 'fa-solid fa-shield-check';
    text.textContent = isPhishing ? 'Phishing Threat Detected' : 'Clean & Safe';
    
    document.getElementById('confidence-val').textContent = `${confPercent}%`;
    setTimeout(() => {
        document.getElementById('confidence-bar').style.width = `${confPercent}%`;
    }, 50);

    const ul = document.getElementById('indicators-list');
    ul.innerHTML = '';
    data.indicators.forEach(ind => {
        const li = document.createElement('li');
        li.textContent = ind;
        ul.appendChild(li);
    });

    let markedBody = escapeHTML(originalBody);
    if(data.highlights && data.highlights.length > 0) {
        data.highlights.forEach(word => {
            if(!word) return;
            const safeWord = escapeHTML(word);
            const regex = new RegExp(`(${safeWord})`, 'gi');
            markedBody = markedBody.replace(regex, `<span class="hl-danger">$1</span>`);
        });
    }
    
    if(!isPhishing && data.highlights.length === 0) {
        markedBody = `<span style="color:#10b981">✓ No suspicious artifacts detected in payload.</span>\n\n` + markedBody;
    }

    document.getElementById('xai-text').innerHTML = markedBody;

    // SSL Handling
    const sslBox = document.getElementById('ssl-cert-box');
    if (data.ssl_cert) {
        sslBox.classList.remove('hidden');
        document.getElementById('ssl-subject').textContent = data.ssl_cert.subject || 'Unknown';
        document.getElementById('ssl-issuer').textContent = data.ssl_cert.issuer || 'Unknown';
        document.getElementById('ssl-expires').textContent = data.ssl_cert.expires || 'Unknown';
        
        const dlBtn = document.getElementById('download-pem-btn');
        dlBtn.onclick = () => {
            const blob = new Blob([data.ssl_cert.pem], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            const subjectSafe = (data.ssl_cert.subject || 'cert').replace(/[^a-z0-9]/gi, '_').toLowerCase();
            a.download = `${subjectSafe}.pem`;
            a.click();
            window.URL.revokeObjectURL(url);
        };
    } else {
        if(sslBox) sslBox.classList.add('hidden');
    }
}

// Fetch Stats
async function fetchStats() {
    try {
        const res = await fetch(`${API_URL}/stats`, { headers: { 'Authorization': `Bearer ${idToken}` }});
        const data = await res.json();
        document.getElementById('stat-total').textContent = data.total_scans;
        document.getElementById('stat-safe').textContent = data.safe_emails;
        document.getElementById('stat-threats').textContent = data.threats_blocked;
    } catch(e) {}
}

// Fetch History for Data Table
async function fetchHistory() {
    try {
        const res = await fetch(`${API_URL}/history`, { headers: { 'Authorization': `Bearer ${idToken}` }});
        const data = await res.json();
        const tbody = document.getElementById('history-tbody');
        tbody.innerHTML = '';
        
        data.forEach(row => {
            const tr = document.createElement('tr');
            const date = new Date(row.timestamp).toLocaleString();
            const badgeCls = row.prediction === 'phishing' ? 'badge-phishing' : 'badge-legit';
            const badgeTxt = row.prediction.toUpperCase();
            
            tr.innerHTML = `
                <td>${date}</td>
                <td>${escapeHTML(row.sender || 'N/A')}</td>
                <td><strong>${escapeHTML(row.subject)}</strong></td>
                <td><span class="badge-status ${badgeCls}">${badgeTxt}</span></td>
                <td>${(row.confidence * 100).toFixed(1)}%</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {}
}

// Fetch History for Chart
async function fetchHistoryForChart() {
    try {
        const res = await fetch(`${API_URL}/history`, { headers: { 'Authorization': `Bearer ${idToken}` }});
        const data = await res.json();
        
        // aggregate by simple dates (limit to last 10)
        let labels = [];
        let safeData = [];
        let threatData = [];

        // Just mocking the timeline with indexes since it's local test data
        data.reverse().forEach((row, i) => {
            labels.push(`Scan ${i+1}`);
            if(row.prediction === 'phishing') {
                threatData.push(1);
                safeData.push(0);
            } else {
                threatData.push(0);
                safeData.push(1);
            }
        });

        const ctx = document.getElementById('threatChart').getContext('2d');
        if(trendChart) trendChart.destroy();
        
        trendChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Safe',
                        data: safeData,
                        backgroundColor: '#10b981'
                    },
                    {
                        label: 'Threats',
                        data: threatData,
                        backgroundColor: '#ef4444'
                    }
                ]
            },
            options: {
                responsive: true,
                scales: {
                    x: { stacked: true, ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                    y: { stacked: true, ticks: { color: '#94a3b8', stepSize: 1 }, grid: { color: '#334155' } }
                },
                plugins: {
                    legend: { labels: { color: '#f8fafc' } }
                }
            }
        });
    } catch(e) {}
}

document.getElementById('refresh-history').addEventListener('click', fetchHistory);

// Web3 Settings Logic
const web3Toggle = document.getElementById('web3-toggle');
const permissionModal = document.getElementById('permission-modal');
const btnGrant = document.getElementById('btn-grant-permission');
const btnCancel = document.getElementById('btn-cancel-permission');

if (web3Toggle) {
    web3Toggle.checked = localStorage.getItem('web3_defense_enabled') === 'true';

    web3Toggle.addEventListener('change', (e) => {
        if (e.target.checked) {
            e.target.checked = false; 
            permissionModal.classList.remove('hidden');
        } else {
            localStorage.setItem('web3_defense_enabled', 'false');
        }
    });

    btnCancel.addEventListener('click', () => {
        permissionModal.classList.add('hidden');
    });

    btnGrant.addEventListener('click', () => {
        localStorage.setItem('web3_defense_enabled', 'true');
        web3Toggle.checked = true;
        permissionModal.classList.add('hidden');
    });
}

// Auth Logic
document.addEventListener('DOMContentLoaded', () => {
    const { auth, signInWithPopup, GoogleAuthProvider, onAuthStateChanged, signOut } = window.firebaseAuth;
    const provider = new GoogleAuthProvider();

    document.getElementById('btn-login').addEventListener('click', async () => {
        const errorDiv = document.getElementById('login-error');
        errorDiv.classList.add('hidden');
        errorDiv.textContent = '';
        try {
            await signInWithPopup(auth, provider);
        } catch (error) {
            console.error(error);
            errorDiv.classList.remove('hidden');
            if (error.code === 'auth/configuration-not-found' || error.code === 'auth/operation-not-allowed') {
                errorDiv.innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="margin-right:8px;"></i> Google Sign-In is not enabled on this Firebase project. Please enable it in the Firebase Console.';
            } else if (error.code !== 'auth/popup-closed-by-user' && error.code !== 'auth/cancelled-popup-request') {
                errorDiv.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="margin-right:8px;"></i> Login failed: ${error.message}`;
            }
        }
    });

    document.getElementById('btn-logout').addEventListener('click', () => {
        signOut(auth);
    });

    onAuthStateChanged(auth, async (user) => {
        if (user) {
            idToken = await user.getIdToken();
            document.getElementById('login-overlay').classList.add('hidden');
            document.getElementById('app-container').classList.remove('hidden');
            
            document.getElementById('user-name').textContent = user.displayName || 'User';
            document.getElementById('user-email').textContent = user.email;
            document.getElementById('user-avatar').textContent = (user.displayName || 'U')[0].toUpperCase();
            
            // Load user data
            fetchStats();
            fetchHistoryForChart();
            if(document.getElementById('history-view').classList.contains('active')) fetchHistory();
        } else {
            idToken = null;
            document.getElementById('login-overlay').classList.remove('hidden');
            document.getElementById('app-container').classList.add('hidden');
        }
    });
});
