document.addEventListener('DOMContentLoaded', () => {
    // --- Navbar & Scroll Animations ---
    const navbar = document.querySelector('.navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            if (window.scrollY > 50) navbar.classList.add('scrolled');
            else navbar.classList.remove('scrolled');
        });
    }

    const observerOptions = { threshold: 0.1 };
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
                if (entry.target.classList.contains('stat-item')) {
                    animateStatsValue(entry.target.querySelector('.count'));
                }
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    document.querySelectorAll('.reveal').forEach(el => observer.observe(el));

    function animateStatsValue(obj) {
        if (!obj) return;
        const start = 0;
        const end = parseInt(obj.getAttribute('data-target'));
        if (isNaN(end)) return;
        const duration = 2000;
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start).toLocaleString();
            if (progress < 1) window.requestAnimationFrame(step);
            else obj.innerHTML = end.toLocaleString() + (obj.dataset.plus || '');
        };
        window.requestAnimationFrame(step);
    }

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                window.scrollTo({ top: target.offsetTop - 80, behavior: 'smooth' });
            }
        });
    });

    // --- AI Scanner Logic ---
    const analyzeForm = document.getElementById('analyzeForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const senderInput = document.getElementById('sender_email');
    const contentInput = document.getElementById('message_content');
    const resultSection = document.getElementById('resultSection');
    
    // UI Elements for display
    const statusBadge = document.getElementById('status-badge');
    const scoreValue = document.getElementById('score-value');
    const riskProgress = document.getElementById('risk-progress');
    const confidenceValue = document.getElementById('confidence-value');
    const highlightedTextEl = document.getElementById('highlighted-text');
    const reasonsList = document.getElementById('reasons-list');
    const detectedUrlsBox = document.getElementById('detected-urls');
    const urlList = document.getElementById('url-list');
    const spamSlot = document.getElementById('similar-spam-slot');

    const explanationToggle = document.getElementById('explanation-toggle');
    const explanationContent = document.getElementById('explanation-content');

    if (explanationToggle && explanationContent) {
        explanationToggle.addEventListener('click', () => {
            const icon = explanationToggle.querySelector('.fa-chevron-down');
            if (explanationContent.style.display === 'none') {
                explanationContent.style.display = 'block';
                if (icon) icon.style.transform = 'rotate(180deg)';
            } else {
                explanationContent.style.display = 'none';
                if (icon) icon.style.transform = 'rotate(0deg)';
            }
        });
        // Set initial state
        explanationContent.style.display = 'none';
    }

    if (analyzeForm && analyzeBtn) {
        analyzeForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            const content = contentInput.value.trim();
            const sender = senderInput ? senderInput.value.trim() : '';

            if (!content) {
                showToast('Please enter a message to analyze.', 'danger');
                return;
            }

            // Loading State
            analyzeBtn.innerHTML = '<span class="spinner"></span> Analyzing Threat...';
            analyzeBtn.disabled = true;

            fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: content, sender_email: sender })
            })
            .then(res => res.json())
            .then(data => {
                analyzeBtn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Run AI Analysis';
                analyzeBtn.disabled = false;

                if (data.error) {
                    showToast('Error: ' + data.error, 'danger');
                    return;
                }

                renderResults(data, content);
                showToast(data.status === 'phishing' ? '🚨 Phishing Detected!' : '✅ Message Appears Safe', data.status === 'phishing' ? 'danger' : 'success');
            })
            .catch(err => {
                analyzeBtn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Run AI Analysis';
                analyzeBtn.disabled = false;
                showToast('Connection error during analysis.', 'danger');
            });
        });
    }

    function renderResults(data, originalText) {
        resultSection.style.display = 'block';
        
        // Status
        if (data.status === 'phishing') {
            statusBadge.innerHTML = 'PHISHING';
            statusBadge.style.background = 'var(--danger)';
            statusBadge.style.color = 'white';
        } else {
            statusBadge.innerHTML = 'SAFE';
            statusBadge.style.background = 'var(--success)';
            statusBadge.style.color = 'white';
        }
        statusBadge.style.padding = '0.4rem 1rem';
        statusBadge.style.borderRadius = '20px';
        statusBadge.style.fontSize = '0.75rem';
        statusBadge.style.fontWeight = 'bold';

        // Animate Score
        animateCounter(scoreValue, 0, data.risk_score, 1000, '%');
        animateCounter(confidenceValue, 0, data.confidence || 0, 1000, '%');

        // Risk Meter
        if (riskProgress) {
            const circumference = 2 * Math.PI * 45;
            const offset = circumference - (data.risk_score / 100) * circumference;
            riskProgress.style.stroke = data.status === 'phishing' ? 'var(--danger)' : 'var(--success)';
            riskProgress.style.strokeDashoffset = offset;
        }

        // Highlights
        if (data.highlights && highlightedTextEl) {
            let processed = originalText;
            const susp = data.highlights.suspicious || [];
            const trust = data.highlights.trusted || [];

            susp.sort((a,b) => b.length - a.length).forEach(word => {
                const regex = new RegExp(`(${escapeRegExp(word)})`, 'gi');
                processed = processed.replace(regex, '<span style="color: var(--danger); font-weight: 700; background: rgba(239, 68, 68, 0.1); border-bottom: 2px solid var(--danger); padding: 0 2px;">$1</span>');
            });

            trust.sort((a,b) => b.length - a.length).forEach(word => {
                const regex = new RegExp(`(${escapeRegExp(word)})`, 'gi');
                processed = processed.replace(regex, '<span style="color: var(--success); font-weight: 700; background: rgba(34, 197, 94, 0.1); border-bottom: 2px solid var(--success); padding: 0 2px;">$1</span>');
            });

            highlightedTextEl.innerHTML = processed;
        }

        // Reasons
        reasonsList.innerHTML = '';
        (data.reasons || []).forEach(r => {
            const li = document.createElement('li');
            li.style.display = 'flex';
            li.style.gap = '1rem';
            li.style.padding = '1rem';
            li.style.background = 'var(--bg-main)';
            li.style.borderRadius = '12px';
            li.style.borderLeft = `4px solid ${r.isWarning ? 'var(--danger)' : 'var(--success)'}`;
            
            li.innerHTML = `
                <div style="font-size: 1.25rem; color: ${r.isWarning ? 'var(--danger)' : 'var(--success)'};">
                    <i class="fa-solid ${r.isWarning ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i>
                </div>
                <div>
                    <div style="font-weight: 700; font-size: 0.95rem; margin-bottom: 0.2rem;">${r.text}</div>
                    <div style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.5;">${r.explanation}</div>
                </div>
            `;
            reasonsList.appendChild(li);
        });

        // URLs
        if (data.reasons && data.reasons.some(r => r.category === 'urls')) {
            detectedUrlsBox.style.display = 'block';
            // Simple extraction for demo:
            const urls = originalText.match(/https?:\/\/[^\s]+/g) || [];
            urlList.innerHTML = urls.map(u => `<div style="margin-bottom: 0.5rem;"><i class="fa-solid fa-link"></i> ${u}</div>`).join('');
        } else {
            detectedUrlsBox.style.display = 'none';
        }

        // Similar Spam
        if (data.similar_spam && data.similar_spam.length > 0 && spamSlot) {
            spamSlot.innerHTML = `<h4 style="margin-bottom: 1.5rem;"><i class="fa-solid fa-database"></i> Matching Threat Patterns</h4>`;
            data.similar_spam.forEach(s => {
                spamSlot.innerHTML += `
                    <div style="background: var(--bg-main); padding: 1rem; border-radius: 12px; margin-bottom: 1rem; border: 1px solid var(--border-color);">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                            <span style="font-weight: 600; font-size: 0.9rem;">Similarity Match</span>
                            <span style="color: var(--danger); font-weight: 800;">${s.score}%</span>
                        </div>
                        <div style="width: 100%; height: 4px; background: var(--bg-secondary); border-radius: 2px;">
                            <div style="width: ${s.score}%; height: 100%; background: var(--danger); border-radius: 2px;"></div>
                        </div>
                        <p style="margin-top: 0.8rem; font-size: 0.85rem; color: var(--text-muted); font-style: italic;">"${s.preview}..."</p>
                    </div>
                `;
            });
        } else if (spamSlot) {
            spamSlot.innerHTML = '';
        }

        // Scroll
        setTimeout(() => {
            resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 300);
    }

    function animateCounter(el, start, end, duration, suffix = '') {
        if (!el) return;
        let startTs = null;
        const step = (ts) => {
            if (!startTs) startTs = ts;
            const progress = Math.min((ts - startTs) / duration, 1);
            el.innerHTML = Math.floor(progress * (end - start) + start) + suffix;
            if (progress < 1) window.requestAnimationFrame(step);
        };
        window.requestAnimationFrame(step);
    }

    function escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
});
