// PHISHIED Real Detection Logic

document.addEventListener('DOMContentLoaded', () => {
    const checkButton = document.getElementById('checkUrlBtn');

    if (checkButton) {
        checkButton.addEventListener('click', performDetection);
    }
});

async function performDetection() {
    const urlInput = document.getElementById('urlInput');
    const resultBox = document.getElementById('resultBox');
    const resultTitle = document.getElementById('resultTitle');
    const resultMessage = document.getElementById('resultMessage');
    const urlFeaturesBody = document.getElementById('urlFeaturesBody');
    const securityFeaturesBody = document.getElementById('securityFeaturesBody');
    const contentFeaturesBody = document.getElementById('contentFeaturesBody');
    const externalIntelSection = document.getElementById('externalIntelSection');
    const externalIntelResult = document.getElementById('externalIntelResult');
    const domainInfoSection = document.getElementById('domainInfoSection');
    const domainInfoBody = document.getElementById('domainInfoBody');
    const checkButton = document.getElementById('checkUrlBtn');

    const url = urlInput.value.trim();

    if (!url) {
        alert("Please enter a valid URL.");
        return;
    }

    // UI Feedback: Loading
    const originalBtnText = checkButton.innerText;
    checkButton.innerText = "Analyzing...";
    checkButton.disabled = true;
    resultBox.style.display = 'none';

    if (urlFeaturesBody) urlFeaturesBody.innerHTML = '';
    if (securityFeaturesBody) securityFeaturesBody.innerHTML = '';
    if (contentFeaturesBody) contentFeaturesBody.innerHTML = '';
    if (externalIntelSection) externalIntelSection.style.display = 'none';
    if (externalIntelResult) externalIntelResult.innerHTML = '';
    if (domainInfoSection) domainInfoSection.style.display = 'none';
    if (domainInfoBody) domainInfoBody.innerHTML = '';

    try {
        const response = await fetch('/api/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (response.ok) {
            // Display Result
            resultBox.style.display = 'block';

            if (data.is_phishing) {
                resultBox.className = "result-box result-phishing alert alert-danger";
                resultTitle.innerText = "⚠ WARNING: PHISHING DETECTED";
                resultMessage.innerText = `This website exhibits high-risk characteristics (Confidence: ${data.confidence}%). Do not visit or enter credentials.`;
            } else {
                resultBox.className = "result-box result-safe alert alert-success";
                resultTitle.innerText = "✅ WEBSITE SEEMS LEGITIMATE";
                resultMessage.innerText = `No major threats detected based on analysis (Confidence: ${data.confidence}%). Proceed with caution.`;
            }

            // Display structured features
            if (data.structured_features) {
                const urlFeatures = data.structured_features.filter(f => f.type === "URL Features");
                const securityFeatures = data.structured_features.filter(f => f.type === "Security Indicators");
                const contentFeatures = data.structured_features.filter(f => f.type === "Content / Behavior Indicators");

                const renderRows = (features) => features.map(feat => `
                    <tr>
                        <td width="70%">${feat.name}</td>
                        <td width="30%" class="fw-bold">${feat.value}</td>
                    </tr>
                `).join("");

                if (urlFeaturesBody) urlFeaturesBody.innerHTML = renderRows(urlFeatures);
                if (securityFeaturesBody) securityFeaturesBody.innerHTML = renderRows(securityFeatures);
                if (contentFeaturesBody) contentFeaturesBody.innerHTML = renderRows(contentFeatures);
            }

            // Display external threat intelligence if present and not skipped
            if (data.external_threat_intel && externalIntelSection && externalIntelResult) {
                const threatData = data.external_threat_intel;
                
                if (threatData.status !== "skipped") {
                    externalIntelSection.style.display = 'block';
                    
                    if (threatData.status === "unsafe") {
                        externalIntelResult.className = "alert mb-0 p-2 alert-danger bg-danger bg-opacity-10 border-danger text-danger";
                        externalIntelResult.innerHTML = `<strong>⚠ THREAT DETECTED:</strong> ${threatData.message}`;
                    } else if (threatData.status === "safe") {
                        externalIntelResult.className = "alert mb-0 p-2 alert-success bg-success bg-opacity-10 border-success text-success";
                        externalIntelResult.innerHTML = `<strong>✓ CLEAR:</strong> ${threatData.message}`;
                    } else {
                        externalIntelResult.className = "alert mb-0 p-2 alert-warning bg-warning bg-opacity-10 border-warning text-dark";
                        externalIntelResult.innerHTML = `<strong>⚠ ERROR:</strong> ${threatData.message}`;
                    }
                }
            }

            // Display Domain Info if available
            if (data.domain_info && domainInfoSection && domainInfoBody) {
                const domainData = data.domain_info;
                domainInfoSection.style.display = 'block';

                if (domainData.success) {
                    let ageWarningHTML = '';
                    if (domainData.is_suspiciously_new) {
                        ageWarningHTML = `<span class="badge bg-danger ms-2" title="Domains less than 30 days old are common in phishing attacks.">⚠ Suspiciously New</span>`;
                    }
                    
                    domainInfoBody.innerHTML = `
                        <tr>
                            <td width="70%">Domain Checked</td>
                            <td width="30%" class="fw-bold">${domainData.domain}</td>
                        </tr>
                        <tr>
                            <td width="70%">Creation Date</td>
                            <td width="30%" class="fw-bold">${domainData.creation_date}</td>
                        </tr>
                        <tr>
                            <td width="70%">Domain Age (Days)</td>
                            <td width="30%" class="fw-bold">
                                ${domainData.age_in_days} ${ageWarningHTML}
                            </td>
                        </tr>
                    `;
                } else {
                    domainInfoBody.innerHTML = `
                        <tr>
                            <td colspan="2" class="text-muted"><i class="fas fa-exclamation-triangle"></i> ${domainData.error}</td>
                        </tr>
                    `;
                }
            }

        } else {
            alert("Error: " + (data.error || "Unknown error occurred"));
        }

    } catch (error) {
        console.error('Error:', error);
        alert("Failed to connect to the detection server. Is Flask running?");
    } finally {
        checkButton.innerText = originalBtnText;
        checkButton.disabled = false;
    }
}
