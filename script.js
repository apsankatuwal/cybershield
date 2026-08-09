const scanInput = document.getElementById("scanInput");
const scanButton = document.getElementById("scanButton");
const results = document.getElementById("resultContent");

scanButton.addEventListener("click", analyzeThreat);

function analyzeThreat() {
    const text = scanInput.value.trim();

    if (!text) {
        results.innerHTML = `
            <div class="empty-result">
                <div class="empty-icon">⚠️</div>
                <h3>Nothing to Analyze</h3>
                <p>Please paste a suspicious message, email, or URL first.</p>
            </div>
        `;
        return;
    }

    const message = text.toLowerCase();

    let score = 0;
    const warnings = [];

    // -----------------------------
    // 1. URGENCY / PRESSURE
    // -----------------------------

    const urgencyWords = [
        "urgent",
        "immediately",
        "right now",
        "act now",
        "within 24 hours",
        "limited time",
        "hurry",
        "last chance"
    ];

    if (containsAny(message, urgencyWords)) {
        score += 12;

        warnings.push({
            icon: "⏰",
            title: "Urgency detected",
            description: "The message pressures you to act quickly."
        });
    }

    // -----------------------------
    // 2. THREATS
    // -----------------------------

    const threatWords = [
        "suspended",
        "blocked",
        "terminated",
        "legal action",
        "account will be closed",
        "account will be locked",
        "police",
        "arrest"
    ];

    if (containsAny(message, threatWords)) {
        score += 18;

        warnings.push({
            icon: "🚨",
            title: "Threatening language",
            description: "Fear or consequences are being used to pressure you."
        });
    }

    // -----------------------------
    // 3. PRIZE / REWARD SCAMS
    // -----------------------------

    const prizeWords = [
        "you won",
        "you have won",
        "winner",
        "congratulations",
        "free iphone",
        "free gift",
        "claim your prize",
        "reward",
        "lottery"
    ];

    if (containsAny(message, prizeWords)) {
        score += 18;

        warnings.push({
            icon: "🎁",
            title: "Prize or reward pattern",
            description: "The message contains language commonly used in reward scams."
        });
    }

    // -----------------------------
    // 4. CREDENTIAL REQUESTS
    // -----------------------------

    const credentialWords = [
        "password",
        "otp",
        "one time password",
        "verification code",
        "login",
        "verify your account",
        "confirm your identity",
        "security code"
    ];

    if (containsAny(message, credentialWords)) {
        score += 18;

        warnings.push({
            icon: "🔑",
            title: "Credential request",
            description: "The message may be trying to obtain sensitive login information."
        });
    }

    // -----------------------------
    // 5. FINANCIAL REQUESTS
    // -----------------------------

    const financialWords = [
        "bank account",
        "credit card",
        "debit card",
        "payment",
        "send money",
        "transfer money",
        "banking information",
        "account number"
    ];

    if (containsAny(message, financialWords)) {
        score += 18;

        warnings.push({
            icon: "💳",
            title: "Financial information request",
            description: "The message references money or sensitive financial information."
        });
    }

    // -----------------------------
    // 6. URL ANALYSIS
    // -----------------------------

    const urlPattern = /(https?:\/\/[^\s]+)/gi;
    const urls = text.match(urlPattern);

    if (urls) {
        urls.forEach((url) => {

            const cleanUrl = url.replace(/[.,!?)]$/, "");
            const lowerUrl = cleanUrl.toLowerCase();

            // HTTP
            if (lowerUrl.startsWith("http://")) {
                score += 8;

                warnings.push({
                    icon: "🔓",
                    title: "Unencrypted HTTP link",
                    description: "The link does not use HTTPS encryption."
                });
            }

            // URL shorteners
            const shorteners = [
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "is.gd",
                "cutt.ly",
                "shorturl.at"
            ];

            if (shorteners.some(domain => lowerUrl.includes(domain))) {
                score += 15;

                warnings.push({
                    icon: "🔗",
                    title: "Shortened URL detected",
                    description: "Shortened links can hide the final destination."
                });
            }

            // IP address
            const ipPattern =
                /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/;

            if (ipPattern.test(cleanUrl)) {
                score += 20;

                warnings.push({
                    icon: "🌐",
                    title: "IP address used as destination",
                    description: "The link uses an IP address instead of a normal domain."
                });
            }

            // @ symbol
            if (cleanUrl.includes("@")) {
                score += 15;

                warnings.push({
                    icon: "⚠️",
                    title: "Suspicious URL structure",
                    description: "The @ symbol can be abused to disguise a destination."
                });
            }

            // Very long URL
            if (cleanUrl.length > 100) {
                score += 5;

                warnings.push({
                    icon: "📏",
                    title: "Unusually long URL",
                    description: "Very long URLs can sometimes be used to hide suspicious destinations."
                });
            }
        });
    }

    // -----------------------------
    // FINAL SCORE
    // -----------------------------

    score = Math.min(score, 100);

    let riskLevel;
    let riskIcon;

    if (score >= 75) {
        riskLevel = "HIGH RISK";
        riskIcon = "🔴";
    } else if (score >= 40) {
        riskLevel = "SUSPICIOUS";
        riskIcon = "🟠";
    } else {
        riskLevel = "LOW RISK";
        riskIcon = "🟢";
    }

    // -----------------------------
    // NO WARNINGS
    // -----------------------------

    if (warnings.length === 0) {
        warnings.push({
            icon: "✅",
            title: "No major warning signs detected",
            description: "CyberShield did not find obvious phishing indicators."
        });
    }

    displayResults(score, riskLevel, riskIcon, warnings);
}


// Check whether any word exists in the message
function containsAny(text, words) {
    return words.some(word => text.includes(word));
}


// Display the result
function displayResults(score, riskLevel, riskIcon, warnings) {

    const warningHTML = warnings
        .map(warning => `
            <div class="warning-item">
                <span class="warning-icon">${warning.icon}</span>

                <div>
                    <strong>${warning.title}</strong>
                    <p>${warning.description}</p>
                </div>
            </div>
        `)
        .join("");

    let recommendation;

    if (score >= 75) {

        recommendation = `
            <strong>Do not click or respond.</strong>
            Do not provide passwords, OTPs, banking details,
            or personal information. Verify the request through
            an official website or application.
        `;

    } else if (score >= 40) {

        recommendation = `
            Proceed with caution. Verify the sender and destination
            independently before clicking links or sharing information.
        `;

    } else {

        recommendation = `
            No major warning signs were detected. However, always
            verify unexpected messages before sharing sensitive information.
        `;
    }

    results.innerHTML = `
        <div class="analysis-result">

            <div class="risk-icon">
                ${riskIcon}
            </div>

            <div class="risk-label">
                ${riskLevel}
            </div>

            <div class="score">
                ${score}<span>/100</span>
            </div>

            <div class="score-bar">
                <div
                    class="score-progress"
                    style="width: ${score}%"
                ></div>
            </div>

            <h3>Detected Indicators</h3>

            <div class="warning-list">
                ${warningHTML}
            </div>

            <div class="recommendation">
                <h3>🛡️ Recommended Action</h3>

                <p>
                    ${recommendation}
                </p>
            </div>

        </div>
    `;
}