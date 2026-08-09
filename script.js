const scanInput = document.getElementById("scanInput");
const scanButton = document.getElementById("scanButton");
const clearButton = document.getElementById("clearButton");
const results = document.getElementById("resultContent");

scanButton.addEventListener("click", analyzeThreat);

function analyzeThreat() {
    const text = scanInput.value.trim();

    if (text === "") {
        results.innerHTML = `
            <h3>Please enter something to analyze.</h3>
            <p>Paste a suspicious message, email, or URL first.</p>
        `;
        return;
    }

    let score = 0;
    let warnings = [];

    const message = text.toLowerCase();

    // 1. Urgency detection
    const urgencyWords = [
        "urgent",
        "immediately",
        "right now",
        "act now",
        "within 24 hours",
        "limited time",
        "hurry"
    ];

    if (containsAny(message, urgencyWords)) {
        score += 15;

        warnings.push(
            "Urgency or pressure tactics detected"
        );
    }

    // 2. Threat detection
    const threatWords = [
        "suspended",
        "blocked",
        "terminated",
        "legal action",
        "account will be closed",
        "account will be locked"
    ];

    if (containsAny(message, threatWords)) {
        score += 20;

        warnings.push(
            "Threatening or fear-based language detected"
        );
    }

    // 3. Prize / reward scam detection
    const prizeWords = [
        "you won",
        "you have won",
        "winner",
        "congratulations",
        "free iphone",
        "free gift",
        "claim your prize",
        "reward"
    ];

    if (containsAny(message, prizeWords)) {
        score += 20;

        warnings.push(
            "Possible prize or reward scam pattern"
        );
    }

    // 4. Credential detection
    const credentialWords = [
        "password",
        "otp",
        "one time password",
        "verification code",
        "login",
        "verify your account",
        "confirm your identity"
    ];

    if (containsAny(message, credentialWords)) {
        score += 20;

        warnings.push(
            "Possible request for sensitive credentials"
        );
    }

    // 5. Financial information
    const financialWords = [
        "bank account",
        "credit card",
        "debit card",
        "payment",
        "send money",
        "transfer money",
        "banking information"
    ];

    if (containsAny(message, financialWords)) {
        score += 20;

        warnings.push(
            "Possible financial information request"
        );
    }

    // 6. Suspicious URL detection
    const urlPattern = /(https?:\/\/[^\s]+)/gi;
    const urls = text.match(urlPattern);

    if (urls) {

        urls.forEach((url) => {

            // HTTP instead of HTTPS
            if (url.toLowerCase().startsWith("http://")) {
                score += 10;

                warnings.push(
                    "Unencrypted HTTP link detected"
                );
            }

            // URL shorteners
            const shorteners = [
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "is.gd",
                "cutt.ly"
            ];

            if (shorteners.some(domain => url.includes(domain))) {
                score += 20;

                warnings.push(
                    "URL shortening service detected"
                );
            }

            // IP address in URL
            const ipPattern =
                /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/;

            if (ipPattern.test(url)) {
                score += 25;

                warnings.push(
                    "IP address used instead of a normal domain"
                );
            }

            // @ symbol
            if (url.includes("@")) {
                score += 20;

                warnings.push(
                    "Suspicious @ symbol detected in URL"
                );
            }

        });
    }

    // Prevent score from going above 100
    score = Math.min(score, 100);

    // Determine risk level
    let riskLevel;

    if (score >= 70) {
        riskLevel = "HIGH RISK";
    } else if (score >= 35) {
        riskLevel = "SUSPICIOUS";
    } else {
        riskLevel = "LOW RISK";
    }

    // If nothing suspicious was detected
    if (warnings.length === 0) {
        warnings.push(
            "No major suspicious indicators detected"
        );
    }

    displayResults(score, riskLevel, warnings);
}


function containsAny(text, words) {
    return words.some(word => text.includes(word));
}


function displayResults(score, riskLevel, warnings) {

    let riskIcon;

    if (riskLevel === "HIGH RISK") {
        riskIcon = "🔴";
    } else if (riskLevel === "SUSPICIOUS") {
        riskIcon = "🟠";
    } else {
        riskIcon = "🟢";
    }

    const warningHTML = warnings
        .map(warning => `<li>⚠️ ${warning}</li>`)
        .join("");

    let recommendation;

    if (score >= 70) {

        recommendation = `
            <strong>Do not click or respond.</strong>
            Avoid sharing passwords, OTPs, banking details,
            or personal information. Verify the request through
            an official website or application.
        `;

    } else if (score >= 35) {

        recommendation = `
            Be careful before interacting with this content.
            Verify the sender and destination independently.
        `;

    } else {

        recommendation = `
            No major warning signs were detected.
            However, always verify unexpected messages before
            sharing sensitive information.
        `;
    }

    results.innerHTML = `
        <div class="analysis-result">

            <div class="risk-icon">
                ${riskIcon}
            </div>

            <h3>${riskLevel}</h3>

            <div class="score">
                ${score}<span>/100</span>
            </div>

            <h4>Detected Indicators</h4>

            <ul>
                ${warningHTML}
            </ul>

            <div class="recommendation">
                <h4>🛡️ Recommended Action</h4>

                <p>
                    ${recommendation}
                </p>
            </div>

        </div>
    `;
}


clearButton.addEventListener("click", () => {

    scanInput.value = "";

    results.innerHTML = `
        <h3>Security Analysis</h3>
        <p>
            Your analysis will appear here.
        </p>
    `;

});