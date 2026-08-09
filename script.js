const input = document.getElementById("scanInput");
const button = document.getElementById("scanButton");
const result = document.getElementById("resultContent");
const charCount = document.getElementById("charCount");


/* =========================
   SCAM DETECTION RULES
========================= */

const rules = [

    {
        words: [
            "urgent",
            "immediately",
            "act now",
            "within 10 minutes",
            "within 5 minutes",
            "hurry",
            "last chance"
        ],
        name: "Urgency / Pressure",
        icon: "⏰",
        points: 20,
        text: "The message pressures you to act quickly."
    },

    {
        words: [
            "you won",
            "you have won",
            "winner",
            "prize",
            "reward",
            "claim your prize",
            "lottery",
            "free gift"
        ],
        name: "Prize / Reward",
        icon: "🎁",
        points: 25,
        text: "It claims you have won an unexpected reward."
    },

    {
        words: [
            "password",
            "otp",
            "verification code",
            "login",
            "passcode"
        ],
        name: "Credential Request",
        icon: "🔑",
        points: 25,
        text: "It may be asking for sensitive account information."
    },

    {
        words: [
            "click here",
            "click this link",
            "verify now",
            "claim now",
            "open this link"
        ],
        name: "Suspicious Action",
        icon: "🖱️",
        points: 20,
        text: "It encourages you to follow an unverified link."
    },

    {
        words: [
            "bank account",
            "credit card",
            "debit card",
            "send money",
            "payment",
            "account number"
        ],
        name: "Financial Request",
        icon: "💳",
        points: 20,
        text: "The message involves financial information or payment."
    },

    {
        words: [
            "suspended",
            "blocked",
            "account will be closed",
            "legal action",
            "penalty"
        ],
        name: "Threatening Language",
        icon: "🚨",
        points: 20,
        text: "Fear or consequences are used to pressure you."
    }
];


/* =========================
   CHARACTER COUNTER
========================= */

input.addEventListener("input", () => {
    charCount.textContent = input.value.length;
});


/* =========================
   SCAN
========================= */

button.addEventListener("click", scan);

function scan() {

    const text = input.value.trim();

    if (!text) {

        result.innerHTML = `
            <div class="empty">
                <div class="empty-orb">
                    <div>⚠️</div>
                </div>

                <h3>Nothing to scan</h3>

                <p>
                    Paste a message first and we'll check it.
                </p>

                <div class="info-pill">
                    💡 Try one of the sample messages above.
                </div>
            </div>
        `;

        return;
    }


    button.disabled = true;

    button.querySelector(".button-text").textContent =
        "Analyzing message...";

    button.querySelector(".scan-icon").textContent = "⏳";

    document
        .querySelector(".textarea-wrap")
        .classList.add("scanning");


    setTimeout(() => {

        const message = text.toLowerCase();

        let score = 0;
        let detected = [];


        /* RULE CHECK */

        rules.forEach(rule => {

            if (
                rule.words.some(word =>
                    message.includes(word)
                )
            ) {

                score += rule.points;
                detected.push(rule);

            }

        });


        /* URL DETECTION */

        if (/https?:\/\//.test(message)) {

            score += 15;

            detected.push({
                icon: "🔗",
                name: "External Link",
                text: "The message contains an external link."
            });

        }


        /* SHORT URL */

        if (
            message.includes("bit.ly") ||
            message.includes("tinyurl") ||
            message.includes("t.co")
        ) {

            score += 15;

            detected.push({
                icon: "⚠️",
                name: "Shortened URL",
                text: "The destination of this link may be hidden."
            });

        }


        /* PRIZE + URGENCY */

        const prize = detected.some(
            item => item.name === "Prize / Reward"
        );

        const urgency = detected.some(
            item => item.name === "Urgency / Pressure"
        );


        if (prize && urgency) {

            score += 15;

            detected.push({
                icon: "🚩",
                name: "Prize + Urgency",
                text:
                    "An unexpected reward combined with time pressure is a strong scam indicator."
            });

        }


        score = Math.min(score, 100);


        let risk;
        let icon;

        if (score >= 60) {

            risk = "HIGH RISK";
            icon = "🔴";

        } else if (score >= 30) {

            risk = "SUSPICIOUS";
            icon = "🟠";

        } else {

            risk = "LOW RISK";
            icon = "🟢";

        }


        showResult(
            score,
            risk,
            icon,
            detected
        );


        document
            .querySelector(".textarea-wrap")
            .classList.remove("scanning");


        button.disabled = false;

        button.querySelector(".scan-icon").textContent = "⌕";

        button.querySelector(".button-text").textContent =
            "Check this message";

    }, 1100);
}


/* =========================
   SHOW RESULT
========================= */

function showResult(score, risk, icon, detected) {

    recordScan(score, risk);

    let warnings = detected.map((item, index) => {

        return `
            <div
                class="warning"
                style="animation-delay:${index * 100}ms"
            >

                <span>${item.icon}</span>

                <div>
                    <strong>${item.name}</strong>
                    <p>${item.text}</p>
                </div>

            </div>
        `;

    }).join("");


    if (!warnings) {

        warnings = `
            <div class="warning">

                <span>✅</span>

                <div>
                    <strong>No major indicators</strong>

                    <p>
                        No obvious suspicious patterns were detected.
                    </p>
                </div>

            </div>
        `;

    }


    let action;

    if (score >= 60) {

        action =
            "Don't click or respond. Verify the message through an official source.";

    } else if (score >= 30) {

        action =
            "Be cautious. Verify the sender and avoid sharing sensitive information.";

    } else {

        action =
            "No major warning signs detected. Still stay alert with unexpected messages.";

    }


    const riskStyle =
        score >= 60
            ? "background:#ffe7e2;color:#c94f3b;"
            : score >= 30
                ? "background:#fff0d8;color:#b97820;"
                : "background:#eaf7ed;color:#377c4e;";


    result.innerHTML = `

        <div class="analysis">

            <div class="risk-icon">
                ${icon}
            </div>

            <div
                class="risk"
                style="${riskStyle}"
            >
                ${risk}
            </div>

            <div class="score">
                <span id="scoreNumber">0</span>
                <span>/100</span>
            </div>

            <div class="bar">

                <div
                    id="progress"
                    class="progress"
                ></div>

            </div>

            <h3>Why did we flag this?</h3>

            ${warnings}

            <div class="action">

                <h3>🛡️ What should you do?</h3>

                <p>${action}</p>

            </div>

        </div>
    `;


    /* SCORE ANIMATION */

    const scoreNumber =
        document.getElementById("scoreNumber");

    const progress =
        document.getElementById("progress");


    let current = 0;

    const duration = 900;
    const start = performance.now();


    function animateScore(time) {

        const percentage =
            Math.min(
                (time - start) / duration,
                1
            );


        current =
            Math.floor(
                percentage * score
            );


        scoreNumber.textContent =
            current;


        if (percentage < 1) {

            requestAnimationFrame(
                animateScore
            );

        } else {

            scoreNumber.textContent =
                score;

        }
    }


    requestAnimationFrame(
        animateScore
    );


    setTimeout(() => {
        progress.style.width =
            score + "%";
    }, 120);


    result.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
}


/* =========================
   SCAN HISTORY DASHBOARD
========================= */

const scanHistory = [];

function recordScan(score, risk) {

    scanHistory.push({
        score,
        risk,
        time: new Date()
    });

    renderHistory();

}


function renderHistory() {

    const historyChart =
        document.getElementById("historyChart");

    if (!historyChart) return;


    const total = scanHistory.length;

    const flagged = scanHistory.filter(
        entry => entry.score >= 30
    ).length;

    const avg = total
        ? Math.round(
            scanHistory.reduce(
                (sum, entry) => sum + entry.score,
                0
            ) / total
          )
        : 0;

    document.getElementById("statTotal").textContent = total;
    document.getElementById("statThreats").textContent = flagged;
    document.getElementById("statAvg").textContent = avg;


    if (!total) {

        historyChart.innerHTML = `
            <div class="history-empty">
                <div>📈</div>
                <p>Scan a message to start building your history.</p>
            </div>
        `;

        return;

    }


    const recent = scanHistory.slice(-15);

    historyChart.innerHTML = recent.map(entry => {

        const color =
            entry.score >= 60 ? "#e56845" :
            entry.score >= 30 ? "#f0ad4e" :
            "#5bb875";

        const height = Math.max(entry.score, 4);

        const timeLabel = entry.time.toLocaleTimeString(
            [], { hour: "2-digit", minute: "2-digit" }
        );

        return `
            <div class="history-bar-wrap">

                <div
                    class="history-bar"
                    style="height:${height}%;background:${color};"
                ></div>

                <span class="history-bar-score">${entry.score}</span>
                <span class="history-bar-time">${timeLabel}</span>

            </div>
        `;

    }).join("");

    historyChart.scrollLeft = historyChart.scrollWidth;

}


/* =========================
   EXAMPLES
========================= */

function loadExample(type) {

    const examples = {

        prize:
            "Congratulations! You have won Rs. 50,000! Claim your prize within 10 minutes by clicking this link!",

        bank:
            "URGENT! Your bank account will be suspended immediately. Verify your account now and enter your OTP.",

        safe:
            "Hey, are we still meeting at 5 PM today?"

    };


    input.value =
        examples[type];

    charCount.textContent =
        input.value.length;

    input.focus();


    input.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });


    input.style.transform =
        "scale(1.01)";


    setTimeout(() => {
        input.style.transform =
            "";
    }, 250);
}


/* =========================
   SCROLL REVEAL
========================= */

const observer =
    new IntersectionObserver(
        entries => {

            entries.forEach(entry => {

                if (entry.isIntersecting) {

                    entry.target.classList.add(
                        "visible"
                    );

                    observer.unobserve(
                        entry.target
                    );

                }

            });

        },
        {
            threshold: .12
        }
    );


document
    .querySelectorAll(".reveal")
    .forEach(element => {

        observer.observe(element);

    });


/* =========================
   NAVBAR
========================= */

window.addEventListener("scroll", () => {

    const navbar =
        document.getElementById("navbar");


    if (window.scrollY > 30) {

        navbar.classList.add(
            "scrolled"
        );

    } else {

        navbar.classList.remove(
            "scrolled"
        );

    }

});


/* =========================
   3D TILT
========================= */

document
    .querySelectorAll(".tilt")
    .forEach(card => {

        card.addEventListener(
            "mousemove",
            event => {

                if (window.innerWidth < 850)
                    return;


                const rect =
                    card.getBoundingClientRect();


                const x =
                    event.clientX -
                    rect.left;


                const y =
                    event.clientY -
                    rect.top;


                const centerX =
                    rect.width / 2;


                const centerY =
                    rect.height / 2;


                const rotateX =
                    ((y - centerY) /
                        centerY) * -3;


                const rotateY =
                    ((x - centerX) /
                        centerX) * 3;


                card.style.transform =
                    `
                    perspective(1000px)
                    rotateX(${rotateX}deg)
                    rotateY(${rotateY}deg)
                    translateY(-5px)
                    `;
            }
        );


        card.addEventListener(
            "mouseleave",
            () => {

                card.style.transform =
                    "";

            }
        );

    });


/* =========================
   HERO PARALLAX
========================= */

const heroVisual =
    document.querySelector(
        ".hero-visual"
    );


if (heroVisual) {

    document.addEventListener(
        "mousemove",
        event => {

            if (window.innerWidth < 900)
                return;


            const x =
                (window.innerWidth / 2 -
                    event.clientX) / 90;


            const y =
                (window.innerHeight / 2 -
                    event.clientY) / 90;


            heroVisual.style.marginLeft =
                `${x}px`;

            heroVisual.style.marginTop =
                `${y}px`;

        }
    );

}


/* =========================
   KEYBOARD SHORTCUT
========================= */

document.addEventListener(
    "keydown",
    event => {

        if (
            event.ctrlKey &&
            event.key === "Enter"
        ) {

            scan();

        }

    }

);