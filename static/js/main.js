/**
 * PhishGuard — Frontend Interactions
 * ====================================
 * Handles form submission, API calls, animated score ring,
 * and result rendering. No URLs are stored client-side.
 */

"use strict";

// ── DOM references ──────────────────────────────────────────────────────────
const form          = document.getElementById("url-form");
const urlInput      = document.getElementById("url-input");
const btnAnalyse    = document.getElementById("btn-analyse");
const btnText       = btnAnalyse.querySelector(".btn-text");
const btnSpinner    = btnAnalyse.querySelector(".btn-spinner");
const inputError    = document.getElementById("input-error");

const resultPanel   = document.getElementById("result-panel");
const scoreValue    = document.getElementById("score-value");
const ringFill      = document.getElementById("ring-fill");
const verdictBadge  = document.getElementById("verdict-badge");
const verdictUrl    = document.getElementById("verdict-url");

const flagsList     = document.getElementById("flags-list");
const noFlags       = document.getElementById("no-flags");
const flagsSection  = document.getElementById("flags-section");

const improvList    = document.getElementById("improvements-list");
const noImprov      = document.getElementById("no-improvements");

// SVG ring circumference: 2π × r = 2π × 50 ≈ 314.16
const CIRCUMFERENCE = 2 * Math.PI * 50;

// ── Utility: validate URL format client-side (light check only) ─────────────
function looksLikeUrl(value) {
  return value.trim().length > 3 && /\S+\.\S+/.test(value.trim());
}

// ── UI helpers ───────────────────────────────────────────────────────────────
function setLoading(on) {
  btnAnalyse.disabled = on;
  btnText.hidden      = on;
  btnSpinner.hidden   = !on;
  urlInput.disabled   = on;
}

function showError(msg) {
  inputError.textContent = msg;
  urlInput.classList.add("input-error-state");
}

function clearError() {
  inputError.textContent = "";
  urlInput.classList.remove("input-error-state");
}

/**
 * Animate the SVG ring from its current dashoffset to the target value.
 * @param {number} score  0–100
 */
function animateRing(score) {
  const targetOffset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
  // Use requestAnimationFrame for smooth start
  requestAnimationFrame(() => {
    ringFill.style.strokeDashoffset = targetOffset;
  });
}

/**
 * Animate the score counter from 0 to target.
 * @param {number} target
 */
function animateCounter(target) {
  const duration = 700; // ms
  const start    = performance.now();
  const from     = parseInt(scoreValue.textContent, 10) || 0;

  function step(now) {
    const elapsed  = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // Ease-out cubic
    const eased    = 1 - Math.pow(1 - progress, 3);
    scoreValue.textContent = Math.round(from + (target - from) * eased);
    if (progress < 1) requestAnimationFrame(step);
    else scoreValue.textContent = target;
  }
  requestAnimationFrame(step);
}

// ── Render result ────────────────────────────────────────────────────────────
function renderResult(data) {
  const { score, verdict, band, url, flags, improvements } = data;

  // Panel visibility + band class
  resultPanel.hidden = false;
  resultPanel.className = "result-panel band-" + band;

  // Score ring + counter
  animateRing(score);
  animateCounter(score);

  // Verdict
  verdictBadge.textContent = verdict;
  verdictBadge.className   = "verdict-badge " + band;
  verdictUrl.textContent   = url;

  // Flags
  flagsList.innerHTML = "";
  if (flags && flags.length) {
    flags.forEach(f => {
      const li = document.createElement("li");
      li.textContent = f;
      flagsList.appendChild(li);
    });
    noFlags.hidden = true;
    flagsList.hidden = false;
  } else {
    noFlags.hidden = false;
    flagsList.hidden = true;
  }

  // Improvements
  improvList.innerHTML = "";
  if (improvements && improvements.length) {
    improvements.forEach(imp => {
      const li = document.createElement("li");
      li.textContent = imp;
      improvList.appendChild(li);
    });
    noImprov.hidden = true;
    improvList.hidden = false;
  } else {
    noImprov.hidden = false;
    improvList.hidden = true;
  }

  // Smooth scroll to result
  resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ── API call ─────────────────────────────────────────────────────────────────
async function analyseUrl(url) {
  const response = await fetch("/api/analyse", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ url }),
  });

  if (!response.ok) {
    throw new Error(`Server returned ${response.status}`);
  }

  return response.json();
}

// ── Form submit handler ──────────────────────────────────────────────────────
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();

  const raw = urlInput.value.trim();

  if (!raw) {
    showError("Please enter a URL.");
    urlInput.focus();
    return;
  }

  if (!looksLikeUrl(raw)) {
    showError("That doesn't look like a valid URL. Try including a domain, e.g. example.com");
    urlInput.focus();
    return;
  }

  setLoading(true);

  try {
    const data = await analyseUrl(raw);

    if (data.error) {
      showError("Analysis failed: " + data.error);
      return;
    }

    renderResult(data);
  } catch (err) {
    showError("Could not reach the server. Is Flask running?");
    console.error("Analysis error:", err);
  } finally {
    setLoading(false);
  }
});

// ── Clear error on re-type ───────────────────────────────────────────────────
urlInput.addEventListener("input", () => {
  if (inputError.textContent) clearError();
});

// ── Allow Enter key when input is focused (already handled by form submit) ──
// ── Keyboard shortcut: Ctrl/Cmd + Enter ─────────────────────────────────────
document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
    form.requestSubmit();
  }
});
