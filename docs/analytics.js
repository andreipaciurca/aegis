// Google Analytics 4, loaded only after explicit visitor consent.
//
// Replace GA_MEASUREMENT_ID below with your real Measurement ID
// (looks like "G-XXXXXXXXXX") from analytics.google.com. Until you do,
// this script shows the consent banner but never actually loads GA,
// so nothing is tracked.
(function () {
  "use strict";

  var GA_MEASUREMENT_ID = "G-XXXXXXXXXX";
  var CONSENT_KEY = "aegis_analytics_consent";

  function loadGA() {
    if (GA_MEASUREMENT_ID.indexOf("XXXXXXXXXX") !== -1) return;
    var s = document.createElement("script");
    s.async = true;
    s.src = "https://www.googletagmanager.com/gtag/js?id=" + GA_MEASUREMENT_ID;
    document.head.appendChild(s);
    window.dataLayer = window.dataLayer || [];
    function gtag() { window.dataLayer.push(arguments); }
    window.gtag = gtag;
    gtag("js", new Date());
    gtag("config", GA_MEASUREMENT_ID, { anonymize_ip: true });
  }

  function showBanner() {
    var bar = document.createElement("div");
    bar.setAttribute("role", "region");
    bar.setAttribute("aria-label", "Cookie consent");
    bar.style.cssText =
      "position:fixed;left:16px;right:16px;bottom:16px;z-index:9999;" +
      "max-width:640px;margin:0 auto;display:flex;flex-wrap:wrap;gap:12px;" +
      "align-items:center;justify-content:space-between;" +
      "background:var(--panel,#1e1e2e);border:1px solid var(--border,#313244);" +
      "border-radius:12px;padding:14px 16px;" +
      "box-shadow:0 8px 24px rgba(0,0,0,.35);" +
      "font:13px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;" +
      "color:var(--text,#cdd6f4);";

    var msg = document.createElement("div");
    msg.style.cssText = "flex:1 1 320px;color:var(--subtle,#9399b2);";
    msg.textContent =
      "This site uses Google Analytics (aggregate location/referrer data, no raw IP shown) to see which docs are useful. No account, no ad tracking.";

    var btns = document.createElement("div");
    btns.style.cssText = "display:flex;gap:8px;flex:0 0 auto;";

    var decline = document.createElement("button");
    decline.type = "button";
    decline.textContent = "Decline";
    decline.style.cssText =
      "background:transparent;color:var(--subtle,#9399b2);" +
      "border:1px solid var(--border,#313244);border-radius:8px;" +
      "padding:8px 14px;cursor:pointer;font:inherit;";

    var accept = document.createElement("button");
    accept.type = "button";
    accept.textContent = "Accept";
    accept.style.cssText =
      "background:var(--accent,#cba6f7);color:var(--bg,#11111b);" +
      "border:none;border-radius:8px;padding:8px 14px;cursor:pointer;" +
      "font:inherit;font-weight:600;";

    decline.addEventListener("click", function () {
      localStorage.setItem(CONSENT_KEY, "denied");
      bar.remove();
    });
    accept.addEventListener("click", function () {
      localStorage.setItem(CONSENT_KEY, "granted");
      bar.remove();
      loadGA();
    });

    btns.appendChild(decline);
    btns.appendChild(accept);
    bar.appendChild(msg);
    bar.appendChild(btns);
    document.body.appendChild(bar);
  }

  function init() {
    var consent = localStorage.getItem(CONSENT_KEY);
    if (consent === "granted") {
      loadGA();
    } else if (consent !== "denied") {
      showBanner();
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
