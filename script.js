// ---- CONFIG ----
const WORKER_BASE = "https://cyber-exposure-core.YOUR_SUBDOMAIN.workers.dev"; // replace after deploy
// ---- UTIL ----
async function sha256hex(str){
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function el(id){ return document.getElementById(id); }

// ---- CONSENT UI ----
const allowBtn = el('allowBtn');
const allowOsintBtn = el('allowOsintBtn');
const consentText = el('consentText');
const consentCheckbox = el('confirmOsintCheckbox');

consentText.addEventListener('input', ()=> {
  allowOsintBtn.disabled = !(consentText.value.trim().toUpperCase()==='I CONSENT' && consentCheckbox.checked);
});

allowBtn.addEventListener('click', async () => {
  allowBtn.disabled = true;
  // collect fingerprint & show report card
  const fp = await collectBasicFingerprint();
  el('fpHash').textContent = fp.hash;
  el('uaInfo').textContent = JSON.stringify(fp.ua, null, 2);
  document.getElementById('consentCard').style.display = 'none';
  document.getElementById('reportCard').style.display = 'block';
  // Send minimal fingerprint to backend (consented)
  await fetch(WORKER_BASE + '/collect', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(fp.payload)
  });
});

allowOsintBtn.addEventListener('click', ()=> {
  // same as allow but also enable OSINT scan UI
  allowBtn.click();
  el('startOsint').disabled = false;
});

// ---- COLLECT BASIC FINGERPRINT ----
async function collectBasicFingerprint(){
  const ua = navigator.userAgent;
  const payload = {
    fingerprintSeed: ua + screen.width + 'x' + screen.height + (navigator.language||''),
    userAgent: ua,
    language: navigator.language,
    screen: { width: screen.width, height: screen.height, pr: window.devicePixelRatio },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'
  };
  const hash = await sha256hex(payload.fingerprintSeed);
  return { hash, ua:payload.userAgent, payload: {...payload, fingerprint: hash} };
}

// ---- OSINT SCAN UI ----
el('startOsint').addEventListener('click', async () =>{
  const uname = el('usernameInput').value.trim();
  if(!uname) return alert('Enter a username first');
  el('resultsGrid').innerHTML = '';
  el('progress').style.display = 'block';
  updateProgress(0);
  // request backend to run OSINT scan (consent implied because allowOsintBtn was enabled)
  const res = await fetch(WORKER_BASE + '/osint-scan', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ query: uname })
  });
  const job = await res.json();
  // Show results
  renderOsintResults(job);
  el('progress').style.display = 'none';
});

// update progress bar (0..100)
function updateProgress(p){
  const bar = el('progressBar');
  bar.style.width = Math.max(0,Math.min(100,p)) + '%';
}

// render results with icons and links
function renderOsintResults(job){
  const grid = el('resultsGrid');
  grid.innerHTML = job.results.map(r => `
    <div class="platform">
      <h4>${r.platform}</h4>
      <div class="muted">${r.match_type} · confidence ${Math.round(r.confidence*100)}%</div>
      <div class="link"><a target="_blank" href="${r.url}">${r.url}</a></div>
      <div class="snippet">${r.snippet? r.snippet : ''}</div>
    </div>
  `).join('');
  // save last job id for export
  window._lastJob = job;
}

// Export JSON
el('exportBtn').addEventListener('click', ()=>{
  const job = window._lastJob;
  if(!job) return alert('No results to export');
  const blob = new Blob([JSON.stringify(job,null,2)],{type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `osint-${job.query}-${(new Date()).toISOString().slice(0,19)}.json`;
  document.body.appendChild(a); a.click(); a.remove();
});

// ---- helper: simple fetch wrapper with timeout ----
async function fetchWithTimeout(url, opts={}, timeout=10000){
  const controller = new AbortController();
  const id = setTimeout(()=>controller.abort(), timeout);
  try {
    return await fetch(url, {...opts, signal: controller.signal});
  } finally { clearTimeout(id); }
}
