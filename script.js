// Frontend script for Cyber-Blue OSINT scanner
let WORKER_BASE = ""; // will prompt if empty

// small SHA-256 -> hex helper (fingerprint)
async function sha256hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}
function el(id){ return document.getElementById(id); }

// consent UI
const allowBtn = el('allowBtn'), enableOsintBtn = el('enableOsintBtn'), consentText = el('consentText'), confirmCheckbox = el('confirmCheckbox');

consentText.addEventListener('input', toggleOsintBtn);
confirmCheckbox.addEventListener('change', toggleOsintBtn);
function toggleOsintBtn(){
  enableOsintBtn.disabled = !(confirmCheckbox.checked && consentText.value.trim().toUpperCase()==='I CONSENT');
}

// collect fingerprint and reveal report
allowBtn.addEventListener('click', async ()=>{
  allowBtn.disabled = true;
  const fp = await collectBasicFingerprint();
  el('fpHash').textContent = fp.hash;
  el('uaInfo').textContent = JSON.stringify(fp.payload, null, 2);
  document.getElementById('consentCard').style.display = 'none';
  document.getElementById('reportCard').style.display = 'block';
  // ask for worker base if not set
  if(!WORKER_BASE) WORKER_BASE = prompt('Enter Worker base URL (e.g. https://cyber-exposure-core.YOURDOMAIN.workers.dev)') || '';
  if(WORKER_BASE) {
    // send fingerprint to backend (consented)
    await fetch(WORKER_BASE + '/collect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(fp.payload)});
  } else {
    alert('Worker base URL not set. You must set it to store scans.');
  }
});

// enable osint button click -> just triggers same allow behavior
enableOsintBtn.addEventListener('click', ()=> { allowBtn.click(); el('startOsint').disabled = false; });

// collect fingerprint
async function collectBasicFingerprint(){
  const ua = navigator.userAgent || '';
  const seed = ua + '|' + screen.width + 'x' + screen.height + '|' + (navigator.language||'') + '|' + (Intl.DateTimeFormat().resolvedOptions().timeZone||'');
  const hash = await sha256hex(seed);
  const payload = { fingerprint: hash, fingerprintSeed: seed, userAgent: ua, language: navigator.language, screen: {width: screen.width, height: screen.height, pr: window.devicePixelRatio}, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '' };
  return { hash, payload };
}

// OSINT scan
el('startOsint').addEventListener('click', async ()=>{
  const uname = el('usernameInput').value.trim();
  if(!uname) return alert('Enter username');
  if(!WORKER_BASE) WORKER_BASE = prompt('Enter Worker base URL') || '';
  if(!WORKER_BASE) return alert('Worker base required');
  // use fingerprint as owner token
  const owner = el('fpHash').textContent.trim();
  if(!owner) return alert('You must run Allow Scan first');
  el('resultsGrid').innerHTML = '';
  el('progress').style.display = 'block';
  updateProgress(10);
  try {
    const res = await fetch(WORKER_BASE + '/osint-scan', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ query: uname, owner })
    });
    const job = await res.json();
    updateProgress(100);
    renderResults(job);
    window._lastJob = job;
  } catch (e) {
    alert('Scan failed: ' + e.message);
  } finally {
    setTimeout(()=>{ el('progress').style.display='none'; updateProgress(0); }, 800);
  }
});

function updateProgress(n){ el('progressBar').style.width = Math.max(0,Math.min(100,n)) + '%'; }

function renderResults(job){
  if(job.error) return alert(job.error);
  const grid = el('resultsGrid');
  grid.innerHTML = job.results.map(r => `
    <div class="platform">
      <h4>${r.platform}</h4>
      <div class="muted">${r.match_type} · confidence ${Math.round((r.confidence||0)*100)}%</div>
      <div class="link"><a href="${r.url}" target="_blank" rel="noopener noreferrer">${r.url}</a></div>
      <div class="snippet">${r.snippet ? r.snippet : ''}</div>
    </div>
  `).join('');
}

// simulate tracking (educational)
el('simulateBtn').addEventListener('click', async ()=>{
  if(!WORKER_BASE) WORKER_BASE = prompt('Enter Worker base URL') || '';
  if(!WORKER_BASE) return alert('Worker URL required');
  const owner = el('fpHash').textContent.trim();
  if(!owner) return alert('Run Allow Scan first');
  const res = await fetch(WORKER_BASE + '/simulate-tracking?owner=' + encodeURIComponent(owner));
  const sim = await res.json();
  if(sim.error) return alert(sim.error);
  // show simulation results in resultsGrid
  el('resultsGrid').innerHTML = `<div class="platform"><h4>Simulated Tracking Report</h4><pre>${JSON.stringify(sim,null,2)}</pre></div>`;
  window._lastJob = sim;
});

// export JSON
el('exportBtn').addEventListener('click', ()=>{
  const job = window._lastJob;
  if(!job) return alert('No data to export');
  const blob = new Blob([JSON.stringify(job,null,2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `osint_${(job.query||'sim')}_${(new Date()).toISOString().slice(0,19)}.json`;
  document.body.appendChild(a); a.click(); a.remove();
});
