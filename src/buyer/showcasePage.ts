/**
 * Minimal viewer for the procurement event stream: a two-agent chat over the
 * five DACS stages, following the conversation model of the DACS Directory's
 * `/try-chat` (Community, MIT) with labels adapted to the private-RFQ flow.
 * Served by the showcase server; polls `/demo/procurement/{jobId}`.
 */

export function showcasePageHtml(): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Private RFQ showcase</title>
<style>
:root{--bg:#0b0d12;--fg:#e8eaf0;--mute:#8b93a7;--buyer:#2b6fff;--seller:#ff6b2b;--chain:#1fbf75;--card:#141825}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:16px}
h1{font-size:18px;margin:0 0 4px}.sub{color:var(--mute);font-size:13px;margin-bottom:12px}
.stages{display:grid;grid-template-columns:repeat(5,1fr);gap:6px;margin:12px 0}
.stage{background:var(--card);border-radius:8px;padding:8px;font-size:12px;color:var(--mute);border:1px solid transparent}
.stage.on{color:var(--fg);border-color:var(--chain)}.stage b{display:block;font-size:13px}
.turn{display:flex;gap:10px;margin:10px 0;align-items:flex-start}.turn.right{flex-direction:row-reverse}.turn.center{justify-content:center}
.av{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;font-weight:700;flex:none;color:#fff}
.bubble{background:var(--card);border-radius:12px;padding:9px 12px;max-width:72%}.center .bubble{max-width:90%;text-align:center;font-size:13px}
.buyer .av{background:var(--buyer)}.seller .av{background:var(--seller)}.chain .av{background:var(--chain)}
.ref{display:block;font:12px ui-monospace,monospace;color:var(--mute);word-break:break-all;margin-top:4px}
.ref a{color:var(--chain);text-decoration:none}
.status{font-size:13px;color:var(--mute);margin:8px 0}
select,input{background:var(--card);color:var(--fg);border:1px solid #2a3047;border-radius:6px;padding:6px 8px}
</style></head><body><main>
<h1>Private RFQ showcase</h1>
<div class="sub">Buyer (ChatGPT via MCP) negotiates privately with an independent seller; only the signed commitment and the payment reach Demos.</div>
<div>Job: <select id="job"></select> <span class="status" id="status"></span></div>
<div class="stages" id="stages"></div>
<div id="chat"></div>
<div id="subnet"></div>
</main>
<script>
const STAGES=[["Identify","DACS-1","A signed, on-chain listing."],["Vet","DACS-2","Check the counterparty."],["Negotiate","DACS-3","Both sides sign the terms."],["Settle","DACS-4","Payment, with evidence."],["Verify","DACS-5","Not part of this showcase."]];
const PHASE={queued:0,connecting:0,discovering:0,selecting:1,agreeing:2,settling:3,delivering:3,recovering:3,verifying:4,evaluating:4,complete:4};
const EXPLORER="https://explorer.demos.sh";
function speaker(e){ if(e.txRef||e.anchorRef) return "chain"; const l=e.label; if(/^Buyer|^Private RFQ|^Connecting|^Verified|^Paying|^Waiting|^Negotiation ended/.test(l)) return "buyer"; if(/countered|offered|accepted|rejected|Deal settled/.test(l)) return /^Buyer/.test(l)?"buyer":"seller"; return "buyer"; }
function render(job){
  document.getElementById("status").textContent=job.status+" / "+job.phase+(job.error?(" — "+job.error):"");
  let stage=0; job.events.forEach(e=>{ const s=PHASE[e.phase]; if(s!==undefined&&s>stage) stage=s; });
  document.getElementById("stages").innerHTML=STAGES.map((s,i)=>'<div class="stage'+(i<=stage?' on':'')+'"><b>'+s[0]+'</b>'+s[1]+' · '+s[2]+'</div>').join("");
  const chat=document.getElementById("chat"); chat.innerHTML="";
  for(const e of job.events){ const who=speaker(e); const side=who==="buyer"?"left":who==="seller"?"right":"center";
    const refs=(e.txRef?'<span class="ref">tx <a target="_blank" href="'+EXPLORER+'/transactions/'+e.txRef+'">'+e.txRef+'</a></span>':'')+(e.anchorRef?'<span class="ref">anchor '+e.anchorRef+'</span>':'');
    const name=who==="buyer"?"B":who==="seller"?"S":"D";
    chat.insertAdjacentHTML("beforeend",'<div class="turn '+who+' '+side+'"><div class="av">'+name+'</div><div class="bubble">'+e.label.replace(/</g,"&lt;")+refs+'<span class="ref">'+e.at+'</span></div></div>');
  }
}
async function loadJobs(){ const r=await fetch("/demo/procurement"); const jobs=await r.json(); const sel=document.getElementById("job"); const cur=sel.value; sel.innerHTML=jobs.map(j=>'<option value="'+j.id+'">'+j.id+' · '+j.status+'</option>').join(""); if(cur) sel.value=cur; return jobs; }
async function subnet(){ const r=await fetch("/demo/subnet"); if(!r.ok){ document.getElementById("subnet").innerHTML=""; return; } const j=await r.json(); const rows=j.rows.map(x=>'<tr><td class="ref">'+x.hash.slice(0,16)+'…</td><td class="ref">'+x.from.slice(0,10)+'…</td><td class="ref">'+x.to.slice(0,10)+'…</td><td>'+x.status+'</td><td class="ref">'+x.at+'</td><td class="ref">ciphertext only</td></tr>').join(""); document.getElementById("subnet").innerHTML='<h2 style="font-size:15px;margin:18px 0 4px">Private channel on subnet '+j.uid+'</h2><div class="sub">'+j.note.replace(/</g,"&lt;")+'</div><table style="width:100%;font-size:12px;border-collapse:collapse"><tr style="color:var(--mute)"><th align="left">tx</th><th align="left">from</th><th align="left">to</th><th align="left">status</th><th align="left">at</th><th align="left">content</th></tr>'+rows+'</table>'; }
async function tick(){ const jobs=await loadJobs(); const id=document.getElementById("job").value||(jobs[0]&&jobs[0].id); if(!id) return; const r=await fetch("/demo/procurement/"+encodeURIComponent(id)); if(r.ok) render(await r.json()); }
document.getElementById("job").addEventListener("change",tick); tick(); subnet(); setInterval(tick,3000); setInterval(subnet,10000);
</script></body></html>`;
}
