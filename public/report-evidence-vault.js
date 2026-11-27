(() => {
"use strict";
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const post=async body=>{const r=await fetch("/api/evidence",{method:"POST",credentials:"same-origin",cache:"no-store",headers:{"content-type":"application/json"},body:JSON.stringify(body)});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||"Evidence API unavailable ("+r.status+")");return j};
const get=async id=>{const r=await fetch("/api/evidence?id="+encodeURIComponent(id),{credentials:"same-origin",cache:"no-store"});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||"Evidence record unavailable ("+r.status+")");return j};
async function run(){
 let scan;try{scan=JSON.parse(sessionStorage.getItem("scamDetectorReport")||"null")}catch{return}
 const root=document.getElementById("report");if(!scan?.scanId||!root||root.querySelector(".error"))return;
 let record=null,errorMessage="";
 try{
  const created=await post({scanId:scan.scanId});
  record=await get(created.evidenceId);
  if(record.integrity?.manifestValid&&record.integrity?.custodyChain?.valid){
   await post({evidenceId:created.evidenceId,eventType:"integrity_verified"});
   record=await get(created.evidenceId);
  }
 }catch(e){errorMessage=e instanceof Error?e.message:"Evidence vault unavailable";}
 const section=document.createElement("section");section.className="forensic-section forensic-vault";
 section.innerHTML='<h2>Server-side Evidence Vault & Chain of Custody</h2>'+
 (record?'<div class="forensic-grid">'+
 '<div class="forensic-cell"><small>Evidence record ID</small><strong>'+esc(record.evidenceId)+'</strong></div>'+
 '<div class="forensic-cell"><small>Server record created</small><strong>'+esc(record.createdAt)+'</strong></div>'+
 '<div class="forensic-cell"><small>Manifest SHA-256</small><strong class="forensic-hash">'+esc(record.manifestSha256)+'</strong></div>'+
 '<div class="forensic-cell"><small>Integrity verification</small><strong>'+((record.integrity?.manifestValid&&record.integrity?.custodyChain?.valid)?"Verified":"Verification failed / incomplete")+'</strong></div></div>'+
 '<p class="forensic-small">The manifest is generated server-side from the scan, findings and retained intelligence rows associated with this signed-in account. It does not contain raw HTTP traffic, every transient third-party response, the original website files or the exported PDF.</p>'+
 '<h3>Recorded custody events</h3><table class="forensic-table"><thead><tr><th>Sequence</th><th>Event</th><th>Actor account ID</th><th>Recorded time (UTC)</th><th>Event SHA-256</th></tr></thead><tbody>'+
 (record.custodyEvents||[]).map(e=>'<tr><td>'+esc(e.sequenceNo)+'</td><td>'+esc(e.eventType)+'</td><td>'+esc(e.actorUserId)+'</td><td>'+esc(e.createdAt)+'</td><td class="forensic-hash">'+esc(e.eventHash)+'</td></tr>').join("")+
 '</tbody></table>'+
 '<p class="forensic-small"><b>Integrity limitation:</b> The event chain is hash-linked and verified by the application. It is not independently timestamped, digitally signed, or protected against a privileged database administrator rewriting the database and recomputing the chain. Preserve a separately obtained copy with the receiving authority or trusted custodian.</p>':
 '<div class="forensic-note"><b>Server evidence vault not available for this scan.</b> '+esc(errorMessage||"Sign in and perform a new scan to create an account-owned evidence record.")+' Guest scans and scans not owned by the signed-in account cannot be added to this vault.</div>');
 const existing=root.querySelector(".forensic-section");if(existing)existing.insertAdjacentElement("afterend",section);else root.appendChild(section);
 const button=document.querySelector(".toolbar button");
 if(button){
  button.removeAttribute("onclick");
  button.addEventListener("click",async event=>{
   event.preventDefault();
   if(record?.evidenceId){try{await post({evidenceId:record.evidenceId,eventType:"pdf_export_initiated"});}catch(e){console.warn("PDF_EXPORT_EVENT_NOT_RECORDED",e instanceof Error?e.name:"UnknownError");}}
   window.print();
  });
 }
}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",()=>void run());else void run();
})();