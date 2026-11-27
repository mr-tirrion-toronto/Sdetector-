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
 '<h3>Recorded custody events</h3><table id="custody-event-table" class="forensic-table"><thead><tr><th>Sequence</th><th>Event</th><th>Actor account ID</th><th>Recorded time (UTC)</th><th>Event SHA-256</th></tr></thead><tbody>'+
 (record.custodyEvents||[]).map(e=>'<tr><td>'+esc(e.sequenceNo)+'</td><td>'+esc(e.eventType)+'</td><td>'+esc(e.actorUserId)+'</td><td>'+esc(e.createdAt)+'</td><td class="forensic-hash">'+esc(e.eventHash)+'</td></tr>').join("")+
 '</tbody></table>'+
 '<p class="forensic-small"><b>Integrity limitation:</b> The event chain is hash-linked and verified by the application. It is not independently timestamped, digitally signed, or protected against a privileged database administrator rewriting the database and recomputing the chain. Preserve a separately obtained copy with the receiving authority or trusted custodian.</p>':
 '<div class="forensic-note"><b>Server evidence vault not available for this scan.</b> '+esc(errorMessage||"Sign in and perform a new scan to create an account-owned evidence record.")+' Guest scans and scans not owned by the signed-in account cannot be added to this vault.</div>');
 if(record){
  const pdfPanel=document.createElement("div");
  pdfPanel.className="forensic-section";
  pdfPanel.innerHTML='<h3>PDF file integrity — SHA-256</h3><p class="forensic-small">After saving this report as a PDF, select the saved PDF below. Its bytes are hashed locally in your browser; the file itself is never uploaded. The digest can be recorded and later checked against the recorded copy.</p><input id="evidence-pdf-file" type="file" accept=".pdf,application/pdf"><div class="forensic-cell" style="margin-top:10px"><small>Selected PDF SHA-256</small><strong id="evidence-pdf-digest" class="forensic-hash">No PDF selected</strong></div><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px"><button id="evidence-pdf-record" type="button" disabled>Record this PDF hash</button><button id="evidence-pdf-verify" type="button" disabled>Verify against stored hash</button></div><p id="evidence-pdf-status" class="forensic-small" aria-live="polite"></p>';
  section.appendChild(pdfPanel);
  const input=pdfPanel.querySelector("#evidence-pdf-file");
  const digestLabel=pdfPanel.querySelector("#evidence-pdf-digest");
  const status=pdfPanel.querySelector("#evidence-pdf-status");
  const recordButton=pdfPanel.querySelector("#evidence-pdf-record");
  const verifyButton=pdfPanel.querySelector("#evidence-pdf-verify");
  let selectedFile=null,selectedHash=null;
  const lastRecorded=()=>[...(record?.custodyEvents||[])].reverse().find(e=>e.eventType==="pdf_hash_recorded");
  const refreshRows=()=>{
   const tbody=section.querySelector(".forensic-table tbody");
   if(tbody)tbody.innerHTML=(record?.custodyEvents||[]).map(e=>'<tr><td>'+esc(e.sequenceNo)+'</td><td>'+esc(e.eventType)+'</td><td>'+esc(e.actorUserId)+'</td><td>'+esc(e.createdAt)+'</td><td class="forensic-hash">'+esc(e.eventHash)+'</td></tr>').join("");
  };
  input.addEventListener("change",async()=>{
   selectedFile=input.files?.[0]||null;selectedHash=null;recordButton.disabled=true;verifyButton.disabled=true;
   if(!selectedFile){digestLabel.textContent="No PDF selected";status.textContent="";return;}
   if(selectedFile.size<8||selectedFile.size>100*1024*1024){status.textContent="Select a PDF between 8 bytes and 100 MB.";return;}
   try{
    const bytes=await selectedFile.arrayBuffer();
    const header=new TextDecoder().decode(new Uint8Array(bytes.slice(0,5)));
    if(header!=="%PDF-"){status.textContent="The selected file does not have a valid PDF header.";return;}
    if(!crypto?.subtle)throw new Error("SHA-256 is unavailable in this browser.");
    const digest=await crypto.subtle.digest("SHA-256",bytes);
    selectedHash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,"0")).join("");
    digestLabel.textContent=selectedHash;
    const previous=lastRecorded();
    if(previous?.details?.pdfSha256===selectedHash){
     status.textContent="This file matches the latest PDF digest already recorded for this evidence record.";
     verifyButton.disabled=false;
    }else{
     status.textContent=previous?"This PDF differs from the latest recorded copy. Record it as a new PDF version if intentional.":"PDF hashed locally. Record this digest in the custody trail.";
     recordButton.disabled=false;
    }
   }catch(error){status.textContent=error instanceof Error?error.message:"Could not hash the selected PDF.";}
  });
  recordButton.addEventListener("click",async()=>{
   if(!selectedFile||!selectedHash)return;
   recordButton.disabled=true;
   try{
    await post({evidenceId:record.evidenceId,eventType:"pdf_hash_recorded",pdfSha256:selectedHash,fileSizeBytes:selectedFile.size});
    record=await get(record.evidenceId);refreshRows();
    status.textContent="PDF SHA-256 digest recorded in the account custody trail. The PDF bytes were not uploaded.";
    recordButton.disabled=true;verifyButton.disabled=false;
   }catch(error){status.textContent=error instanceof Error?error.message:"Could not record PDF hash.";recordButton.disabled=false;}
  });
  verifyButton.addEventListener("click",async()=>{
   if(!selectedHash)return;
   verifyButton.disabled=true;
   try{
    await post({evidenceId:record.evidenceId,eventType:"pdf_hash_verified",pdfSha256:selectedHash});
    record=await get(record.evidenceId);refreshRows();
    status.textContent="Verified: the selected PDF bytes match the latest digest recorded in the custody trail.";
   }catch(error){status.textContent=error instanceof Error?error.message:"PDF hash verification failed.";verifyButton.disabled=false;}
  });
 }
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