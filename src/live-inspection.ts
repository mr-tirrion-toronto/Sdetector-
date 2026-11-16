import type { Finding } from "./analyzer";

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
interface Check<T> { status: "available" | "unavailable" | "not_checked"; errorCode: string | null; data: T | null }
interface DnsData { records: Array<{type:string;value:string;ttl:number|null}>; dnssec: boolean|null }
interface CertificateData { source:string; latestIssuedAt:string|null; latestExpiresAt:string|null; issuer:string|null; commonName:string|null; expired:boolean|null }
interface TlsData { subject:string|null; issuer:string|null; notBefore:string|null; notAfter:string|null; expired:boolean|null; daysUntilExpiry:number|null; signatureAlgorithm:string|null; publicKeyAlgorithm:string|null; publicKeyBits:number|null; chainLength:number; chainComplete:boolean|null; problems:string[] }
interface RegistrationData { createdAt:string|null; registrar:string|null; ageDays:number|null }
interface WebsiteContentData { title:string|null; fetchedUrl:string|null; redirected:boolean; contentBytes:number; indicators:string[] }
export interface LiveInspection {
  checkedAt: string;
  privacy: string;
  dns: Check<DnsData>;
  certificateTransparency: Check<CertificateData>;
  tls: Check<TlsData>;
  registration: Check<RegistrationData>;
  websiteContent: Check<WebsiteContentData>;
  findings: Finding[];
  limitations: string[];
}

const FETCH_TIMEOUT_MS = 6500;
const CONTENT_LIMIT = 256 * 1024;
function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
async function fetchTimed(fetcher: FetchLike, input: string, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try { return await fetcher(input, { ...init, signal: controller.signal }); }
  finally { clearTimeout(timer); }
}
async function readLimited(response: Response, maxBytes = CONTENT_LIMIT): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new Error("RESPONSE_TOO_LARGE");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let total = 0, output = "";
  try {
    while (true) {
      const {done,value}=await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { await reader.cancel(); throw new Error("RESPONSE_TOO_LARGE"); }
      output += decoder.decode(value,{stream:true});
    }
    return output + decoder.decode();
  } finally { reader.releaseLock(); }
}
function unavailable<T>(errorCode:string): Check<T> { return {status:"unavailable",errorCode,data:null}; }
function safeDate(value:unknown):string|null {
  if (typeof value!=="string" || !value) return null;
  const parsed=Date.parse(value);
  return Number.isFinite(parsed)?new Date(parsed).toISOString():null;
}
function safeHost(hostname:string):boolean {
  const host=hostname.toLowerCase().replace(/\.$/,"");
  if (!host.includes(".") || host.length>253 || host==="localhost" || host.endsWith(".local") ||
      host.endsWith(".internal") || host.endsWith(".test") || host.endsWith(".invalid")) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":")) return false;
  return /^[a-z0-9.-]+$/.test(host);
}
async function dnsLookup(hostname:string,fetcher:FetchLike):Promise<Check<DnsData>> {
  try {
    const types=["A","AAAA","MX","NS","TXT"];
    const responses=await Promise.all(types.map(async type=>{
      const url=new URL("https://cloudflare-dns.com/dns-query");
      url.searchParams.set("name",hostname);url.searchParams.set("type",type);
      const response=await fetchTimed(fetcher,url.toString(),{headers:{accept:"application/dns-json"},redirect:"follow"});
      if(!response.ok)throw new Error("DNS_HTTP_"+response.status);
      const payload=await response.json() as Record<string,unknown>;
      if(!Array.isArray(payload.Answer))return [];
      return payload.Answer.filter(isRecord).slice(0,12).map(answer=>({
        type:String(answer.type??type),value:String(answer.data??"").slice(0,255),
        ttl:typeof answer.TTL==="number"?answer.TTL:null
      }));
    }));
    return {status:"available",errorCode:null,data:{
      records:responses.flat().slice(0,40),dnssec:null
    }};
  } catch(error) { return unavailable(error instanceof Error?error.name:"DNS_LOOKUP_FAILED"); }
}
async function certificateLookup(hostname:string,fetcher:FetchLike):Promise<Check<CertificateData>> {
  try {
    const url=new URL("https://crt.sh/");
    url.searchParams.set("q",hostname);url.searchParams.set("output","json");
    const response=await fetchTimed(fetcher,url.toString(),{headers:{accept:"application/json"},redirect:"follow"});
    if(!response.ok)throw new Error("CT_HTTP_"+response.status);
    const raw=await readLimited(response,512*1024);
    const rows=JSON.parse(raw) as unknown;
    if(!Array.isArray(rows))throw new Error("CT_INVALID_RESPONSE");
    const certs=rows.filter(isRecord).map(row=>({
      issued:safeDate(row.not_before),expires:safeDate(row.not_after),
      issuer:typeof row.issuer_name==="string"?row.issuer_name.slice(0,180):null,
      commonName:typeof row.common_name==="string"?row.common_name.slice(0,253):null
    })).filter(row=>row.issued).sort((a,b)=>Date.parse(b.issued!)-Date.parse(a.issued!));
    const latest=certs[0];
    if(!latest)return unavailable("NO_CERTIFICATE_RECORDS");
    return {status:"available",errorCode:null,data:{
      source:"Certificate Transparency (crt.sh)",latestIssuedAt:latest.issued,
      latestExpiresAt:latest.expires,issuer:latest.issuer,commonName:latest.commonName,
      expired:latest.expires?Date.parse(latest.expires)<Date.now():null
    }};
  } catch(error) { return unavailable(error instanceof Error?error.name:"CT_LOOKUP_FAILED"); }
}
async function tlsLookup(hostname:string,fetcher:FetchLike):Promise<Check<TlsData>> {
  try {
    if(!safeHost(hostname))return unavailable("HOST_NOT_ELIGIBLE_FOR_TLS_CHECK");
    const response=await fetchTimed(fetcher,"https://tools.trustico.com/api/chain/analyze-url",{
      method:"POST",headers:{"content-type":"application/json",accept:"application/json"},
      body:JSON.stringify({url:"https://"+hostname+"/"}),redirect:"follow"
    });
    if(response.status===429)throw new Error("TLS_PROVIDER_RATE_LIMITED");
    if(!response.ok)throw new Error("TLS_PROVIDER_HTTP_"+response.status);
    const payload=await response.json() as unknown;
    if(!isRecord(payload)||payload.success!==true||!isRecord(payload.data)||!isRecord(payload.data.certificate))throw new Error("TLS_PROVIDER_INVALID_RESPONSE");
    const cert=payload.data.certificate;
    const validation=isRecord(payload.data.validation)?payload.data.validation:{};
    const chain=Array.isArray(payload.data.chain)?payload.data.chain:[];
    const problems=Array.isArray(validation.problems)?validation.problems.map(value=>String(value).slice(0,240)).slice(0,10):[];
    const publicKey=isRecord(cert.publicKey)?cert.publicKey:{};
    return {status:"available",errorCode:null,data:{
      subject:isRecord(cert.subject)?String(cert.subject.commonName??"").slice(0,253)||null:null,
      issuer:isRecord(cert.issuer)?String(cert.issuer.commonName??"").slice(0,180)||null:null,
      notBefore:safeDate(cert.notBefore),notAfter:safeDate(cert.notAfter),
      expired:typeof cert.isExpired==="boolean"?cert.isExpired:null,
      daysUntilExpiry:typeof cert.daysUntilExpiry==="number"?cert.daysUntilExpiry:null,
      signatureAlgorithm:typeof cert.signatureAlgorithm==="string"?cert.signatureAlgorithm.slice(0,100):null,
      publicKeyAlgorithm:typeof publicKey.algorithm==="string"?publicKey.algorithm.slice(0,40):null,
      publicKeyBits:typeof publicKey.bits==="number"?publicKey.bits:null,
      chainLength:chain.length,chainComplete:typeof validation.chainComplete==="boolean"?validation.chainComplete:null,problems
    }};
  } catch(error) { return unavailable(error instanceof Error?error.message.slice(0,80):"TLS_LOOKUP_FAILED"); }
}
async function rdapLookup(hostname:string,fetcher:FetchLike):Promise<Check<RegistrationData>> {
  try {
    const response=await fetchTimed(fetcher,"https://rdap.org/domain/"+encodeURIComponent(hostname),{
      headers:{accept:"application/rdap+json"},redirect:"follow"
    });
    if(!response.ok)throw new Error("RDAP_HTTP_"+response.status);
    const payload=await response.json() as Record<string,unknown>;
    const events=Array.isArray(payload.events)?payload.events.filter(isRecord):[];
    const registration=events.find(event=>String(event.eventAction??"").toLowerCase().includes("registration"));
    const created=safeDate(registration?.eventDate);
    const entities=Array.isArray(payload.entities)?payload.entities.filter(isRecord):[];
    const registrar=entities.find(entity=>Array.isArray(entity.roles)&&entity.roles.includes("registrar"));
    const vcard=Array.isArray(registrar?.vcardArray)?registrar?.vcardArray[1]:null;
    const registrarName=Array.isArray(vcard)&&Array.isArray(vcard[1])?String(vcard[1][3]??"").slice(0,180):null;
    return {status:"available",errorCode:null,data:{
      createdAt:created,registrar:registrarName||null,
      ageDays:created?Math.max(0,Math.floor((Date.now()-Date.parse(created))/86400000)):null
    }};
  } catch(error) { return unavailable(error instanceof Error?error.name:"RDAP_LOOKUP_FAILED"); }
}
async function contentLookup(inputUrl:string,hostname:string,fetcher:FetchLike):Promise<Check<WebsiteContentData>> {
  try {
    const target=new URL(inputUrl);
    target.username="";target.password="";target.search="";target.hash="";
    if(!safeHost(hostname))return unavailable("HOST_NOT_ELIGIBLE_FOR_REMOTE_READER");
    // The third-party reader fetches public pages. Query strings are stripped to avoid forwarding tokens or personal data.
    const endpoint="https://r.jina.ai/"+target.toString();
    const response=await fetchTimed(fetcher,endpoint,{
      headers:{
        accept:"application/json","x-timeout":"6","x-token-budget":"4000",
        "x-no-cache":"true","x-robots-txt":"true","dnt":"true"
      },redirect:"follow"
    });
    if(!response.ok)throw new Error("READER_HTTP_"+response.status);
    const payload=JSON.parse(await readLimited(response)) as unknown;
    if(!isRecord(payload)||!isRecord(payload.data))throw new Error("READER_INVALID_RESPONSE");
    const data=payload.data;
    const text=typeof data.content==="string"?data.content.slice(0,32000):"";
    const title=typeof data.title==="string"?data.title.slice(0,240):null;
    const fetchedUrl=typeof data.url==="string"?data.url.slice(0,2048):null;
    const redirected=Boolean(fetchedUrl&&new URL(fetchedUrl).hostname.toLowerCase()!==hostname.toLowerCase());
    const indicators:string[]=[];
    if(/<input[^>]+type\s*=\s*["']?password/i.test(text)||/password\s*(field|input|form)/i.test(text))indicators.push("password_input");
    if(/<form\b/i.test(text)||/\[form\]|submit button|sign in form/i.test(text))indicators.push("form_detected");
    if(/one[- ]time password|\botp\b|verification code|security code/i.test(text))indicators.push("credential_verification_language");
    if(/wallet connect|connect wallet|seed phrase|recovery phrase|private key/i.test(text))indicators.push("crypto_wallet_or_secret_request");
    if(/urgent.{0,50}(account|payment|verify|suspend)|account.{0,40}(suspended|locked|limited)|verify.{0,30}immediately/i.test(text))indicators.push("urgent_account_pressure");
    if(/gift card|claim.{0,30}(prize|reward)|you have won|free crypto|guaranteed profit/i.test(text))indicators.push("prize_or_financial_lure");
    if(/wire transfer|bank transfer|payment details|credit card number/i.test(text))indicators.push("payment_data_language");
    return {status:"available",errorCode:null,data:{title,fetchedUrl,redirected,contentBytes:new TextEncoder().encode(text).byteLength,indicators}};
  } catch(error) { return unavailable(error instanceof Error?error.name:"CONTENT_LOOKUP_FAILED"); }
}

export async function inspectLiveDomain(inputUrl:string,hostname:string,fetcher:FetchLike=fetch):Promise<LiveInspection> {
  const [dns,certificateTransparency,registration,websiteContent]=await Promise.all([
    dnsLookup(hostname,fetcher),certificateLookup(hostname,fetcher),
    rdapLookup(hostname,fetcher),contentLookup(inputUrl,hostname,fetcher)
  ]);
  const findings:Finding[]=[];
  const add=(code:string,title:string,severity:"info"|"low"|"medium"|"high",points:number,evidence:string,recommendation:string)=>findings.push({code,title,severity,points,evidence,recommendation});
  if(dns.status==="available"&&dns.data?.records.length===0)add("DNS_NO_PUBLIC_RECORDS","No public DNS records were returned","medium",15,"The public DNS lookup returned no A, AAAA, MX, NS or TXT answers.","Confirm the domain spelling and verify the domain through its official registrar.");
  if(certificateTransparency.status==="available"&&certificateTransparency.data?.expired===true)add("CT_LATEST_CERT_EXPIRED","Latest certificate-transparency record is expired","low",5,"The latest certificate record found in Certificate Transparency has an expiry date in the past. This does not establish the live endpoint's current certificate state.","Open the organisation's official site independently and check its browser TLS certificate before entering information.");
  if(registration.status==="available"&&registration.data?.ageDays!==null&&registration.data?.ageDays!==undefined&&registration.data.ageDays<30)add("DOMAIN_RECENTLY_REGISTERED","Domain was registered recently","medium",15,"RDAP registration data indicates an age of approximately "+registration.data.ageDays+" days.","Treat unexpected links on a recently registered domain with extra caution and verify the sender independently.");
  const content=websiteContent.data;
  if(websiteContent.status==="available"&&content){
    if(content.redirected)add("CROSS_DOMAIN_REDIRECT","Website reader followed a redirect to another hostname","medium",15,"The content reader reports a final hostname different from the submitted hostname: "+content.fetchedUrl+".","Check whether the redirect destination belongs to the organisation you intended to visit.");
    if(content.indicators.includes("password_input"))add("LIVE_PASSWORD_INPUT","Live page contains a password input","info",0,"The remote page content includes a password input. Legitimate sites also use password fields, so this is context rather than proof of phishing.","Only enter credentials after confirming the exact domain independently.");
    if(content.indicators.includes("form_detected"))add("LIVE_FORM_DETECTED","Live page contains a form","info",0,"The remote page content contains a form or submit control. Forms are common on legitimate sites too.","Check the domain and the purpose of the form before submitting personal information.");
    if(content.indicators.includes("credential_verification_language"))add("LIVE_CREDENTIAL_LANGUAGE","Page requests verification or one-time-code information","medium",15,"The live page text contains language associated with passwords, one-time codes or identity verification.","Never share one-time codes or recovery codes from an unexpected link.");
    if(content.indicators.includes("crypto_wallet_or_secret_request"))add("LIVE_CRYPTO_SECRET_REQUEST","Page contains crypto-wallet or recovery-secret language","high",35,"The live page text refers to wallet connection, seed phrases, recovery phrases or private keys.","Never enter a seed phrase or private key into a website reached through an unsolicited message.");
    if(content.indicators.includes("urgent_account_pressure"))add("LIVE_URGENT_ACCOUNT_PRESSURE","Page uses urgent account-pressure language","medium",15,"The live page text combines urgency with account locking, suspension or verification language.","Verify the alert through the organisation's official app or website, not the supplied link.");
    if(content.indicators.includes("prize_or_financial_lure"))add("LIVE_PRIZE_OR_FINANCIAL_LURE","Page contains prize or financial-lure language","medium",15,"The live page text includes prize, reward or guaranteed-profit wording.","Be cautious of unexpected prizes, guaranteed returns or requests for upfront fees.");
    if(content.indicators.includes("payment_data_language"))add("LIVE_PAYMENT_DATA_LANGUAGE","Page refers to payment or bank details","info",0,"The live page text contains payment or card-data language. This alone is not proof of fraud.","Only provide payment details after independently verifying the merchant and domain.");
  }
  const limitations=[
    "Live content is retrieved by the Jina Reader service from a public URL. The submitted query string and fragment are removed before the hostname and path are sent to that service.",
    "The content reader respects robots.txt and does not receive browser cookies, passwords or authentication headers from this scanner.",
    "Live TLS certificate details and chain validation are obtained through Trustico SSL Tools. The hostname only is sent to that provider, which has a shared unauthenticated rate limit. Certificate Transparency is a separate public issuance-history source.",
    "Redirect information is limited to the final URL reported by the content reader, not a complete packet-level redirect trace.",
    "Page content can change, be personalised, or be hidden behind JavaScript or access controls. A content check is not a complete malware sandbox."
  ];
  return {checkedAt:new Date().toISOString(),privacy:"The content reader receives only the URL hostname and path. Query strings, fragments, embedded credentials and browser cookies are not forwarded. The TLS provider receives only the HTTPS hostname.",dns,certificateTransparency,tls,registration,websiteContent,findings,limitations};
}
