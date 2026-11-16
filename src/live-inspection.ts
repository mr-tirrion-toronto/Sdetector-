import type { Finding } from "./analyzer";
import { analyzeBusinessClaims } from "./business-claims";
import { getDomain } from "tldts";

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
interface Check<T> { status: "available" | "unavailable" | "not_checked"; errorCode: string | null; data: T | null }
interface DnsData { records: Array<{type:string;value:string;ttl:number|null}>; dnssec: boolean|null }
interface CertificateData { source:string; queriedDomain:string; found:boolean; matchingNames:string[]; latestIssuedAt:string|null; latestExpiresAt:string|null; issuer:string|null; commonName:string|null; expired:boolean|null }
export interface TlsData { subject:string|null; issuer:string|null; notBefore:string|null; notAfter:string|null; expired:boolean|null; daysUntilExpiry:number|null; signatureAlgorithm:string|null; publicKeyAlgorithm:string|null; publicKeyBits:number|null; subjectAltNames:string[]; hostnameMatch:boolean|null; chainLength:number; chainComplete:boolean|null; problems:string[] }
interface RegistrationData { queriedDomain:string; createdAt:string|null; registrar:string|null; ageDays:number|null }
interface WebsiteContentData { title:string|null; fetchedUrl:string|null; redirected:boolean; contentBytes:number; indicators:string[]; businessSignals:string[]; businessFindings:Finding[]; payoutVerification:"not_verified_from_public_page"; operatorVerification:"not_independently_verified"; operatorDisclosure:{legalEntityDetected:boolean;contactDetailsDetected:boolean;termsLinkDetected:boolean;privacyLinkDetected:boolean}; httpStatus:number|null; contentType:string|null; cachedAt:string|null; source:string }
export interface LiveInspection {
  checkedAt: string;
  registrableDomain: string;
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
function providerErrorCode(error:unknown,fallback:string):string {
  if(error instanceof Error){
    const message=error.message.slice(0,100);
    if(/^(DNS|CT|RDAP|READER|TLS_PROVIDER)_HTTP_\d+$/.test(message))return message;
    if(["RESPONSE_TOO_LARGE","CT_INVALID_RESPONSE","NO_CERTIFICATE_RECORDS","TLS_PROVIDER_INVALID_RESPONSE","TLS_PROVIDER_RATE_LIMITED","NONSTANDARD_PORT_NOT_SENT_TO_READER","FIRECRAWL_RATE_LIMITED","FIRECRAWL_KEYLESS_CREDITS_EXHAUSTED","FIRECRAWL_INVALID_RESPONSE","NO_VERIFIED_PUBLIC_ADDRESS"].includes(message))return message;
    return (error.name + ":" + message).slice(0,100) || fallback;
  }
  return fallback;
}
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
        type:({1:"A",28:"AAAA",15:"MX",2:"NS",16:"TXT"} as Record<number,string>)[Number(answer.type)]??String(answer.type??type),value:String(answer.data??"").slice(0,255),
        ttl:typeof answer.TTL==="number"?answer.TTL:null
      }));
    }));
    return {status:"available",errorCode:null,data:{
      records:responses.flat().slice(0,40),dnssec:null
    }};
  } catch(error) { return unavailable(providerErrorCode(error,"DNS_LOOKUP_FAILED")); }
}
function dnsNameMatches(hostname:string,pattern:string):boolean {
  const host=hostname.toLowerCase().replace(/\.$/,"");
  const name=pattern.toLowerCase().replace(/\.$/,"");
  if(name.startsWith("*.")){
    const suffix=name.slice(2);
    const prefix=host.slice(0,-suffix.length-1);
    return getDomain(suffix,{allowPrivateDomains:true})===suffix && host.endsWith("."+suffix)&&prefix.length>0&&!prefix.includes(".");
  }
  return host===name;
}
async function certificateLookup(hostname:string,registrableDomain:string,fetcher:FetchLike):Promise<Check<CertificateData>> {
  try {
    const url=new URL("https://api.certspotter.com/v1/issuances");
    url.searchParams.set("domain",registrableDomain);url.searchParams.set("include_subdomains","true");
    url.searchParams.set("expand","dns_names");url.searchParams.set("limit","100");
    const response=await fetchTimed(fetcher,url.toString(),{headers:{accept:"application/json"},redirect:"follow"});
    if(!response.ok)throw new Error("CT_HTTP_"+response.status);
    const raw=await readLimited(response,512*1024);
    const rows=JSON.parse(raw) as unknown;
    if(!Array.isArray(rows))throw new Error("CT_INVALID_RESPONSE");
    const certs=rows.filter(isRecord).map(row=>{
      const names=Array.isArray(row.dns_names)?row.dns_names.map(name=>String(name).toLowerCase().slice(0,253)):[];
      return {issued:safeDate(row.not_before),expires:safeDate(row.not_after),matchingNames:names.filter(name=>dnsNameMatches(hostname,name))};
    }).filter(row=>row.issued&&row.matchingNames.length>0)
      .sort((a,b)=>Date.parse(b.issued!)-Date.parse(a.issued!));
    const latest=certs[0];
    if(!latest)return {status:"available",errorCode:null,data:{
      source:"Certificate Transparency (Cert Spotter)",queriedDomain:registrableDomain,found:false,matchingNames:[],
      latestIssuedAt:null,latestExpiresAt:null,issuer:null,commonName:null,expired:null
    }};
    return {status:"available",errorCode:null,data:{
      source:"Certificate Transparency (Cert Spotter)",queriedDomain:registrableDomain,found:true,
      matchingNames:latest.matchingNames.slice(0,10),latestIssuedAt:latest.issued,
      latestExpiresAt:latest.expires,issuer:null,commonName:latest.matchingNames[0]??null,
      expired:latest.expires?Date.parse(latest.expires)<Date.now():null
    }};
  } catch(error) { return unavailable(providerErrorCode(error,"CT_LOOKUP_FAILED")); }
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
    const payload=JSON.parse(await readLimited(response,512*1024)) as unknown;
    if(!isRecord(payload)||payload.success!==true||!isRecord(payload.data)||!isRecord(payload.data.certificate))throw new Error("TLS_PROVIDER_INVALID_RESPONSE");
    const cert=payload.data.certificate;
    const validation=isRecord(payload.data.validation)?payload.data.validation:{};
    const chain=Array.isArray(payload.data.chain)?payload.data.chain:[];
    const problems=Array.isArray(validation.problems)?validation.problems.map(value=>String(value).slice(0,240)).slice(0,10):[];
    const publicKey=isRecord(cert.publicKey)?cert.publicKey:{};
    const sanEntries=isRecord(cert.extensions)&&Array.isArray(cert.extensions.subjectAltName)?cert.extensions.subjectAltName.filter(isRecord).filter(item=>String(item.type).toLowerCase()==="dns"):[];
    const sanExtensionPresent=isRecord(cert.extensions)&&Array.isArray(cert.extensions.subjectAltName);
    const subjectAltNames=sanEntries.map(item=>String(item.value).toLowerCase().slice(0,253)).slice(0,100);
    return {status:"available",errorCode:null,data:{
      subject:isRecord(cert.subject)?String(cert.subject.commonName??"").slice(0,253)||null:null,
      issuer:isRecord(cert.issuer)?String(cert.issuer.commonName??"").slice(0,180)||null:null,
      notBefore:safeDate(cert.notBefore),notAfter:safeDate(cert.notAfter),
      expired:typeof cert.isExpired==="boolean"?cert.isExpired:null,
      daysUntilExpiry:typeof cert.daysUntilExpiry==="number"?cert.daysUntilExpiry:null,
      signatureAlgorithm:typeof cert.signatureAlgorithm==="string"?cert.signatureAlgorithm.slice(0,100):null,
      publicKeyAlgorithm:typeof publicKey.algorithm==="string"?publicKey.algorithm.slice(0,40):null,
      publicKeyBits:typeof publicKey.bits==="number"?publicKey.bits:null,
      subjectAltNames,hostnameMatch:sanExtensionPresent?sanEntries.some(item=>dnsNameMatches(hostname,String(item.value))):null,
      chainLength:chain.length,chainComplete:typeof validation.chainComplete==="boolean"?validation.chainComplete:null,problems
    }};
  } catch(error) { return unavailable(error instanceof Error?error.message.slice(0,80):"TLS_LOOKUP_FAILED"); }
}
async function rdapLookup(hostname:string,registrableDomain:string,fetcher:FetchLike):Promise<Check<RegistrationData>> {
  try {
    const bootstrapResponse=await fetchTimed(fetcher,"https://data.iana.org/rdap/dns.json",{
      headers:{accept:"application/json"},redirect:"follow"
    });
    if(!bootstrapResponse.ok)throw new Error("RDAP_BOOTSTRAP_HTTP_"+bootstrapResponse.status);
    const bootstrap=await bootstrapResponse.json() as Record<string,unknown>;
    const services=Array.isArray(bootstrap.services)?bootstrap.services:[];
    const labels=registrableDomain.toLowerCase().split(".");
    let baseUrl:string|null=null;
    for(let i=0;i<labels.length;i++){
      const suffix=labels.slice(i).join(".");
      const service=services.find(item=>Array.isArray(item)&&Array.isArray(item[0])&&
        (item[0] as unknown[]).some(value=>String(value).toLowerCase()===suffix));
      if(service&&Array.isArray(service)&&Array.isArray(service[1])&&typeof service[1][0]==="string"){
        baseUrl=service[1][0];break;
      }
    }
    if(!baseUrl||!baseUrl.startsWith("https://"))throw new Error("RDAP_SERVER_NOT_FOUND");
    const endpoint=new URL("domain/"+encodeURIComponent(registrableDomain),baseUrl.endsWith("/")?baseUrl:baseUrl+"/");
    const response=await fetchTimed(fetcher,endpoint.toString(),{
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
    const fn=Array.isArray(vcard)?vcard.find(item=>Array.isArray(item)&&item[0]==="fn"):null;
    const registrarName=Array.isArray(fn)?String(fn[3]??"").slice(0,180):null;
    return {status:"available",errorCode:null,data:{
      queriedDomain:registrableDomain,createdAt:created,registrar:registrarName||null,
      ageDays:created?Math.max(0,Math.floor((Date.now()-Date.parse(created))/86400000)):null
    }};
  } catch(error) { return unavailable(providerErrorCode(error,"RDAP_LOOKUP_FAILED")); }
}
function isPublicIpv4(value:string):boolean {
  const parts=value.split(".").map(Number);
  if(parts.length!==4||parts.some(part=>!Number.isInteger(part)||part<0||part>255))return false;
  const n=parts.reduce((acc,part)=>(acc*256+part)>>>0,0)>>>0;
  const blocked:Array<[number,number]>=[
    [0x00000000,0x00ffffff],[0x0a000000,0x0affffff],[0x64400000,0x647fffff],
    [0x7f000000,0x7fffffff],[0xa9fe0000,0xa9feffff],[0xac100000,0xac1fffff],
    [0xc0000000,0xc00000ff],[0xc0000200,0xc00002ff],[0xc0586300,0xc05863ff],
    [0xc0a80000,0xc0a8ffff],[0xc6120000,0xc613ffff],[0xc6336400,0xc63364ff],
    [0xcb007100,0xcb0071ff],[0xe0000000,0xffffffff]
  ];
  return !blocked.some(([low,high])=>n>=low&&n<=high);
}
function isPublicIpv6(value:string):boolean {
  const host=value.toLowerCase().split("%")[0];
  if(host==="::"||host==="::1"||host.startsWith("::ffff:")||host.startsWith("64:ff9b:")||
    host.startsWith("2001:db8:")||host.startsWith("2001:0:")||host.startsWith("2002:")||
    host.startsWith("fc")||host.startsWith("fd")||/^fe[89ab]/.test(host)||host.startsWith("ff"))return false;
  const first=Number.parseInt(host.split(":")[0]||"0",16);
  return Number.isFinite(first)&&first>=0x2000&&first<=0x3fff;
}
function hasVerifiedPublicAddress(dns:Check<DnsData>):boolean {
  if(dns.status!=="available"||!dns.data)return false;
  const addresses=dns.data.records.filter(record=>record.type==="A"||record.type==="AAAA");
  return addresses.length>0&&addresses.every(record=>record.type==="A"?isPublicIpv4(record.value):isPublicIpv6(record.value));
}
async function contentLookup(inputUrl:string,hostname:string,fetcher:FetchLike,dns:Check<DnsData>):Promise<Check<WebsiteContentData>> {
  try {
    const target=new URL(inputUrl);
    target.username="";target.password="";target.search="";target.hash="";
    if(target.port && !["80","443"].includes(target.port))return unavailable("NONSTANDARD_PORT_NOT_SENT_TO_READER");
    if(!safeHost(hostname))return unavailable("HOST_NOT_ELIGIBLE_FOR_REMOTE_READER");
    if(!hasVerifiedPublicAddress(dns))return unavailable("NO_VERIFIED_PUBLIC_ADDRESS");
    const endpoint="https://api.firecrawl.dev/v2/scrape";
    const response=await fetchTimed(fetcher,endpoint,{
      method:"POST",
      headers:{"content-type":"application/json",accept:"application/json"},
      body:JSON.stringify({
        url:target.toString(),formats:["html"],onlyMainContent:false,
        timeout:12000,maxAge:21600000
      }),
      redirect:"follow"
    });
    if(response.status===429)throw new Error("FIRECRAWL_RATE_LIMITED");
    if(response.status===402)throw new Error("FIRECRAWL_KEYLESS_CREDITS_EXHAUSTED");
    if(!response.ok)throw new Error("FIRECRAWL_HTTP_"+response.status);
    const payload=JSON.parse(await readLimited(response,512*1024)) as unknown;
    if(!isRecord(payload)||payload.success!==true||!isRecord(payload.data))throw new Error("FIRECRAWL_INVALID_RESPONSE");
    const data=payload.data;
    const metadata=isRecord(data.metadata)?data.metadata:{};
    const html=typeof data.html==="string"?data.html.slice(0,32000):"";
    const markdown=typeof data.markdown==="string"?data.markdown.slice(0,32000):"";
    const text=html||markdown;
    const title=typeof metadata.title==="string"?metadata.title.slice(0,240):null;
    const fetchedUrl=typeof metadata.url==="string"?metadata.url.slice(0,2048):
      typeof metadata.sourceURL==="string"?metadata.sourceURL.slice(0,2048):null;
    const redirected=Boolean(fetchedUrl&&new URL(fetchedUrl).hostname.toLowerCase()!==hostname.toLowerCase());
    const indicators:string[]=[];
    if(/<input[^>]+type\s*=\s*["']?password/i.test(text)||/password\s*(field|input|form)/i.test(text))indicators.push("password_input");
    if(/<form\b/i.test(text)||/\[form\]|submit button|sign in form/i.test(text))indicators.push("form_detected");
    if(/one[- ]time password|\botp\b|verification code|security code/i.test(text))indicators.push("credential_verification_language");
    if(/wallet connect|connect wallet|seed phrase|recovery phrase|private key/i.test(text))indicators.push("crypto_wallet_or_secret_request");
    if(/urgent.{0,50}(account|payment|verify|suspend)|account.{0,40}(suspended|locked|limited)|verify.{0,30}immediately/i.test(text))indicators.push("urgent_account_pressure");
    if(/gift card|claim.{0,30}(prize|reward)|you have won|free crypto|guaranteed profit/i.test(text))indicators.push("prize_or_financial_lure");
    if(/wire transfer|bank transfer|payment details|credit card number/i.test(text))indicators.push("payment_data_language");
    if(/this domain is (?:parked|for sale)|domain (?:is )?(?:for sale|available for purchase)|buy this domain|domain parking|parked free|sedo domain parking|afternic/i.test(text)||/resources and information/i.test(title||""))indicators.push("domain_parked_or_for_sale");
    const businessAssessment=analyzeBusinessClaims(text,html);
    return {status:"available",errorCode:null,data:{
      title,fetchedUrl,redirected,contentBytes:new TextEncoder().encode(text).byteLength,indicators,
      businessSignals:businessAssessment.signals,businessFindings:businessAssessment.findings,payoutVerification:businessAssessment.payoutVerification,operatorVerification:businessAssessment.operatorVerification,operatorDisclosure:businessAssessment.operatorDisclosure,
      httpStatus:typeof metadata.statusCode==="number"?metadata.statusCode:null,
      contentType:typeof metadata.contentType==="string"?metadata.contentType.slice(0,100):null,
      cachedAt:typeof metadata.cachedAt==="string"?metadata.cachedAt.slice(0,40):null,
      source:"Firecrawl keyless scrape"
    }};
  } catch(error) { return unavailable(providerErrorCode(error,"FIRECRAWL_LOOKUP_FAILED")); }
}

export async function inspectLiveDomain(inputUrl:string,hostname:string,fetcher:FetchLike=fetch,cachedTls?:TlsData|null):Promise<LiveInspection> {
  const registrableDomain=getDomain(hostname,{allowPrivateDomains:true})||hostname;
  const tlsPromise:Promise<Check<TlsData>>=cachedTls
    ? Promise.resolve({status:"available",errorCode:null,data:cachedTls})
    : tlsLookup(hostname,fetcher);
  const [dns,certificateTransparency,tls,registration]=await Promise.all([
    dnsLookup(hostname,fetcher),certificateLookup(hostname,registrableDomain,fetcher),tlsPromise,rdapLookup(hostname,registrableDomain,fetcher)
  ]);
  const websiteContent=await contentLookup(inputUrl,hostname,fetcher,dns);
  const findings:Finding[]=[];
  const add=(code:string,title:string,severity:"info"|"low"|"medium"|"high",points:number,evidence:string,recommendation:string)=>findings.push({code,title,severity,points,evidence,recommendation});
  if(tls.status==="available"&&tls.data){
    if(tls.data.hostnameMatch===false)add("TLS_HOSTNAME_MISMATCH","TLS certificate does not cover this hostname","high",30,"The live certificate DNS names do not include "+hostname+".","Do not bypass browser certificate warnings. Stop and verify the domain through an independently trusted channel.");
    if(tls.data.expired===true)add("LIVE_TLS_CERT_EXPIRED","Live HTTPS certificate is expired","medium",15,"The TLS inspection provider reports that the certificate presented by "+hostname+" is expired.","Do not enter sensitive information. Contact the website owner through an independently verified channel.");
    else if(tls.data.daysUntilExpiry!==null&&tls.data.daysUntilExpiry<14)add("LIVE_TLS_CERT_NEAR_EXPIRY","Live HTTPS certificate is close to expiry","low",5,"The presented TLS certificate is due to expire in approximately "+tls.data.daysUntilExpiry+" days.","This is a site-maintenance warning, not proof of phishing. Avoid sensitive actions if the browser also reports a certificate warning.");
    if(tls.data.chainComplete===false||tls.data.problems.length>0)add("LIVE_TLS_CHAIN_PROBLEM","TLS certificate chain has validation problems","medium",12,"The TLS inspection provider reported: "+(tls.data.problems.join("; ")||"an incomplete certificate chain")+".","Do not bypass browser certificate warnings. Verify the destination independently.");
  }
  if(dns.status==="available"&&dns.data?.records.length===0)add("DNS_NO_PUBLIC_RECORDS","No public DNS records were returned","medium",15,"The public DNS lookup returned no A, AAAA, MX, NS or TXT answers.","Confirm the domain spelling and verify the domain through its official registrar.");
  if(certificateTransparency.status==="available"&&certificateTransparency.data?.expired===true)add("CT_LATEST_CERT_EXPIRED","Latest certificate-transparency record is expired","low",5,"The latest certificate record found in Certificate Transparency has an expiry date in the past. This does not establish the live endpoint's current certificate state.","Open the organisation's official site independently and check its browser TLS certificate before entering information.");
  if(registration.status==="available"&&registration.data?.ageDays!==null&&registration.data?.ageDays!==undefined&&registration.data.ageDays<30)add("DOMAIN_RECENTLY_REGISTERED","Domain was registered recently","medium",15,"RDAP registration data indicates an age of approximately "+registration.data.ageDays+" days.","Treat unexpected links on a recently registered domain with extra caution and verify the sender independently.");
  const content=websiteContent.data;
  if(websiteContent.status==="available"&&content){
    findings.push(...content.businessFindings);
    if(content.redirected)add("CROSS_DOMAIN_REDIRECT","Website reader followed a redirect to another hostname","medium",15,"The content reader reports a final hostname different from the submitted hostname: "+content.fetchedUrl+".","Check whether the redirect destination belongs to the organisation you intended to visit.");
    if(content.indicators.includes("password_input"))add("LIVE_PASSWORD_INPUT","Live page contains a password input","info",0,"The remote page content includes a password input. Legitimate sites also use password fields, so this is context rather than proof of phishing.","Only enter credentials after confirming the exact domain independently.");
    if(content.indicators.includes("form_detected"))add("LIVE_FORM_DETECTED","Live page contains a form","info",0,"The remote page content contains a form or submit control. Forms are common on legitimate sites too.","Check the domain and the purpose of the form before submitting personal information.");
    if(content.indicators.includes("credential_verification_language"))add("LIVE_CREDENTIAL_LANGUAGE","Page requests verification or one-time-code information","medium",15,"The live page text contains language associated with passwords, one-time codes or identity verification.","Never share one-time codes or recovery codes from an unexpected link.");
    if(content.indicators.includes("crypto_wallet_or_secret_request"))add("LIVE_CRYPTO_SECRET_REQUEST","Page contains crypto-wallet or recovery-secret language","high",35,"The live page text refers to wallet connection, seed phrases, recovery phrases or private keys.","Never enter a seed phrase or private key into a website reached through an unsolicited message.");
    if(content.indicators.includes("urgent_account_pressure"))add("LIVE_URGENT_ACCOUNT_PRESSURE","Page uses urgent account-pressure language","medium",15,"The live page text combines urgency with account locking, suspension or verification language.","Verify the alert through the organisation's official app or website, not the supplied link.");
    if(content.indicators.includes("prize_or_financial_lure"))add("LIVE_PRIZE_OR_FINANCIAL_LURE","Page contains prize or financial-lure language","medium",15,"The live page text includes prize, reward or guaranteed-profit wording.","Be cautious of unexpected prizes, guaranteed returns or requests for upfront fees.");
    if(content.indicators.includes("payment_data_language"))add("LIVE_PAYMENT_DATA_LANGUAGE","Page refers to payment or bank details","info",0,"The live page text contains payment or card-data language. This alone is not proof of fraud.","Only provide payment details after independently verifying the merchant and domain.");
    if(content.indicators.includes("domain_parked_or_for_sale"))add("DOMAIN_PARKED_OR_FOR_SALE","Domain appears parked or offered for sale","medium",20,"The content provider returned domain-parking or domain-for-sale wording rather than a verifiable operating business page. The advertised service could not be inspected at this hostname.","Do not register, deposit money or trust earning claims on a parked domain. Confirm the exact active website address with the promoter and verify the operator independently.");
  }
  const limitations=[
    "Live page content is retrieved through Firecrawl keyless scraping. Only the public hostname and path are sent; query strings, fragments and embedded credentials are removed. Keyless requests are rate-limited per source IP and may be unavailable when the daily allowance is exhausted.",
    "Firecrawl receives no browser cookies, passwords or authentication headers from this scanner. The scanner checks DNS answers and sends a page for extraction only when all returned A/AAAA addresses are public.",
    "Live TLS certificate details and chain validation are obtained through Trustico SSL Tools. The hostname only is sent to that provider, which has a shared unauthenticated rate limit. Certificate Transparency is a separate public issuance-history source.",
    "Redirect information is limited to the final URL reported by the content reader, not a complete packet-level redirect trace.",
    "Page content can change, be personalised, or be hidden behind JavaScript or access controls. A content check is not a complete malware sandbox."
  ];
  return {checkedAt:new Date().toISOString(),registrableDomain,privacy:"Firecrawl receives only the public URL hostname and path. Query strings, fragments, embedded credentials and browser cookies are not forwarded. The TLS provider receives only the HTTPS hostname and has a shared rate limit of 100 requests per hour.",dns,certificateTransparency,tls,registration,websiteContent,findings,limitations};
}
