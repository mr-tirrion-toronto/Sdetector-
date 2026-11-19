import type { Finding } from "./analyzer";
import { getDomain } from "tldts";

export const BRAND_REGISTRY_VERSION = "2026-11-19.1";
interface BrandEntry { name:string; domains:string[]; aliases:string[] }
const BRANDS:BrandEntry[] = [
  {name:"Google",domains:["google.com","google.co.tz"],aliases:["google","gmail","youtube"]},
  {name:"Microsoft",domains:["microsoft.com","microsoftonline.com","live.com","office.com"],aliases:["microsoft","outlook","office365","office"]},
  {name:"Apple",domains:["apple.com","icloud.com"],aliases:["apple","icloud"]},
  {name:"Amazon",domains:["amazon.com","amazon.co.uk","amazon.co.tz"],aliases:["amazon"]},
  {name:"PayPal",domains:["paypal.com"],aliases:["paypal"]},
  {name:"Meta",domains:["meta.com","facebook.com","instagram.com","whatsapp.com"],aliases:["facebook","instagram","whatsapp","meta"]},
  {name:"Netflix",domains:["netflix.com"],aliases:["netflix"]},
  {name:"TikTok",domains:["tiktok.com"],aliases:["tiktok"]},
  {name:"Binance",domains:["binance.com"],aliases:["binance"]},
  {name:"Coinbase",domains:["coinbase.com"],aliases:["coinbase"]},
  {name:"Steam",domains:["steampowered.com","steamcommunity.com"],aliases:["steam"]},
  {name:"Roblox",domains:["roblox.com"],aliases:["roblox"]},
  {name:"DHL",domains:["dhl.com"],aliases:["dhl"]},
  {name:"FedEx",domains:["fedex.com"],aliases:["fedex"]},
  {name:"Visa",domains:["visa.com"],aliases:["visa"]},
  {name:"Mastercard",domains:["mastercard.com"],aliases:["mastercard"]},
  {name:"CRDB Bank",domains:["crdbbank.co.tz","crdbbank.com"],aliases:["crdb","crdbbank"]},
  {name:"NMB Bank",domains:["nmbbank.co.tz"],aliases:["nmb","nmbbank"]},
  {name:"NBC Tanzania",domains:["nbc.co.tz"],aliases:["nbc"]},
  {name:"Tanzania Revenue Authority",domains:["tra.go.tz"],aliases:["tra","traonline"]},
  {name:"NIDA Tanzania",domains:["nida.go.tz"],aliases:["nida"]},
  {name:"Vodacom Tanzania",domains:["vodacom.co.tz"],aliases:["vodacom","mpesa"]},
  {name:"Airtel",domains:["airtel.com","airtel.co.tz"],aliases:["airtel","airtelmoney"]},
  {name:"Yas Tanzania",domains:["yas.co.tz"],aliases:["yas","tigopesa"]}
];

function distance(a:string,b:string):number {
  const row=Array.from({length:b.length+1},(_,i)=>i);
  for(let i=1;i<=a.length;i++){
    let previous=row[0]; row[0]=i;
    for(let j=1;j<=b.length;j++){
      const old=row[j];
      row[j]=Math.min(row[j]+1,row[j-1]+1,previous+(a[i-1]===b[j-1]?0:1));
      previous=old;
    }
  }
  return row[b.length];
}
function clean(value:string):string { return value.toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g,"").replace(/[^a-z0-9]/g,""); }
function isOfficial(host:string,domains:string[]):boolean {
  return domains.some(domain=>host===domain||host.endsWith("."+domain)||getDomain(host)===domain);
}
export interface BrandMatch {
  brand:string; officialDomains:string[]; matchType:"brand_in_hostname"|"lookalike_hostname"|"brand_in_page_title"|"punycode_brand_context";
  confidence:"medium"|"high"; evidence:string; score:number; source:"curated_official_domain_registry";
}
export interface BrandAssessment { status:"matches_found"|"no_match"|"not_checked"; registryVersion:string; matches:BrandMatch[]; findings:Finding[]; limitations:string[] }
export function detectBrandImpersonation(input:{hostname:string;pageTitle?:string|null;indicators?:string[];businessSignals?:string[]}):BrandAssessment {
  const host=input.hostname.toLowerCase().replace(/\.$/,"");
  const registrable=getDomain(host)||host;
  const hostParts=host.split(".");
  const searchable=hostParts.slice(0,-1).map(clean).filter(Boolean);
  const title=clean(input.pageTitle||"");
  const authContext=(input.indicators||[]).some(x=>["password_input","form_detected","credential_verification_language"].includes(x));
  const matches:BrandMatch[]=[];
  for(const brand of BRANDS){
    if(isOfficial(host,brand.domains)) continue;
    const aliases=brand.aliases.map(clean);
    const exact=searchable.some(part=>aliases.some(alias=>part.includes(alias)));
    const typo=searchable.some(part=>aliases.some(alias=>alias.length>=6&&part.length>=alias.length-2&&part.length<=alias.length+2&&distance(part,alias)<=1));
    const titleHit=authContext&&brand.aliases.some(alias=>title.includes(clean(alias)));
    const punycodeContext=hostParts.some(part=>part.startsWith("xn--"))&&titleHit;
    if(!exact&&!typo&&!titleHit) continue;
    const matchType:BrandMatch["matchType"]=punycodeContext?"punycode_brand_context":typo?"lookalike_hostname":exact?"brand_in_hostname":"brand_in_page_title";
    const score=punycodeContext?32:typo?28:exact?24:16;
    const evidence=punycodeContext
      ?"A punycode hostname is paired with a known brand name in a page title containing credential/form indicators."
      :typo?"A hostname label is within one edit of a known brand identifier, but the registrable domain is not in the curated official-domain list."
      :exact?"A brand identifier appears in the hostname, but the registrable domain is not in the curated official-domain list."
      :"A known brand appears in the page title alongside password/form indicators, while the hostname is not an official domain in this registry.";
    matches.push({brand:brand.name,officialDomains:brand.domains,matchType,confidence:typo||punycodeContext?"high":"medium",evidence,score,source:"curated_official_domain_registry"});
  }
  matches.sort((a,b)=>b.score-a.score);
  const top=matches.slice(0,3);
  const findings:Finding[]=top.map(match=>({
    code:"BRAND_IMPERSONATION_"+match.matchType.toUpperCase(),
    title:"Possible "+match.brand+" brand impersonation",
    severity:match.confidence==="high"?"high":"medium",
    points:match.score,
    evidence:match.evidence+" Observed registrable domain: "+registrable+". Expected official domains include: "+match.officialDomains.join(", ")+".",
    recommendation:"Do not sign in or provide payment details. Open the organisation's official domain from a trusted bookmark or independently verified source and compare the exact hostname."
  }));
  return {status:top.length?"matches_found":"no_match",registryVersion:BRAND_REGISTRY_VERSION,matches:top,findings,limitations:[
    "The brand registry is a curated detection list, not a complete list of every trademark or official domain.",
    "A brand-name match is a warning signal, not proof of impersonation. Legitimate resellers, fan sites and independent commentary can mention brands.",
    "Official-domain ownership must be checked independently; this module does not contact brand owners."
  ]};
}
