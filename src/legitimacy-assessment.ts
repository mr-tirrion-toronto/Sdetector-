import type { BrandAssessment } from "./brand-intelligence";
import type { LiveInspection } from "./live-inspection";
import type { ThreatIntelResult } from "./threat-intel";
import type { ExternalThreatIntelResult } from "./external-threat-intel";
import type { IndependentEvidence } from "./independent-evidence";
import type { Finding } from "./analyzer";

export interface LegitimacyCheck {
 id:string;label:string;status:"warning"|"observed"|"no_match"|"unavailable"|"manual_review";
 evidence:string;source:string;
}
export interface LegitimacyAssessment {
 status:"known_threat"|"possible_impersonation"|"suspicious_business_claims"|"evidence_available_not_verified"|"not_verified";
 label:string;summary:string;checks:LegitimacyCheck[];positiveObservations:number;warnings:number;
 notVerified:string[];limitations:string[];
}
export function assessLegitimacy(input:{
 brands:BrandAssessment;live:LiveInspection|null;threat:ThreatIntelResult;
 externalThreat?:ExternalThreatIntelResult;
 findings:Finding[];independentEvidence:IndependentEvidence;
}):LegitimacyAssessment{
 const checks:LegitimacyCheck[]=[];
 const threat=input.threat;
 const externalMatches=input.externalThreat?.providers.filter(provider=>provider.confirmed&&provider.matched)??[];
 const hasKnownThreat=threat.matched||externalMatches.length>0;
 const threatSources=[...threat.feeds.filter(f=>f.status==="ok").map(f=>f.source),...externalMatches.map(provider=>provider.source.replace(/_/g," "))];
 checks.push(hasKnownThreat
  ?{id:"threat_reputation",label:"Threat reputation",status:"warning",evidence:"A known-threat indicator matched one or more configured threat-intelligence records.",source:threatSources.join(", ")||"Threat intelligence"}
  :threat.status==="available"
   ?{id:"threat_reputation",label:"Threat reputation",status:"no_match",evidence:"No exact match was found in the currently available feeds. This does not prove safety or legitimacy.",source:threat.feeds.filter(f=>f.status==="ok").map(f=>f.source).join(", ")}
   :{id:"threat_reputation",label:"Threat reputation",status:"unavailable",evidence:"Threat-intelligence coverage was unavailable, partial or not configured; no clean verdict can be inferred.",source:"Configured threat-intelligence providers"});
 const matches=input.brands.matches;
 checks.push(matches.length
  ?{id:"brand_identity",label:"Brand/domain consistency",status:"warning",evidence:matches.map(m=>m.brand+" · "+m.evidence).join(" " ),source:"Curated official-domain registry"}
  :{id:"brand_identity",label:"Brand/domain consistency",status:"no_match",evidence:"No match was found in the current curated brand registry. The registry is not exhaustive and does not certify the operator.",source:"Curated official-domain registry"});
 const live=input.live;
 const tls=live?.tls;
 checks.push(tls?.status==="available"&&tls.data
  ?tls.data.hostnameMatch===true
   ?{id:"tls",label:"TLS hostname coverage",status:"observed",evidence:"The inspected TLS certificate covers the submitted hostname. Encryption does not prove the operator is legitimate.",source:"Live TLS certificate inspection"}
   :tls.data.hostnameMatch===false
    ?{id:"tls",label:"TLS hostname coverage",status:"warning",evidence:"The inspected TLS certificate does not cover the submitted hostname.",source:"Live TLS certificate inspection"}
    :{id:"tls",label:"TLS hostname coverage",status:"unavailable",evidence:"A certificate was inspected but hostname coverage could not be confirmed.",source:"Live TLS certificate inspection"}
  :{id:"tls",label:"TLS hostname coverage",status:"unavailable",evidence:"Live TLS certificate inspection was unavailable.",source:"TLS provider"});
 const registration=live?.registration;
 checks.push(registration?.status==="available"&&registration.data
  ?{id:"registration",label:"Domain registration",status:registration.data.ageDays!==null&&registration.data.ageDays<30?"warning":"observed",evidence:"RDAP reports "+(registration.data.ageDays===null?"an unknown domain age":registration.data.ageDays+" days since registration")+(registration.data.registrar?"; registrar: "+registration.data.registrar:"")+". RDAP registrant identity may be redacted.",source:"RDAP"}
  :{id:"registration",label:"Domain registration",status:"unavailable",evidence:"Registration information could not be retrieved.",source:"RDAP"});
 const dns=live?.dns;
 checks.push(dns?.status==="available"
  ?{id:"dns",label:"DNS infrastructure",status:"observed",evidence:"Public DNS records were returned for the hostname. DNS resolution is an infrastructure observation, not a trust signal.",source:"Cloudflare DNS-over-HTTPS"}
  :{id:"dns",label:"DNS infrastructure",status:"unavailable",evidence:"Public DNS lookup was unavailable.",source:"Cloudflare DNS-over-HTTPS"});
 const page=live?.websiteContent.data;
 const disclosure=page?.operatorDisclosure;
 checks.push(disclosure
  ?disclosure.legalEntityDetected&&disclosure.contactDetailsDetected&&disclosure.termsLinkDetected&&disclosure.privacyLinkDetected
   ?{id:"operator_disclosure",label:"Public operator disclosure",status:"observed",evidence:"The captured page contains a legal-entity indicator, contact details, Terms and Privacy links. These statements have not been independently verified.",source:"Static public-page inspection"}
   :{id:"operator_disclosure",label:"Public operator disclosure",status:"warning",evidence:"One or more expected operator disclosures were not detected in the captured page. Page capture may be incomplete.",source:"Static public-page inspection"}
  :{id:"operator_disclosure",label:"Public operator disclosure",status:"unavailable",evidence:"The public page could not be inspected.",source:"Static public-page inspection"});
 const advanceFee=input.findings.filter(f=>["BUSINESS_PAY_TO_WITHDRAW","BUSINESS_UPFRONT_WORK_FEE","BUSINESS_RECHARGE_TO_EARN"].includes(f.code));
 checks.push(advanceFee.length
  ?{id:"business_model",label:"Business model / payment claims",status:"warning",evidence:advanceFee.map(f=>f.title+": "+f.evidence).join(" "),source:"Static public-page content analysis"}
  :{id:"business_model",label:"Business model / payment claims",status:"no_match",evidence:"No configured advance-fee or recharge-to-earn signal was detected in the captured public page. This is not proof of a legitimate business model.",source:"Static public-page content analysis"});
 checks.push({id:"official_registry",label:"Official company / regulator records",status:"manual_review",evidence:"Use the official registry links below to confirm exact legal identity, registration status, licence scope and operator contact details. These records have not been queried automatically.",source:input.independentEvidence.sources.filter(s=>s.category==="company_registry"||s.category==="official_guidance").map(s=>s.label).join("; ")});
 checks.push({id:"payouts",label:"Actual customer / worker payouts",status:"manual_review",evidence:"No bank settlement, payment-processor record, escrow evidence or independently verified payout was obtained. Website testimonials and screenshots are not proof.",source:"Not available from public-page inspection"});
 const warnings=checks.filter(c=>c.status==="warning").length;
 const positiveObservations=checks.filter(c=>c.status==="observed").length;
 const status:LegitimacyAssessment["status"]=hasKnownThreat?"known_threat":matches.length?"possible_impersonation":advanceFee.length?"suspicious_business_claims":positiveObservations>=2?"evidence_available_not_verified":"not_verified";
 const label=status==="known_threat"?"Known threat detected":status==="possible_impersonation"?"Possible brand impersonation":status==="suspicious_business_claims"?"Suspicious business/payment claims":status==="evidence_available_not_verified"?"Some positive observations · Not verified":"Legitimacy not verified";
 const summary=status==="known_threat"?"A configured threat-intelligence source matched this hostname or URL. Do not interact with it.":
  status==="possible_impersonation"?"The submitted domain has evidence consistent with possible brand impersonation. Confirm the destination through the brand's independently sourced official channel.":
  status==="suspicious_business_claims"?"The public page contains payment or earning claims that require careful verification, especially any request for deposits or fees to unlock earnings.":
  status==="evidence_available_not_verified"?"Some technical and disclosure observations are available, but they do not establish who controls the domain or prove the business is legitimate.":
  "There is not enough independent evidence to establish the website operator's identity or legitimacy.";
 return {status,label,summary,checks,positiveObservations,warnings,notVerified:[
  "Domain registrant / beneficial owner identity and control of this website.",
  "Company registration and regulatory licence validity in the relevant jurisdiction.",
  "Whether the claimed service is actually delivered to customers.",
  "Whether advertised wages, withdrawals or payouts are genuinely paid.",
  "Whether the website is officially operated by any brand whose name it mentions."
 ],limitations:[
  "This is an evidence checklist, not a legal certification or a guarantee that a website is legitimate.",
  "A TLS certificate, domain age, DNS response, company record or lack of a threat-feed match cannot independently prove trustworthiness.",
  "Manual registry links are investigation leads; the scanner has not completed those external checks."
 ]};
}
