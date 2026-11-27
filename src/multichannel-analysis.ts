export type AnalysisChannel = "sms" | "email" | "phone" | "whatsapp" | "telegram" | "social" | "job" | "investment" | "qr" | "file";
export type RiskLevel = "low" | "guarded" | "high" | "critical";
export interface Signal { code:string; title:string; severity:"info"|"low"|"medium"|"high"; points:number; evidence:string; recommendation:string }
export interface MultiChannelResult {
  channel:AnalysisChannel; score:number; riskLevel:RiskLevel; confidence:"limited"|"moderate";
  verdict:"suspicious_signals_detected"|"no_obvious_signals"|"insufficient_evidence";
  signals:Signal[]; extractedUrls:string[]; phoneNumbers:string[]; limitations:string[];
  checks:Record<string,string>;
}
const URL_RE=/https?:\/\/[^\s<>"']+/gi;
const PHONE_RE=/(?:\+\d{1,3}[\s().-]*)?(?:\d[\s().-]*){7,14}\d/g;
const URGENCY=/(urgent|immediately|within\s+\d+\s*(minutes?|hours?)|act now|account.{0,20}(suspend|blocked|close)|haraka|mara moja|akaunti.{0,20}(fungwa|simamishwa))/i;
const CREDENTIALS=/(?:\b(?:password|passcode|pin|otp|one[- ]time code|verification code|login details)\b|nenosiri|nywila|namba ya siri|msimbo wa uthibitisho)/i;
const PAYMENT=/(send (money|payment|fee)|pay (now|a fee|to unlock)|gift card|crypto|bitcoin|wallet address|m-pesa|mpesa|tigo pesa|airtel money|mixx by yas|lipa sasa|tuma pesa|ada ya usajili)/i;
const IMPERSONATION=/(?:\b(?:bank|support team|customer care|tax authority|police|government|TRA|NIDA|TCRA)\b|mamlaka|benki|huduma kwa wateja)/i;
const REWARD=/(you (have )?won|prize|giveaway|claim your|free gift|umejishindia|zawadi|bahati nasibu)/i;
const SHORTENERS=new Set(["bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rb.gy","shorturl.at","rebrand.ly"]);
const COUNTRY_CODES:Record<string,string>={TZ:"255",KE:"254",UG:"256",RW:"250",BI:"257",ZM:"260",MW:"265",ZA:"27",NG:"234",GH:"233",US:"1",GB:"44",IN:"91"};
function add(signals:Signal[],code:string,title:string,severity:Signal["severity"],points:number,evidence:string,recommendation:string){signals.push({code,title,severity,points,evidence,recommendation});}
function cleanPhone(value:string):string{return value.replace(/[^\d+]/g,"");}
function assessPhones(text:string,countryCode?:string):{numbers:string[];signals:Signal[];checks:Record<string,string>}{
 const matches=[...text.matchAll(PHONE_RE)].map(m=>cleanPhone(m[0])).filter(v=>v.replace(/\D/g,"").length>=8);
 const numbers=[...new Set(matches)].slice(0,10),signals:Signal[]=[];
 if(!numbers.length)return {numbers,signals,checks:{phone:"No phone number found"}};
 for(const n of numbers){
  const digits=n.replace(/\D/g,"");
  if(digits.length<8||digits.length>15||!/^\+?\d+$/.test(n)){add(signals,"PHONE_INVALID_FORMAT","Invalid phone-number format","medium",18,"A detected number does not fit the international E.164 length/format rules.","Verify the number independently before calling or sending money.");continue;}
  if(countryCode&&COUNTRY_CODES[countryCode.toUpperCase()]&&!digits.startsWith(COUNTRY_CODES[countryCode.toUpperCase()])&&digits.length>=10){
   add(signals,"PHONE_COUNTRY_MISMATCH","Number does not match selected country code","low",7,"The number's calling code differs from the selected country.","Check whether the sender has a legitimate reason to use an international number.");
  }
 }
 return {numbers,signals,checks:{phone:"Format checked only; carrier, allocation, SIM registration, reachability, VoIP and disposable-number status are not verified"}};
}
export function analyzeMultiChannel(input:{channel:AnalysisChannel;content:string;countryCode?:string;headers?:string;fileName?:string;mimeType?:string;fileSignature?:string}):MultiChannelResult{
 const content=input.content.trim();
 if(!content||content.length>12000)throw new Error("Provide content between 1 and 12000 characters.");
 const channel=input.channel;
 const signals:Signal[]=[];
 const lower=content.toLowerCase();
 const urls=(content.match(URL_RE)||[]).map(u=>u.replace(/[),.;!?]+$/,"")).slice(0,20);
 const phone=assessPhones(content,input.countryCode);
 for(const s of phone.signals)signals.push(s);
 if(URGENCY.test(content))add(signals,"SCAM_URGENCY","Pressure or urgency language","medium",13,"The content pressures the recipient to act quickly or threatens account consequences.","Pause and verify through an independently obtained official contact.");
 if(CREDENTIALS.test(content))add(signals,"CREDENTIAL_HARVESTING","Request for credentials or verification codes","high",27,"The content references passwords, PINs, OTPs or verification codes.","Never share an OTP, PIN or password with a sender or caller.");
 if(PAYMENT.test(content))add(signals,"PAYMENT_REQUEST","Payment or money-transfer language","medium",17,"The content asks for money, fees, mobile-money transfers or cryptocurrency.","Verify the payment request with the organisation using its official channel.");
 if(IMPERSONATION.test(content)&&(/click|link|reply|send|call|verify|confirm|login|account|tuma|bonyeza|jibu|piga/i.test(content)))add(signals,"POSSIBLE_IMPERSONATION","Possible organisation impersonation","medium",16,"An organisation or authority is referenced alongside a requested action.","Contact the organisation using a number or website found independently.");
 if(REWARD.test(content))add(signals,"UNEXPECTED_REWARD","Unexpected prize or reward claim","medium",15,"The message uses prize, giveaway or unexpected reward language.","Do not pay a fee or provide personal data to claim an unsolicited prize.");
 for(const url of urls){try{const parsed=new URL(url);if(SHORTENERS.has(parsed.hostname.toLowerCase()))add(signals,"SHORTENED_URL","Shortened link hides its destination","medium",12,"A URL-shortening domain was found: "+parsed.hostname,"Do not open it until its final destination is checked.");if(parsed.protocol!=="https:")add(signals,"INSECURE_LINK","Link does not use HTTPS","low",6,"A submitted link uses HTTP.","Avoid submitting sensitive information over an unencrypted connection.");}catch{add(signals,"URL_PARSE_WARNING","A link could not be parsed","low",4,"A URL-like string could not be parsed reliably.","Check the link carefully and do not open it to test it.");}}
 if(channel==="email"){
  const h=(input.headers||"").toLowerCase();
  const headerLines=h.split(String.fromCharCode(10));
  const authResults=headerLines.find(line=>line.startsWith("authentication-results:"))||h;
  for(const key of ["spf","dkim","dmarc"]){
   const m=authResults.match(new RegExp(key+"=([a-z]+)","i"));
   if(m&&m[1]!=="pass")add(signals,"EMAIL_"+key.toUpperCase()+"_NOT_PASSING",key.toUpperCase()+" authentication not passing","medium",10,"Provided header reports "+key.toUpperCase()+"="+m[1].slice(0,40),"Treat sender authenticity as unverified; inspect full Received and Authentication-Results headers.");
   else if(m&&m[1]==="pass")add(signals,"EMAIL_"+key.toUpperCase()+"_PASS",key.toUpperCase()+" authentication passed","info",0,"Provided header text reports "+key.toUpperCase()+"=pass.","A passing result helps authenticate the sending domain but does not prove the message content is legitimate.");
  }
  const fromLine=headerLines.find(line=>line.startsWith("from:"))||"";
  const replyLine=headerLines.find(line=>line.startsWith("reply-to:"))||"";
  const fromDomain=fromLine.match(/@([a-z0-9.-]+)/)?.[1];
  const replyDomain=replyLine.match(/@([a-z0-9.-]+)/)?.[1];
  if(fromDomain&&replyDomain&&fromDomain!==replyDomain)add(signals,"EMAIL_REPLY_TO_DOMAIN_MISMATCH","Reply-To domain differs from From domain","medium",14,"From and Reply-To headers show different domains.","Verify the reply destination independently before responding.");
  if(!h)add(signals,"EMAIL_HEADERS_MISSING","Email headers were not supplied","info",0,"Only message text was provided; sender authentication cannot be assessed.","Include full original headers for SPF, DKIM, DMARC and routing analysis.");
 }
 if(channel==="phone"&&!phone.numbers.length)add(signals,"NO_PHONE_FOUND","No phone number found","info",0,"No recognisable phone number was found in the submitted content.","Enter a number with its international calling code, for example +255…");
 if(channel==="qr"&&urls.length===0)add(signals,"QR_PAYLOAD_NO_URL","No URL found in QR payload","info",0,"The supplied QR payload did not contain a web URL.","Decode the QR with your device and paste its full payload here; image decoding is not enabled in this version.");
 if(channel==="file"){
  const name=(input.fileName||"").toLowerCase(),mime=(input.mimeType||"").toLowerCase();
  if(/\.(exe|scr|js|jse|vbs|vbe|bat|cmd|ps1|hta|msi|apk|jar|iso|img|lnk)$/i.test(name))add(signals,"RISKY_ATTACHMENT_TYPE","Potentially executable attachment","high",24,"Filename extension indicates a script, executable, shortcut or disk image.","Do not open the attachment; verify the sender and scan the file with endpoint security.");
  if(mime.includes("octet-stream"))add(signals,"GENERIC_ATTACHMENT_MIME","Generic binary MIME type","low",5,"The supplied MIME type is application/octet-stream.","Confirm the real file type using a trusted local security tool.");
  const ext=name.split(".").pop()||"";
  const expected:Record<string,string>={pdf:"pdf",png:"png",jpg:"jpeg",jpeg:"jpeg",gif:"gif",exe:"pe",dll:"pe",msi:"pe",zip:"zip",doc:"ole",xls:"ole",ppt:"ole",docx:"zip",xlsx:"zip",pptx:"zip",apk:"zip",jar:"zip"};
  if(input.fileSignature&&expected[ext]&&expected[ext]!==input.fileSignature)add(signals,"FILE_TYPE_EXTENSION_MISMATCH","File extension does not match detected file signature","high",22,"The file name extension suggests "+ext+" but the local header bytes resemble "+input.fileSignature+".","Do not open the file. Treat extension and content mismatch as suspicious and scan it with endpoint security.");
  add(signals,"FILE_CONTENT_NOT_INSPECTED","File contents were not uploaded or detonated","info",0,"This check uses only the supplied filename, MIME type and optional accompanying text.","A full malware verdict requires safe file hashing, static analysis and sandboxing.");
 }
 if(channel==="job"&&/(registration fee|processing fee|training fee|pay to apply|ada ya maombi|lipa ili kupata kazi)/i.test(content))add(signals,"JOB_FEE_REQUEST","Job offer requests an upfront fee","high",24,"The job content appears to request an upfront application or processing fee.","Verify the employer independently; legitimate recruitment should not rely on suspicious upfront payments.");
 if(channel==="investment"&&/(guaranteed returns?|risk[- ]free|double your money|daily profit|100% profit|faida ya uhakika|ongeza pesa mara mbili)/i.test(content))add(signals,"INVESTMENT_GUARANTEE","Unrealistic or guaranteed investment returns","high",25,"The content promises unusually certain or high returns.","Treat guaranteed-profit claims as a major warning sign and verify regulatory authorisation.");
 const score=Math.min(100,signals.reduce((sum,s)=>sum+s.points,0));
 const riskLevel=score>=65?"critical":score>=40?"high":score>=18?"guarded":"low";
 const meaningful=signals.filter(s=>s.points>0).length;
 const limitations=[
  "This is an initial evidence-based text assessment, not proof that a sender or number is fraudulent or safe.",
  "No submitted URL was opened. Extracted URLs are indicators only and require a separate URL scan.",
  "Phone number format does not establish allocation, active status, subscriber identity, SIM registration, carrier, VoIP or disposable-number status.",
  "Email authentication can only be assessed when trustworthy original headers are supplied; pasted header text is not independently authenticated.",
  "Messaging and social platforms are not queried for private account data or live reputation in this version."
 ];
 if(channel==="qr")limitations.push("This version analyses pasted QR payload text; it does not decode QR images directly.");
 if(channel==="file")limitations.push("This version does not upload, execute, unpack or sandbox files.");
 return {channel,score,riskLevel,confidence:meaningful>=2?"moderate":"limited",verdict:meaningful?"suspicious_signals_detected":"no_obvious_signals",signals,extractedUrls:urls,phoneNumbers:phone.numbers,limitations,checks:{...phone.checks,content:"Local rule-based analysis completed",externalReputation:"Not configured",carrierLookup:"Not configured",aiReview:"Not configured"}};
}
