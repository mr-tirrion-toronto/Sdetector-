export interface PhoneIntelligence {
 status:"available"|"not_configured"|"unavailable";
 provider:"Abstract Phone Validation"|"none";
 valid:boolean|null;
 carrier:string|null;
 lineType:string|null;
 countryCode:string|null;
 riskScore:number|null;
 limitations:string[];
}
interface AbstractResponse { valid?:boolean; carrier?:string|null; line_type?:string|null; country_code?:string|null; risk_score?:number|null }
export async function lookupPhoneIntelligence(phone:string,apiKey?:string):Promise<PhoneIntelligence>{
 const base={provider:"none" as const,valid:null,carrier:null,lineType:null,countryCode:null,riskScore:null};
 if(!apiKey)return {status:"not_configured",...base,limitations:["Phone carrier and line-type intelligence is not configured. Add an Abstract Phone Validation API key to enable provider lookups.","A provider lookup cannot by itself prove who owns a SIM or whether it is registered to the person claiming it."]};
 try{
  const url=new URL("https://phonevalidation.abstractapi.com/v1/");
  url.searchParams.set("api_key",apiKey);
  url.searchParams.set("phone",phone);
  const response=await fetch(url.toString(),{headers:{accept:"application/json"},signal:AbortSignal.timeout(8000)});
  if(!response.ok)return {status:"unavailable",...base,limitations:["Phone intelligence provider returned HTTP "+response.status+". No carrier or line-type conclusion was made."]};
  const data=await response.json() as AbstractResponse;
  return {
   status:"available",provider:"Abstract Phone Validation",
   valid:typeof data.valid==="boolean"?data.valid:null,
   carrier:typeof data.carrier==="string"?data.carrier:null,
   lineType:typeof data.line_type==="string"?data.line_type:null,
   countryCode:typeof data.country_code==="string"?data.country_code:null,
   riskScore:typeof data.risk_score==="number"&&Number.isFinite(data.risk_score)?data.risk_score:null,
   limitations:["Carrier and line type are provider-supplied intelligence and can be incomplete or stale.","A valid number or carrier result does not prove that a SIM is active, registered to a named person, or controlled by the sender.","VoIP or virtual line classification is a risk signal, not proof of fraud."]
  };
 }catch{
  return {status:"unavailable",...base,limitations:["Phone intelligence provider could not be reached. No carrier or line-type conclusion was made."]};
 }
}
