import { getDomain } from "tldts";
import type { BrandMatch } from "./brand-intelligence";
export interface GraphNode { id:string;type:"hostname"|"registrable_domain"|"ip"|"certificate_name"|"threat_domain"|"brand"|"campaign";label:string;source:string }
export interface GraphEdge { from:string;to:string;type:"registered_under"|"resolves_to"|"shares_certificate"|"provider_related"|"impersonates";confidence:"low"|"medium"|"high";evidence:string;source:string;interpretation:string }
export interface RelationshipGraph { nodes:GraphNode[];edges:GraphEdge[];limitations:string[] }
export function buildRelationshipGraph(input:{hostname:string;ips?:string[];certificateNames?:string[];relatedDomains?:string[];campaignBrand?:string|null;brands?:BrandMatch[]}):RelationshipGraph{
 const nodes:GraphNode[]=[];const edges:GraphEdge[]=[];
 const addNode=(node:GraphNode)=>{if(!nodes.some(n=>n.id===node.id))nodes.push(node)};
 const addEdge=(edge:GraphEdge)=>{if(!edges.some(e=>e.from===edge.from&&e.to===edge.to&&e.type===edge.type))edges.push(edge)};
 const host=input.hostname.toLowerCase();const root=getDomain(host)||host;const hostId="host:"+host;const rootId="domain:"+root;
 addNode({id:hostId,type:"hostname",label:host,source:"submitted_url"});
 addNode({id:rootId,type:"registrable_domain",label:root,source:"public_suffix_list"});
 if(host!==root)addEdge({from:hostId,to:rootId,type:"registered_under",confidence:"high",evidence:"Public Suffix List identifies the registrable domain.",source:"tldts",interpretation:"This is a DNS naming relationship, not an ownership verification."});
 for(const ip of [...new Set(input.ips||[])].slice(0,8)){
  if(!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)&&!ip.includes(":"))continue;
  const id="ip:"+ip;addNode({id,type:"ip",label:ip,source:"DNS-over-HTTPS"});
  addEdge({from:hostId,to:id,type:"resolves_to",confidence:"high",evidence:"The DNS provider returned this address for the hostname at scan time.",source:"Cloudflare DNS-over-HTTPS",interpretation:"CDNs and shared hosting mean an IP address does not prove common ownership."});
 }
 for(const name of [...new Set(input.certificateNames||[])].slice(0,12)){
  const normalized=name.replace(/^\*\./,"").toLowerCase();if(normalized===host||normalized===root||!normalized.includes("."))continue;
  const id="cert:"+normalized;addNode({id,type:"certificate_name",label:normalized,source:"TLS certificate SAN"});
  addEdge({from:hostId,to:id,type:"shares_certificate",confidence:"low",evidence:"Both names appear in the inspected leaf certificate's Subject Alternative Name list.",source:"TLS certificate",interpretation:"A shared certificate may be issued for unrelated customers on shared hosting; it does not establish common ownership."});
 }
 for(const domain of [...new Set(input.relatedDomains||[])].slice(0,10)){
  const normalized=domain.toLowerCase();if(normalized===host||!normalized.includes("."))continue;
  const id="threat:"+normalized;addNode({id,type:"threat_domain",label:normalized,source:"PhishDestroy related-domain intelligence"});
  addEdge({from:hostId,to:id,type:"provider_related",confidence:"medium",evidence:"The domain-intelligence provider returned this domain as related to the submitted hostname.",source:"PhishDestroy",interpretation:"Provider relationship is an investigative lead; it may reflect campaign or infrastructure similarity, not proven common ownership."});
 }
 if(input.campaignBrand){
  const id="campaign:"+input.campaignBrand.toLowerCase();addNode({id,type:"campaign",label:input.campaignBrand,source:"PhishDestroy campaign metadata"});
  addEdge({from:hostId,to:id,type:"provider_related",confidence:"medium",evidence:"The provider associated the hostname with this campaign label.",source:"PhishDestroy",interpretation:"Campaign labels are provider intelligence and should be corroborated."});
 }
 for(const brand of (input.brands||[]).slice(0,3)){
  const id="brand:"+brand.brand.toLowerCase();addNode({id,type:"brand",label:brand.brand,source:"Curated brand registry"});
  addEdge({from:hostId,to:id,type:"impersonates",confidence:brand.confidence,evidence:brand.evidence,source:brand.source,interpretation:"This is a possible impersonation relationship, not a statement that the brand owns or operates the hostname."});
 }
 return {nodes:nodes.slice(0,40),edges:edges.slice(0,40),limitations:[
  "Infrastructure links are not ownership links. Shared IPs, CDNs, certificates, hosting providers and templates can connect unrelated organisations.",
  "Provider-related domains are leads for investigation and require independent corroboration.",
  "The graph contains only relationships returned by the sources available during this scan; missing edges do not prove isolation."
 ]};
}
