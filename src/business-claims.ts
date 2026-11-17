import type { Finding } from "./analyzer";

export interface BusinessClaimAssessment {
  model: "paid_chat_or_task_claim" | "online_earning_claim" | "not_detected";
  signals: string[];
  findings: Finding[];
  payoutVerification: "not_verified_from_public_page";
  operatorVerification: "not_independently_verified";
  operatorDisclosure: { legalEntityDetected: boolean; contactDetailsDetected: boolean; termsLinkDetected: boolean; privacyLinkDetected: boolean; operatorNameCandidates: string[] };
  note: string;
}

/**
 * Detects commercial earning and payout claims in public page text.
 * These are explainable rules, not an AI verdict and not proof of fraud.
 */
export function analyzeBusinessClaims(text: string, html = ""): BusinessClaimAssessment {
  const source = text.slice(0, 32000);
  const normalized = source.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
  const signals: string[] = [];
  const findings: Finding[] = [];
  const legalEntityDetected = /\b(?:limited|ltd\.?|llc|inc\.?|plc|gmbh|corp(?:oration)?|company registration (?:number|no\.?))\b/i.test(normalized);
  const contactDetailsDetected = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(normalized) || /(?:\+?\d[\d ()-]{7,}\d)/.test(normalized) || /(?:mailto:|tel:)/i.test(html);
  const termsLinkDetected = /<a\b[^>]*(?:href=["'][^"']*(?:terms|conditions|legal)[^"']*["']|>[^<]*(?:terms of service|terms and conditions|terms)[^<]*<)/i.test(html);
  const privacyLinkDetected = /<a\b[^>]*(?:href=["'][^"']*privacy[^"']*["']|>[^<]*privacy policy[^<]*<)/i.test(html);
  const operatorNameCandidates = Array.from(normalized.matchAll(/(?:operated by|owned by|registered as)\s+([^.;,]{3,80})/gi), match => match[1].trim()).filter(value => /limited|ltd|llc|inc|plc|gmbh|corporation/i.test(value)).slice(0, 3);

  const add = (code: string, title: string, severity: Finding["severity"], points: number,
    evidence: string, recommendation: string) => {
    findings.push({ code, title, severity, points, evidence, recommendation });
  };

  const chatToEarn = /get paid.{0,70}(chat|messag|talk)|paid.{0,50}(chat|messag|conversation)|earn.{0,60}(chat with foreigners|chatting with foreigners)|chat with (lonely )?foreigners.{0,70}(earn|paid|withdraw)/i.test(normalized);
  if (chatToEarn) {
    signals.push("paid_chat_business_claim");
    add("BUSINESS_PAID_CHAT_CLAIM", "Website advertises paid chatting as an earning opportunity", "info", 0,
      "The public page claims users can earn money by chatting with foreigners or by sending messages. This scan cannot verify that real customers exist or that payouts occur.",
      "Ask for written worker terms, the legal company name, a verifiable support contact, the exact pay rate and a withdrawal policy. Do not pay a registration or activation fee.");
  }

  const highDailyEarnings = /(earn|make|paid).{0,45}(at least|up to|minimum|guaranteed).{0,30}(\$|usd|tzs|ksh|ugx|ngn)|(?:\$|usd|tzs|ksh|ugx|ngn)\s?[\d,.]+.{0,35}(per day|daily|every day)/i.test(normalized);
  if (highDailyEarnings) {
    signals.push("specific_or_high_earnings_claim");
    add("BUSINESS_EARNINGS_PROMISE", "Specific or high daily earnings are advertised", "low", 8,
      "The page advertises a specific or minimum daily earning amount. The amount is a marketing claim and is not proof of actual average earnings or completed payouts.",
      "Request independently verifiable payout records, the number of active paying customers, the platform's revenue model and realistic median earnings after fees.");
  }

  const withdrawalFee = /(withdraw|withdrawal|cash\s?out|payout).{0,90}(fee|deposit|tax|unlock|activation|verification|recharge|top.?up|processing payment)|(fee|deposit|tax|unlock|activation|verification|recharge|top.?up).{0,90}(withdraw|withdrawal|cash\s?out|payout)/i.test(normalized);
  if (withdrawalFee) {
    signals.push("payment_required_to_withdraw_claim");
    add("BUSINESS_PAY_TO_WITHDRAW", "Page language suggests payment may be required to withdraw earnings", "high", 35,
      "The page text connects withdrawals or payouts with a fee, deposit, tax, unlock, activation, verification payment or recharge. Context must be checked, but paying money to release supposed earnings is a major advance-fee warning.",
      "Do not send money to unlock a balance. Verify the payment rule directly with a legally identified company using independently sourced contact details.");
  }

  const upfrontFee = /(registration|activation|verification|training|membership|unlock|starter|joining).{0,70}(fee|payment|deposit|recharge|top.?up|pay|tzs\s?[\d,.]+|\$\s?[\d,.]+)|(pay|deposit|recharge|top.?up).{0,70}(registration|activation|verification|training|membership|to start|to work|to earn)/i.test(normalized);
  if (upfrontFee) {
    signals.push("upfront_payment_for_work_claim");
    add("BUSINESS_UPFRONT_WORK_FEE", "Possible upfront payment to start earning", "high", 30,
      "The page connects registration, activation, training, membership or starting work with a payment, deposit or recharge. Confirm the exact requirement before treating this as a verified fee request.",
      "Do not pay to obtain a job or unlock work. Request a written contract and verify the company through an official registry and independently sourced contact details.");
  }

  const rechargeToEarn = /(recharge|top.?up).{0,70}(earn|task|commission|income|withdraw|level)|(earn|task|commission|income|withdraw).{0,70}(recharge|top.?up)/i.test(normalized);
  if (rechargeToEarn) {
    signals.push("recharge_to_earn_model");
    add("BUSINESS_RECHARGE_TO_EARN", "Earning claims are linked to account recharges or top-ups", "high", 30,
      "The public page connects earning, tasks, commissions or withdrawals with recharging or topping up an account. This resembles a known advance-payment pattern; verify the exact flow.",
      "Stop before recharging. A legitimate employer should not require you to deposit your own money to release wages or commissions.");
  }

  const referralRewards = /(refer|invite|recruit).{0,70}(earn|commission|bonus|income|reward)|(earn|commission|bonus|income).{0,70}(refer|invite|recruit)/i.test(normalized);
  if (referralRewards) {
    signals.push("referral_reward_claim");
    add("BUSINESS_REFERRAL_REWARD", "Referral-based rewards are advertised", "medium", 12,
      "The page links referrals or inviting other people with earnings, commissions or bonuses. Referral programmes can be legitimate, but risk increases if recruitment is the main source of income or requires payment.",
      "Check whether earnings come from a real service sold to independent customers rather than deposits or recruitment by new members.");
  }

  const payoutMarketing = /(instant payouts?|withdraw instantly|paid out|\$[\d,.]+\s*(paid|payout)|\b\d[\d,.]*\s*(members|users)\b|payment proof|proof of payment|success stor(y|ies)|testimonials?)/i.test(normalized);
  if (payoutMarketing) {
    signals.push("self_published_payout_or_social_proof_claim");
    add("BUSINESS_UNVERIFIED_PAYOUT_CLAIM", "Payout totals, testimonials or instant-payment claims are self-published", "info", 0,
      "The website displays promotional payout, membership, testimonial or instant-withdrawal claims. Content hosted by the same operator is not independent proof that users received money.",
      "Look for independently verifiable payment evidence, complaints and regulator or company records. Screenshots and testimonials can be fabricated or selectively presented.");
  }

  if (!legalEntityDetected || !contactDetailsDetected || !termsLinkDetected || !privacyLinkDetected) {
    signals.push("operator_identity_disclosure_incomplete");
    add("BUSINESS_OPERATOR_DETAILS_INCOMPLETE", "Public operator details are incomplete or not detectable", "info", 0,
      "The captured page does not expose all expected operator details (legal entity, contact channel, Terms of Service and Privacy Policy). This may reflect an incomplete page capture and is not proof of fraud. The operator has not been independently verified against an official company registry.",
      "Find the legal entity name and registration number, verify them in the relevant official company registry, and confirm the contact details and legal policies through independent sources.");
  }

  const earningClaimDetected = chatToEarn || highDailyEarnings || withdrawalFee || upfrontFee || rechargeToEarn || referralRewards || payoutMarketing;
  return {
    model: chatToEarn ? "paid_chat_or_task_claim" : earningClaimDetected ? "online_earning_claim" : "not_detected",
    signals,
    findings,
    payoutVerification: "not_verified_from_public_page",
    operatorVerification: "not_independently_verified",
    operatorDisclosure: { legalEntityDetected, contactDetailsDetected, termsLinkDetected, privacyLinkDetected, operatorNameCandidates },
    note: "Public page content cannot prove that a platform pays users. Verify payouts independently and never pay money to unlock wages or withdrawals."
  };
}
