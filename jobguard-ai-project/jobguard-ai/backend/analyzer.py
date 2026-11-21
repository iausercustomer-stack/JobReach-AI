"""Layers A, B, G & H: Multilingual recruitment fraud rule engine, job ad analysis,
payment/sensitive-info detection, and cross-document consistency checks.

Handles English, Hindi, and Hinglish with explicit negation and context awareness.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .extractor import extract_structured_job_data
from .schemas import DetectionIndicator, ExtractedJobData, Severity


@dataclass(frozen=True)
class FraudRule:
    rule_id: str
    category: str
    severity: Severity
    weight: int
    pattern: re.Pattern
    explanation: str
    explanation_hi: str
    reason_it_matters: str
    suggested_action: str
    respect_negation: bool = True


NEGATION_PREFIX_RE = re.compile(
    r"(?i)(?:never|do\s+not|don't|does\s+not|doesn't|will\s+not|won't|not\s+ask(?:ing)?\s+(?:for|you\s+to)|"
    r"no\s+(?:upfront\s+)?|zero|without\s+any|free\s+of|beware\s+of|warning\s*:|disclaimer\s*:|"
    r"कभी\s+नहीं|न\s+दें|न\s+करें|नहीं\s+मांग|मत\s+दें|mat\s+do|nahi\s+mangta)\s*(?:pay|charge|ask|collect|demand|share|give|send)?\s*$"
)

SAFETY_DISCLAIMER_RE = re.compile(
    r"(?i)(?:never\s+(?:pay|send|share)\s+(?:any\s+)?(?:registration\s+fee|security\s+deposit|money|fee|otp|upi\s+pin|password)|"
    r"does\s+not\s+charge\s+(?:any\s+)?(?:fee|money|deposit)\s+(?:at\s+any\s+stage|during\s+recruitment|for\s+interviews?)|"
    r"no\s+fee\s+(?:is\s+)?charged\s+during\s+(?:the\s+)?recruitment|"
    r"do\s+not\s+pay\s+any\s+(?:fee|deposit|amount)|"
    r"भर्ती\s+के\s+दौरान\s+कोई\s+शुल्क\s+नहीं\s+लिया\s+जाता|"
    r"कोई\s+भी\s+रजिस्ट्रेशन\s+फीस\s+न\s+दें)"
)


RULES: List[FraudRule] = [
    FraudRule(
        rule_id="advance_registration_fee",
        category="Advance Fee / Registration Scam",
        severity=Severity.CRITICAL,
        weight=45,
        pattern=re.compile(
            r"(?i)\b(?:(?:pay|deposit|submit|transfer|send)\s+(?:a\s+|an\s+|the\s+)?(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*\s*(?:only\s+)?(?:refundable\s+)?(?:registration|application|processing|joining|onboarding|interview|document\s+verification|file)\s*(?:fee|fees|charge|charges)|"
            r"(?:registration|processing|application|interview\s+scheduling|document\s+verification)\s*(?:fee|fees|charge)\s*(?:of\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|is\s+mandatory|to\s+(?:confirm|get\s+selected|schedule)|jama\s+karo|jama\s+karein|bhejo|dena\s+hoga)|"
            r"pehle\s+(?:₹|Rs\.?)?\s*\d[\d,]*\s*(?:registration|joining|processing)\s*(?:fee|fees)\s*(?:jama\s+karo|bhejo|do))\b|"
            r"रजिस्ट्रेशन\s+फीस\s*(?:जमा\s+करें|दें|देनी\s+होगी)|प्रोसेसिंग\s+फीस\s*(?:जमा\s+करें|दें)|जॉइनिंग\s+फीस",
        ),
        explanation="Demands an upfront registration, interview, processing, or verification fee to proceed with hiring.",
        explanation_hi="नौकरी या चयन के लिए पहले रजिस्ट्रेशन, प्रोसेसिंग या सत्यापन शुल्क की मांग की गई है।",
        reason_it_matters="Legitimate employers do not charge candidates to apply, interview, or confirm a job offer.",
        suggested_action="Stop all communication immediately and never pay any fee to confirm a job.",
    ),
    FraudRule(
        rule_id="security_or_equipment_deposit",
        category="Security / Equipment Deposit Scam",
        severity=Severity.CRITICAL,
        weight=45,
        pattern=re.compile(
            r"(?i)\b(?:refundable\s+security\s+deposit|security\s+deposit\s+(?:of\s+(?:₹|Rs\.?|INR|\$)?\s*\d[\d,]*|is\s+required|to\s+confirm|before\s+joining|jama\s+karo)|"
            r"(?:laptop|equipment|id\s+card|kit|asset)\s+(?:security\s+)?(?:deposit|fee|charge)|"
            r"deposit\s+(?:money|₹?\s*\d[\d,]*)\s+to\s+(?:unlock|release|receive)\s+(?:your\s+)?salary)\b|"
            r"सिक्योरिटी\s+डिपॉजिट\s*(?:दें|जमा\s+करें|देना\s+होगा)|लैपटॉप\s+डिपॉजिट",
        ),
        explanation="Requests a 'refundable' security deposit, laptop/kit deposit, or payment to unlock salary.",
        explanation_hi="नौकरी, इंटर्नशिप या लैपटॉप के नाम पर 'रिफंडेबल' सिक्योरिटी डिपॉजिट की मांग की गई है।",
        reason_it_matters="Fraudsters label upfront payments as '100% refundable' to lower skepticism and disappear after payment.",
        suggested_action="Refuse any security or equipment deposit and verify the company independently.",
    ),
    FraudRule(
        rule_id="mandatory_paid_training",
        category="Paid Training / Fake Internship Scam",
        severity=Severity.HIGH,
        weight=36,
        pattern=re.compile(
            r"(?i)\b(?:pay\s+(?:for\s+)?(?:mandatory|compulsory)\s+training\s+before\s+joining|"
            r"mandatory\s+paid\s+(?:training|certification)\s+(?:fee|program)\s+(?:before\s+joining|required\s+for\s+offer)|"
            r"guaranteed\s+(?:job|placement|internship\s+certificate)\s+(?:after|in\s+exchange\s+for)\s+(?:paying|payment|fee)|"
            r"buy\s+(?:our\s+)?(?:internship|training)\s+certificate)\b|"
            r"ट्रेनिंग\s+फीस\s*(?:जमा\s+करें|देनी\s+होगी)",
        ),
        explanation="Requires paying for mandatory training or a paid certificate in exchange for guaranteed employment.",
        explanation_hi="नौकरी की गारंटी के बदले अनिवार्य पेड ट्रेनिंग या सर्टिफिकेट शुल्क मांगा गया है।",
        reason_it_matters="Pay-to-work training traps target students and freshers by selling worthless certificates under a fake job promise.",
        suggested_action="Verify whether the opportunity is a genuine employment offer or a disguised paid course.",
    ),
    FraudRule(
        rule_id="prepaid_task_recharge_scam",
        category="Prepaid Task & Recharge Scam",
        severity=Severity.CRITICAL,
        weight=48,
        pattern=re.compile(
            r"(?i)\b(?:prepaid\s+(?:merchant\s+)?task|task\s+recharge|recharge\s+(?:wallet|account)\s+to\s+(?:complete|unlock)\s+(?:vip\s+)?task|"
            r"vip\s+(?:telegram\s+)?task\s+(?:group|payout|commission)|"
            r"like\s+(?:youtube|instagram)\s+videos\s+(?:and|&)\s+(?:earn|get\s+paid)|"
            r"liking\s+(?:youtube\s+)?videos|rating\s+google\s+maps\s+(?:hotels|restaurants|places))\b|"
            r"प्रीपेड\s+टास्क|वीडियो\s+लाइक\s+करके\s+कमाएं|टास्क\s+रिचार्ज",
        ),
        explanation="Describes a prepaid task, wallet recharge, or paid video-liking / review-rating scheme.",
        explanation_hi="वीडियो लाइक करने, रेटिंग देने या प्रीपेड टास्क रिचार्ज से कमाई का लालच दिया गया है।",
        reason_it_matters="Task scams pay small initial bait amounts (₹150–₹300) before trapping victims into depositing thousands in frozen 'VIP' tasks.",
        suggested_action="Leave the Telegram/WhatsApp group immediately and do not recharge any task wallet.",
    ),
    FraudRule(
        rule_id="unrealistic_wfh_earnings",
        category="Unrealistic Salary / WFH Compensation",
        severity=Severity.HIGH,
        weight=38,
        pattern=re.compile(
            r"(?i)\b(?:earn\s+(?:up\s+to\s+)?(?:₹|Rs\.?|INR)\s*(?:[2-9],\d{3}|[1-9]\d,\d{3}|\d{4,5})(?:\s*(?:-|to|–)\s*(?:₹|Rs\.?|INR)?\s*\d[\d,]*)?\s*(?:per\s+day|daily|\/day)|"
            r"daily\s+(?:income|payout|earning)\s+(?:of\s+)?(?:₹|Rs\.?|INR)\s*(?:[2-9],\d{3}|[1-9]\d,\d{3}|\d{4,5})|"
            r"roz\s+(?:₹|Rs\.?)?\s*\d{4,5}\s+kamay(?:ein|e)|ghar\s+baithe\s+(?:roz|daily)\s+(?:₹|Rs\.?)?\s*\d{3,5})\b|"
            r"घर\s+बैठे\s+रोज़\s*₹?\s*\d[\d,]*\s*कमाएं",
        ),
        explanation="Promises unusually high daily earnings (e.g., ₹3,000–₹10,000/day) for simple work-from-home tasks.",
        explanation_hi="सरल घर बैठे काम के लिए रोज़ाना हजारों रुपये की अवास्तविक कमाई का वादा किया गया है।",
        reason_it_matters="Disproportionately high daily payouts for minimal skills are a primary lure for WFH and task fraud.",
        suggested_action="Benchmark the claimed pay against standard market salaries for that role.",
    ),
    FraudRule(
        rule_id="guaranteed_selection_no_interview",
        category="Fake Selection / Guaranteed Job Promise",
        severity=Severity.HIGH,
        weight=34,
        pattern=re.compile(
            r"(?i)\b(?:guaranteed\s+(?:selection|job|placement|joining)\s+(?:without\s+(?:any\s+)?interview|100%)|"
            r"direct\s+joining\s+(?:without|no)\s+interview|"
            r"selected\s+without\s+(?:any\s+)?interview|no\s+interview\s+required\s+for\s+(?:direct\s+)?joining|"
            r"bina\s+interview\s+(?:ke\s+)?(?:direct\s+)?(?:selection|naukri|job|joining))\b|"
            r"बिना\s+इंटरव्यू\s+(?:के\s+)?(?:सीधी\s+भर्ती|नौकरी|चयन)",
        ),
        explanation="Promises guaranteed job selection or direct joining without any interview or evaluation.",
        explanation_hi="बिना किसी इंटरव्यू या जांच के पक्की नौकरी या सीधे चयन का वादा किया गया है।",
        reason_it_matters="Reputable employers evaluate candidates through interviews or assessments before issuing an offer.",
        suggested_action="Verify the hiring process directly on the employer's official career portal.",
    ),
    FraudRule(
        rule_id="sensitive_credentials_request",
        category="OTP / UPI PIN / Credential Theft",
        severity=Severity.CRITICAL,
        weight=50,
        pattern=re.compile(
            r"(?i)\b(?:(?:share|send|provide|enter|give|bhejo|batao)\s+(?:your\s+|the\s+|apna\s+)?(?:6[\s-]digit\s+)?(?:otp|upi\s+pin|atm\s+pin|cvv|netbanking\s+password|bank\s+password|mpin)|"
            r"(?:otp|upi\s+pin|atm\s+pin|cvv)\s+(?:share\s+karo|bhejo|dalein|dalo|required\s+for\s+(?:salary|verification)))\b|"
            r"(?:ओटीपी|यूपीआई\s+पिन|एटीएम\s+पिन|पासवर्ड)\s*(?:शेयर|साझा|भेजें|बताएं|डालें)",
        ),
        explanation="Requests an OTP, UPI PIN, ATM PIN, CVV, or banking password during recruitment.",
        explanation_hi="भर्ती या सैलरी वेरिफिकेशन के नाम पर ओटीपी, यूपीआई पिन, एटीएम पिन या पासवर्ड मांगा गया है।",
        reason_it_matters="No legitimate HR team ever needs your OTP, UPI PIN, CVV, or banking password to verify identity or set up payroll.",
        suggested_action="Never share OTPs, PINs, or passwords. If already shared, contact your bank and call 1930 immediately.",
    ),
    FraudRule(
        rule_id="remote_access_software",
        category="Remote-Access Software Scam",
        severity=Severity.CRITICAL,
        weight=50,
        pattern=re.compile(
            r"(?i)\b(?:install|download|open|use)\s+(?:the\s+)?(?:anydesk|teamviewer|quicksupport|rustdesk|ultraviewer)|"
            r"\b(?:anydesk|teamviewer|quicksupport|rustdesk)\b.{0,40}\b(?:code|id|verify|interview|hr|onboarding|screen)\b",
        ),
        explanation="Asks you to install remote-access software (AnyDesk, TeamViewer, QuickSupport) for onboarding or HR verification.",
        explanation_hi="ऑनबोर्डिंग या सत्यापन के लिए AnyDesk या TeamViewer जैसे रिमोट-एक्सेस ऐप इंस्टॉल करने को कहा गया है।",
        reason_it_matters="Remote-access apps allow scammers to control your device, read OTPs, and drain bank accounts live.",
        suggested_action="Do not install AnyDesk/TeamViewer for recruiters. Uninstall immediately if already installed.",
    ),
    FraudRule(
        rule_id="messaging_only_funnel",
        category="WhatsApp / Telegram-Only Recruitment Funnel",
        severity=Severity.MEDIUM,
        weight=20,
        pattern=re.compile(
            r"(?i)\b(?:contact\s+(?:hr\s+)?(?:only\s+)?on\s+(?:whatsapp|telegram)|"
            r"message\s+(?:us\s+)?on\s+(?:whatsapp|telegram)\s+(?:to\s+apply|for\s+(?:immediate|direct)\s+joining)|"
            r"join\s+(?:our\s+)?(?:official\s+)?telegram\s+(?:job|hr|task|vip)\s+(?:channel|group)|"
            r"t\.me\/[a-z0-9_]+|wa\.me\/\d+)\b",
        ),
        explanation="Routes the entire recruitment process exclusively through WhatsApp or Telegram.",
        explanation_hi="भर्ती प्रक्रिया को केवल व्हाट्सएप या टेलीग्राम के माध्यम से चलाने के लिए कहा गया है।",
        reason_it_matters="While some small businesses use WhatsApp for scheduling, corporate hiring funnels exclusively on Telegram/WhatsApp lack auditability and are heavily abused by scammers.",
        suggested_action="Ask for an official corporate email confirmation and a listing on the company's career website.",
    ),
    FraudRule(
        rule_id="high_pressure_countdown",
        category="Artificial Urgency / Countdown Pressure",
        severity=Severity.LOW,
        weight=12,
        pattern=re.compile(
            r"(?i)\b(?:offer\s+(?:will\s+be\s+)?(?:cancelled|revoked|expired)\s+(?:within|in)\s+\d+\s*(?:minutes?|mins?|hours?|hrs?)|"
            r"pay\s+within\s+\d+\s*(?:minutes?|mins?|hours?|hrs?)|"
            r"last\s+\d+\s+seats?\s+left.{0,25}(?:apply|pay|register)\s+(?:now|immediately)|"
            r"turant\s+(?:pay|fees|jama))\b|"
            r"तुरंत\s+फीस\s+जमा\s+करें|आज\s+ही\s+पैसे\s+भेजें",
        ),
        explanation="Uses a short countdown deadline paired with pressure to pay or lock a seat immediately.",
        explanation_hi="बिना जांचे तुरंत भुगतान या सीट पक्की करने के लिए कम समय की चेतावनी दी गई है।",
        reason_it_matters="High-pressure countdowns prevent candidates from researching the company or consulting peers.",
        suggested_action="Pause and verify the company before responding; legitimate employers give reasonable time to review offers.",
        respect_negation=False,
    ),
]


def run_rule_analysis(text: str, extracted: ExtractedJobData) -> Tuple[List[DetectionIndicator], bool]:
    """Run Layer A/B/G deterministic rules with negation and context awareness.

    Returns (indicators, has_anti_fraud_disclaimer).
    """
    if not text:
        return [], False

    has_disclaimer = bool(SAFETY_DISCLAIMER_RE.search(text))
    indicators: List[DetectionIndicator] = []
    seen_ids = set()

    for rule in RULES:
        for m in rule.pattern.finditer(text):
            if rule.respect_negation:
                prefix = text[max(0, m.start() - 55):m.start()]
                if NEGATION_PREFIX_RE.search(prefix):
                    continue
            matched = m.group(0).strip()
            dedup_key = (rule.rule_id, matched.lower())
            if dedup_key in seen_ids:
                continue
            seen_ids.add(dedup_key)
            indicators.append(
                DetectionIndicator(
                    id=f"{rule.rule_id}_{len(indicators) + 1}",
                    category=rule.category,
                    matched_text=matched,
                    severity=rule.severity,
                    explanation=rule.explanation,
                    explanation_hi=rule.explanation_hi,
                    detection_method="deterministic_rule_engine",
                    reason_it_matters=rule.reason_it_matters,
                    suggested_action=rule.suggested_action,
                )
            )

    # Layer B: Job advertisement structural anomaly checks (unusually high pay for minimal qualifications)
    if extracted.salary.status == "extracted" and extracted.salary.value:
        sal_val = extracted.salary.value.lower()
        low_qual = bool(
            re.search(
                r"(?i)\b(10th\s+pass|12th\s+pass|no\s+experience\s+(?:required|needed)|no\s+skills?\s+required|anyone\s+can\s+apply|only\s+smartphone\s+needed)\b",
                text,
            )
        )
        high_pay = bool(
            re.search(r"(?:₹|rs\.?|inr)\s*(?:[5-9]\d,\d{3}|[1-9]\d{2},\d{3})\s*(?:per\s+month|\/month|pm)|(?:[1-9]\d)\s*lpa", sal_val)
        )
        if low_qual and high_pay:
            indicators.append(
                DetectionIndicator(
                    id=f"unrealistic_pay_for_qual_{len(indicators) + 1}",
                    category="Salary & Qualification Mismatch",
                    matched_text=extracted.salary.value,
                    severity=Severity.HIGH,
                    explanation="Advertises unusually high compensation alongside minimal or zero qualification requirements.",
                    explanation_hi="न्यूनतम योग्यता के साथ असामान्य रूप से बहुत अधिक वेतन का दावा किया गया है।",
                    detection_method="job_ad_structural_analysis",
                    reason_it_matters="Disproportionate compensation for no-skill roles is a common bait used to attract applicants into fee or data-harvesting scams.",
                    suggested_action="Compare the role's compensation with verified listings for similar entry-level roles.",
                )
            )

    return indicators, has_disclaimer


def compare_document_consistency(
    primary_text: str,
    primary_extracted: ExtractedJobData,
    secondary_text: Optional[str],
) -> List[dict]:
    """Layer H: Compare primary job description against a secondary document (e.g., offer letter or chat)."""
    if not secondary_text or not secondary_text.strip():
        return []

    secondary_extracted = extract_structured_job_data(secondary_text)
    conflicts: List[dict] = []

    fields_to_compare = [
        ("employer", "Employer Name"),
        ("role", "Job Title / Role"),
        ("salary", "Salary / Compensation"),
        ("location", "Job Location"),
        ("recruiter_email", "Recruiter Email"),
    ]

    for attr, label in fields_to_compare:
        f1 = getattr(primary_extracted, attr)
        f2 = getattr(secondary_extracted, attr)
        if f1.status == "extracted" and f2.status == "extracted" and f1.value and f2.value:
            v1_norm = re.sub(r"\s+", " ", f1.value.strip().lower())
            v2_norm = re.sub(r"\s+", " ", f2.value.strip().lower())
            if v1_norm != v2_norm and v1_norm not in v2_norm and v2_norm not in v1_norm:
                conflicts.append(
                    {
                        "field": label,
                        "primary_value": f1.value,
                        "secondary_value": f2.value,
                        "explanation": f"{label} differs between submitted materials ('{f1.value}' vs '{f2.value}').",
                    }
                )

    # Also check internal contradictions inside a single document (e.g., two different company names or conflicting emails)
    if primary_extracted.additional_emails:
        dom1 = primary_extracted.recruiter_email.value.split("@")[-1].lower() if primary_extracted.recruiter_email.value else ""
        for extra in primary_extracted.additional_emails:
            dom2 = extra.split("@")[-1].lower()
            if dom1 and dom2 and dom1 != dom2:
                conflicts.append(
                    {
                        "field": "Email Domain Consistency",
                        "primary_value": primary_extracted.recruiter_email.value,
                        "secondary_value": extra,
                        "explanation": f"Multiple email addresses from different domains appear in the same recruitment material ('{dom1}' vs '{dom2}').",
                    }
                )

    return conflicts
