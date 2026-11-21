import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  detectLanguage,
  exportReportToMarkdown,
  extractStructuredJobData,
  inspectUrlStructurally,
  redactSensitiveInfo,
  runLocalVerification,
} from "../frontend/src/engine/localEngine.mjs";

test("1. Detects English advance registration fee scam as HIGH RISK with 7 categories", () => {
  const rep = runLocalVerification({
    text: "Company: Apex Global\nRole: Operations Executive\nSelected without interview. Pay ₹999 registration fee today.",
  });
  assert.equal(rep.risk_level, "HIGH RISK");
  assert.equal(rep.categories.length, 7);
  assert.ok(rep.suspicious_indicator_count >= 2);
});

test("2. Detects Hindi and Hinglish recruitment fraud signals", () => {
  const hi = runLocalVerification({ text: "बिना इंटरव्यू के नौकरी पाने के लिए ₹2,000 सिक्योरिटी डिपॉजिट दें।" });
  assert.equal(hi.detected_language, "hi");
  assert.equal(hi.risk_level, "HIGH RISK");

  const hinglish = runLocalVerification({ text: "Job ke liye pehle ₹1500 registration fees jama karo." });
  assert.equal(hinglish.detected_language, "hinglish");
  assert.equal(hinglish.risk_level, "HIGH RISK");
});

test("3. Negation handling: anti-fraud disclaimer does not trigger false positive", () => {
  const rep = runLocalVerification({
    text: "Company: Infosys Limited\nRole: Software Engineer\nApply at https://www.infosys.com/careers/ or careers@infosys.com. Never pay any registration fee during recruitment.",
  });
  assert.equal(rep.risk_level, "LOW RISK");
  assert.equal(rep.suspicious_indicator_count, 0);
});

test("4. Word 'urgent' alone does not trigger HIGH RISK", () => {
  const rep = runLocalVerification({
    text: "Company: Razorpay\nRole: Backend Software Engineer\nUrgent reminder: confirm interview via recruiting@razorpay.com.",
  });
  assert.equal(rep.risk_level, "LOW RISK");
});

test("5. Zero-visit URL inspector flags fake Infosys career portal", () => {
  const res = inspectUrlStructurally("https://infosys.careers-verification.xyz/apply");
  assert.equal(res.risk_level, "HIGH RISK");
  assert.equal(res.registrable_domain, "careers-verification.xyz");
  assert.equal(res.impersonated_brand, "INFOSYS");
});

test("6. Unknown company is marked Unverified, not fraudulent", () => {
  const rep = runLocalVerification({
    text: "Company: GreenLeaf Robotics\nRole: Firmware Engineer\nSalary: 8 LPA\nEmail: hr@greenleafrobotics.in",
  });
  assert.equal(rep.risk_level, "LOW RISK");
  assert.equal(rep.categories[0].overall_status, "Unverified");
});

test("7. PII redaction masks Aadhaar, PAN, IFSC, OTP/PIN, and bank account", () => {
  const { redacted, counts } = redactSensitiveInfo(
    "Aadhaar 2345 6789 0123 PAN ABCDE1234F IFSC HDFC0001234 OTP: 981234"
  );
  assert.ok(!redacted.includes("2345 6789 0123"));
  assert.ok(!redacted.includes("ABCDE1234F"));
  assert.ok(!redacted.includes("HDFC0001234"));
  assert.ok(!redacted.includes("981234"));
  assert.ok(Object.keys(counts).length >= 4);
});

test("8. Structured 10-field extraction leaves missing fields explicitly missing", () => {
  const ext = extractStructuredJobData("Company: Zoho\nRole: Frontend Developer");
  assert.equal(ext.employer.status, "extracted");
  assert.equal(ext.requisition_id.status, "missing");
  assert.equal(ext.requisition_id.value, null);
});

test("9. Markdown report export includes risk level and all 7 categories", () => {
  const rep = runLocalVerification({ text: "Company: Infosys\nRole: Systems Engineer" });
  const md = exportReportToMarkdown(rep);
  assert.ok(md.includes("# JobGuard AI — Evidence-Based Verification Report"));
  assert.ok(md.includes("7. Document and Message Consistency"));
});

test("10. Production bundle frontend/dist/index.html exists and contains JobGuard AI", () => {
  const distFile = path.resolve("frontend/dist/index.html");
  const html = fs.readFileSync(distFile, "utf-8");
  assert.ok(html.includes("JobGuard AI"));
  assert.ok(html.includes("Before You Trust the Offer, Verify the Evidence."));
  assert.ok(html.includes("Tesseract"));
  assert.ok(html.includes("1930"));
});
