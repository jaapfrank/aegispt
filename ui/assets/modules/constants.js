export const ASSESSMENT_TYPES = [
  "Website / Web App",
  "Domain / Domains",
  "External IP / WAN",
  "Internal Range / LAN",
  "API",
  "SSL/TLS Only",
  "Authenticated App",
  "Mixed Assessment",
];

export const TEST_PROFILES = [
  "Light",
  "Standard",
  "Deep",
  "External Surface Only",
  "Authenticated Only",
  "SSL/TLS Only",
  "Internal Validation",
  "Adaptive Customer-Specific Mode",
];

export const MODULES = [
  ["discovery", "Discovery"],
  ["web_crawling", "Web Crawling"],
  ["auth_flows", "Auth Flows"],
  ["content_discovery", "Content / Directory Discovery"],
  ["nuclei_checks", "Nuclei Checks"],
  ["zap_active_checks", "ZAP Active Checks"],
  ["ssl_tls_analysis", "SSL / TLS Analysis"],
  ["business_logic_testing", "Business Logic Testing"],
  ["adaptive_ai_generated_tests", "Adaptive AI-Generated Tests"],
  ["internal_validation_modules", "Internal Validation Modules"],
];

export const WIZARD_STEPS = [
  "Assessment Type",
  "Scope Input",
  "Credentials / Access",
  "Test Profile",
  "Test Modules",
  "Safety / Limits",
  "Review / Confirm",
];

export const DEFAULT_MODULE_STATE = {
  discovery: true,
  web_crawling: true,
  auth_flows: false,
  content_discovery: true,
  nuclei_checks: true,
  zap_active_checks: false,
  ssl_tls_analysis: true,
  business_logic_testing: false,
  adaptive_ai_generated_tests: true,
  internal_validation_modules: false,
};

export const DEFAULT_SAFETY = {
  rate_limit_rps: 2,
  concurrency: 2,
  time_budget_minutes: 90,
  active_checks: "guarded",
  adaptive_generation: true,
  max_validation_depth: "standard",
};

export const REPORT_VARIANTS = [
  ["executive", "Executive Report"],
  ["technical", "Technical Report"],
  ["evidence", "Evidence Appendix"],
  ["retest", "Retest / Verification Report"],
];

export const SEVERITY_RANK = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
};
