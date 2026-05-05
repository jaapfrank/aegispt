import { api, apiOrNull } from "./api.js";
import { dom, runtime, state } from "./runtime.js";
import {
  emptyState,
  escapeHtml,
  formatDateTime,
  renderBadgeList,
  renderDisclosure,
  slugify,
  splitComma,
  statusPill,
  stringValue,
  valueOrNull,
} from "./shared.js";

function filteredCodexTasks() {
  const selectedPackIds = new Set(state.mission.packs.map((pack) => pack.id));
  return state.codexTasks.filter(
    (task) => !task.source_context?.pack_id || selectedPackIds.has(task.source_context.pack_id)
  );
}

function assertSelectedEngagement() {
  if (!state.selectedEngagementId) throw new Error("Select or create an engagement first.");
}

function assertSelectedPack() {
  if (!state.selectedPackId) throw new Error("Select or generate a pack first.");
}

function latestItem(items) {
  return Array.isArray(items) && items.length ? items[items.length - 1] : null;
}

function shortId(value) {
  return value ? String(value).slice(0, 8) : "Not recorded";
}

function findOperatorSettingValue(key) {
  const sections = Array.isArray(state.operatorSettings?.sections) ? state.operatorSettings.sections : [];
  for (const section of sections) {
    const settings = Array.isArray(section?.settings) ? section.settings : [];
    const match = settings.find((setting) => String(setting?.key || "") === String(key || ""));
    if (match) return match.value;
  }
  return null;
}

const TOOL_CATALOG = Object.freeze([
  {
    id: "nmap",
    name: "Nmap",
    category: "Discovery",
    tier: "passive",
    description: "Discovers approved hosts and fingerprints exposed services with bounded NSE profiles.",
    findings: ["Open service exposure", "Weak SMB/security-mode signals", "Service fingerprint evidence"],
    prerequisites: ["Approved host, IP, or CIDR target", "Nmap available on the host", "Profile limits selected by the run"],
    chains: ["Internal LAN", "External infrastructure", "IoT discovery"],
  },
  {
    id: "nuclei",
    name: "Nuclei",
    category: "Web",
    tier: "active",
    description: "Runs curated detection templates against approved web or infrastructure targets.",
    findings: ["Known CVE exposure", "Misconfiguration evidence", "Technology-specific detection hits"],
    prerequisites: ["Approved URL or service target", "Curated template set", "Active approval when probes are active"],
    chains: ["External Web", "External infrastructure", "CVE follow-up"],
  },
  {
    id: "zap",
    name: "ZAP",
    category: "Web",
    tier: "active",
    description: "Performs bounded spidering and passive/active web validation through OWASP ZAP.",
    findings: ["XSS indicators", "Security header gaps", "Web scanner alerts"],
    prerequisites: ["Approved web root URL", "ZAP daemon or local runner readiness", "Active approval for active validation"],
    chains: ["External Web", "Authenticated App", "Web baseline"],
  },
  {
    id: "burp",
    name: "Burp Suite",
    category: "Web",
    tier: "passive",
    description: "Uses the optional Burp REST integration for lightweight approved web scans.",
    findings: ["Burp scanner issues", "HTTP misconfiguration", "Web application exposure"],
    prerequisites: ["Configured Burp API URL", "Approved web target", "Named scan configuration"],
    chains: ["External Web", "Authenticated App"],
  },
  {
    id: "content-discovery",
    name: "ffuf Content Discovery",
    category: "Web",
    tier: "active",
    description: "Runs approval-gated, rate-limited endpoint and directory discovery against approved web roots.",
    findings: ["Hidden endpoint discovered", "Admin or backup path exposure", "Unexpected API surface"],
    prerequisites: ["Approved web root URL", "ffuf/gobuster/feroxbuster installed", "Active approval and rate limits"],
    chains: ["External Web", "Authenticated App", "Web baseline"],
  },
  {
    id: "nikto",
    name: "Nikto",
    category: "Web",
    tier: "passive",
    description: "Checks approved web servers for configuration issues, dangerous files, headers, and outdated server signals.",
    findings: ["Web server configuration finding", "Dangerous file exposure", "Outdated software signal"],
    prerequisites: ["Approved web target", "Nikto installed", "Bounded JSON evidence capture"],
    chains: ["External Web", "Web baseline", "Configuration review"],
  },
  {
    id: "sqlmap",
    name: "sqlmap",
    category: "Web",
    tier: "active",
    description: "Confirms SQL injection only on explicitly supplied or ZAP-flagged injectable parameters.",
    findings: ["Confirmed SQL injection", "Injectable parameter evidence", "Input validation weakness"],
    prerequisites: ["Approved parameter URL", "Explicit parameter or ZAP injectable signal", "Active approval"],
    chains: ["External Web", "Authenticated App", "Injection confirmation"],
  },
  {
    id: "ssti-probe",
    name: "SSTI Probe",
    category: "Web",
    tier: "active",
    description: "Confirms server-side template injection with marker-wrapped mathematical expressions only, covering reflected parameters and explicitly configured stored-form contexts.",
    findings: ["SSTI Confirmed with engine evidence", "Template expression evaluation", "Critical input validation weakness"],
    prerequisites: ["Approved web or API root", "Active approval", "No command, file-read, or config-dump payloads"],
    chains: ["External Web", "Authenticated App", "Injection confirmation"],
  },
  {
    id: "headers-security",
    name: "HTTP Headers Security",
    category: "Web",
    tier: "active",
    description: "Analyzes CORS, CSP, clickjacking, HSTS, and disclosure headers with bounded Origin reflection probes and no cross-origin data extraction.",
    findings: ["CORS credential reflection", "CSP unsafe source policy", "Clickjacking exposure", "Missing or incomplete HSTS", "Information disclosure header"],
    prerequisites: ["Approved web root", "Active approval for Origin probes", "No CORS data extraction or clickjacking PoC creation"],
    chains: ["External Web", "Authenticated App", "Configuration review"],
  },
  {
    id: "graphql-probe",
    name: "GraphQL Probe",
    category: "API",
    tier: "active",
    description: "Discovers GraphQL endpoints and IDEs, validates introspection exposure, bounded depth handling, field suggestions, and argument injection signals.",
    findings: ["GraphQL introspection schema disclosure", "Missing query depth limit", "Field suggestion leakage", "GraphQL argument injection signal"],
    prerequisites: ["Approved web or API root", "Active approval", "Depth probe capped at 20 levels and batch probe capped at 2 queries"],
    chains: ["API Assessment", "External Web", "Authenticated App"],
  },
  {
    id: "xxe-probe",
    name: "XXE Probe",
    category: "Web",
    tier: "active",
    description: "Validates XML External Entity exposure on approved XML-capable endpoints with read-only file URI probes and provided OOB evidence.",
    findings: ["XXE file-read exposure", "Blind out-of-band XXE evidence", "XML input validation weakness"],
    prerequisites: ["Approved web root or XML endpoint", "Active approval", "No DoS payloads or SSRF chaining"],
    chains: ["External Web", "Authenticated App", "Injection confirmation"],
  },
  {
    id: "jwt-probe",
    name: "JWT Probe",
    category: "Authentication",
    tier: "active",
    description: "Discovers JWT usage and validates none-algorithm, bounded weak-secret, explicit key-material algorithm-confusion, and authorized replay-only claims risks.",
    findings: ["JWT None Algorithm Accepted", "JWT Weak Secret Cracked", "JWT Algorithm Confusion", "JWT Claims Manipulation Possible"],
    prerequisites: ["Approved web or API target", "Active approval", "Explicit replay context for token mutation acceptance checks"],
    chains: ["External Web", "Authenticated App", "API Security"],
  },
  {
    id: "session-security",
    name: "Session Security",
    category: "Authentication",
    tier: "active",
    description: "Validates session fixation, cookie flags, token entropy, logout invalidation, and session-token-in-URL exposure with configured credentials only.",
    findings: ["Session Fixation - Token Not Rotated After Login", "Session Cookie Missing Secure/HttpOnly/SameSite", "Session Not Invalidated on Logout", "Session Token Entropy Weakness"],
    prerequisites: ["Approved web root", "Configured username/password credential context", "Active approval", "No other-user session hijacking"],
    chains: ["Authenticated App", "External Web", "API Security"],
  },
  {
    id: "auth-flow",
    name: "Auth Flow Security",
    category: "Authentication",
    tier: "active",
    description: "Validates password reset token quality, reset-token reuse, host-header poisoning, username enumeration, brute-force protection, and insecure credential submission with configured test accounts only.",
    findings: ["Predictable Password Reset Token", "Password Reset Token Reuse Accepted", "Password Reset Host Header Injection", "Username Enumeration", "Missing Brute Force Protection"],
    prerequisites: ["Approved web root", "Configured test-account credentials", "Active approval", "Failed-login attempts capped at 10"],
    chains: ["Authenticated App", "External Web", "API Security"],
  },
  {
    id: "client-state",
    name: "Client-State Authorization",
    category: "Authentication",
    tier: "active",
    description: "Validates server-side authorization gaps exposed by client-controlled hidden fields, role cookies, privilege parameters, price fields, and workflow step-skipping.",
    findings: ["Hidden field privilege escalation", "Cookie-based privilege escalation", "Request parameter authorization bypass", "Price or amount manipulation", "Workflow step-skipping"],
    prerequisites: ["Approved web root", "Configured authenticated access context", "Active approval", "Parameter and cookie manipulation only"],
    chains: ["Authenticated App", "External Web", "API Security"],
  },
  {
    id: "vuln-components",
    name: "Vulnerable Components",
    category: "Web",
    tier: "active",
    description: "Fingerprints exposed web framework and JavaScript dependency versions, probes approved dependency files, and matches results against the local CVE cache.",
    findings: ["Outdated library with CVE references", "Exposed dependency manifest", "Vulnerable web component signal"],
    prerequisites: ["Approved web root URL", "Active approval", "Local CVE cache or supplied CVE fixture records"],
    chains: ["External Web", "Authenticated App", "Configuration review"],
  },
  {
    id: "idor-bac",
    name: "IDOR / Broken Access Control",
    category: "Authentication",
    tier: "active",
    description: "Validates horizontal and vertical access-control failures with bounded identifier substitution, configured accounts, explicit role-parameter contexts, method override checks, and scoped admin path exposure review.",
    findings: ["IDOR - Horizontal Privilege Escalation", "Privilege escalation via role/admin parameter", "Admin path exposed without authentication"],
    prerequisites: ["Approved web or API root", "Configured authenticated accounts", "Active approval and bounded ±20 identifier checks"],
    chains: ["Authenticated App", "API Security", "External Web"],
  },
  {
    id: "xss-extended",
    name: "XSS Extended",
    category: "Web",
    tier: "active",
    description: "Completes XSS coverage beyond baseline crawling with same-origin HTML upload checks, AJAX/JSON response-context probes, and sensitive JSON XSSI review.",
    findings: ["Stored XSS via Unrestricted HTML Upload", "AJAX/JSON XSS in Response Context", "Cross-Site Script Inclusion data leakage"],
    prerequisites: ["Approved web or API root", "Active approval", "Explicit upload, AJAX, JSON, or evidence contexts"],
    chains: ["External Web", "Authenticated App", "API Security"],
  },
  {
    id: "ssrf-probe",
    name: "SSRF Probe",
    category: "Web",
    tier: "active",
    description: "Validates server-side request forgery with URL parameters, Host and forwarding headers, governed OOB callback evidence, approved internal-service URLs, and explicitly enabled cloud metadata checks.",
    findings: ["SSRF - Blind (OOB Confirmed)", "SSRF - Internal Service Accessible", "SSRF - Cloud Metadata Exposed"],
    prerequisites: ["Approved web or API root", "Active approval", "Governed OOB callback context or approved internal/cloud metadata context"],
    chains: ["External Web", "Authenticated App", "API Security"],
  },
  {
    id: "deserialization-probe",
    name: "Deserialization Probe",
    category: "Web",
    tier: "active",
    description: "Validates insecure deserialization with Java URLDNS-only callback evidence, PHP object-injection error analysis, Python pickle signals, and unprotected .NET ViewState review.",
    findings: ["Java Deserialization - Potential RCE (ysoserial URLDNS confirmed)", "PHP Object Injection - Serialized Object Accepted", ".NET ViewState - Unsigned or Unencrypted State"],
    prerequisites: ["Approved web or API root", "Active approval", "Governed OOB context for Java URLDNS confirmation", "No RCE gadget chains"],
    chains: ["External Web", "Authenticated App", "API Security"],
  },
  {
    id: "external-osint",
    name: "Shodan / Censys",
    category: "Discovery",
    tier: "passive",
    description: "Queries passive external exposure APIs for approved hosts, domains, and URLs without scanning the target.",
    findings: ["Public service exposure", "Public vulnerability exposure", "External asset intelligence"],
    prerequisites: ["Approved host, domain, or URL", "Configured Shodan or Censys API credentials", "Read-only API access"],
    chains: ["External attack surface", "External Web", "OSINT recon"],
  },
  {
    id: "metasploit",
    name: "Metasploit",
    category: "Lateral Movement",
    tier: "exploitation",
    description: "Executes curated, approval-gated exploit modules with loopback payload handling and immediate teardown.",
    findings: ["Confirmed exploitability", "Controlled session proof", "Compromise validation evidence"],
    prerequisites: ["Prior source finding", "Two-person intrusive approval", "Loopback LHOST and approved host scope"],
    chains: ["Full Internal", "Full AD Assessment", "Intrusive exploitation"],
  },
  {
    id: "netexec",
    name: "NetExec",
    category: "Lateral Movement",
    tier: "intrusive",
    description: "Validates SMB exposure, signing, share access, and bounded authenticated SMB checks.",
    findings: ["SMB signing weakness", "Null-session exposure", "Pass-the-hash validation"],
    prerequisites: ["Approved hosts", "Stored auth binding for intrusive mode", "Intrusive SMB approval for authenticated checks"],
    chains: ["Internal LAN", "Full AD Assessment"],
  },
  {
    id: "impacket-lateral",
    name: "Impacket",
    category: "Lateral Movement",
    tier: "exploitation",
    description: "Runs secretsdump, DCSync, or bounded remote-exec validation through protected evidence handling.",
    findings: ["Domain compromise validation", "Protected credential material evidence", "Remote execution confirmation"],
    prerequisites: ["Approved host/domain scope", "Stored credential or NTLM binding", "Intrusive exploitation approval"],
    chains: ["Full AD Assessment", "Intrusive exploitation"],
  },
  {
    id: "bloodhound-collect",
    name: "BloodHound",
    category: "Credential",
    tier: "active",
    description: "Collects read-only AD graph data and imports attack-path context.",
    findings: ["AD attack paths", "Kerberoastable accounts", "Choke-point privileges"],
    prerequisites: ["Domain-read credentials", "Approved directory target", "Active AD collection approval"],
    chains: ["Active Directory", "Full AD Assessment"],
  },
  {
    id: "responder",
    name: "Responder",
    category: "Credential",
    tier: "intrusive",
    description: "Performs time-boxed LLMNR/NBT-NS poisoning only inside approved internal CIDRs.",
    findings: ["Captured NTLMv2 hash evidence", "Name-resolution poisoning exposure", "Credential-capture risk"],
    prerequisites: ["Approved internal CIDR and interface", "Two-person intrusive approval", "Protected hash storage"],
    chains: ["Internal LAN", "Full Internal"],
  },
  {
    id: "ldap-enum",
    name: "LDAP Enumeration",
    category: "Discovery",
    tier: "passive",
    description: "Reads approved directory metadata for users, groups, computers, and domain policy signals.",
    findings: ["Directory exposure", "Weak policy evidence", "Identity inventory gaps"],
    prerequisites: ["Approved LDAP/AD target", "Read-only credentials when required", "Directory scope in ROE"],
    chains: ["Active Directory", "Full AD Assessment"],
  },
  {
    id: "snmp-enum",
    name: "SNMP Enumeration",
    category: "Discovery",
    tier: "passive",
    description: "Collects read-only SNMP identity, interface, ARP, and route evidence for approved hosts.",
    findings: ["Default community exposure", "Network device inventory", "Routing/interface leakage"],
    prerequisites: ["Approved LAN hosts", "Read-only community list", "SNMP UDP reachability"],
    chains: ["Internal LAN", "IoT discovery"],
  },
  {
    id: "mdns-ssdp",
    name: "mDNS / SSDP",
    category: "Discovery",
    tier: "passive",
    description: "Observes local service announcements and UPnP advertisements for approved LAN assessments.",
    findings: ["Service broadcast exposure", "IoT discovery evidence", "UPnP surface indicators"],
    prerequisites: ["Approved LAN segment", "Local network visibility", "Passive discovery mode"],
    chains: ["Internal LAN", "Smart home", "IoT discovery"],
  },
  {
    id: "ipv6-discovery",
    name: "IPv6 Discovery",
    category: "Discovery",
    tier: "passive",
    description: "Discovers IPv6 neighbors and routers with bounded follow-up against discovered approved addresses.",
    findings: ["Unmanaged IPv6 exposure", "Router advertisement evidence", "IPv6 service surface"],
    prerequisites: ["Approved LAN segment", "IPv6 local visibility", "Bounded target limit"],
    chains: ["Internal LAN", "Network segmentation"],
  },
  {
    id: "aws-inventory",
    name: "AWS Inventory",
    category: "Cloud",
    tier: "passive",
    description: "Collects read-only AWS account and resource metadata for approved cloud accounts.",
    findings: ["Public cloud exposure", "Weak IAM/resource posture", "Inventory coverage gaps"],
    prerequisites: ["Configured cloud credentials", "Approved account/region scope", "Read-only permissions"],
    chains: ["Cloud", "External attack surface"],
  },
  {
    id: "semgrep",
    name: "Semgrep",
    category: "Code",
    tier: "passive",
    description: "Scans allowlisted local code paths with curated static-analysis rules.",
    findings: ["Code-level vulnerability pattern", "Secret-handling weakness", "Unsafe framework usage"],
    prerequisites: ["Allowlisted repository path", "Curated rule set", "No live target interaction"],
    chains: ["Repository review", "CI/CD security"],
  },
  {
    id: "playwright-web",
    name: "Playwright Web",
    category: "Web",
    tier: "active",
    description: "Captures browser evidence and validates approved web workflows without destructive actions.",
    findings: ["Browser workflow exposure", "DOM/client-side issues", "Storage and console evidence"],
    prerequisites: ["Approved URL", "Browser automation runtime", "Auth context when testing authenticated paths"],
    chains: ["External Web", "Authenticated App", "Business logic"],
  },
  {
    id: "credential-attacks",
    name: "Credential Attacks",
    category: "Credential",
    tier: "active",
    description: "Runs approval-gated Kerberoast, AS-REP roast, offline cracking, or password-spray workflows.",
    findings: ["Roastable account evidence", "Recovered password risk", "Password spray exposure"],
    prerequisites: ["Inventory-backed candidates", "Protected credential material", "Lockout policy for spraying"],
    chains: ["Active Directory", "Full AD Assessment"],
  },
  {
    id: "hashcat",
    name: "Hashcat",
    backendTool: "credential-attacks",
    category: "Credential",
    tier: "active",
    description: "Performs offline cracking only against protected hash bundles already captured by approved workflows.",
    findings: ["Recovered password proof", "Weak password policy evidence", "Crackable hash material"],
    prerequisites: ["Protected hash bundle", "Approved wordlist", "No online authentication attempts"],
    chains: ["Credential Attacks", "Full AD Assessment"],
    params: { credential_attack_mode: "hashcat" },
  },
  {
    id: "llm-probe",
    name: "LLM Probe",
    category: "Specialized",
    tier: "active",
    description: "Tests approved LLM application surfaces for prompt-injection and unsafe-agent behavior.",
    findings: ["Prompt injection", "Sensitive data leakage", "Unsafe tool-use behavior"],
    prerequisites: ["Approved LLM app target", "Non-destructive prompt set", "Active approval"],
    chains: ["LLM / AI App"],
  },
  {
    id: "camera-test",
    name: "Camera Test",
    category: "Specialized",
    tier: "active",
    description: "Audits approved IP camera surfaces with read-only RTSP/ONVIF and bounded default-credential checks.",
    findings: ["Unauthenticated camera exposure", "Default credential risk", "RTSP metadata leakage"],
    prerequisites: ["Approved camera hosts", "Read-only methods", "Bounded credential attempt limit"],
    chains: ["IoT discovery", "Internal LAN"],
  },
  {
    id: "iot-default-creds",
    name: "IoT Default Creds",
    category: "Specialized",
    tier: "active",
    description: "Checks discovered management interfaces for bounded default-account exposure.",
    findings: ["Default credential exposure", "Unauthenticated management interface", "Weak embedded-device posture"],
    prerequisites: ["Inventory context", "Approved hosts", "Attempt limits and active approval"],
    chains: ["IoT discovery", "Internal LAN"],
  },
  {
    id: "smart-home",
    name: "Smart Home",
    category: "Specialized",
    tier: "passive",
    description: "Reviews approved smart-home hubs and protocols with read-only MQTT and HTTP checks.",
    findings: ["MQTT anonymous access", "Home Assistant API exposure", "OpenHAB/Domoticz/Node-RED exposure"],
    prerequisites: ["Approved LAN hosts", "Read-only mode", "No device control"],
    chains: ["Smart home", "IoT discovery"],
  },
  {
    id: "api-assessment",
    name: "API Assessment",
    category: "Web",
    tier: "active",
    description: "Runs bounded OWASP API checks against approved OpenAPI, Postman, or GraphQL inputs.",
    findings: ["API authorization weakness", "Schema exposure", "Injection and validation issues"],
    prerequisites: ["Approved API base URL or spec", "Rate limits", "Auth context when required"],
    chains: ["API Security", "Authenticated App"],
  },
  {
    id: "biz-logic-probe",
    name: "Business Logic Probe",
    category: "Web",
    tier: "active",
    description: "Validates IDOR, privilege, and workflow authorization assumptions in approved authenticated flows.",
    findings: ["IDOR", "Broken access control", "Privilege escalation"],
    prerequisites: ["Auth context", "Approved object ranges", "Active approval and low-rate limits"],
    chains: ["Authenticated App", "API Security"],
  },
  {
    id: "mobile-android",
    name: "Mobile Android",
    category: "Specialized",
    tier: "passive",
    description: "Performs static APK review for manifest, transport, storage, and embedded configuration issues.",
    findings: ["Insecure Android manifest setting", "Cleartext transport", "Hardcoded configuration exposure"],
    prerequisites: ["Authorized APK artifact", "Static-only assessment", "No emulator or device mutation"],
    chains: ["Mobile app"],
  },
  {
    id: "cloud-native",
    name: "Cloud Native",
    category: "Cloud",
    tier: "passive",
    description: "Reviews approved cloud-native and Kubernetes-style configuration evidence.",
    findings: ["Container/Kubernetes misconfiguration", "Weak workload exposure", "Cloud-native inventory risk"],
    prerequisites: ["Approved cloud-native evidence", "Read-only collection", "Configured credentials when required"],
    chains: ["Cloud", "Kubernetes"],
  },
  {
    id: "cicd-security",
    name: "CI/CD Security",
    category: "Code",
    tier: "passive",
    description: "Reviews approved pipeline configuration and repository delivery controls.",
    findings: ["Unsafe pipeline permission", "Secret exposure risk", "Deployment control gap"],
    prerequisites: ["Approved CI/CD configuration", "Read-only integration", "No pipeline mutation"],
    chains: ["CI/CD", "Repository review"],
  },
  {
    id: "desktop-client",
    name: "Desktop Client",
    category: "Specialized",
    tier: "passive",
    description: "Reviews approved desktop-client artifacts for configuration and packaging weaknesses.",
    findings: ["Insecure client configuration", "Weak update channel", "Sensitive local storage pattern"],
    prerequisites: ["Approved client artifact", "Static/offline review", "No endpoint mutation"],
    chains: ["Desktop client"],
  },
  {
    id: "network-segmentation",
    name: "Network Segmentation",
    category: "Discovery",
    tier: "active",
    description: "Checks approved network boundaries with passive reachability or bounded active segmentation probes.",
    findings: ["Segmentation bypass", "Unexpected lateral reachability", "VLAN boundary weakness"],
    prerequisites: ["Approved VLAN/subnet scope", "Mode-specific approval", "Raw packet capability for active mode"],
    chains: ["Internal LAN", "Full Internal"],
  },
  {
    id: "ssh-audit",
    name: "SSH Audit",
    backendTool: "external-infra",
    category: "Discovery",
    tier: "passive",
    description: "Audits SSH service posture as part of external or internal infrastructure review.",
    findings: ["Weak SSH algorithm", "Legacy key-exchange support", "SSH banner/configuration exposure"],
    prerequisites: ["Approved host with SSH service", "External-infra runner path", "Passive service review"],
    chains: ["External infrastructure", "Internal LAN"],
    params: { focus: "ssh-audit" },
  },
  {
    id: "easm-discover",
    name: "EASM Discover",
    category: "Discovery",
    tier: "passive",
    description: "Discovers passive external attack surface from approved root domains.",
    findings: ["Discovered subdomain", "Unreviewed external asset", "Certificate/DNS exposure"],
    prerequisites: ["Approved root domain", "Passive sources", "Operator approval before scope expansion"],
    chains: ["External attack surface", "External Web"],
  },
  {
    id: "external-infra",
    name: "External Infrastructure",
    category: "Discovery",
    tier: "active",
    description: "Reviews approved IP ranges and non-web services with service detection and infrastructure checks.",
    findings: ["Exposed remote access service", "Database/VPN/RDP exposure", "Infrastructure CVE signal"],
    prerequisites: ["Approved IP/CIDR/root-domain scope", "Profile limits", "Active approval for active service checks"],
    chains: ["External infrastructure", "Full External Web"],
  },
  {
    id: "httpx",
    name: "httpx",
    category: "Discovery",
    tier: "passive",
    description: "Fingerprints approved HTTP services with lightweight status, title, and technology evidence.",
    findings: ["HTTP service inventory", "Technology fingerprint", "Reachability and title evidence"],
    prerequisites: ["Approved URL or host target", "ProjectDiscovery httpx-toolkit or fallback runner", "Passive limits"],
    chains: ["External Web", "Autonomous Web", "External attack surface"],
  },
]);

const TOOL_CATEGORY_ORDER = ["Discovery", "Web", "Credential", "Lateral Movement", "Cloud", "Code", "Specialized"];
let selectedCatalogToolId = "nmap";
let selectedCatalogTarget = "";

function toolBackendId(tool) {
  return tool.backendTool || tool.id;
}

function buildLaneModeEnabled() {
  const value = findOperatorSettingValue("instance.build_lane_mode");
  if (typeof value === "boolean") return value;
  return ["true", "1", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function setBuildLanePanelVisibility() {
  const enabled = buildLaneModeEnabled();
  document.querySelectorAll(".pack-codex-panel").forEach((panel) => {
    panel.classList.toggle("hidden", !enabled);
    panel.setAttribute("aria-hidden", enabled ? "false" : "true");
  });
  return enabled;
}

function toneForStatus(status) {
  const normalized = String(status || "pending").toLowerCase();
  if (
    [
      "complete",
      "completed",
      "validated",
      "approved",
      "deployed",
      "passed",
      "prepared",
      "ready_for_existing_pipeline",
    ].includes(normalized)
  ) {
    return "complete";
  }
  if (["running", "active", "preparing", "in_progress"].includes(normalized)) {
    return "active";
  }
  if (
    [
      "failed",
      "blocked",
      "rejected",
      "cancelled",
      "validation_failed",
      "not_allowed",
      "pending_approval",
    ].includes(normalized)
  ) {
    return "blocked";
  }
  return "pending";
}

function summarizeArtifactsByType(artifacts) {
  return (artifacts || []).reduce((counts, artifact) => {
    const key = artifact.artifact_type || "artifact";
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

function reimportArtifactPayload(artifact) {
  return {
    artifact_type: artifact.artifact_type,
    logical_name: artifact.logical_name,
    content_text: artifact.content_text ?? null,
    content_json: artifact.content_json ?? null,
    methodology_tags: artifact.methodology_tags || [],
    provenance_json: {
      ...(artifact.provenance_json || {}),
      staged_from_pack_forge: true,
    },
  };
}

function renderLifecycleCard(title, status, summary) {
  return `
    <div class="status-count-card tone-${toneForStatus(status)}">
      <strong>${escapeHtml(title)}</strong>
      <small>${statusPill(status)}</small>
      <small>${escapeHtml(summary)}</small>
    </div>
  `;
}

function toolTierLabel(tool) {
  if (tool.tier === "exploitation") return "exploitation";
  return tool.tier || "passive";
}

function toolRiskTier(tool) {
  return tool.tier === "exploitation" ? "intrusive" : tool.tier || "passive";
}

function selectedTool() {
  return TOOL_CATALOG.find((tool) => tool.id === selectedCatalogToolId) || TOOL_CATALOG[0];
}

function currentRunTargetOptions() {
  const values = [];
  const seen = new Set();
  const add = (value) => {
    const normalized = String(value || "").trim();
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    values.push(normalized);
  };
  (state.selectedRun?.tasks || []).forEach((task) => {
    add(task.target_id);
    if (Array.isArray(task.params_json?.targets)) {
      task.params_json.targets.forEach(add);
    }
  });
  const targets = state.selectedRun?.configuration_json?.targets || {};
  Object.values(targets).forEach((value) => {
    if (Array.isArray(value)) value.forEach(add);
    else add(value);
  });
  return values;
}

function renderToolLibraryTargetSelect(targets) {
  if (!state.selectedRun?.id) {
    return `<p class="micro-copy">Select or create a run before adding a manual proposal.</p>`;
  }
  if (!targets.length) {
    return `<p class="micro-copy">The selected run has no recorded target yet, so proposals stay disabled.</p>`;
  }
  if (!selectedCatalogTarget || !targets.includes(selectedCatalogTarget)) {
    selectedCatalogTarget = targets[0];
  }
  return `
    <label class="field compact-field">
      <span>Proposal target</span>
      <select data-tool-library-target>
        ${targets
          .map(
            (target) => `
              <option value="${escapeHtml(target)}" ${target === selectedCatalogTarget ? "selected" : ""}>
                ${escapeHtml(target)}
              </option>
            `
          )
          .join("")}
      </select>
    </label>
  `;
}

function renderToolLibrary() {
  if (!dom.toolLibrary) return;
  const tool = selectedTool();
  const targets = currentRunTargetOptions();
  const categoryCounts = TOOL_CATEGORY_ORDER.map(
    (category) => `${category}: ${TOOL_CATALOG.filter((item) => item.category === category).length}`
  );
  dom.toolLibrary.innerHTML = `
    <div class="tool-library-shell">
      <div class="tool-library-intro detail-surface">
        <div>
          <p class="eyebrow">Operator catalogue</p>
          <h4>${TOOL_CATALOG.length} implemented capabilities</h4>
          <p>
            This catalogue explains existing runners and supporting tools. Manual proposals are review-only:
            they do not queue tasks, dispatch tools, grant approvals, deploy packs, bind runtime packs, or expand scope.
          </p>
        </div>
        <div class="tool-library-summary">
          <span class="metric-pill" data-testid="tool-library-count">${TOOL_CATALOG.length} tools</span>
          <span class="metric-pill">${escapeHtml(`${new Set(TOOL_CATALOG.map((item) => item.category)).size} categories`)}</span>
        </div>
      </div>
      <div class="chip-row split-top">
        ${categoryCounts.map((item) => `<span class="badge">${escapeHtml(item)}</span>`).join("")}
      </div>
      <div class="tool-library-layout split-top">
        <div class="tool-card-grid" data-testid="tool-library-grid">
          ${TOOL_CATALOG.map(
            (item) => `
              <button
                class="tool-card ${item.id === tool.id ? "selected" : ""}"
                type="button"
                data-tool-pick="${escapeHtml(item.id)}"
                data-testid="tool-card"
              >
                <span class="tool-card-kicker">${escapeHtml(item.category)}</span>
                <strong>${escapeHtml(item.name)}</strong>
                <span>${escapeHtml(item.description)}</span>
                <span class="tool-card-meta">${escapeHtml(toolTierLabel(item))}</span>
              </button>
            `
          ).join("")}
        </div>
        <div class="tool-detail detail-surface" data-testid="tool-detail">
          <div class="panel-head compact-head">
            <div>
              <p class="eyebrow">${escapeHtml(tool.category)}</p>
              <h4>${escapeHtml(tool.name)}</h4>
            </div>
            ${statusPill(toolTierLabel(tool))}
          </div>
          <p>${escapeHtml(tool.description)}</p>
          <div class="info-pair-grid split-top">
            <div>
              <p class="eyebrow">Runner binding</p>
              <p>${escapeHtml(toolBackendId(tool))}</p>
            </div>
            <div>
              <p class="eyebrow">Authorization tier</p>
              <p>${escapeHtml(toolTierLabel(tool))}</p>
            </div>
          </div>
          ${renderDisclosure({
            title: "Typical Findings",
            summary: `${tool.findings.length} example outcome${tool.findings.length === 1 ? "" : "s"}`,
            open: true,
            body: `<ul>${tool.findings.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`,
          })}
          ${renderDisclosure({
            title: "Prerequisites",
            summary: `${tool.prerequisites.length} guardrail${tool.prerequisites.length === 1 ? "" : "s"}`,
            body: `<ul>${tool.prerequisites.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`,
          })}
          ${renderDisclosure({
            title: "Assessment Modes",
            summary: tool.chains.join(" · "),
            body: `<ul>${tool.chains.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`,
          })}
          <div class="detail-surface split-top">
            <p class="eyebrow">Manual proposal</p>
            ${renderToolLibraryTargetSelect(targets)}
            <p class="micro-copy">
              Add-to-run creates an operator-review proposal only. Approval still records review intent and does not dispatch work.
            </p>
            <button
              class="action secondary split-top"
              type="button"
              data-tool-library-add="${escapeHtml(tool.id)}"
              data-testid="tool-add-current-run"
              ${state.selectedRun?.id && targets.length ? "" : "disabled"}
            >
              Add to current run
            </button>
          </div>
        </div>
      </div>
    </div>
  `;
  dom.toolLibrary.querySelectorAll("[data-tool-pick]").forEach((item) => {
    item.addEventListener("click", () => {
      selectedCatalogToolId = item.dataset.toolPick || TOOL_CATALOG[0].id;
      renderToolLibrary();
    });
  });
  dom.toolLibrary.querySelector("[data-tool-library-target]")?.addEventListener("change", (event) => {
    selectedCatalogTarget = event.target.value || "";
  });
  dom.toolLibrary.querySelector("[data-tool-library-add]")?.addEventListener("click", async () => {
    await createToolLibraryProposal(tool);
  });
}

async function createToolLibraryProposal(tool) {
  if (!state.selectedRun?.id) {
    throw new Error("Select a run before creating a manual tool proposal.");
  }
  const targets = currentRunTargetOptions();
  const target = selectedCatalogTarget && targets.includes(selectedCatalogTarget) ? selectedCatalogTarget : targets[0];
  if (!target) {
    throw new Error("The selected run has no recorded target for a manual tool proposal.");
  }
  const proposal = await api(`/api/v1/runs/${state.selectedRun.id}/tool-proposals`, {
    method: "POST",
    body: {
      tool_id: tool.id,
      proposed_tool: toolBackendId(tool),
      proposed_target: target,
      proposed_params: {
        ...(tool.params || {}),
        title: `Manual Tool Library proposal: ${tool.name}`,
        summary: tool.description,
        catalog_category: tool.category,
        authorization_tier: toolTierLabel(tool),
        typical_findings: tool.findings,
        prerequisites: tool.prerequisites,
        chain_membership: tool.chains,
      },
      reasoning_text: `Operator selected ${tool.name} from the Tool Library for review against ${target}.`,
      risk_tier: toolRiskTier(tool),
    },
  });
  state.selectedAiInsights = await apiOrNull(`/api/v1/runs/${state.selectedRun.id}/ai-insights`);
  runtime.actions.pushStatus?.(
    `Manual proposal created for ${tool.name}; review it in Mission Control or Live Agents.`,
    "success"
  );
  renderToolLibrary();
  return proposal;
}

function nextLifecycleSuggestion(bundle, relatedCodexTasks) {
  const latestTask = latestItem(relatedCodexTasks);
  const latestValidation = latestItem(bundle.validations);
  const latestApproval = latestItem(bundle.approvals);
  const latestDeployment = latestItem(bundle.deployments);
  const packStatus = String(bundle.pack.status || "").toLowerCase();

  if (!relatedCodexTasks.length) {
    return {
      title: "Create a supervised build-lane task if this pack needs operator-guided refinement.",
      detail:
        "The pack registry is already in place. A build-lane task is only needed when the operator wants a controlled artifact review or refinement pass.",
    };
  }
  if (!state.selectedCodexResult && latestTask && String(latestTask.status).toLowerCase() !== "prepared") {
    return {
      title: "Prepare the selected build-lane task before editing or exporting workspace artifacts.",
      detail:
        "This generates the dry-run commands, workspace path, and validation hooks without changing the active runtime.",
    };
  }
  if (!latestValidation || ["generated", "proposed"].includes(packStatus)) {
    return {
      title: "Validate the generated pack before approval.",
      detail:
        "Validation is the first gate. It syntax-checks and dry-runs the existing artifacts before any approval or deployment decision.",
    };
  }
  if (String(latestValidation.status || "").toLowerCase() !== "validated") {
    return {
      title: "Resolve validation blockers before moving to approval.",
      detail:
        "The validation lane reported a non-ready status. Review the blocking issues and rerun validation instead of bypassing the pack lifecycle.",
    };
  }
  if (!latestApproval || !["approved", "deployed"].includes(packStatus)) {
    return {
      title: "Approval is the next controlled step.",
      detail:
        "The pack has a passing validation result. Review the operator notes and approval trail, then approve if the pack is ready for deployment.",
    };
  }
  if (!latestDeployment || packStatus !== "deployed") {
    return {
      title: "Deploy the approved pack so runs can bind to a fixed version.",
      detail:
        "Deployment makes the reviewed pack version available to engagement runtime binding without changing the runtime in place.",
    };
  }
  return {
    title: "The pack is deployed. Review provenance and prepared tasks for future refinement.",
    detail:
      "This pack is already bound through the normal deployment lane. Any further build-lane work should remain a new supervised refinement cycle.",
  };
}

function renderArtifactPreview(artifact) {
  const provenanceSummary = Object.entries(artifact.provenance_json || {})
    .filter(([, value]) => value !== null && value !== undefined && value !== "" && value !== false)
    .slice(0, 4)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : String(value)}`);

  return renderDisclosure({
    title: artifact.logical_name,
    summary: `${artifact.artifact_type} · ${artifact.status}`,
    body: `
      <div class="info-pair-grid">
        <div>
          <p class="eyebrow">Checksum</p>
          <p>${escapeHtml(artifact.checksum_sha256)}</p>
        </div>
        <div>
          <p class="eyebrow">Content Shape</p>
          <p>${escapeHtml(
            [
              artifact.has_content_text || artifact.content_text ? "text" : null,
              artifact.has_content_json || artifact.content_json ? "json" : null,
            ]
              .filter(Boolean)
              .join(" + ") || "metadata only"
          )}</p>
        </div>
      </div>
      ${renderBadgeList(artifact.methodology_tags, "split-top")}
      ${
        provenanceSummary.length
          ? `<div class="split-top"><p class="eyebrow">Provenance</p><ul>${provenanceSummary
              .map((entry) => `<li>${escapeHtml(entry)}</li>`)
              .join("")}</ul></div>`
          : `<p class="micro-copy split-top">No explicit provenance highlights recorded on this artifact.</p>`
      }
      ${
        artifact.validation_checks?.length
          ? `<div class="split-top"><p class="eyebrow">Validation Expectations</p><ul>${artifact.validation_checks
              .map((entry) => `<li>${escapeHtml(entry)}</li>`)
              .join("")}</ul></div>`
          : ""
      }
    `,
  });
}

export function createPacksModule() {
  async function withPackAction(actionLabel, handler) {
    state.loading.packAction = actionLabel;
    renderPackForge();
    try {
      await handler();
    } finally {
      state.loading.packAction = null;
      renderPackForge();
    }
  }

  function renderPackSummary(bundle, relatedCodexTasks, busyAction) {
    const latestValidation = latestItem(bundle.validations);
    const latestApproval = latestItem(bundle.approvals);
    const latestDeployment = latestItem(bundle.deployments);

    const lifecycleCards = [
      renderLifecycleCard(
        "Proposal",
        relatedCodexTasks[0]?.status || bundle.pack.status,
        relatedCodexTasks.length
          ? `${relatedCodexTasks.length} linked build-lane task${relatedCodexTasks.length === 1 ? "" : "s"}`
          : "No linked build-lane task yet"
      ),
      renderLifecycleCard(
        "Validation",
        latestValidation?.status || "not_run",
        latestValidation?.summary || "Validation has not been executed yet."
      ),
      renderLifecycleCard(
        "Approval",
        latestApproval?.decision || "not_requested",
        latestApproval ? `Last reviewer: ${latestApproval.approver_id}` : "Approval has not been requested."
      ),
      renderLifecycleCard(
        "Deployment",
        latestDeployment?.status || "not_deployed",
        latestDeployment
          ? `${latestDeployment.deployment_target}${latestDeployment.run_profile_name ? ` · ${latestDeployment.run_profile_name}` : ""}`
          : "No deployment has been recorded."
      ),
    ].join("");

    return `
      <h4>${escapeHtml(bundle.pack.name)} <span class="badge">${escapeHtml(bundle.pack.version)}</span></h4>
      <p>${statusPill(bundle.pack.status)} ${escapeHtml(bundle.pack.generation_mode)}</p>
      <p>${escapeHtml(bundle.pack.description || "No description recorded.")}</p>
      <div class="info-pair-grid split-top" data-testid="codex-pack-overview">
        <div>
          <p class="eyebrow">Inventory Source</p>
          <p>${escapeHtml(shortId(bundle.context.source_inventory_snapshot_id))}</p>
        </div>
        <div>
          <p class="eyebrow">Relevance Decision</p>
          <p>${escapeHtml(shortId(bundle.context.relevance_decision_id))}</p>
        </div>
        <div>
          <p class="eyebrow">Threat Intel</p>
          <p>${escapeHtml(String(bundle.context.source_threat_intel_refs.length || 0))} reference(s)</p>
        </div>
        <div>
          <p class="eyebrow">Latest Validation</p>
          <p>${statusPill(bundle.context.latest_validation_status || "not_run")}</p>
        </div>
      </div>
      ${renderBadgeList(bundle.pack.methodology_tags, "split-top")}
      <div class="status-grid split-top" data-testid="codex-lifecycle">
        ${lifecycleCards}
      </div>
      ${
        busyAction
          ? `
            <div class="detail-surface split-top" data-testid="pack-action-status">
              <h4>Pack action in progress</h4>
              <p>${escapeHtml(busyAction)}</p>
              <p class="micro-copy">The promotion lane remains controlled while validation, approval, or deployment completes.</p>
            </div>
          `
          : ""
      }
      <div class="panel-actions">
        <button class="action ghost" type="button" data-nav-screen="mission-control">Open Mission Control</button>
        <button class="action ghost" type="button" data-nav-screen="report-center">Open Report Center</button>
      </div>
    `;
  }

  function renderPackRegistry(bundle, relatedCodexTasks) {
    return `
      <div class="stack-zone">
        <div class="list-card">
          <h4>Capability Packs</h4>
          <div class="stack-zone split-top">
            ${state.mission.packs
              .map(
                (pack) => `
                  <div class="list-card ${pack.id === state.selectedPackId ? "selected" : ""}" data-pack-pick="${pack.id}" data-testid="pack-card">
                    <h4>${escapeHtml(pack.name)} <span class="badge">${escapeHtml(pack.version)}</span></h4>
                    <p>${statusPill(pack.status)} ${escapeHtml(pack.generation_mode)}</p>
                  </div>
                `
              )
              .join("")}
          </div>
        </div>
        ${renderDisclosure({
          title: "Artifact Registry",
          summary: `${bundle.artifacts.length} artifact${bundle.artifacts.length === 1 ? "" : "s"} across ${Object.keys(summarizeArtifactsByType(bundle.artifacts)).length || 0} types`,
          open: true,
          testId: "pack-registry-artifacts",
          body: bundle.artifacts.length
            ? bundle.artifacts
                .map(
                  (artifact) => `
                    <div class="artifact-card split-top">
                      <h4>${escapeHtml(artifact.logical_name)}</h4>
                      <p>${escapeHtml(`${artifact.artifact_type} · ${artifact.status}`)}</p>
                      ${renderBadgeList(artifact.methodology_tags)}
                      <p class="micro-copy split-top">${escapeHtml(artifact.checksum_sha256)}</p>
                    </div>
                  `
                )
                .join("")
            : "<p>No pack artifacts recorded.</p>",
        })}
        <div class="wizard-panel-grid">
          <div class="detail-surface">
            <h4>Validation</h4>
            ${
              bundle.validations.length
                ? bundle.validations
                    .map((validation) => {
                      const blockingIssues = validation.blocking_issues_json || [];
                      return `
                        <div class="split-top">
                          <p>${statusPill(validation.status)} ${escapeHtml(validation.validator)} · ${escapeHtml(validation.summary || "No summary")}</p>
                          <p class="micro-copy">${escapeHtml(`${blockingIssues.length} blocking issue${blockingIssues.length === 1 ? "" : "s"} · ${formatDateTime(validation.created_at)}`)}</p>
                        </div>
                      `;
                    })
                    .join("")
                : "<p>No validation results yet.</p>"
            }
          </div>
          <div class="detail-surface">
            <h4>Approvals</h4>
            ${
              bundle.approvals.length
                ? bundle.approvals
                    .map(
                      (approval) => `
                        <div class="split-top">
                          <p>${statusPill(approval.decision)} ${escapeHtml(approval.approver_id)} · ${escapeHtml(approval.notes || "No notes")}</p>
                          <p class="micro-copy">${escapeHtml(formatDateTime(approval.created_at))}</p>
                        </div>
                      `
                    )
                    .join("")
                : "<p>No pack approvals recorded.</p>"
            }
          </div>
        </div>
        <div class="detail-surface">
          <h4>Deployments & Linked Build-Lane Tasks</h4>
          <p>${escapeHtml(`${bundle.deployments.length} deployment${bundle.deployments.length === 1 ? "" : "s"} · ${relatedCodexTasks.length} linked build-lane task${relatedCodexTasks.length === 1 ? "" : "s"}`)}</p>
          ${
            bundle.deployments.length
              ? bundle.deployments
                  .map(
                    (deployment) => `
                      <p class="micro-copy split-top">${escapeHtml(
                        `${deployment.status} to ${deployment.deployment_target}${
                          deployment.run_profile_name ? ` · ${deployment.run_profile_name}` : ""
                        }`
                      )}</p>
                    `
                  )
                  .join("")
              : "<p class='micro-copy'>No deployment history yet.</p>"
          }
        </div>
      </div>
    `;
  }

  function renderCodexSuggestions(bundle, relatedCodexTasks) {
    const latestTask = relatedCodexTasks.find((task) => task.id === state.selectedCodexTaskId) || relatedCodexTasks[0] || null;
    const suggestion = nextLifecycleSuggestion(bundle, relatedCodexTasks);
    const visibility = bundle.context.operator_visibility;

    dom.codexSuggestions.innerHTML = `
      <h4>Operator Suggestions</h4>
      <p>${escapeHtml(suggestion.title)}</p>
      <p class="micro-copy">${escapeHtml(suggestion.detail)}</p>
      <div class="info-pair-grid split-top">
        <div>
          <p class="eyebrow">Linked Task</p>
          <p>${latestTask ? escapeHtml(`${latestTask.task_type} · ${latestTask.id}`) : "No build-lane task selected"}</p>
        </div>
        <div>
          <p class="eyebrow">Task Status</p>
          <p>${latestTask ? statusPill(latestTask.status) : statusPill("not_requested")}</p>
        </div>
        <div>
          <p class="eyebrow">Approval Lane</p>
          <p>${latestTask ? statusPill(latestTask.approval_status) : statusPill("not_requested")}</p>
        </div>
        <div>
          <p class="eyebrow">Runtime Safety</p>
          <p>${bundle.context.active_runtime_mutation_allowed ? "Runtime mutation allowed" : "Runtime mutation blocked"}</p>
        </div>
      </div>
      ${
        latestTask
          ? `
            <div class="split-top">
              <p class="eyebrow">Generation Reason</p>
              <p>${escapeHtml(latestTask.generation_reason || bundle.context.generation_reason || "No generation reason recorded.")}</p>
            </div>
          `
          : `
            <div class="split-top">
              <p class="eyebrow">Generation Reason</p>
              <p>${escapeHtml(bundle.context.generation_reason || "No build-lane task is linked yet, so only pack-level generation context is available.")}</p>
            </div>
          `
      }
      ${renderDisclosure({
        title: "Required Operator Visibility",
        summary: `${visibility.required_badges.length} badges · ${visibility.required_fields.length} required fields`,
        body: `
          <p class="eyebrow">Required badges</p>
          ${renderBadgeList(visibility.required_badges)}
          <p class="eyebrow split-top">Required fields</p>
          <ul>${visibility.required_fields.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        `,
      })}
      ${renderDisclosure({
        title: "Review Sections",
        summary: `${visibility.review_sections.length} controlled review sections`,
        body: `
          <ul>${visibility.review_sections.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
          <p class="eyebrow split-top">Finding provenance remains visible via</p>
          <ul>${visibility.finding_provenance_fields.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        `,
      })}
    `;
  }

  function renderCodexPackPreview(bundle) {
    const artifactCounts = summarizeArtifactsByType(bundle.context.artifacts);
    const artifactBadges = Object.entries(artifactCounts).map(([artifactType, count]) => `${artifactType} (${count})`);

    dom.codexPackPreview.innerHTML = `
      <h4>Generated Pack Preview</h4>
      <p>${escapeHtml(
        `${bundle.context.artifacts.length} exportable artifact${bundle.context.artifacts.length === 1 ? "" : "s"} are tied to this pack review bundle.`
      )}</p>
      ${renderBadgeList(artifactBadges, "split-top")}
      <div class="artifact-preview-list split-top">
        ${
          bundle.context.artifacts.length
            ? bundle.context.artifacts.map((artifact) => renderArtifactPreview(artifact)).join("")
            : emptyState("No exported artifacts were recorded for this pack.")
        }
      </div>
      <p class="micro-copy split-top">The full artifact registry, validations, approvals, and deployment history remain visible in the registry panel to the left.</p>
    `;
  }

  function renderCodexContext(bundle) {
    dom.codexContext.innerHTML = `
      <h4>Build Lane Guardrails</h4>
      <p>${statusPill(bundle.context.pack_status)} ${escapeHtml(bundle.context.generation_mode)}</p>
      <div class="info-pair-grid split-top">
        <div>
          <p class="eyebrow">Suggested Branch</p>
          <p>${escapeHtml(bundle.context.repo_conventions.suggested_branch_name)}</p>
        </div>
        <div>
          <p class="eyebrow">Workspace Root</p>
          <p>${escapeHtml(bundle.context.repo_conventions.workspace_root)}</p>
        </div>
      </div>
      ${renderDisclosure({
        title: "Runtime Guardrails",
        summary: `${bundle.context.runtime_guardrails.length} rules that keep supervised build work out of the live runtime`,
        body: `<ul>${bundle.context.runtime_guardrails.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`,
      })}
      ${renderDisclosure({
        title: "Validation Hooks",
        summary: `${bundle.context.validation_hooks.length} existing pack lifecycle hooks`,
        body: bundle.context.validation_hooks
          .map(
            (hook) => `
              <div class="split-top">
                <p>${statusPill(hook.blocking ? "blocked" : "review")} ${escapeHtml(`${hook.name} · ${hook.method} ${hook.path}`)}</p>
                <p class="micro-copy">${escapeHtml(hook.description)}</p>
                ${
                  hook.artifact_types?.length
                    ? `<p class="micro-copy">Artifact focus: ${escapeHtml(hook.artifact_types.join(", "))}</p>`
                    : ""
                }
                ${
                  hook.expected_checks?.length
                    ? `<p class="micro-copy">Expected checks: ${escapeHtml(hook.expected_checks.join(" · "))}</p>`
                    : ""
                }
                ${
                  hook.workspace_files?.length
                    ? `<p class="micro-copy">Workspace files: ${escapeHtml(hook.workspace_files.join(" · "))}</p>`
                    : ""
                }
              </div>
            `
          )
          .join(""),
      })}
      ${renderDisclosure({
        title: "Repository Conventions",
        summary: `${bundle.context.repo_conventions.notes_file}, ${bundle.context.repo_conventions.change_summary_file}, ${bundle.context.repo_conventions.review_bundle_file}`,
        body: `
          <p class="micro-copy">${escapeHtml(bundle.context.repo_conventions.export_command)}</p>
          <p class="micro-copy split-top">${escapeHtml(bundle.context.repo_conventions.validation_command)}</p>
          <ul class="split-top">${bundle.context.repo_conventions.rules.map((rule) => `<li>${escapeHtml(rule)}</li>`).join("")}</ul>
        `,
      })}
    `;
  }

  function renderCodexTaskResult(bundle) {
    const latestValidation = bundle ? latestItem(bundle.validations) : null;
    const validationPassed = String(latestValidation?.status || "").toLowerCase() === "passed";
    const canStageReimport = Boolean(state.selectedCodexResult && validationPassed && bundle?.artifacts?.length);

    dom.codexTaskResult.innerHTML = state.selectedCodexResult
      ? `
        <h4>Prepared Task Output</h4>
        <p>${statusPill(state.selectedCodexResult.status)} dry run ${String(state.selectedCodexResult.dry_run)}</p>
        <p>${escapeHtml(state.selectedCodexResult.summary)}</p>
        ${renderDisclosure({
          title: "Prepared Commands",
          summary: `${state.selectedCodexResult.prepared_commands.length} commands`,
          open: true,
          body: `<ul>${state.selectedCodexResult.prepared_commands.map((command) => `<li>${escapeHtml(command)}</li>`).join("")}</ul>`,
          testId: "codex-prepared-commands",
        })}
        ${renderDisclosure({
          title: "Output Files",
          summary: `${state.selectedCodexResult.output_files.length} repo-backed artifacts`,
          body: `<ul>${state.selectedCodexResult.output_files.map((path) => `<li>${escapeHtml(path)}</li>`).join("")}</ul>`,
        })}
        ${renderDisclosure({
          title: "Task Guardrails",
          summary: `${state.selectedCodexResult.guardrails.length} execution guardrails`,
          body: `<ul>${state.selectedCodexResult.guardrails.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`,
        })}
        ${renderDisclosure({
          title: "Validation Handoff",
          summary: `${state.selectedCodexResult.validation_hooks.length} existing validation hooks`,
          body: state.selectedCodexResult.validation_hooks
            .map(
              (hook) => `
                <div class="split-top">
                  <p>${statusPill(hook.blocking ? "blocked" : "review")} ${escapeHtml(`${hook.name} · ${hook.method} ${hook.path}`)}</p>
                  <p class="micro-copy">${escapeHtml(hook.description)}</p>
                  ${
                    hook.artifact_types?.length
                      ? `<p class="micro-copy">Artifact focus: ${escapeHtml(hook.artifact_types.join(", "))}</p>`
                      : ""
                  }
                  ${
                    hook.expected_checks?.length
                      ? `<p class="micro-copy">Expected checks: ${escapeHtml(hook.expected_checks.join(" · "))}</p>`
                      : ""
                  }
                  ${
                    hook.workspace_files?.length
                      ? `<p class="micro-copy">Workspace files: ${escapeHtml(hook.workspace_files.join(" · "))}</p>`
                      : ""
                  }
                </div>
              `
            )
            .join(""),
          testId: "codex-validation-handoff",
        })}
        <div class="detail-surface split-top" data-testid="codex-reimport-panel">
          <h4>Controlled Artifact Reimport</h4>
          <p>
            ${statusPill(canStageReimport ? "ready" : "blocked")}
            ${escapeHtml(
              canStageReimport
                ? "Validation result is available. Reimport will create a generated child pack that still needs validation, approval, and deployment."
                : "Prepare a build-lane task and record a passing pack validation result before staging reimported artifacts."
            )}
          </p>
          <p class="micro-copy">
            Reimport never deploys automatically and never mutates a runtime-bound pack in place.
          </p>
          <button class="action secondary split-top" type="button" data-stage-codex-reimport ${canStageReimport ? "" : "disabled"}>
            Stage Validated Child Pack
          </button>
        </div>
      `
      : emptyState(
          bundle
            ? "Create or select a build-lane task to view prepared commands, output files, and validation hooks."
            : "Prepared task output appears here."
        );
  }

  function renderPackForge() {
    const buildLaneEnabled = setBuildLanePanelVisibility();

    renderAdaptiveForm();
    renderToolLibrary();
    if (buildLaneEnabled) {
      renderCodexTaskForm();
    } else {
      dom.codexTaskForm.innerHTML = "";
      dom.codexTaskForm.onsubmit = null;
      dom.prepareCodexTaskBtn.disabled = true;
      dom.codexSuggestions.innerHTML = "";
      dom.codexPackPreview.innerHTML = "";
      dom.codexContext.innerHTML = "";
      dom.codexTaskResult.innerHTML = "";
    }

    if (!state.selectedPackBundle) {
      dom.validatePackBtn.disabled = true;
      dom.approvePackBtn.disabled = true;
      dom.deployPackBtn.disabled = true;
      dom.packSummary.innerHTML = emptyState(
        "Generate or select a capability pack to review promotion readiness."
      );
      dom.packForgeDetail.innerHTML = emptyState(
        "Pack artifacts, validations, approvals, deployments, and build-lane tasks appear here."
      );
      if (buildLaneEnabled) {
        dom.codexSuggestions.innerHTML = emptyState(
          "Operator suggestions appear once a pack and optional build-lane task are linked."
        );
        dom.codexPackPreview.innerHTML = emptyState(
          "Generated pack previews appear once a review bundle is available."
        );
        dom.codexContext.innerHTML = emptyState("Build-lane context is available once a pack is selected.");
        dom.codexTaskResult.innerHTML = emptyState(
          "Prepared task output appears here."
        );
        dom.prepareCodexTaskBtn.disabled = true;
      }
      return;
    }

    const bundle = state.selectedPackBundle;
    const busyAction = state.loading.packAction;
    const actionBusy = Boolean(busyAction);
    const relatedCodexTasks = filteredCodexTasks();
    if (relatedCodexTasks.length && !relatedCodexTasks.some((task) => task.id === state.selectedCodexTaskId)) {
      state.selectedCodexTaskId = relatedCodexTasks[0].id;
    }
    dom.validatePackBtn.disabled =
      actionBusy || ["validated", "approved", "deployed"].includes(bundle.pack.status);
    dom.approvePackBtn.disabled =
      actionBusy || !["validated", "approved", "deployed"].includes(bundle.pack.status);
    dom.deployPackBtn.disabled =
      actionBusy || !["approved", "deployed"].includes(bundle.pack.status);
    dom.prepareCodexTaskBtn.disabled = !buildLaneEnabled || actionBusy || !relatedCodexTasks.length;

    dom.packSummary.innerHTML = renderPackSummary(bundle, relatedCodexTasks, busyAction);
    dom.packForgeDetail.innerHTML = renderPackRegistry(bundle, relatedCodexTasks);
    dom.packForgeDetail.querySelectorAll("[data-pack-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedPackId = item.dataset.packPick;
        await runtime.actions.loadSelectedPack?.();
        renderPackForge();
        runtime.actions.renderMissionControl?.();
      });
    });

    if (buildLaneEnabled) {
      renderCodexSuggestions(bundle, relatedCodexTasks);
      renderCodexPackPreview(bundle);
      renderCodexContext(bundle);
      renderCodexTaskResult(bundle);
      dom.codexTaskResult.querySelector("[data-stage-codex-reimport]")?.addEventListener("click", async () => {
        try {
          await stageCodexReimport(bundle);
        } catch (error) {
          runtime.actions.pushStatus?.(error.message || "Unable to stage build-lane reimport.", "error");
        }
      });
    }
  }

  function renderAdaptiveForm() {
    const inventorySnapshot = runtime.actions.latestInventorySnapshot?.();
    dom.adaptiveForm.innerHTML = `
      <label class="field">
        <span>Inventory Basis</span>
        <div class="detail-surface">
          <p>${inventorySnapshot ? escapeHtml(`${inventorySnapshot.id} · ${inventorySnapshot.summary_json.endpoint_count} endpoints`) : "No inventory snapshot available."}</p>
          <p class="micro-copy">Adaptive planning uses the latest inventory snapshot and selected engagement scope.</p>
        </div>
      </label>
      <label class="field">
        <span>Advisory Source</span>
        <input name="source" type="text" value="vendor-advisory" />
      </label>
      <label class="field">
        <span>Advisory ID</span>
        <input name="advisory_id" type="text" placeholder="CVE-2026-1000" />
      </label>
      <label class="field">
        <span>Title</span>
        <input name="title" type="text" placeholder="Auth regression follow-up" />
      </label>
      <label class="field">
        <span>Summary</span>
        <textarea name="summary" rows="3" placeholder="Summarize the relevant advisory or testing pattern."></textarea>
      </label>
      <label class="field">
        <span>Affected Product</span>
        <input name="product" type="text" placeholder="grafana" />
      </label>
      <label class="field">
        <span>Product Match Hint</span>
        <input name="hint" type="text" placeholder="grafana labs" />
      </label>
      <label class="field">
        <span>Attack Surface Type</span>
        <input name="attack_surface_type" type="text" value="auth" />
      </label>
      <label class="field">
        <span>Severity</span>
        <input name="severity" type="text" value="high" />
      </label>
      <label class="field">
        <span>Suggested Patterns</span>
        <input name="patterns" type="text" value="playwright,zap" />
      </label>
      <label class="field">
        <span>Pack Name</span>
        <input name="pack_name" type="text" placeholder="customer-adaptive-pack" />
      </label>
      <button class="action primary" type="submit">Generate Adaptive Pack</button>
    `;
    dom.adaptiveForm.onsubmit = async (event) => {
      event.preventDefault();
      assertSelectedEngagement();
      const inventoryId = runtime.actions.latestInventorySnapshot?.()?.id;
      if (!inventoryId) {
        throw new Error("Create or seed an inventory snapshot before generating adaptive coverage.");
      }
      const form = new FormData(dom.adaptiveForm);
      await withPackAction("Generating adaptive pack", async () => {
        const threatIntel = await api("/api/v1/threat-intel/ingest", {
          method: "POST",
          body: {
            records: [
              {
                source: stringValue(form.get("source")) || "vendor-advisory",
                advisory_id: stringValue(form.get("advisory_id")),
                title: stringValue(form.get("title")) || "Adaptive testing advisory",
                summary: valueOrNull(form.get("summary")),
                affected_products: splitComma(form.get("product")),
                product_match_hints: splitComma(form.get("hint")),
                attack_surface_type: valueOrNull(form.get("attack_surface_type")),
                suggested_test_patterns: splitComma(form.get("patterns")),
                confidence: 0.9,
                severity: valueOrNull(form.get("severity")),
                references: [],
              },
            ],
          },
        });
        const relevance = await api("/api/v1/relevance/analyze", {
          method: "POST",
          body: {
            engagement_id: state.selectedEngagementId,
            inventory_snapshot_id: inventoryId,
            threat_intel_ids: [threatIntel[0].id],
            include_prior_findings: true,
          },
        });
        const pack = await api("/api/v1/packs/generate", {
          method: "POST",
          body: {
            engagement_id: state.selectedEngagementId,
            relevance_decision_id: relevance.id,
            name: valueOrNull(form.get("pack_name")) || undefined,
          },
        });
        state.selectedPackId = pack.id;
        runtime.actions.pushStatus?.(`Adaptive pack ${pack.name} ${pack.version} generated.`, "success");
        await runtime.actions.refreshSelectedEngagement?.();
      });
    };
  }

  function renderCodexTaskForm() {
    dom.codexTaskForm.innerHTML = `
      <label class="field">
        <span>Task Type</span>
        <input name="task_type" type="text" value="pack_refinement" />
      </label>
      <label class="field">
        <span>Scope</span>
        <textarea name="scope" rows="3" placeholder="Refine or review the selected adaptive pack."></textarea>
      </label>
      <label class="field">
        <span>Generation Reason</span>
        <textarea name="generation_reason" rows="3" placeholder="Explain why this supervised build-lane task is needed."></textarea>
      </label>
      <button class="action secondary" type="submit">Create Build-Lane Task</button>
      <div class="stack-zone split-top">
        ${filteredCodexTasks()
          .map(
            (task) => `
              <div class="list-card ${task.id === state.selectedCodexTaskId ? "selected" : ""}" data-codex-pick="${task.id}" data-testid="codex-task-card">
                <h4>${escapeHtml(task.task_type)}</h4>
                <p>${statusPill(task.status)} ${escapeHtml(task.validation_status)}</p>
                <p class="micro-copy">${escapeHtml(`Task ${task.id}`)}</p>
                <p class="micro-copy split-top">Select this task to inspect prepared output, controlled commands, and validation handoff.</p>
              </div>
            `
          )
          .join("") || emptyState("No build-lane tasks are linked to the selected pack yet.")}
      </div>
    `;
    dom.codexTaskForm.onsubmit = async (event) => {
      event.preventDefault();
      assertSelectedPack();
      const form = new FormData(dom.codexTaskForm);
      const task = await api("/api/v1/codex/tasks", {
        method: "POST",
        body: {
          task_type: stringValue(form.get("task_type")) || "pack_refinement",
          scope: stringValue(form.get("scope")) || "Review selected pack artifacts.",
          inputs: { selected_engagement_id: state.selectedEngagementId },
          constraints: { runtime_mutation: false, protected_runtime: true },
          expected_output: { review_bundle: true, validation_required: true },
          generation_reason: stringValue(form.get("generation_reason")) || "Operator requested pack review.",
          source_context: { pack_id: state.selectedPackId },
        },
      });
      state.selectedCodexTaskId = task.id;
      state.selectedCodexResult = null;
      runtime.actions.pushStatus?.("Build-lane task created in the supervised build lane.", "success");
      state.codexTasks = await api("/api/v1/codex/tasks");
      renderPackForge();
    };
    dom.codexTaskForm.querySelectorAll("[data-codex-pick]").forEach((item) => {
      item.addEventListener("click", async () => {
        state.selectedCodexTaskId = item.dataset.codexPick;
        state.selectedCodexResult = await apiOrNull(`/api/v1/codex/tasks/${state.selectedCodexTaskId}/result`);
        renderPackForge();
      });
    });
  }

  async function validateSelectedPack() {
    assertSelectedPack();
    await withPackAction("Validating selected pack", async () => {
      await api(`/api/v1/packs/${state.selectedPackId}/validate`, { method: "POST" });
      runtime.actions.pushStatus?.("Pack validation completed.", "success");
      await runtime.actions.refreshSelectedEngagement?.();
    });
  }

  async function approveSelectedPack() {
    assertSelectedPack();
    await withPackAction("Promoting pack for approval", async () => {
      await api(
        `/api/v1/packs/${state.selectedPackId}/approve?notes=Approved%20from%20operator%20console`,
        { method: "POST" }
      );
      runtime.actions.pushStatus?.("Pack approved for promotion.", "success");
      await runtime.actions.refreshSelectedEngagement?.();
    });
  }

  async function deploySelectedPack() {
    assertSelectedPack();
    assertSelectedEngagement();
    await withPackAction("Deploying approved pack", async () => {
      await api(`/api/v1/packs/${state.selectedPackId}/deploy`, {
        method: "POST",
        body: {
          engagement_id: state.selectedEngagementId,
          deployment_target: "engagement-runtime",
          run_profile_name: state.selectedRun?.profile?.name || null,
        },
      });
      runtime.actions.pushStatus?.("Pack deployed and available for run binding.", "success");
      await runtime.actions.refreshSelectedEngagement?.();
    });
  }

  async function prepareSelectedCodexTask() {
    const taskId = state.selectedCodexTaskId || filteredCodexTasks()[0]?.id;
    if (!taskId) {
      throw new Error("Create or select a build-lane task first.");
    }
    await withPackAction("Preparing build-lane dry-run task", async () => {
      state.selectedCodexResult = await api(`/api/v1/codex/tasks/${taskId}/run`, {
        method: "POST",
        body: {
          base_url: window.location.origin,
          workspace_root: `./codex-workspaces/${slugify(runtime.actions.selectedPack?.()?.name || "pack")}`,
          dry_run: true,
        },
      });
      runtime.actions.pushStatus?.("Build-lane task prepared in dry-run mode.", "success");
      renderPackForge();
    });
  }

  async function stageCodexReimport(bundle) {
    assertSelectedPack();
    const latestValidation = latestItem(bundle.validations);
    if (!latestValidation || String(latestValidation.status || "").toLowerCase() !== "passed") {
      throw new Error("Run pack validation successfully before staging build-lane reimport.");
    }
    await withPackAction("Staging controlled build-lane reimport", async () => {
      const response = await api(`/api/v1/packs/${state.selectedPackId}/codex-reimport`, {
        method: "POST",
        body: {
          codex_task_id: state.selectedCodexTaskId,
          pack_version: bundle.pack.version,
          validation_result: latestValidation,
          change_summary: "Pack Forge staged validated build-lane workspace output for operator review.",
          operator_notes: "Staged from Pack Forge; runtime use still requires validation, approval, deployment, and binding.",
          artifacts: (bundle.artifacts || []).map((artifact) => reimportArtifactPayload(artifact)),
        },
      });
      state.selectedPackId = response.staged_pack.id;
      state.selectedCodexResult = null;
      runtime.actions.pushStatus?.("Build-lane reimport staged as a generated child pack.", "success");
      await runtime.actions.refreshSelectedEngagement?.();
    });
  }

  return {
    filteredCodexTasks,
    prepareSelectedCodexTask,
    renderPackForge,
    validateSelectedPack,
    approveSelectedPack,
    deploySelectedPack,
  };
}
