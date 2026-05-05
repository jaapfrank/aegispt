import {
  ASSESSMENT_TYPES,
  DEFAULT_MODULE_STATE,
  DEFAULT_SAFETY,
  MODULES,
  TEST_PROFILES,
  WIZARD_STEPS,
} from "./constants.js";
import { api } from "./api.js";
import { buildEmptyAccount, buildEmptyWizardState, dom, patchState, runtime, state } from "./runtime.js";
import {
  countMeaningfulAccessContexts,
  emptyState,
  executionPlanForProfile,
  capitalizeWord,
  enabledModules,
  escapeHtml,
  formatDateTime,
  fieldHelp,
  fieldLabel,
  flattenTargetValues,
  hasMeaningfulAccount,
  hasMeaningfulAccessContext,
  humanizeCheckMode,
  humanizeDepthLabel,
  inferAuthStrategyFromAccess,
  isLikelyCidr,
  isLikelyDomain,
  isLikelyIp,
  isLikelyUrl,
  numberValue,
  readinessSummary,
  renderAccessContextSummary,
  renderBadgeList,
  renderDisclosure,
  renderTargetSummary,
  requiresCredentials,
  splitComma,
  splitLines,
  stringValue,
  textareaField,
  valueOrNull,
} from "./shared.js";

const RECENT_MISSION_SCOPE_CACHE = new Map();
const RECENT_MISSION_PREFILL_CACHE = new Map();
const RECENT_MISSION_SCOPE_REQUESTS = new Set();

const ASSESSMENT_MODE_OPTIONS = [
  {
    value: "",
    label: "Disabled",
    copy: "Keep the current one-run-at-a-time launch model.",
  },
  {
    value: "FULL-INTERNAL-LAN",
    label: "Full Internal LAN",
    copy: "Chain passive discovery, active enrichment, credential validation, and exploit confirmation per phase.",
  },
  {
    value: "FULL-EXTERNAL-WEB",
    label: "Full External Web",
    copy: "Chain passive web mapping, active web validation, and gated intrusive confirmation.",
  },
  {
    value: "FULL-AD-ASSESSMENT",
    label: "Full AD Assessment",
    copy: "Chain directory baseline, BloodHound, credential impact, and gated lateral confirmation.",
  },
  {
    value: "FULL-LAN-IOT",
    label: "Full LAN + IoT",
    copy: "Chain LAN discovery, IoT enumeration, smart-home analysis, credential checks, segmentation, and optional intrusive validation.",
  },
];

const ASSESSMENT_TILE_OPTIONS = [
  {
    key: "external-web",
    label: "External Web",
    icon: "🌐",
    badge: "Popular",
    badgeClass: "badge-amber",
    phaseTags: [{ label: "passive", cls: "tag-p" }, { label: "active", cls: "tag-a" }],
    description: "Websites, web apps, and public application surfaces reachable from the internet.",
    assessmentType: "Website / Web App",
    quickReply: "Our web application",
    recommended: true,
  },
  {
    key: "external-infrastructure",
    label: "External IPs",
    icon: "🖧",
    badge: "New",
    badgeClass: "badge-green",
    phaseTags: [{ label: "passive", cls: "tag-p" }, { label: "active", cls: "tag-a" }],
    description: "External IP ranges, exposed services, SSH/RDP/VPN endpoints, and non-web internet-facing hosts.",
    assessmentType: "External IP / WAN",
    quickReply: "Our external infrastructure",
    recommended: true,
  },
  {
    key: "internal-lan",
    label: "Internal LAN",
    icon: "🏠",
    badge: "Popular",
    badgeClass: "badge-amber",
    phaseTags: [{ label: "passive", cls: "tag-p" }, { label: "active", cls: "tag-a" }, { label: "credential", cls: "tag-c" }],
    description: "Internal network ranges, subnets, office segments, and on-premise servers.",
    assessmentType: "Internal Range / LAN",
    quickReply: "My LAN network",
    recommended: true,
  },
  {
    key: "active-directory",
    label: "Active Directory",
    icon: "🛡️",
    badge: "AD",
    badgeClass: "badge-violet",
    phaseTags: [{ label: "passive", cls: "tag-p" }, { label: "active", cls: "tag-a" }, { label: "credential", cls: "tag-c" }, { label: "exploit", cls: "tag-e" }],
    description: "Domain controllers, AD identities, trust edges, and directory attack paths.",
    assessmentType: "Internal Range / LAN",
    quickReply: "Active Directory",
  },
  {
    key: "full-internal",
    label: "Full Internal",
    icon: "🎯",
    badge: "Complete",
    badgeClass: "badge-red",
    phaseTags: [{ label: "P1", cls: "tag-p" }, { label: "P2", cls: "tag-a" }, { label: "P3", cls: "tag-c" }, { label: "P4", cls: "tag-e" }],
    description: "Broader internal validation across LAN, identity, and deeper follow-up workflows.",
    assessmentType: "Internal Range / LAN",
    quickReply: "Full internal assessment",
  },
  {
    key: "smart-home-lan",
    label: "Smart Home / IoT LAN",
    icon: "🏠🔒",
    badge: "IoT",
    badgeClass: "badge-green",
    phaseTags: [{ label: "P1", cls: "tag-p" }, { label: "P2", cls: "tag-a" }, { label: "P3", cls: "tag-a" }, { label: "P6", cls: "tag-c" }],
    description: "Smart home hubs, IP cameras, consumer IoT, gateways, SNMP devices, segmentation, and IPv6 on an internal LAN.",
    assessmentType: "Internal Range / LAN",
    quickReply: "Smart home / IoT LAN",
    recommended: true,
  },
  {
    key: "wifi-wireless",
    label: "WiFi / Wireless",
    icon: "📶",
    badge: "Passive",
    badgeClass: "badge-green",
    phaseTags: [{ label: "passive", cls: "tag-p" }],
    description: "Authorized wireless sites, SSIDs, BSSIDs, adapter context, and passive AP posture review.",
    assessmentType: "WiFi / Wireless",
    quickReply: "WiFi assessment",
    recommended: true,
  },
  {
    key: "cloud",
    label: "Cloud (AWS/Azure)",
    icon: "☁️",
    badge: null,
    badgeClass: null,
    phaseTags: [{ label: "passive", cls: "tag-p" }, { label: "active", cls: "tag-a" }],
    description: "Cloud infrastructure, IAM exposure, and tenant-facing control plane review.",
    assessmentType: "Mixed Assessment",
    quickReply: "Cloud environment",
  },
  {
    key: "api-security",
    label: "API Security",
    icon: "{ }",
    badge: null,
    badgeClass: null,
    phaseTags: [{ label: "passive", cls: "tag-p" }, { label: "active", cls: "tag-a" }],
    description: "REST, GraphQL, gRPC, and other endpoint-centric application surfaces.",
    assessmentType: "API",
    quickReply: "Our API",
    recommended: true,
  },
  {
    key: "llm-ai-app",
    label: "LLM / AI App",
    icon: "🤖",
    badge: "New",
    badgeClass: "badge-violet",
    phaseTags: [{ label: "active", cls: "tag-a" }],
    description: "Prompt injection, model misuse, agent behavior, and AI-assisted app workflows.",
    assessmentType: "Website / Web App",
    quickReply: "LLM / AI application",
  },
  {
    key: "custom",
    label: "Custom",
    icon: "⚙️",
    badge: null,
    badgeClass: null,
    phaseTags: [{ label: "fine-tune", cls: "tag-custom" }],
    description: "Build your own combination and refine the exact run model in Advanced Configuration.",
    assessmentType: "Mixed Assessment",
    quickReply: "A mixed environment",
  },
  {
    key: "ssl-tls",
    label: "SSL/TLS Only",
    icon: "🔐",
    badge: "TLS",
    badgeClass: "badge-green",
    phaseTags: [{ label: "passive", cls: "tag-p" }],
    description: "Certificate, protocol, cipher, and transport-security posture for a specific hostname, URL, or IP.",
    assessmentType: "SSL/TLS Only",
    quickReply: "TLS posture review",
    recommended: true,
  },
  {
    key: "authenticated-app",
    label: "Authenticated App",
    icon: "🔑",
    badge: "Access",
    badgeClass: "badge-violet",
    phaseTags: [{ label: "active", cls: "tag-a" }, { label: "credential", cls: "tag-c" }],
    description: "Application testing where login, session, API token, or role context is central to the assessment.",
    assessmentType: "Authenticated App",
    quickReply: "Authenticated app",
    recommended: true,
  },
];

const TILE_FLOW_SPECIAL_KEYS = new Set(["active-directory", "full-internal", "smart-home-lan", "wifi-wireless", "cloud", "llm-ai-app", "custom"]);

const AUTHORIZATION_LEVEL_OPTIONS = [
  {
    value: "passive",
    label: "Passive only",
    copy: "Stop after the passive baseline and wait before a higher tier begins.",
    boundaryCopy: "Auto stops after Phase 1.",
    tierRank: 0,
  },
  {
    value: "active",
    label: "Active",
    copy: "Pre-authorize the active validation tier, then stop before credential or exploitation work.",
    boundaryCopy: "Auto stops before the credential tier.",
    tierRank: 1,
  },
  {
    value: "full",
    label: "Full",
    copy: "Pre-authorize every non-exploitation tier; exploit confirmation also needs its own unlocker and typed scope.",
    boundaryCopy: "Auto-runs pre-authorized phases; exploitation still shows its explicit gate unless separately unlocked.",
    tierRank: 3,
  },
];

const ACCESS_UNLOCKER_OPTIONS = [
  {
    key: "unauthenticated_lane",
    label: "No credentials available",
    copy: "Run discovery, service enumeration, safe SMB/LDAP probes, web baseline, and infrastructure checks without secrets.",
    unlocks: "Unauthenticated LAN lane",
    unlocksByContext: {
      web: "Unauthenticated web/API checks",
    },
    appliesTo: ["all"],
    className: "passive",
  },
  {
    key: "directory_context",
    label: "AD/domain context known",
    copy: "Use known domain, DC, DNS, or base DN hints to make LDAP and identity mapping less blind.",
    unlocks: "LDAP/AD targeting",
    appliesTo: ["lan-ad"],
    className: "active",
  },
  {
    key: "credential_refs",
    label: "Credential refs available",
    copy: "Use stored secret references for authenticated SMB/LDAP/BloodHound style checks.",
    unlocks: "Credentialed validation",
    unlocksByContext: {
      web: "Credential/API access",
    },
    appliesTo: ["all"],
    className: "credential",
  },
  {
    key: "hash_or_password_material",
    label: "Hashes or password candidates",
    copy: "Use protected material for Kerberos/NTLM validation and controlled password-audit workflows.",
    unlocks: "Credential review",
    appliesTo: ["lan-ad"],
    className: "credential",
  },
  {
    key: "intrusive_lan_authorized",
    label: "Intrusive LAN checks authorized",
    copy: "Allow noisy LAN checks only inside the approved boundary and with the kill switch available.",
    unlocks: "Intrusive LAN phase",
    appliesTo: ["lan-ad"],
    className: "intrusive",
  },
  {
    key: "exploit_confirmation_authorized",
    label: "Exploit confirmation authorized",
    copy: "Permit confirmation with exploitation tools only after Full authorization and exact scope confirmation.",
    unlocks: "Exploit confirmation",
    appliesTo: ["all"],
    className: "intrusive",
  },
];

const FULL_ACCESS_UNLOCKER_TILE_KEYS = new Set([
  "internal-lan",
  "active-directory",
  "smart-home-lan",
  "custom",
]);

const PHASE_TIER_STYLES = {
  passive: {
    stroke: "#2e8b57",
    fill: "#ecf8f1",
    accent: "#d7f1e1",
    badge: "#d5f2df",
    text: "#165a38",
  },
  active: {
    stroke: "#3d9ccc",
    fill: "#ecf7fc",
    accent: "#d8eef8",
    badge: "#d9f3ff",
    text: "#124c6b",
  },
  "intrusive-credential": {
    stroke: "#c28a25",
    fill: "#fff7ea",
    accent: "#f5e5bf",
    badge: "#fce8be",
    text: "#6f4c10",
  },
  "intrusive-exploitation": {
    stroke: "#bf4c3a",
    fill: "#fff0ec",
    accent: "#f7d6cf",
    badge: "#ffd8d2",
    text: "#6f2218",
  },
};

const TOOL_ICON_LABELS = {
  "external-infra": "WAN",
  "nmap": "NMAP",
  "ldap-enum": "LDAP",
  "easm": "EASM",
  "httpx": "HTTPX",
  "nuclei": "NUCL",
  "zap": "ZAP",
  "burp": "BURP",
  "bloodhound": "BLOOD",
  "netexec": "SMB",
  "responder": "RESP",
  "kerberoast": "KRB",
  "asreproast": "ASREP",
  "hashcat": "CRACK",
  "metasploit": "MSF",
  "impacket": "IMPKT",
  "llm-probe": "LLM",
  "biz-logic": "BIZ",
  "aws-inventory": "AWS",
  "oauth-probe": "OAUTH",
};

const PROFILE_TARGET_GROUPS = {
  "passive-external-infrastructure": ["network", "domain", "web"],
  "passive-network-discovery": ["network"],
  "passive-identity-ldap-enum": ["network", "directory"],
  "passive-easm-discovery": ["domain", "web"],
  "passive-network-service-enumeration": ["network"],
  "passive-web-baseline": ["web", "api"],
  "passive-web-nuclei-audit": ["web", "api"],
  "active-external-infrastructure": ["network", "domain", "web"],
  "active-web-safe": ["web", "api"],
  "passive-web-burp": ["web", "api"],
  "active-business-logic": ["web", "api"],
  "active-web-oauth-probe": ["web", "api"],
  "active-ad-bloodhound": ["directory", "network"],
  "passive-lan-smb-enum": ["network"],
  "intrusive-lan-credential-capture": ["network"],
  "active-ad-kerberoast": ["directory"],
  "active-ad-asreproast": ["directory"],
  "active-offline-hash-crack": ["directory"],
  "intrusive-lan-smb-auth": ["network"],
  "intrusive-ad-password-spray": ["directory", "network"],
  "intrusive-exploitation": ["network", "web"],
  "intrusive-impacket-remote-exec": ["network", "directory"],
  "intrusive-impacket-secretsdump": ["network", "directory"],
  "intrusive-impacket-dcsync": ["directory"],
  "active-llm-application-probe": ["ai", "web"],
  "passive-wifi-survey": ["wireless"],
};

const LAN_DISCOVERY_EXECUTION_PROFILES = new Set([
  "passive-network-discovery",
  "passive-network-service-enumeration",
]);

const PROFILE_EXPECTATION_COPY = {
  "passive-external-infrastructure": "External IP truth, service exposure, SSH posture, and passive SMB reachability.",
  "passive-network-discovery": "Inventory, exposed hosts, and live-reachability truth.",
  "passive-identity-ldap-enum": "Directory posture, trust hints, and identity inventory.",
  "passive-easm-discovery": "Surface inventory, DNS truth, and discovered entry points.",
  "passive-network-service-enumeration": "Service banners, ports, and protocol fingerprints.",
  "passive-web-baseline": "HTTP stack inventory, routes, and response fingerprints.",
  "passive-web-nuclei-audit": "Safe CVE and exposure validation from curated templates.",
  "active-external-infrastructure": "Infrastructure-focused nuclei validation after the passive external baseline.",
  "active-web-safe": "Guarded web validation with proof-backed application signals.",
  "passive-web-burp": "Proxy-driven request mapping and normalized web issues.",
  "active-business-logic": "IDOR, privilege, and workflow authorization weaknesses.",
  "active-web-oauth-probe": "OAuth/OIDC redirect, state, PKCE, token leakage, scope, and implicit-flow evidence.",
  "active-ad-bloodhound": "AD path analysis, roastable accounts, and graph-backed exposure.",
  "passive-lan-smb-enum": "SMB signing, shares, and null-session posture.",
  "intrusive-lan-credential-capture": "Captured NTLM challenge-response material in scope.",
  "active-ad-kerberoast": "Kerberoastable service accounts and crack-ready hashes.",
  "active-ad-asreproast": "AS-REP roastable users and crack-ready hashes.",
  "active-offline-hash-crack": "Offline crack attempts against approved protected bundles.",
  "intrusive-lan-smb-auth": "Authenticated SMB access, share proof, and pass-the-hash validation.",
  "intrusive-ad-password-spray": "Bounded spray outcomes under confirmed lockout policy.",
  "intrusive-exploitation": "Controlled exploit confirmation with immediate evidence only.",
  "intrusive-impacket-remote-exec": "Remote whoami/hostname confirmation without persistence.",
  "intrusive-impacket-secretsdump": "Credential extraction proof stored only as protected output.",
  "intrusive-impacket-dcsync": "Domain-compromise validation for approved directory scope.",
  "active-llm-application-probe": "Prompt-injection, leakage, and unsafe-agent behavior proof.",
  "passive-wifi-survey": "Passive SSID, BSSID, channel, security posture, WPS, PMF, and rogue/unknown AP evidence.",
  "passive-lan-iot-discovery": "mDNS, SSDP, UPnP, and smart-device discovery evidence.",
  "passive-lan-nse-full": "Read-only LAN NSE scripts and expanded IoT port fingerprinting.",
  "passive-lan-snmp-enum": "SNMP identity, interfaces, ARP, and routing evidence.",
  "passive-lan-smart-home-audit": "MQTT, Home Assistant, OpenHAB, Domoticz, and Node-RED exposure signals.",
  "active-lan-camera-audit": "ONVIF, RTSP, snapshot, and bounded camera default-credential checks.",
  "active-lan-default-creds-audit": "Bounded default credential testing for discovered management interfaces.",
  "passive-lan-segmentation-check": "Segmentation, route, ARP, and cross-segment reachability evidence.",
  "passive-lan-ipv6-discovery": "IPv6 neighbor, router, and link-local reachability evidence.",
};

const MISSION_PREVIEW_DEFINITIONS = {
  "FULL-INTERNAL-LAN": {
    mode: "FULL-INTERNAL-LAN",
    label: "Full Internal LAN",
    phases: [
      {
        key: "passive-discovery",
        label: "Phase 1 · Passive Discovery",
        tier: "passive",
        icon: "DISC",
        estimatedMinutes: 20,
        findingCopy: "Hosts, services, and initial directory posture.",
        profiles: ["passive-network-discovery", "passive-identity-ldap-enum", "passive-easm-discovery"],
      },
      {
        key: "active-enrichment",
        label: "Phase 2 · Active Enrichment",
        tier: "active",
        icon: "ACT",
        estimatedMinutes: 28,
        findingCopy: "Service detail, web issues, AD pathing, and SMB posture.",
        profiles: [
          "passive-network-service-enumeration",
          "passive-web-baseline",
          "passive-web-nuclei-audit",
          "active-ad-bloodhound",
          "passive-lan-smb-enum",
        ],
      },
      {
        key: "intrusive-credential",
        label: "Phase 3 · Intrusive Credential Validation",
        tier: "intrusive-credential",
        icon: "CREDS",
        estimatedMinutes: 24,
        findingCopy: "Credential capture, roast paths, spray proof, and SMB auth validation.",
        profiles: [
          "intrusive-lan-credential-capture",
          "active-ad-kerberoast",
          "active-ad-asreproast",
          "active-offline-hash-crack",
          "intrusive-lan-smb-auth",
          "intrusive-ad-password-spray",
        ],
      },
      {
        key: "intrusive-exploitation",
        label: "Phase 4 · Intrusive Exploitation",
        tier: "intrusive-exploitation",
        icon: "EXP",
        estimatedMinutes: 18,
        findingCopy: "Controlled exploit confirmation and lateral movement proof only.",
        profiles: [
          "intrusive-exploitation",
          "intrusive-impacket-remote-exec",
          "intrusive-impacket-secretsdump",
          "intrusive-impacket-dcsync",
        ],
      },
    ],
  },
  "FULL-LAN-IOT": {
    mode: "FULL-LAN-IOT",
    label: "Full LAN + IoT",
    phases: [
      {
        key: "iot-discovery",
        label: "Phase 1 · Discovery",
        tier: "passive",
        icon: "DISC",
        estimatedMinutes: 20,
        findingCopy: "LAN hosts plus mDNS/SSDP smart-device inventory.",
        profiles: ["passive-network-discovery", "passive-lan-iot-discovery"],
      },
      {
        key: "iot-enumeration",
        label: "Phase 2 · Enumeration",
        tier: "active",
        icon: "ENUM",
        estimatedMinutes: 35,
        findingCopy: "Service detail, safe NSE scripts, SNMP device data, ARP, and routes.",
        profiles: ["passive-network-service-enumeration", "passive-lan-nse-full", "passive-lan-snmp-enum"],
      },
      {
        key: "iot-service-analysis",
        label: "Phase 3 · Service Analysis",
        tier: "active",
        icon: "IOT",
        estimatedMinutes: 30,
        findingCopy: "MQTT, Home Assistant, ONVIF, RTSP, and camera exposure checks.",
        profiles: ["passive-lan-smart-home-audit", "active-lan-camera-audit"],
      },
      {
        key: "iot-credential-testing",
        label: "Phase 4 · Credential Testing",
        tier: "active",
        icon: "AUTH",
        estimatedMinutes: 25,
        findingCopy: "Bounded default credential checks and SMB posture.",
        profiles: ["active-lan-default-creds-audit", "passive-lan-smb-enum"],
      },
      {
        key: "iot-segmentation",
        label: "Phase 5 · Segmentation",
        tier: "active",
        icon: "SEG",
        estimatedMinutes: 24,
        findingCopy: "Subnet, segmentation, route, and IPv6 exposure truth.",
        profiles: ["passive-lan-segmentation-check", "passive-lan-ipv6-discovery"],
      },
      {
        key: "iot-intrusive",
        label: "Phase 6 · Optional Intrusive",
        tier: "intrusive-credential",
        icon: "INTR",
        estimatedMinutes: 30,
        findingCopy: "Full infrastructure follow-up and Responder capture only after explicit approval.",
        profiles: ["passive-lan-infrastructure-audit", "intrusive-lan-credential-capture"],
      },
    ],
  },
  "FULL-EXTERNAL-WEB": {
    mode: "FULL-EXTERNAL-WEB",
    label: "Full External Web",
    phases: [
      {
        key: "passive-surface",
        label: "Phase 1 · Passive Surface Mapping",
        tier: "passive",
        icon: "SURF",
        estimatedMinutes: 16,
        findingCopy: "Surface inventory, baseline web responses, and discovered entry points.",
        profiles: ["passive-easm-discovery", "passive-web-baseline"],
      },
      {
        key: "active-web-validation",
        label: "Phase 2 · Active Web Validation",
        tier: "active",
        icon: "WEB",
        estimatedMinutes: 26,
        findingCopy: "Safe web validation, business logic issues, OAuth/OIDC posture, and normalized evidence.",
        profiles: ["passive-web-nuclei-audit", "active-web-safe", "passive-web-burp", "active-business-logic", "active-web-oauth-probe"],
      },
      {
        key: "intrusive-confirmation",
        label: "Phase 3 · Intrusive Confirmation",
        tier: "intrusive-exploitation",
        icon: "INTR",
        estimatedMinutes: 18,
        findingCopy: "High-risk confirmation limited to explicitly approved follow-up proof.",
        profiles: ["active-llm-application-probe", "intrusive-exploitation"],
      },
    ],
  },
  "FULL-AD-ASSESSMENT": {
    mode: "FULL-AD-ASSESSMENT",
    label: "Full AD Assessment",
    phases: [
      {
        key: "directory-baseline",
        label: "Phase 1 · Directory Baseline",
        tier: "passive",
        icon: "DIR",
        estimatedMinutes: 14,
        findingCopy: "Directory inventory, trust anchors, and baseline posture.",
        profiles: ["passive-identity-ldap-enum"],
      },
      {
        key: "directory-enumeration",
        label: "Phase 2 · Directory Enumeration",
        tier: "active",
        icon: "GRAPH",
        estimatedMinutes: 18,
        findingCopy: "BloodHound paths, privilege edges, and AD attack-path truth.",
        profiles: ["active-ad-bloodhound"],
      },
      {
        key: "credential-impact",
        label: "Phase 3 · Credential Impact",
        tier: "intrusive-credential",
        icon: "AUTH",
        estimatedMinutes: 22,
        findingCopy: "Roast, crack, and spray outcomes under approved controls.",
        profiles: [
          "active-ad-kerberoast",
          "active-ad-asreproast",
          "active-offline-hash-crack",
          "intrusive-ad-password-spray",
        ],
      },
      {
        key: "lateral-confirmation",
        label: "Phase 4 · Lateral Confirmation",
        tier: "intrusive-exploitation",
        icon: "MOVE",
        estimatedMinutes: 18,
        findingCopy: "SMB auth, remote exec, secretsdump, or DCSync proof.",
        profiles: [
          "intrusive-lan-smb-auth",
          "intrusive-impacket-remote-exec",
          "intrusive-impacket-secretsdump",
          "intrusive-impacket-dcsync",
        ],
      },
    ],
  },
};

const WIZARD_FLOW_DEPTH_OPTIONS = {
  passive: {
    goal: "inventory-first",
    safetyPosture: "passive-only",
    authorization: "passive",
    profile: "Standard",
    title: "Phases 1 only",
    eta: "~15 min",
    phases: "1 phase · 3 tools",
  },
  active: {
    goal: "standard-assessment",
    safetyPosture: "balanced",
    authorization: "active",
    profile: "Standard",
    title: "Phases 1-2",
    eta: "~60-90 min",
    phases: "2 phases · 7 tools",
  },
  full: {
    goal: "deep-assessment",
    safetyPosture: "thorough",
    authorization: "full",
    profile: "Deep",
    title: "Full - all 4 phases",
    eta: "~2-3 hours",
    phases: "4 phases · 19 conditional runners",
  },
};

const WIZARD_TARGET_GUIDANCE = {
  "external-web": {
    question: "What is the target website or app?",
    placeholder: "e.g. https://app.example.com",
    examples: ["https://app.example.com", "portal.example.com", "https://staging.example.com"],
    addLabel: "+ Add URL",
    hint: "URLs and domains become web targets. API base paths should use the API Security tile.",
    predictedGroup: "urls/domains",
  },
  "external-infrastructure": {
    question: "What is the external IP range or host?",
    placeholder: "e.g. 203.0.113.0/24 or vpn.example.com",
    examples: ["203.0.113.0/24", "198.51.100.42", "vpn.example.com"],
    addLabel: "+ Add host/range",
    hint: "CIDRs and IPs become perimeter infrastructure targets; hostnames stay in the domain scope.",
    predictedGroup: "cidr_ranges/ip_addresses/domains",
  },
  "internal-lan": {
    question: "What is the target network?",
    placeholder: "e.g. 10.0.20.0/24 or 192.168.1.0/24",
    examples: ["10.0.20.0/24", "192.168.1.0/24", "172.16.0.0/16"],
    addLabel: "+ Add range",
    hint: "Multiple targets? Add them with the + button. Discovered hosts are added automatically during Phase 1.",
    predictedGroup: "cidr_ranges/ip_addresses",
  },
  "active-directory": {
    question: "What is the AD network, domain, or domain controller?",
    placeholder: "e.g. corp.example.local, dc01.corp.example.local, or 10.0.20.0/24",
    examples: ["corp.example.local", "dc01.corp.example.local", "10.0.20.0/24"],
    addLabel: "+ Add AD scope",
    hint: "Domain names guide LDAP/AD targeting; CIDRs start with discovery before identity-specific checks.",
    predictedGroup: "domains/cidr_ranges",
  },
  "full-internal": {
    question: "What is the internal LAN or AD scope?",
    placeholder: "e.g. 10.0.20.0/24 or corp.example.local",
    examples: ["10.0.20.0/24", "corp.example.local", "dc01.corp.example.local"],
    addLabel: "+ Add scope",
    hint: "Full Internal combines LAN discovery with AD-aware follow-up where prerequisites are available.",
    predictedGroup: "cidr_ranges/domains",
  },
  "smart-home-lan": {
    question: "What is the smart home or IoT network?",
    placeholder: "e.g. 192.168.1.0/24 or 10.0.20.0/24",
    examples: ["192.168.1.0/24", "10.0.20.0/24", "172.16.0.0/24"],
    addLabel: "+ Add IoT range",
    hint: "IoT discovery starts with local network inventory, then mDNS, SSDP, SNMP, camera, and segmentation checks.",
    predictedGroup: "cidr_ranges/ip_addresses",
  },
  "wifi-wireless": {
    question: "Which WiFi site and allowlisted SSIDs/BSSIDs are authorized?",
    placeholder: "e.g. HQ-Amsterdam | CorpWiFi | aa:bb:cc:dd:ee:ff | wlan0",
    examples: ["HQ-Amsterdam | CorpWiFi | aa:bb:cc:dd:ee:ff | wlan0", "Warehouse-2 | GuestWiFi | | wlan1"],
    addLabel: "+ Add WiFi scope",
    hint: "Format: site | SSID | BSSID | adapter. BSSID may be blank when unknown; adapter and wireless ROE remain required.",
    predictedGroup: "wireless_sites/ssids/bssids",
  },
  cloud: {
    question: "What cloud account, tenant, or control-plane scope should be reviewed?",
    placeholder: "e.g. aws-account-123456789012 or tenant.example.com",
    examples: ["aws-account-123456789012", "tenant.example.com", "azure-tenant-example"],
    addLabel: "+ Add cloud scope",
    hint: "Cloud targets remain non-secret identifiers here. Credentials and account bindings belong in Advanced Configuration.",
    predictedGroup: "domains/identifiers",
  },
  "api-security": {
    question: "What is the API base URL or endpoint?",
    placeholder: "e.g. https://api.example.com/v1",
    examples: ["https://api.example.com/v1", "https://api.example.com/graphql", "api.example.com"],
    addLabel: "+ Add API",
    hint: "API URLs are routed to API base URL scope so the API assessment runner receives the right target type.",
    predictedGroup: "api_base_urls",
  },
  "llm-ai-app": {
    question: "What AI app or workflow URL should be tested?",
    placeholder: "e.g. https://chat.example.com",
    examples: ["https://chat.example.com", "https://agent.example.com", "ai.example.com"],
    addLabel: "+ Add AI app",
    hint: "AI app targets route to the LLM application probe when active validation is selected.",
    predictedGroup: "urls/domains",
  },
  "ssl-tls": {
    question: "What hostname, URL, or IP should receive the TLS-only review?",
    placeholder: "e.g. portal.example.com or https://portal.example.com",
    examples: ["portal.example.com", "https://app.example.com", "203.0.113.10"],
    addLabel: "+ Add TLS target",
    hint: "TLS-only scope stays limited to certificate, protocol, cipher, and transport posture.",
    predictedGroup: "domains/urls/ip_addresses",
  },
  "authenticated-app": {
    question: "What authenticated application URL should be tested?",
    placeholder: "e.g. https://portal.example.com",
    examples: ["https://portal.example.com", "https://app.example.com/login", "portal.example.com"],
    addLabel: "+ Add app",
    hint: "Credential, session, or manual auth context can be added in the preview access section.",
    predictedGroup: "urls/domains",
  },
  custom: {
    question: "What exact target or scope should this custom mission use?",
    placeholder: "e.g. https://app.example.com, api.example.com, or 203.0.113.10",
    examples: ["https://app.example.com", "api.example.com", "203.0.113.10"],
    addLabel: "+ Add target",
    hint: "Custom scope is interpreted from the value type, then can be refined in Advanced Configuration.",
    predictedGroup: "auto-detected",
  },
};

function wizardDepthConfig(choice = "active") {
  return WIZARD_FLOW_DEPTH_OPTIONS[String(choice || "active").trim()] || WIZARD_FLOW_DEPTH_OPTIONS.full;
}

function guidedTilePlanningOverride(tileKey = "", depthChoice = "active") {
  const normalizedKey = String(tileKey || "").trim();
  const depth = wizardDepthConfig(depthChoice);
  if (normalizedKey === "ssl-tls") {
    return {
      primaryGoal: depth.authorization === "passive" ? "inventory-first" : "standard-assessment",
      testProfile: "SSL/TLS Only",
      safetyPosture: "passive-only",
      authStrategy: "unauthenticated",
      modules: moduleState(["ssl_tls_analysis"]),
      safety: profileSafetyPreset("SSL/TLS Only"),
    };
  }
  if (normalizedKey === "authenticated-app") {
    const passive = depth.authorization === "passive";
    const testProfile = passive ? "Standard" : "Authenticated Only";
    return {
      primaryGoal: passive ? "inventory-first" : "authenticated-review",
      testProfile,
      safetyPosture: passive ? "passive-only" : "balanced",
      authStrategy: passive ? "unauthenticated" : "advanced-details",
      modules: profileModulePreset(testProfile),
      safety: passive ? profileSafetyPreset("Light") : profileSafetyPreset(testProfile),
    };
  }
  return null;
}

function applyGuidedTilePlanningOverride(tileKey = "", depthChoice = "active") {
  const override = guidedTilePlanningOverride(tileKey, depthChoice);
  if (!override) return;
  state.wizard.data.test_profile = override.testProfile;
  state.wizard.data.intake_preferences.primary_goal = override.primaryGoal;
  state.wizard.data.intake_preferences.safety_posture = override.safetyPosture;
  state.wizard.data.intake_preferences.auth_strategy = override.authStrategy;
  Object.assign(state.wizard.data.modules, override.modules);
  Object.assign(state.wizard.data.safety, override.safety);
}

function targetGuidanceForTile(tileKey = "") {
  return WIZARD_TARGET_GUIDANCE[tileKey] || WIZARD_TARGET_GUIDANCE["external-web"];
}

function targetBucketForTileValue(value, selectedKey = "") {
  const normalized = String(value || "").trim();
  if (selectedKey === "wifi-wireless") return "wireless_sites";
  if (isLikelyCidr(normalized)) return "cidr_ranges";
  if (isLikelyIp(normalized)) return "ip_addresses";
  if (selectedKey === "api-security" || isLikelyUrl(normalized)) return selectedKey === "api-security" ? "api_base_urls" : "urls";
  return "domains";
}

function buildWizardTargetsForTileValue(value, selectedKey = "") {
  const target = String(value || "").trim();
  if (selectedKey === "wifi-wireless") {
    const parts = target.split("|").map((item) => item.trim());
    return {
      domains: [],
      subdomains: [],
      urls: [],
      ip_addresses: [],
      cidr_ranges: [],
      api_base_urls: [],
      wireless_sites: parts[0] ? [parts[0]] : [],
      ssids: parts[1] ? [parts[1]] : [],
      bssids: parts[2] ? [parts[2]] : [],
    };
  }
  const bucket = targetBucketForTileValue(target, selectedKey);
  return {
    domains: bucket === "domains" ? [target] : [],
    subdomains: [],
    urls: bucket === "urls" ? [target] : [],
    ip_addresses: bucket === "ip_addresses" ? [target] : [],
    cidr_ranges: bucket === "cidr_ranges" ? [target] : [],
    api_base_urls: bucket === "api_base_urls" ? [target] : [],
    wireless_sites: [],
    ssids: [],
    bssids: [],
  };
}

function wizardMatrixExecutionProfile(tileKey, depthChoice, targetValue) {
  const tile = assessmentTileByKey(tileKey);
  const depth = wizardDepthConfig(depthChoice);
  const targets = buildWizardTargetsForTileValue(targetValue, tileKey);
  if (targetsContainPrivateNetwork(targets)) return "passive-network-discovery";
  if (tileKey === "ssl-tls") return "passive-web-baseline";
  if (tileKey === "authenticated-app") return depth.authorization === "passive" ? "passive-web-baseline" : "active-web-safe";
  if (tileKey === "api-security") return depth.authorization === "passive" ? "passive-web-baseline" : "active-api-assessment";
  if (tileKey === "llm-ai-app") return depth.authorization === "passive" ? "passive-web-baseline" : "active-llm-application-probe";
  if (tileKey === "wifi-wireless") return "passive-wifi-survey";
  if (tileKey === "external-infrastructure") return "passive-external-infrastructure";
  if (tile?.assessmentType === "Internal Range / LAN") return "passive-network-discovery";
  if (depth.authorization === "passive") return "passive-web-baseline";
  if (["cloud", "custom"].includes(tileKey) || depth.authorization === "full") return "active-web-safe";
  return "passive-web-nuclei-audit";
}

function wizardMatrixAssessmentMode(tileKey, depthChoice) {
  const keys = normalizeAssessmentTileKeys(tileKey === "full-internal" ? ["internal-lan", "active-directory"] : [tileKey]);
  return guidedAssessmentModeForSelection({
    keys,
    selectedTile: assessmentTileByKey(primaryAssessmentTileKey(keys)),
    depthChoice,
  });
}

export function buildWizardInputPredictionMatrix() {
  return {
    generated_at: new Date().toISOString(),
    assessment_tiles: ASSESSMENT_TILE_OPTIONS.map((tile) => {
      const selectedKeys = normalizeAssessmentTileKeys(tile.key === "full-internal" ? ["internal-lan", "active-directory"] : [tile.key]);
      const guidance = targetGuidanceForTile(tile.key);
      const exampleTarget = guidance.examples[0] || "";
      return {
        key: tile.key,
        label: tile.label,
        assessment_type: tile.assessmentType,
        selected_keys: selectedKeys,
        target_guidance: {
          question: guidance.question,
          placeholder: guidance.placeholder,
          examples: [...guidance.examples],
          predicted_group: guidance.predictedGroup,
          example_bucket: targetBucketForTileValue(exampleTarget, tile.key),
        },
        depths: Object.keys(WIZARD_FLOW_DEPTH_OPTIONS).map((depthKey) => {
          const depth = wizardDepthConfig(depthKey);
          const chain = wizardMatrixAssessmentMode(tile.key, depthKey);
          const profiles = chain ? MISSION_PREVIEW_DEFINITIONS[chain]?.phases.flatMap((phase) => phase.profiles) || [] : [];
          return {
            key: depthKey,
            goal: depth.goal,
            safety_posture: depth.safetyPosture,
            authorization_level: depth.authorization,
            test_profile: depth.profile,
            assessment_mode: chain,
            expected_execution_profile: wizardMatrixExecutionProfile(tile.key, depthKey, exampleTarget),
            expected_chain_profiles: profiles,
            prereq_visibility: visibleAccessUnlockerOptionsForKeys([tile.key]).map((option) => option.key),
          };
        }),
      };
    }),
  };
}

export function humanizeAssessmentMode(value) {
  const normalized = String(value || "").trim().toUpperCase();
  const option = ASSESSMENT_MODE_OPTIONS.find((candidate) => candidate.value === normalized);
  return option?.label || (normalized ? normalized.replaceAll("-", " ") : "Disabled");
}

function assessmentTileByKey(key) {
  return ASSESSMENT_TILE_OPTIONS.find((option) => option.key === String(key || "").trim()) || null;
}

function normalizeAssessmentTileKeys(keys = []) {
  const normalized = [];
  (Array.isArray(keys) ? keys : [keys]).forEach((key) => {
    const value = String(key || "").trim();
    if (!value || normalized.includes(value)) return;
    if (value === "full-internal") {
      ["internal-lan", "active-directory"].forEach((comboKey) => {
        if (!normalized.includes(comboKey)) normalized.push(comboKey);
      });
      return;
    }
    if (assessmentTileByKey(value)) normalized.push(value);
  });
  return normalized;
}

function selectedAssessmentTileKeys(wizard = state.wizard) {
  const explicit = normalizeAssessmentTileKeys(wizard?.intake?.selectedAssessmentTileKeys || []);
  if (explicit.length) return explicit;
  const single = String(wizard?.intake?.selectedAssessmentTileKey || "").trim();
  return normalizeAssessmentTileKeys(single ? [single] : []);
}

function primaryAssessmentTileKey(keys = selectedAssessmentTileKeys()) {
  const normalized = normalizeAssessmentTileKeys(keys);
  return normalized[0] || "";
}

function assessmentSelectionLabel(keys = selectedAssessmentTileKeys()) {
  const tiles = normalizeAssessmentTileKeys(keys).map(assessmentTileByKey).filter(Boolean);
  if (!tiles.length) return "";
  if (tiles.some((tile) => tile.key === "internal-lan") && tiles.some((tile) => tile.key === "active-directory")) {
    return "Internal LAN + Active Directory";
  }
  return tiles.map((tile) => tile.label).join(" + ");
}

function deriveAssessmentTileKey(data, intake = state.wizard?.intake || {}) {
  const explicit = primaryAssessmentTileKey(intake.selectedAssessmentTileKeys || []) || String(intake.selectedAssessmentTileKey || "").trim();
  if (explicit) {
    const explicitTile = assessmentTileByKey(explicit);
    if (
      explicitTile &&
      (explicitTile.assessmentType === data.assessment_type || TILE_FLOW_SPECIAL_KEYS.has(explicitTile.key))
    ) {
      return explicitTile.key;
    }
  }

  const intent = String(data.intake_preferences?.mission_intent || "").toLowerCase();
  if (/\b(active directory|domain controller|ldap|kerberos|bloodhound|sharphound)\b/.test(intent)) {
    return "active-directory";
  }
  if (/\b(external infrastructure|external ips?|external ip \/ wan|internet-facing hosts?|public ip|wan|rdp|vpn|ssh|non-web|port scan)\b/.test(intent)) {
    return "external-infrastructure";
  }
  if (/\b(cloud|aws|azure|gcp|subscription|tenant)\b/.test(intent)) {
    return "cloud";
  }
  if (/\b(llm|ai app|ai assistant|prompt injection|agent)\b/.test(intent)) {
    return "llm-ai-app";
  }
  if (/\b(tls|ssl|certificate|cipher|transport security)\b/.test(intent)) {
    return "ssl-tls";
  }
  if (/\b(authenticated app|authenticated application|portal with login|logged[- ]in portal|role[- ]based)\b/.test(intent)) {
    return "authenticated-app";
  }
  if (String(data.assessment_type || "").trim() === "API") return "api-security";
  if (String(data.assessment_type || "").trim() === "SSL/TLS Only") return "ssl-tls";
  if (String(data.assessment_type || "").trim() === "Authenticated App") return "authenticated-app";
  if (String(data.assessment_type || "").trim() === "Internal Range / LAN") return "internal-lan";
  if (String(data.assessment_type || "").trim() === "Mixed Assessment") return "custom";
  return "external-web";
}

function selectedAssessmentTile(wizard = state.wizard) {
  const explicit = primaryAssessmentTileKey(selectedAssessmentTileKeys(wizard));
  if (
    !explicit &&
    String(wizard?.intake?.sources?.target_type || "").trim() === "still-needed" &&
    !String(wizard?.data?.intake_preferences?.mission_intent || "").trim() &&
    String(wizard?.data?.assessment_type || "").trim() === "Website / Web App"
  ) {
    return null;
  }
  return assessmentTileByKey(deriveAssessmentTileKey(wizard.data, wizard.intake));
}

function activeDepthDescriptionForSelection(keys = selectedAssessmentTileKeys(state.wizard), data = state.wizard?.data || {}) {
  const normalizedKeys = normalizeAssessmentTileKeys(keys);
  const fallbackKeys = normalizedKeys.length
    ? normalizedKeys
    : normalizeAssessmentTileKeys([deriveAssessmentTileKey(data, state.wizard?.intake || {})]);
  const primaryTile = assessmentTileByKey(primaryAssessmentTileKey(fallbackKeys));
  const assessmentType = String(primaryTile?.assessmentType || data.assessment_type || "").trim();
  const lanOrAdContext =
    assessmentType === "Internal Range / LAN" ||
    fallbackKeys.some((key) => ["internal-lan", "active-directory", "smart-home-lan"].includes(key));
  return lanOrAdContext
    ? "Vulnerability detection + AD mapping"
    : "Vulnerability detection + web application analysis";
}

function accessUnlockerContextForKeys(keys = selectedAssessmentTileKeys(state.wizard), data = state.wizard?.data || {}) {
  const normalized = normalizeAssessmentTileKeys(keys);
  const fallback = normalized.length
    ? normalized
    : normalizeAssessmentTileKeys([deriveAssessmentTileKey(data, state.wizard?.intake || {})]);
  return fallback.some((key) => FULL_ACCESS_UNLOCKER_TILE_KEYS.has(key)) ? "lan-ad" : "web";
}

function accessUnlockerApplies(option, context) {
  const appliesTo = Array.isArray(option.appliesTo) && option.appliesTo.length ? option.appliesTo : ["all"];
  return appliesTo.includes("all") || appliesTo.includes(context);
}

function visibleAccessUnlockerOptionsForKeys(keys = selectedAssessmentTileKeys(state.wizard), data = state.wizard?.data || {}) {
  const context = accessUnlockerContextForKeys(keys, data);
  return ACCESS_UNLOCKER_OPTIONS.filter((option) => accessUnlockerApplies(option, context));
}

function visibleAccessUnlockerOptions(data = state.wizard?.data || {}) {
  return visibleAccessUnlockerOptionsForKeys(selectedAssessmentTileKeys(state.wizard), data);
}

function accessUnlockerUnlocks(option, context = accessUnlockerContextForKeys()) {
  return option.unlocksByContext?.[context] || option.unlocks;
}

function recentMissionCandidates() {
  return [...(state.engagements || [])]
    .filter((engagement) => engagement && engagement.id)
    .sort((left, right) => new Date(right.created_at || 0).getTime() - new Date(left.created_at || 0).getTime())
    .slice(0, 3);
}

function firstTruthyTargetLabel(targets) {
  const groups = [
    ...(targets?.cidr_ranges || []),
    ...(targets?.ip_addresses || []),
    ...(targets?.api_base_urls || []),
    ...(targets?.urls || []),
    ...(targets?.domains || []),
    ...(targets?.subdomains || []),
    ...(targets?.wireless_sites || []),
    ...(targets?.ssids || []),
    ...(targets?.bssids || []),
  ].filter(Boolean);
  if (!groups.length) return "No target on record";
  return groups.length > 1 ? `${groups[0]} +${groups.length - 1} more` : groups[0];
}

function buildTargetsFromAllowlist(allowlist = {}, configurationTargets = {}, assessmentType = "") {
  const apiTargets = Array.isArray(configurationTargets?.api_base_urls) ? configurationTargets.api_base_urls.filter(Boolean) : [];
  const urlTargets = Array.isArray(configurationTargets?.urls) ? configurationTargets.urls.filter(Boolean) : [];
  const domainTargets = Array.isArray(configurationTargets?.domains) ? configurationTargets.domains.filter(Boolean) : [];
  const subdomainTargets = Array.isArray(configurationTargets?.subdomains) ? configurationTargets.subdomains.filter(Boolean) : [];
  const sourceUrls = Array.isArray(allowlist?.urls) ? allowlist.urls.filter(Boolean) : [];
  const sourceIpAddresses = [
    ...(Array.isArray(allowlist?.hosts) ? allowlist.hosts.filter(Boolean) : []),
    ...(Array.isArray(allowlist?.ip_addresses) ? allowlist.ip_addresses.filter(Boolean) : []),
  ];
  const sourceCidrs = [
    ...(Array.isArray(allowlist?.cidrs) ? allowlist.cidrs.filter(Boolean) : []),
    ...(Array.isArray(allowlist?.cidr_ranges) ? allowlist.cidr_ranges.filter(Boolean) : []),
  ];
  const normalized = {
    domains: [],
    subdomains: [],
    urls: [],
    ip_addresses: sourceIpAddresses,
    cidr_ranges: sourceCidrs,
    api_base_urls: [],
    wireless_sites: [
      ...(Array.isArray(configurationTargets?.wireless_sites) ? configurationTargets.wireless_sites.filter(Boolean) : []),
      ...(Array.isArray(allowlist?.wireless_sites) ? allowlist.wireless_sites.filter(Boolean) : []),
    ],
    ssids: [
      ...(Array.isArray(configurationTargets?.ssids) ? configurationTargets.ssids.filter(Boolean) : []),
      ...(Array.isArray(allowlist?.ssids) ? allowlist.ssids.filter(Boolean) : []),
    ],
    bssids: [
      ...(Array.isArray(configurationTargets?.bssids) ? configurationTargets.bssids.filter(Boolean) : []),
      ...(Array.isArray(allowlist?.bssids) ? allowlist.bssids.filter(Boolean) : []),
    ],
  };

  const apiUrlSet = new Set(apiTargets);
  sourceUrls.forEach((value) => {
    if (apiUrlSet.has(value)) {
      normalized.api_base_urls.push(value);
      return;
    }
    if (assessmentType === "API" && !urlTargets.includes(value)) {
      normalized.api_base_urls.push(value);
      return;
    }
    normalized.urls.push(value);
  });

  const configuredDomains = new Set([...domainTargets, ...subdomainTargets]);
  const sourceDomains = Array.isArray(allowlist?.domains) ? allowlist.domains.filter(Boolean) : [];
  sourceDomains.forEach((value) => {
    if (configuredDomains.has(value)) {
      if (subdomainTargets.includes(value)) normalized.subdomains.push(value);
      else normalized.domains.push(value);
      return;
    }
    const dotCount = value.split(".").length;
    if (dotCount > 2) normalized.subdomains.push(value);
    else normalized.domains.push(value);
  });

  normalized.api_base_urls = [...new Set(normalized.api_base_urls)];
  normalized.urls = [...new Set(normalized.urls)];
  normalized.domains = [...new Set(normalized.domains)];
  normalized.subdomains = [...new Set(normalized.subdomains)];
  normalized.ip_addresses = [...new Set(normalized.ip_addresses)];
  normalized.cidr_ranges = [...new Set(normalized.cidr_ranges)];
  normalized.wireless_sites = [...new Set(normalized.wireless_sites)];
  normalized.ssids = [...new Set(normalized.ssids)];
  normalized.bssids = [...new Set(normalized.bssids)];
  return normalized;
}

function buildExclusionsFromDenylist(denylist = {}, configurationExclusions = {}) {
  const configuredApiExclusions = Array.isArray(configurationExclusions?.api_base_urls)
    ? configurationExclusions.api_base_urls.filter(Boolean)
    : [];
  const sourceUrls = Array.isArray(denylist?.urls) ? denylist.urls.filter(Boolean) : [];
  const sourceIpAddresses = [
    ...(Array.isArray(denylist?.hosts) ? denylist.hosts.filter(Boolean) : []),
    ...(Array.isArray(denylist?.ip_addresses) ? denylist.ip_addresses.filter(Boolean) : []),
  ];
  const sourceCidrs = [
    ...(Array.isArray(denylist?.cidrs) ? denylist.cidrs.filter(Boolean) : []),
    ...(Array.isArray(denylist?.cidr_ranges) ? denylist.cidr_ranges.filter(Boolean) : []),
  ];
  return {
    domains: Array.isArray(denylist?.domains) ? [...new Set(denylist.domains.filter(Boolean))] : [],
    urls: sourceUrls.filter((value) => !configuredApiExclusions.includes(value)),
    ip_addresses: [...new Set(sourceIpAddresses)],
    cidr_ranges: [...new Set(sourceCidrs)],
    api_base_urls: [...new Set(configuredApiExclusions.concat(sourceUrls.filter((value) => configuredApiExclusions.includes(value))))],
    notes: Array.isArray(denylist?.notes) ? String(denylist.notes[0] || "").trim() : String(configurationExclusions?.notes || "").trim(),
  };
}

function recentMissionSummaryForEngagement(engagementId) {
  const cached = RECENT_MISSION_SCOPE_CACHE.get(String(engagementId || ""));
  if (!cached) return "Loading target details...";
  if (cached.error) return "Scope not recorded yet";
  return cached.targetLabel || "No target on record";
}

function recentMissionDateLabel(value) {
  if (!value) return "Unknown date";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown date";
  return date.toLocaleDateString();
}

function contextualTargetValuesForTile(tileKey = "", targets = {}) {
  const normalizedKey = String(tileKey || "").trim();
  const groupsByTile = {
    "external-web": ["urls", "domains", "subdomains"],
    "external-infrastructure": ["cidr_ranges", "ip_addresses", "domains", "subdomains"],
    "internal-lan": ["cidr_ranges", "ip_addresses"],
    "active-directory": ["domains", "subdomains", "cidr_ranges", "ip_addresses"],
    "full-internal": ["cidr_ranges", "domains", "subdomains", "ip_addresses"],
    "smart-home-lan": ["cidr_ranges", "ip_addresses"],
    cloud: ["domains", "subdomains"],
    "api-security": ["api_base_urls", "urls", "domains", "subdomains"],
    "llm-ai-app": ["urls", "domains", "subdomains"],
    "ssl-tls": ["domains", "urls", "ip_addresses"],
    "authenticated-app": ["urls", "domains", "subdomains"],
    custom: ["urls", "api_base_urls", "domains", "subdomains", "ip_addresses", "cidr_ranges"],
  };
  if (normalizedKey === "wifi-wireless") {
    const sites = Array.isArray(targets.wireless_sites) ? targets.wireless_sites.filter(Boolean) : [];
    const ssids = Array.isArray(targets.ssids) ? targets.ssids.filter(Boolean) : [];
    const bssids = Array.isArray(targets.bssids) ? targets.bssids.filter(Boolean) : [];
    const count = Math.max(sites.length, ssids.length, bssids.length);
    return Array.from({ length: count }, (_, index) => [sites[index] || "", ssids[index] || "", bssids[index] || "", ""].join(" | ").trim())
      .filter((value) => value.replaceAll("|", "").trim());
  }
  return (groupsByTile[normalizedKey] || groupsByTile.custom)
    .flatMap((group) => Array.isArray(targets[group]) ? targets[group].filter(Boolean) : []);
}

function recentTargetChipsForTile(tileKey = "", limit = 3) {
  const normalizedKey = String(tileKey || "").trim() || primaryAssessmentTileKey(selectedAssessmentTileKeys(state.wizard));
  const assessmentType = assessmentTileByKey(normalizedKey)?.assessmentType || "";
  const seen = new Set();
  const chips = [];
  recentMissionCandidates().forEach((engagement) => {
    const cached = RECENT_MISSION_SCOPE_CACHE.get(String(engagement?.id || ""));
    if (!cached || cached.error || !cached.allowlist) return;
    const targets = buildTargetsFromAllowlist(cached.allowlist, {}, assessmentType);
    contextualTargetValuesForTile(normalizedKey, targets).forEach((value) => {
      const normalizedValue = String(value || "").trim();
      if (!normalizedValue || seen.has(normalizedValue) || chips.length >= limit) return;
      seen.add(normalizedValue);
      chips.push(normalizedValue);
    });
  });
  return chips;
}

function targetQuickFillChipsForTile(tileKey = "", guidance = targetGuidanceForTile(tileKey)) {
  const recentTargets = recentTargetChipsForTile(tileKey);
  return recentTargets.length ? recentTargets : [...(guidance.examples || [])];
}

function normalizedAuthorizationLevel(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return AUTHORIZATION_LEVEL_OPTIONS.some((option) => option.value === normalized) ? normalized : "passive";
}

function authorizationOption(value) {
  return AUTHORIZATION_LEVEL_OPTIONS.find((option) => option.value === normalizedAuthorizationLevel(value))
    || AUTHORIZATION_LEVEL_OPTIONS[0];
}

function selectedAuthorizationLevel(data = state.wizard?.data || {}) {
  return normalizedAuthorizationLevel(data.assessment_mode?.authorization_level);
}

function normalizeAccessUnlockers(value = {}) {
  const source = value && typeof value === "object" ? value : {};
  const normalized = ACCESS_UNLOCKER_OPTIONS.reduce((next, option) => {
    next[option.key] = Boolean(source[option.key]);
    return next;
  }, { unauthenticated_lane: true });
  if (!Object.keys(source).length || !Object.values(normalized).some(Boolean)) {
    normalized.unauthenticated_lane = true;
  }
  return normalized;
}

function selectedAccessUnlockerKeys(data = state.wizard?.data || {}, options = visibleAccessUnlockerOptions(data)) {
  const unlockers = normalizeAccessUnlockers(data.access?.prerequisites);
  const selected = options
    .filter((option) => unlockers[option.key])
    .map((option) => option.key);
  return selected.length ? selected : ["unauthenticated_lane"];
}

function accessUnlockerLabel(optionKey) {
  return ACCESS_UNLOCKER_OPTIONS.find((option) => option.key === optionKey)?.label || optionKey;
}

function buildAccessPrerequisiteLine(data = state.wizard?.data || {}) {
  const labels = selectedAccessUnlockerKeys(data).map(accessUnlockerLabel);
  if (!labels.length) return "I will run the unauthenticated lane first and stop before prerequisite-gated checks.";
  return `Access prerequisites declared before launch: ${labels.join(", ")}. Missing gated prerequisites remain visible instead of being silently skipped.`;
}

function authorizationTierRank(value) {
  return Number(authorizationOption(value)?.tierRank || 0);
}

function chainAuthorizationAvailable(data = state.wizard?.data || {}) {
  return Boolean(String(data.assessment_mode?.mode || "").trim());
}

function normalizedScopeConfirmation(value) {
  const normalized = String(value || "").trim();
  if (!normalized) return "";
  try {
    const parsed = new URL(normalized);
    const path = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");
    return `${parsed.protocol}//${parsed.host.toLowerCase()}${path}`.toLowerCase();
  } catch {
    return normalized.replace(/\/+$/, "").toLowerCase();
  }
}

function missionScopeConfirmationToken(data = state.wizard?.data || {}) {
  return flattenTargetValues(data.targets)[0] || "";
}

function missionScopeConfirmationSummary(data = state.wizard?.data || {}) {
  const scopeValues = flattenTargetValues(data.targets);
  if (!scopeValues.length) return "approved scope";
  if (scopeValues.length === 1) return scopeValues[0];
  return `${scopeValues.slice(0, 3).join(", ")}${scopeValues.length > 3 ? `, plus ${scopeValues.length - 3} more` : ""}`;
}

function hasValidFullAuthorizationConfirmation(data = state.wizard?.data || {}) {
  if (selectedAuthorizationLevel(data) !== "full") return true;
  const expectedToken = normalizedScopeConfirmation(missionScopeConfirmationToken(data));
  if (!expectedToken) return false;
  return normalizedScopeConfirmation(data.assessment_mode?.typed_scope_confirmation) === expectedToken;
}

function effectiveAssessmentModeAutoAdvance(data = state.wizard?.data || {}) {
  if (!chainAuthorizationAvailable(data)) {
    return Boolean(data.assessment_mode?.auto_advance_on_phase_complete);
  }
  return selectedAuthorizationLevel(data) !== "passive";
}

function compatibleAssessmentModesForSelection(keys = selectedAssessmentTileKeys(state.wizard), selectedTile = assessmentTileByKey(primaryAssessmentTileKey(keys))) {
  const normalizedKeys = normalizeAssessmentTileKeys(keys);
  if (normalizedKeys.includes("smart-home-lan")) {
    return ["FULL-LAN-IOT"];
  }
  if (normalizedKeys.includes("active-directory") && !normalizedKeys.includes("internal-lan")) {
    return ["FULL-AD-ASSESSMENT"];
  }
  if (
    normalizedKeys.includes("internal-lan") ||
    normalizedKeys.includes("active-directory") ||
    selectedTile?.assessmentType === "Internal Range / LAN"
  ) {
    return ["FULL-INTERNAL-LAN"];
  }
  if (
    normalizedKeys.includes("external-web") ||
    normalizedKeys.includes("api-security") ||
    selectedTile?.assessmentType === "Website / Web App" ||
    selectedTile?.assessmentType === "API"
  ) {
    return ["FULL-EXTERNAL-WEB"];
  }
  return [];
}

function guidedAssessmentModeForSelection({
  keys = selectedAssessmentTileKeys(state.wizard),
  selectedTile = assessmentTileByKey(primaryAssessmentTileKey(keys)),
  depthChoice = state.wizard.intake.flowDepthChoice || "active",
} = {}) {
  if (String(depthChoice || "").trim() === "passive") return "";
  return compatibleAssessmentModesForSelection(keys, selectedTile)[0] || "";
}

function depthChoiceKeyForGoal(goal) {
  const normalized = String(goal || "").trim();
  if (["quick-overview", "inventory-first"].includes(normalized)) return "passive";
  if (["standard-assessment", "authenticated-review"].includes(normalized)) return "active";
  if (["deep-assessment", "adaptive-coverage", "internal-validation"].includes(normalized)) return "full";
  return "";
}

function depthChoiceOptions(assessmentType, tileKey = "") {
  const normalizedType = String(assessmentType || "").trim();
  const internalAssessment = normalizedType === "Internal Range / LAN";
  const perimeterAssessment = normalizedType === "External IP / WAN";
  const authenticatedAssessment = normalizedType === "Authenticated App";
  const apiAssessment = normalizedType === "API";
  const tlsAssessment = normalizedType === "SSL/TLS Only";

  let passiveReply = "Inventory first";
  let activeReply = "Standard assessment";
  let fullReply = "Deep assessment";
  let passiveHints = ["Inventory first"];
  let activeHints = ["Standard assessment"];
  let fullHints = ["Deep assessment"];

  if (perimeterAssessment) {
    passiveReply = "Quick perimeter overview";
    activeReply = "Perimeter review";
    fullReply = "Deep follow-up after discovery";
    passiveHints = ["Quick perimeter overview"];
    activeHints = ["Perimeter review"];
    fullHints = ["Deep follow-up after discovery", "Adaptive follow-up after discovery"];
  } else if (internalAssessment) {
    passiveReply = "Inventory first";
    activeReply = "Standard internal assessment";
    fullReply = "Deep internal validation";
    passiveHints = ["Inventory first", "Visibility with clear per-item detail"];
    activeHints = ["Standard internal assessment"];
    fullHints = ["Deep internal validation"];
  } else if (authenticatedAssessment) {
    activeReply = "Authenticated review";
    passiveHints = ["Inventory first"];
    activeHints = ["Authenticated review", "Standard assessment"];
    fullHints = ["Deep assessment"];
  } else if (apiAssessment) {
    passiveReply = "Inventory first";
    activeReply = "Standard assessment";
    fullReply = "Deep API assessment";
    passiveHints = ["Inventory first"];
    activeHints = ["Authenticated API review", "Standard assessment"];
    fullHints = ["Deep API assessment", "Adaptive customer-specific testing"];
  } else if (tlsAssessment) {
    passiveReply = "Quick overview";
    activeReply = "Standard assessment";
    fullReply = "Standard assessment";
    passiveHints = ["Quick overview"];
    activeHints = ["Standard assessment"];
    fullHints = [];
  } else {
    passiveHints = ["Quick overview", "Inventory first"];
    activeHints = ["Standard assessment"];
    fullHints = ["Deep assessment", "Adaptive customer-specific testing"];
  }

  if (tileKey === "cloud") {
    activeReply = "Adaptive customer-specific testing";
    fullReply = "Deep assessment";
    activeHints = ["Adaptive customer-specific testing"];
    fullHints = ["Deep assessment"];
  }
  if (tileKey === "llm-ai-app") {
    activeReply = "Standard assessment";
    fullReply = "Adaptive customer-specific testing";
    activeHints = ["Standard assessment"];
    fullHints = ["Adaptive customer-specific testing"];
  }
  if (tileKey === "custom") {
    activeReply = "Standard assessment";
    fullReply = "Adaptive customer-specific testing";
    activeHints = ["Standard assessment"];
    fullHints = ["Adaptive customer-specific testing"];
  }

  return [
    {
      key: "passive",
      eyebrow: "Low impact",
      label: "Passive only",
      description: internalAssessment
        ? "Map hosts, services, and visible estate safely before any deeper validation."
        : "Prioritize discovery and visibility with the lightest practical footprint.",
      quickReply: passiveReply,
      safetyPosture: "passive-only",
      legacyHints: passiveHints,
    },
    {
      key: "active",
      eyebrow: "Balanced",
      label: "Active scan",
      description: perimeterAssessment
        ? "Validate the exposed perimeter with bounded active follow-up."
        : "Run the normal operator workflow with active validation where it fits the surface.",
      quickReply: activeReply,
      safetyPosture: "balanced",
      legacyHints: activeHints,
    },
    {
      key: "full",
      eyebrow: "Deep",
      label: "Full including exploitation",
      description: internalAssessment
        ? "Prepare deeper internal validation and approval-aware exploit confirmation when allowed."
        : "Go beyond baseline validation and prepare the deepest approved follow-up path.",
      quickReply: fullReply,
      safetyPosture: internalAssessment ? "thorough" : "thorough",
      legacyHints: fullHints,
    },
  ];
}

function inferGoalFromDepthAnswer(answer, assessmentType, tileKey = "") {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(passive only|passive)\b/.test(normalized)) {
    return String(assessmentType || "").trim() === "External IP / WAN" ? "quick-overview" : "inventory-first";
  }
  if (/\b(active scan|active)\b/.test(normalized)) {
    if (tileKey === "cloud" || tileKey === "custom" || tileKey === "llm-ai-app") return "adaptive-coverage";
    if (String(assessmentType || "").trim() === "Authenticated App") return "authenticated-review";
    return "standard-assessment";
  }
  if (/\b(full including exploitation|full|exploitation)\b/.test(normalized)) {
    if (String(assessmentType || "").trim() === "Internal Range / LAN") return "internal-validation";
    if (tileKey === "cloud" || tileKey === "custom" || tileKey === "llm-ai-app") return "adaptive-coverage";
    return "deep-assessment";
  }
  return null;
}

function tileFlowOrderedQuestions(wizard = state.wizard) {
  const assessmentType = String(wizard?.data?.assessment_type || "").trim();
  const targetFirstTypes = new Set(["Internal Range / LAN", "External IP / WAN"]);
  if (targetFirstTypes.has(assessmentType)) {
    return ["intent", "scope", "goal", "auth", "auth-details", "boundaries"];
  }
  return ["intent", "goal", "scope", "auth", "auth-details", "boundaries"];
}

function legacyOrderedQuestions() {
  return ["intent", "goal", "scope", "auth", "auth-details", "safety", "boundaries"];
}

function activeOrderedQuestions(wizard = state.wizard) {
  return wizard.intake.flowMode === "tile" ? tileFlowOrderedQuestions(wizard) : legacyOrderedQuestions();
}

export function createWizardModule() {
  let chatgptOAuthStatusInFlight = false;

  function patchWizardFields(fields, reason) {
    patchState({ wizard: { ...state.wizard, ...fields } }, reason);
  }

  function patchWizardIntakeFields(fields, reason) {
    patchWizardFields({ intake: { ...state.wizard.intake, ...fields } }, reason);
  }

  function patchWizardAccessAccounts(accounts, reason) {
    patchWizardFields(
      {
        data: {
          ...state.wizard.data,
          access: {
            ...state.wizard.data.access,
            accounts,
          },
        },
      },
      reason
    );
  }

  function missionLaunchDurationMs() {
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
    return reducedMotion ? 60 : 860;
  }

  function wait(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
  }

  async function showMissionLaunchOverlay({ engagementName, profileName, targetSummary }) {
    document.querySelectorAll(".mission-created-overlay").forEach((overlay) => overlay.remove());
    const overlay = document.createElement("div");
    overlay.className = "mission-created-overlay";
    overlay.dataset.testid = "mission-created-overlay";
    overlay.innerHTML = `
      <div class="mission-created-panel">
        <p class="eyebrow">Mission Created</p>
        <h3>${escapeHtml(engagementName || "New mission")}</h3>
        <p>${escapeHtml("Run dossier, scope seed, and queued checks are ready for Mission Control.")}</p>
        <div class="mission-created-metrics">
          <span>${escapeHtml(profileName || "selected execution lane")}</span>
          <span>${escapeHtml(targetSummary || "approved scope")}</span>
          <span>${escapeHtml("authorized checks auto-start when runtime is attached")}</span>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    await wait(missionLaunchDurationMs());
    overlay.classList.add("leaving");
    await wait(window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ? 10 : 140);
    overlay.remove();
  }

  function renderWizard() {
    ensureConversationDefaults();
    const wizard = state.wizard;
    const context = buildConversationContext();
    const guidedFlow = wizard.intake.flowMode === "tile";
    dom.wizardPanel.closest(".wizard-main")?.classList.toggle("mission-wizard-flow", guidedFlow);
    dom.wizardStepper.innerHTML = guidedFlow ? renderConversationStepper(context) : renderConversationStepper(context);
    dom.wizardPanel.innerHTML = guidedFlow ? renderGuidedWizardFlow(context) : renderConversationPanel(context);
    dom.wizardErrors.innerHTML = wizard.errors.length
      ? wizard.errors.map((error) => `<div>${escapeHtml(error)}</div>`).join("")
      : "";
    dom.wizardSummary.innerHTML = guidedFlow ? "" : renderWizardSummary(wizard, context.estimate, context);
    if (dom.wizardAdvancedDrawer) {
      dom.wizardAdvancedDrawer.innerHTML = renderAdvancedDrawer(context);
      dom.wizardAdvancedDrawer.classList.toggle("hidden", !wizard.intake.advancedOpen);
    }

    dom.wizardBackBtn.disabled = wizard.submitting || !hasConversationHistory();
    dom.wizardNextBtn.classList.toggle("hidden", context.confirmationReady || context.question.id === "intent");
    dom.wizardConfirmBtn.classList.toggle("hidden", !context.confirmationReady);
    dom.wizardConfirmBtn.disabled = wizard.submitting || !context.confirmationSubmitReady;
    dom.wizardNextBtn.disabled = wizard.submitting || !context.question.allowSubmission;
    dom.wizardBackBtn.textContent = wizard.submitting ? "Locked" : "Previous Topic";
    dom.wizardNextBtn.textContent = wizard.submitting
      ? "Saving..."
      : context.isReviewingEarlierTopic
        ? "Apply Answer & Return"
        : "Apply Answer";
    dom.wizardConfirmBtn.textContent = wizard.submitting
      ? "Creating Mission..."
      : context.fullAuthorizationPending
        ? "Type Target To Unlock Full Authorization"
        : chainAuthorizationAvailable(wizard.data) && selectedAuthorizationLevel(wizard.data) === "full"
          ? "Authorize Full Mission & Open Mission Control"
          : "Create Mission & Open Mission Control";
    if (guidedFlow) {
      dom.wizardBackBtn.classList.add("hidden");
      dom.wizardNextBtn.classList.add("hidden");
      dom.wizardConfirmBtn.classList.add("hidden");
    }

    queueRecentMissionScopePrefetch();
    attachConversationHandlers(context);
    attachAdvancedHandlers();
    if (wizard.intake.advancedOpen) {
      queueChatGptOAuthStatusRefresh();
    }

    const answerInput = document.getElementById("wizard-answer-input");
    const shouldAutofocusAnswer =
      typeof window.matchMedia !== "function" ||
      !window.matchMedia("(max-width: 900px)").matches;
    const currentQuestionKey = `${context.question.id}:${context.confirmationReady ? "confirm" : "question"}`;
    const questionChanged = wizard.intake.lastRenderedQuestionKey !== currentQuestionKey;
    wizard.intake.lastRenderedQuestionKey = currentQuestionKey;
    if (answerInput && shouldAutofocusAnswer) {
      answerInput.focus();
      if (typeof answerInput.value === "string" && typeof answerInput.setSelectionRange === "function") {
        answerInput.setSelectionRange(answerInput.value.length, answerInput.value.length);
      }
    } else if (!shouldAutofocusAnswer && questionChanged) {
      const mobileTargetSelector = context.confirmationReady
        ? '[data-testid="wizard-confirmation-summary"]'
        : '[data-testid="conversation-question"]';
      const scrollToMobileTarget = () => {
        document.querySelector(mobileTargetSelector)?.scrollIntoView({
          block: "start",
          behavior: "auto",
        });
      };
      if (typeof window.requestAnimationFrame === "function") {
        window.requestAnimationFrame(() => window.requestAnimationFrame(scrollToMobileTarget));
      } else {
        scrollToMobileTarget();
      }
    }
  }

  function ensureConversationDefaults() {
    const wizard = state.wizard;
    const intake = wizard.intake;
    const preferences = wizard.data.intake_preferences;
    const previousNameContext = snapshotEngagementNameContext(wizard.data);
    let compatibilityChanged = false;

    if (!wizard.data.engagement_name) {
      wizard.data.engagement_name = suggestedEngagementName(wizard.data);
    }

    compatibilityChanged = reconcileGoalCompatibility("inferred").changed || compatibilityChanged;

    if (!preferences.output_style) {
      if (/per[- ]?item|clear information|detailed|every found item/i.test(preferences.mission_intent || "")) {
        preferences.output_style = "detailed-per-item";
        intake.sources.output = "confirmed";
      } else if (preferences.primary_goal === "inventory-first") {
        preferences.output_style = "detailed-per-item";
        if (intake.sources.output === "still-needed") intake.sources.output = "inferred";
      } else if (["deep-assessment", "authenticated-review", "adaptive-coverage", "internal-validation"].includes(preferences.primary_goal)) {
        preferences.output_style = "technical-detail";
        if (intake.sources.output === "still-needed") intake.sources.output = "inferred";
      } else if (intake.sources.output === "still-needed") {
        preferences.output_style = "balanced-technical";
        intake.sources.output = "inferred";
      }
    } else if (intake.sources.output === "still-needed") {
      intake.sources.output = "inferred";
    }

    if (
      shouldAskAuthQuestion(wizard.data) &&
      intake.sources.auth === "inferred" &&
      preferences.auth_strategy === "unauthenticated" &&
      !hasMeaningfulAccessContext(wizard.data.access)
    ) {
      preferences.auth_strategy = "";
      intake.sources.auth = "still-needed";
    }

    if (
      !preferences.auth_strategy &&
      intake.sources.intent !== "still-needed" &&
      !shouldAskAuthQuestion(wizard.data)
    ) {
      preferences.auth_strategy = "unauthenticated";
      if (intake.sources.auth === "still-needed") intake.sources.auth = "inferred";
    }

    if (preferences.auth_strategy === "unauthenticated") {
      if (
        hasMeaningfulAccount(wizard.data.access.accounts) ||
        stringValue(wizard.data.access.manual_auth_steps) ||
        stringValue(wizard.data.access.cookie_notes)
      ) {
        clearAccessContext();
      }
      alignPlanForUnauthenticatedAccess();
    }

    if (!preferences.safety_posture) {
      const canInferInventorySafety =
        wizard.data.assessment_type !== "Internal Range / LAN" &&
        wizard.data.assessment_type !== "SSL/TLS Only";
      if (
        ["inventory-first", "quick-overview"].includes(preferences.primary_goal) && canInferInventorySafety
      ) {
        preferences.safety_posture = "conservative";
        if (intake.sources.safety === "still-needed") intake.sources.safety = "inferred";
      }
    }

    if (!preferences.boundary_handling) {
      const hasExclusions = flattenTargetValues(wizard.data.exclusions).length > 0 || wizard.data.exclusions.notes;
      const shouldPromptBoundaries = requiresExplicitBoundaryConfirmation(wizard.data);
      if (!hasExclusions && preferences.lateral_discovery !== "requested" && !shouldPromptBoundaries) {
        preferences.boundary_handling = "standard-scope-only";
        if (intake.sources.boundaries === "still-needed") intake.sources.boundaries = "inferred";
      }
    }

    if (compatibilityChanged) {
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, wizard.data);
    }

    const recommended = recommendedQuestionId(wizard);
    if (wizard.intake.activeQuestionId === "confirm" && recommended !== "confirm") {
      wizard.intake.activeQuestionId = recommended;
    }
    if (!wizard.intake.activeQuestionId) {
      wizard.intake.activeQuestionId = recommended;
    }
  }

  function buildConversationContext() {
    const wizard = state.wizard;
    const estimate = estimateMission(wizard.data);
    const recommendedQuestion = recommendedQuestionId(wizard);
    const activeQuestionId =
      wizard.intake.activeQuestionId && wizard.intake.activeQuestionId !== "confirm"
        ? wizard.intake.activeQuestionId
        : recommendedQuestion;
    const question = buildQuestion(activeQuestionId === "confirm" ? "confirm" : activeQuestionId, estimate);
    const summary = buildSummaryBuckets(wizard, estimate);
    const reviewMode = determineReviewMode(activeQuestionId, recommendedQuestion);
    return {
      estimate,
      question,
      recommendedQuestionId: recommendedQuestion,
      confirmationReady: question.id === "confirm" && validateEntireWizard().length === 0,
      confirmationSubmitReady:
        question.id === "confirm" &&
        validateEntireWizard().length === 0 &&
        hasValidFullAuthorizationConfirmation(wizard.data),
      fullAuthorizationPending:
        question.id === "confirm" &&
        chainAuthorizationAvailable(wizard.data) &&
        selectedAuthorizationLevel(wizard.data) === "full" &&
        !hasValidFullAuthorizationConfirmation(wizard.data),
      progress: buildConversationProgress(wizard),
      summary,
      reviewMode,
      isReviewingEarlierTopic:
        reviewMode === "earlier",
      isReviewingOtherTopic:
        Boolean(wizard.intake.reviewQuestionId) &&
        wizard.intake.reviewQuestionId === activeQuestionId &&
        activeQuestionId !== "confirm" &&
        activeQuestionId !== recommendedQuestion,
    };
  }

  function determineReviewMode(activeQuestionId, recommendedQuestionId) {
    if (
      !state.wizard.intake.reviewQuestionId ||
      state.wizard.intake.reviewQuestionId !== activeQuestionId ||
      !activeQuestionId ||
      activeQuestionId === "confirm" ||
      activeQuestionId === recommendedQuestionId
    ) {
      return null;
    }

    const baseOrder = activeOrderedQuestions(state.wizard);
    const order = [...baseOrder.slice(0, 2), "output", ...baseOrder.slice(2), "safety", "confirm"];
    const activeIndex = order.indexOf(activeQuestionId);
    const recommendedIndex = order.indexOf(recommendedQuestionId);
    if (activeIndex === -1 || recommendedIndex === -1) return "other";
    if (activeIndex < recommendedIndex) return "earlier";
    if (activeIndex > recommendedIndex) return "later";
    return "other";
  }

  function questionStillNeedsInput(wizard, questionId) {
    const data = wizard.data;
    if (questionId === "intent") {
      return wizard.intake.sources.intent === "still-needed" || questionHasBlockingErrors(wizard, questionId);
    }
    if (questionId === "goal") {
      return wizard.intake.sources.goal === "still-needed" || questionHasBlockingErrors(wizard, questionId);
    }
    if (questionId === "scope") {
      return (
        !flattenTargetValues(data.targets).length ||
        wizard.intake.sources.scope === "still-needed" ||
        questionHasBlockingErrors(wizard, questionId)
      );
    }
    if (questionId === "auth") {
      return shouldAskAuthQuestion(data) && wizard.intake.sources.auth === "still-needed";
    }
    if (questionId === "auth-details") return needsAuthDetails(data) || questionHasBlockingErrors(wizard, questionId);
    if (questionId === "safety") {
      return wizard.intake.sources.safety === "still-needed" || questionHasBlockingErrors(wizard, questionId);
    }
    if (questionId === "boundaries") {
      const boundaryConfirmationRequired = requiresExplicitBoundaryConfirmation(data);
      if (boundaryConfirmationRequired) {
        return !["confirmed", "override"].includes(String(wizard.intake.sources.boundaries || ""));
      }
      return wizard.intake.sources.boundaries === "still-needed";
    }
    return false;
  }

  function validationErrorsForQuestion(wizard, questionId) {
    if (questionId === "intent") return validateWizardStep(0);
    if (questionId === "scope") return validateWizardStep(1);
    if (questionId === "auth-details") return validateWizardStep(2);
    if (questionId === "goal") {
      return [...new Set([...validateWizardStep(3), ...validateWizardStep(4)])];
    }
    if (questionId === "safety") return validateWizardStep(5);
    return [];
  }

  function transitionValidationErrorsForQuestion(wizard, questionId) {
    const errors = validationErrorsForQuestion(wizard, questionId);
    if (
      questionId === "scope" &&
      errors.length === 1 &&
      errors[0] === "Add at least one target in scope." &&
      !flattenTargetValues(wizard.data.targets).length &&
      wizard.intake.sources.scope === "still-needed"
    ) {
      return [];
    }
    return errors;
  }

  function questionHasBlockingErrors(wizard, questionId) {
    return validationErrorsForQuestion(wizard, questionId).length > 0;
  }

  function realignConversationAfterAdvancedChange() {
    const wizard = state.wizard;
    const activeQuestionId = wizard.intake.activeQuestionId;
    const recommendedQuestionIdValue = recommendedQuestionId(wizard);
    if (
      !activeQuestionId ||
      activeQuestionId === recommendedQuestionIdValue
    ) {
      return;
    }
    if (
      wizard.intake.reviewQuestionId === activeQuestionId &&
      questionStillNeedsInput(wizard, activeQuestionId)
    ) {
      return;
    }
    wizard.intake.activeQuestionId = recommendedQuestionIdValue;
    if (wizard.intake.reviewQuestionId === activeQuestionId) {
      wizard.intake.reviewQuestionId = null;
    }
  }

  function buildConversationProgress(wizard) {
    const onConfirmationScreen = recommendedQuestionId(wizard) === "confirm" || wizard.intake.activeQuestionId === "confirm";
    const assessmentComplete =
      !questionStillNeedsInput(wizard, "intent") &&
      String(wizard.data.assessment_type || "").trim() !== "";
    const targetDepthComplete =
      !questionStillNeedsInput(wizard, "scope") &&
      !questionStillNeedsInput(wizard, "goal") &&
      !questionStillNeedsInput(wizard, "auth") &&
      !questionStillNeedsInput(wizard, "auth-details") &&
      !questionStillNeedsInput(wizard, "boundaries");
    const nextTargetDepthQuestionId = [...new Set(
      activeOrderedQuestions(wizard)
        .filter((questionId) => !["intent", "boundaries"].includes(questionId))
        .map((questionId) => (questionId === "auth-details" ? resolveConversationTopicQuestionId("auth") : questionId))
    )].find((questionId) => {
      if (questionId === "auth") {
        return questionStillNeedsInput(wizard, "auth") || questionStillNeedsInput(wizard, "auth-details");
      }
      return questionStillNeedsInput(wizard, questionId);
    }) || resolveConversationTopicQuestionId("auth");
    return [
      {
        label: "Assessment",
        state: assessmentComplete ? "complete" : "active",
        questionId: "intent",
      },
      {
        label: "Target & Depth",
        state: !assessmentComplete ? "pending" : targetDepthComplete ? "complete" : "active",
        questionId: nextTargetDepthQuestionId,
      },
      {
        label: "Preview",
        state: !targetDepthComplete ? "pending" : onConfirmationScreen ? "complete" : "pending",
        questionId: "confirm",
      },
      {
        label: "Authorise",
        state: !targetDepthComplete ? "pending" : onConfirmationScreen ? "active" : "pending",
        questionId: "confirm",
      },
    ];
  }

  function renderConversationStepper(context) {
    return `
      <div class="steps wizard-step-flow" data-testid="wizard-step-flow">
        ${context.progress
          .map((item, index) => {
            const dotState = item.state === "complete" ? "done" : item.state;
            const lineState = item.state === "complete" ? "done" : item.state === "active" ? "active" : "";
            return `
              <button class="step wizard-step-flow-item ${escapeHtml(item.state)}" type="button" data-edit-question="${escapeHtml(item.questionId)}" data-testid="wizard-stage-${index + 1}">
                <span class="step-dot wizard-step-flow-dot ${escapeHtml(dotState)}" aria-hidden="true">${item.state === "complete" ? "✓" : index + 1}</span>
                <span class="step-label wizard-step-flow-label ${escapeHtml(dotState)}">${escapeHtml(item.label)}</span>
              </button>
              ${index < context.progress.length - 1 ? `<span class="step-line wizard-step-flow-line ${escapeHtml(lineState)}" aria-hidden="true"></span>` : ""}
            `;
          })
          .join("")}
      </div>
    `;
  }

  function renderWizardStepBar(activeStep = wizardFlowStepIndex(buildConversationContext())) {
    const steps = [
      { step: 1, label: "1 · Choose", questionId: "intent" },
      { step: 2, label: "2 · Target", questionId: recommendedQuestionId(state.wizard) === "goal" ? "goal" : "scope" },
      { step: 3, label: "3 · Preview", questionId: "confirm" },
      { step: 4, label: "4 · Launch", questionId: "confirm" },
    ];
    return `
      <div class="wizard-step-bar" aria-label="Wizard demo steps" data-testid="wizard-bottom-stepper">
        ${steps.map((item) => `
          <button
            class="demo-tab ${item.step === activeStep ? "on active" : ""}"
            type="button"
            data-wizard-step-target="${escapeHtml(item.questionId)}"
            data-wizard-step-number="${escapeHtml(String(item.step))}"
          >${escapeHtml(item.label)}</button>
        `).join("")}
      </div>
    `;
  }

  function wizardFlowStepIndex(context = buildConversationContext()) {
    if (state.wizard.lastCreated) return 4;
    if (context.question?.id === "intent") return 1;
    if (context.question?.id === "confirm") return 3;
    return 2;
  }

  function renderAssessmentTypeTiles() {
    const selectedKeys = selectedAssessmentTileKeys(state.wizard);
    const selectedKey = primaryAssessmentTileKey(selectedKeys) || selectedAssessmentTile(state.wizard)?.key || "";
    const selectionBar = renderAssessmentSelectionBar();
    const comboHint = (selectedKeys.includes("internal-lan") || selectedKeys.includes("active-directory"))
      ? `
        <div class="combo-hint" data-testid="wizard-combo-hint">
          <span class="combo-hint-icon">💡</span>
          <span class="combo-hint-text">Internal LAN + Active Directory is a common combination. BloodHound attack paths map across both.</span>
          <button class="combo-add" type="button" data-assessment-combo="internal-lan,active-directory">Use this combo →</button>
        </div>
      `
      : "";
    return `
      ${selectionBar}
      <div class="tile-grid" data-testid="wizard-assessment-tile-grid">
        ${ASSESSMENT_TILE_OPTIONS.map((tile) => {
          const selectedIndex = selectedKeys.indexOf(tile.key);
          const selected = selectedIndex >= 0;
          const order = selectedIndex + 1;
          const phaseTags = Array.isArray(tile.phaseTags) ? tile.phaseTags : [];
          return `
            <button
              class="tile ${selected ? "selected" : ""} ${selected && order > 1 ? "t2" : ""}"
              type="button"
              data-assessment-tile-key="${escapeHtml(tile.key)}"
              data-flow-mode="tile"
              data-history-text="${escapeHtml(tile.label)}"
              data-testid="wizard-assessment-tile-${escapeHtml(tile.key)}"
              aria-pressed="${selected ? "true" : "false"}"
            >
              <div class="tile-num">${escapeHtml(String(selected ? order : tile.key === "custom" ? "+" : "1"))}</div>
              <div class="tile-top">
                <span class="tile-icon">${escapeHtml(tile.icon)}</span>
                ${tile.badge ? `<span class="tile-badge ${escapeHtml(tile.badgeClass || "")}">${escapeHtml(tile.badge)}</span>` : ""}
              </div>
              <div class="tile-title">${escapeHtml(tile.label)}</div>
              <div class="tile-desc">${escapeHtml(tile.description)}</div>
              <div class="tile-tags">
                ${phaseTags.map((tag) => `<span class="tag ${escapeHtml(tag.cls)}">${escapeHtml(tag.label)}</span>`).join("")}
              </div>
            </button>
          `;
        }).join("")}
      </div>
      ${comboHint}
      ${renderWizardStepBar(1)}
    `;
  }

  function renderDepthTiles() {
    const currentTile = selectedAssessmentTile(state.wizard);
    const options = depthChoiceOptions(state.wizard.data.assessment_type, currentTile?.key || "");
    const selectedDepth = depthChoiceKeyForGoal(state.wizard.data.intake_preferences.primary_goal);
    const activeDescription = activeDepthDescriptionForSelection(selectedAssessmentTileKeys(state.wizard), state.wizard.data);
    return `
      <div class="depth-grid" data-testid="conversation-quick-replies">
        ${options.map((option) => {
          const selected = selectedDepth === option.key;
          const icon = option.key === "passive" ? "🔍" : option.key === "active" ? "⚡" : "🎯";
          const phaseTags = option.key === "passive"
            ? [{ label: "Phase 1", cls: "tag-p" }]
            : option.key === "active"
              ? [{ label: "P1", cls: "tag-p" }, { label: "P2", cls: "tag-a" }]
              : [{ label: "P1", cls: "tag-p" }, { label: "P2", cls: "tag-a" }, { label: "P3", cls: "tag-c" }, { label: "P4", cls: "tag-e" }];
          return `
            <button
              class="d-tile ${selected ? `dsel ${option.key === "full" ? "damber" : option.key === "active" ? "" : ""}` : ""}"
              type="button"
              data-quick-reply="${escapeHtml(option.quickReply)}"
              data-depth-choice="${escapeHtml(option.key)}"
              data-depth-safety="${escapeHtml(option.safetyPosture)}"
              data-history-text="${escapeHtml(option.label)}"
              data-testid="wizard-depth-tile-${escapeHtml(option.key)}"
              aria-pressed="${selected ? "true" : "false"}"
            >
              <div class="d-icon">${escapeHtml(icon)}</div>
              <div class="d-title">${escapeHtml(option.key === "passive" ? "Passive" : option.key === "active" ? "Active Scan" : "Full Pentest")}</div>
              <div class="d-desc">${escapeHtml(option.key === "passive" ? "Discovery and enumeration only" : option.key === "active" ? activeDescription : "Credential attacks + exploitation")}</div>
              <div class="d-phases">${phaseTags.map((tag) => `<span class="tag ${escapeHtml(tag.cls)}">${escapeHtml(tag.label)}</span>`).join("")}</div>
            </button>
          `;
        }).join("")}
      </div>
    `;
  }

  function renderQuestionChoiceSurface(question) {
    if (question.id === "intent") return renderAssessmentTypeTiles();
    if (question.id === "goal") return renderDepthTiles();
    return "";
  }

  function renderAssessmentSelectionBar() {
    const selectedKeys = selectedAssessmentTileKeys(state.wizard);
    const selectedTiles = selectedKeys.map(assessmentTileByKey).filter(Boolean);
    if (!selectedTiles.length) return "";
    return `
      <div class="selection-bar" data-testid="wizard-selection-bar">
        <span class="sel-label">Selected:</span>
        <div class="sel-chips">
          ${selectedTiles.map((tile, index) => `
            <div class="sel-chip ${index > 0 ? "c2" : ""}" data-testid="wizard-selection-chip">
              <span class="sel-chip-icon" aria-hidden="true">${escapeHtml(tile.icon)}</span>
              <span>${escapeHtml(tile.label)}</span>
              <button class="sel-chip-remove" type="button" data-assessment-remove-key="${escapeHtml(tile.key)}" aria-label="${escapeHtml(`Remove ${tile.label}`)}">×</button>
            </div>
          `).join("")}
        </div>
        <div class="sel-actions">
          <div class="sel-count" id="sel-count" data-testid="wizard-selection-count">${escapeHtml(`${selectedKeys.length} type${selectedKeys.length === 1 ? "" : "s"} selected`)}</div>
          <button class="sel-clear" type="button" data-wizard-clear-assessment="true">Clear all</button>
          <button class="btn btn-p sel-next" type="button" data-assessment-submit-selection="true" data-testid="wizard-assessment-submit-selection">Target & Depth →</button>
        </div>
      </div>
    `;
  }

  function renderRecentMissionRow() {
    const recentEngagements = recentMissionCandidates();
    return `
      <section class="wizard-recent-missions" data-testid="wizard-recent-missions">
        <div class="wizard-section-head">
          <p class="eyebrow">Recent Missions</p>
        </div>
        ${
          recentEngagements.length
            ? `
              <div class="wizard-recent-mission-row">
                ${recentEngagements
                  .map(
                    (engagement) => `
                      <button
                        class="wizard-recent-mission-card"
                        type="button"
                        data-recent-engagement-prefill="${escapeHtml(engagement.id)}"
                        data-testid="wizard-recent-mission-card"
                      >
                        <span class="wizard-recent-mission-icon" aria-hidden="true">↗</span>
                        <span class="wizard-recent-mission-copy">
                          <strong>${escapeHtml(engagement.name || "Recent mission")}</strong>
                          <small>${escapeHtml(recentMissionSummaryForEngagement(engagement.id))}</small>
                        </span>
                        <span class="wizard-recent-mission-meta">${escapeHtml(recentMissionDateLabel(engagement.created_at))}</span>
                      </button>
                    `
                  )
                  .join("")}
              </div>
            `
            : `<p class="micro-copy">No recent missions yet. Start with the closest assessment type below.</p>`
        }
      </section>
    `;
  }

  function flowStep() {
    const step = Number(state.wizard.intake.flowStep || 1);
    if (state.wizard.lastCreated) return 4;
    return Math.max(1, Math.min(4, Number.isFinite(step) ? step : 1));
  }

  function flowTargetValue(data = state.wizard.data) {
    const values = flattenTargetValues(data.targets);
    if (values.length) return values[0];
    const selectedKey = primaryAssessmentTileKey(selectedAssessmentTileKeys(state.wizard));
    if (selectedKey === "wifi-wireless") return "HQ-Amsterdam | CorpWiFi | aa:bb:cc:dd:ee:ff | wlan0";
    if (["internal-lan", "active-directory"].includes(selectedKey) || selectedAssessmentTileKeys(state.wizard).includes("internal-lan")) {
      return "10.0.20.0/24";
    }
    if (selectedKey === "api-security") return "https://api.example.com";
    if (selectedKey === "external-infrastructure") return "203.0.113.0/24";
    return "https://app.example.com";
  }

  function targetBucketForValue(value, selectedKey = primaryAssessmentTileKey(selectedAssessmentTileKeys(state.wizard))) {
    return targetBucketForTileValue(value, selectedKey);
  }

  function targetBucketDisplayLabel(bucket) {
    const labels = {
      urls: "URL",
      api_base_urls: "API base URL",
      ip_addresses: "IP address",
      cidr_ranges: "CIDR range",
      domains: "domain",
      wireless_sites: "wireless site",
    };
    return labels[String(bucket || "").trim()] || String(bucket || "target").replaceAll("_", " ");
  }

  function buildTargetsForFlowValue(value) {
    const target = String(value || "").trim() || flowTargetValue();
    const selectedKey = primaryAssessmentTileKey(selectedAssessmentTileKeys(state.wizard));
    if (selectedKey === "wifi-wireless") return buildWizardTargetsForTileValue(target, selectedKey);
    const bucket = targetBucketForValue(target, selectedKey);
    return {
      domains: bucket === "domains" ? [target] : [],
      subdomains: [],
      urls: bucket === "urls" ? [target] : [],
      ip_addresses: bucket === "ip_addresses" ? [target] : [],
      cidr_ranges: bucket === "cidr_ranges" ? [target] : [],
      api_base_urls: bucket === "api_base_urls" ? [target] : [],
      wireless_sites: [],
      ssids: [],
      bssids: [],
    };
  }

  function flowDepthConfig(choice = state.wizard.intake.flowDepthChoice || "active") {
    return wizardDepthConfig(choice);
  }

  function applyGuidedSelectionToData({ targetValue = flowTargetValue(), depthChoice = state.wizard.intake.flowDepthChoice || "active", step = flowStep() } = {}) {
    const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
    if (step >= 3 && containsUnauthorizedExpansion(targetValue)) {
      patchWizardFields(
        {
          errors: ["I need exact authorized targets before I can build a mission preview."],
          intake: {
            ...state.wizard.intake,
            flowMode: "tile",
            flowStep: 2,
          },
        },
        "wizard.guidedFlow.broadScopeRejected"
      );
      renderWizard();
      return;
    }
    const keys = selectedAssessmentTileKeys(state.wizard);
    const primaryKey = primaryAssessmentTileKey(keys);
    const selectedTile = assessmentTileByKey(primaryKey);
    const depth = flowDepthConfig(depthChoice);
    const overrides = state.wizard.intake.overrides || {};
    const preserveAssessmentTypeOverride = Boolean(overrides.assessment_type);
    const preservePlanningOverrides = Boolean(overrides.profile || overrides.modules || overrides.safety);
    const compatibleAssessmentModes = compatibleAssessmentModesForSelection(keys, selectedTile);
    const selectedAssessmentMode = String(state.wizard.data.assessment_mode?.mode || "").trim();
    const compatibleSelectedAssessmentMode = compatibleAssessmentModes.includes(selectedAssessmentMode)
      ? selectedAssessmentMode
      : "";
    const wirelessParts = primaryKey === "wifi-wireless"
      ? String(targetValue || "").split("|").map((item) => item.trim())
      : [];
    const guidedAssessmentMode =
      compatibleSelectedAssessmentMode ||
      guidedAssessmentModeForSelection({ keys, selectedTile, depthChoice });
    const nextData = {
      ...state.wizard.data,
      engagement_name: state.wizard.data.engagement_name || assessmentSelectionLabel(keys) || selectedTile?.label || "AegisPT Assessment",
      assessment_type: preserveAssessmentTypeOverride
        ? state.wizard.data.assessment_type
        : selectedTile?.assessmentType || state.wizard.data.assessment_type,
      targets: buildTargetsForFlowValue(targetValue),
      intake_preferences: {
        ...state.wizard.data.intake_preferences,
        mission_intent: assessmentSelectionLabel(keys) || selectedTile?.label || state.wizard.data.intake_preferences.mission_intent,
        primary_goal: overrides.profile ? state.wizard.data.intake_preferences.primary_goal : depth.goal,
        output_style: state.wizard.data.intake_preferences.output_style || "balanced-technical",
        auth_strategy: state.wizard.data.intake_preferences.auth_strategy || "unauthenticated",
        safety_posture: overrides.safety ? state.wizard.data.intake_preferences.safety_posture : depth.safetyPosture,
        boundary_handling: state.wizard.data.intake_preferences.boundary_handling || "standard-scope-only",
      },
      assessment_mode: {
        ...state.wizard.data.assessment_mode,
        mode: guidedAssessmentMode,
        authorization_level: depth.authorization,
        typed_scope_confirmation: guidedAssessmentMode
          ? state.wizard.data.assessment_mode?.typed_scope_confirmation || ""
          : "",
      },
      wireless: primaryKey === "wifi-wireless"
        ? {
            ...(state.wizard.data.wireless || {}),
            site: wirelessParts[0] || state.wizard.data.wireless?.site || "",
            adapter: wirelessParts[3] || state.wizard.data.wireless?.adapter || "",
            approved_ssids: wirelessParts[1] ? [wirelessParts[1]] : [...(state.wizard.data.wireless?.approved_ssids || [])],
            approved_bssids: wirelessParts[2] ? [wirelessParts[2]] : [...(state.wizard.data.wireless?.approved_bssids || [])],
            excluded_ssids: [...(state.wizard.data.wireless?.excluded_ssids || [])],
            excluded_bssids: [...(state.wizard.data.wireless?.excluded_bssids || [])],
            roe_acknowledged: true,
            passive_only: true,
            rf_disruptive_actions: false,
            handshake_capture: false,
            credential_harvesting: false,
            wps_pin_testing: false,
            evil_twin: false,
            jamming: false,
          }
        : state.wizard.data.wireless,
      test_profile: overrides.profile ? state.wizard.data.test_profile : depth.profile,
    };
    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, nextData);
    patchWizardFields(
      {
        data: nextData,
        intake: {
          ...state.wizard.intake,
          flowMode: "tile",
          flowStep: step,
          flowDepthChoice: depthChoice,
          selectedAssessmentTileKey: primaryKey,
          selectedAssessmentTileKeys: keys,
          sources: {
            ...state.wizard.intake.sources,
            intent: keys.length ? "confirmed" : "still-needed",
            target_type: keys.length ? "confirmed" : "still-needed",
            scope: targetValue ? "confirmed" : "still-needed",
            goal: "confirmed",
            auth: "confirmed",
            safety: "confirmed",
            boundaries: "confirmed",
            output: "confirmed",
          },
        },
      },
      "wizard.guidedFlow.apply"
    );
    if (!preservePlanningOverrides) {
      applyAssessmentTypePreset(nextData.assessment_type);
    }
    if (depth.profile && !overrides.profile) {
      state.wizard.data.test_profile = depth.profile;
      if (!overrides.modules && !overrides.safety) {
        applyProfilePreset(depth.profile);
      }
    }
    if (!preservePlanningOverrides && nextData.assessment_type === "External IP / WAN") {
      applyAssessmentTypePreset(nextData.assessment_type);
    }
    if (!overrides.profile) {
      state.wizard.data.intake_preferences.primary_goal = depth.goal;
    }
    if (!overrides.safety) {
      state.wizard.data.intake_preferences.safety_posture = depth.safetyPosture;
      applySafetyPreference(depth.safetyPosture);
    }
    if (
      !preservePlanningOverrides &&
      ["inventory-first", "quick-overview"].includes(state.wizard.data.intake_preferences.primary_goal)
    ) {
      applyInventoryGoalTuning(state.wizard.data.intake_preferences.primary_goal);
    }
    enforceDiscoveryFirstSafetyGuardrails(state.wizard.data);
    state.wizard.data.assessment_mode = nextData.assessment_mode;
    state.wizard.data.targets = nextData.targets;
    state.wizard.data.wireless = nextData.wireless;
    if (primaryKey === "wifi-wireless") {
      state.wizard.data.safety.active_checks = "passive-only";
      state.wizard.data.safety.adaptive_generation = false;
      state.wizard.data.safety.max_validation_depth = "light";
      state.wizard.data.test_profile = "Standard";
    }
    applyGuidedTilePlanningOverride(primaryKey, depthChoice);
    refreshSuggestedEngagementNameIfAutomatic(snapshotEngagementNameContext(state.wizard.data), state.wizard.data);
  }

  function renderGuidedAssessmentStep() {
    return `
      <div class="wizard-intake-shell wizard-flow-step" data-testid="conversation-question">
        ${renderRecentMissionRow()}
        <section class="wizard-assessment-surface">
          <div class="wizard-section-head">
            <p class="eyebrow">Assessment Types</p>
          </div>
          ${renderAssessmentTypeTiles()}
        </section>
      </div>
    `;
  }

  function renderGuidedTargetStep() {
    const targetValue = flowTargetValue();
    const selectedKeys = selectedAssessmentTileKeys(state.wizard);
    const selectedKey = primaryAssessmentTileKey(selectedKeys);
    const guidance = targetGuidanceForTile(
      selectedKeys.includes("internal-lan") && selectedKeys.includes("active-directory") ? "full-internal" : selectedKey
    );
    const targetChips = targetQuickFillChipsForTile(
      selectedKeys.includes("internal-lan") && selectedKeys.includes("active-directory") ? "full-internal" : selectedKey,
      guidance
    );
    const targetBucket = targetBucketForValue(targetValue, selectedKey);
    const heading = assessmentSelectionLabel(selectedKeys) || "Selected Assessment";
    const depthChoice = state.wizard.intake.flowDepthChoice || "full";
    return `
      <div class="wizard-flow-step wizard-target-depth-step" data-testid="conversation-question">
        ${renderAssessmentSelectionBar()}
        <div class="page-h">${escapeHtml(heading)}</div>
        <div class="page-sub">Two quick questions - we'll generate the mission plan from your answers.</div>
        <section class="q-card" data-testid="wizard-target-card">
          <div class="q-meta">
            <span class="q-step-label">Question 1 of 2 · Target</span>
            <span class="q-badge">Required</span>
          </div>
          <div class="q-text">${escapeHtml(guidance.question)}</div>
          <input id="wizard-target-input" class="q-input" type="text" value="${escapeHtml(targetValue)}" placeholder="${escapeHtml(guidance.placeholder)}" aria-label="${escapeHtml(guidance.question || "Assessment target")}" data-testid="wizard-target-input" />
          <div class="q-tags">
            ${targetChips.map((value) => `<button class="q-tag" type="button" data-wizard-target-value="${escapeHtml(value)}">${escapeHtml(value)}</button>`).join("")}
            <button class="q-tag" type="button" data-wizard-target-add="true">${escapeHtml(guidance.addLabel)}</button>
          </div>
          <div class="q-hint">${escapeHtml(guidance.hint)}</div>
          <div class="q-hint" data-testid="wizard-target-interpretation">Predicted interpretation: ${escapeHtml(targetBucketDisplayLabel(targetBucket))} target for ${escapeHtml(heading)}.</div>
        </section>
        <section class="q-card" data-testid="wizard-depth-card">
          <div class="q-meta">
            <span class="q-step-label">Question 2 of 2 · Depth</span>
            <span class="q-badge">Required</span>
          </div>
          <div class="q-text">How deep should the assessment go?</div>
          ${renderDepthTilesForFlow(depthChoice)}
        </section>
        <div class="nav-row">
          <button class="btn btn-s" type="button" data-wizard-flow-step="1">← Back</button>
          <button class="btn btn-p" type="button" data-wizard-preview="true">Preview Mission →</button>
        </div>
        ${renderWizardStepBar(2)}
      </div>
    `;
  }

  function renderDepthTilesForFlow(selectedChoice = "active") {
    const activeDescription = activeDepthDescriptionForSelection(selectedAssessmentTileKeys(state.wizard), state.wizard.data);
    const options = [
      { key: "passive", icon: "🔍", title: "Passive", desc: "Discovery and enumeration only", tags: [{ label: "Phase 1", cls: "tag-p" }] },
      { key: "active", icon: "⚡", title: "Active Scan", desc: activeDescription, tags: [{ label: "P1", cls: "tag-p" }, { label: "P2", cls: "tag-a" }] },
      { key: "full", icon: "🎯", title: "Full Pentest", desc: "Credential attacks + exploitation", tags: [{ label: "P1", cls: "tag-p" }, { label: "P2", cls: "tag-a" }, { label: "P3", cls: "tag-c" }, { label: "P4", cls: "tag-e" }] },
    ];
    return `
      <div class="depth-grid" data-testid="conversation-quick-replies">
        ${options.map((option) => `
          <button class="d-tile ${option.key === selectedChoice ? `dsel ${option.key === "full" ? "damber" : ""}` : ""}" type="button" data-wizard-depth-choice="${escapeHtml(option.key)}" data-testid="wizard-depth-tile-${escapeHtml(option.key)}" aria-pressed="${option.key === selectedChoice ? "true" : "false"}">
            <div class="d-icon">${escapeHtml(option.icon)}</div>
            <div class="d-title">${escapeHtml(option.title)}</div>
            <div class="d-desc">${escapeHtml(option.desc)}</div>
            <div class="d-phases">${option.tags.map((tag) => `<span class="tag ${escapeHtml(tag.cls)}">${escapeHtml(tag.label)}</span>`).join("")}</div>
          </button>
        `).join("")}
      </div>
    `;
  }

  function renderGuidedPreviewStep() {
    const target = flowTargetValue();
    const depth = flowDepthConfig();
    const heading = assessmentSelectionLabel() || "Mission Preview";
    // Use depth config directly so the auth level always matches the depth tile selection
    const fullAuth = depth.authorization === "full";
    const confirmed = hasValidFullAuthorizationConfirmation(state.wizard.data);
    const estimate = estimateMission(state.wizard.data);
    const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
    const family = guidedPhaseFamily(state.wizard.data, plan);
    const fullAuthCopy = guidedFullAuthorizationCopy(family);
    return `
      <div class="wizard-flow-step wizard-preview-step" data-testid="conversation-question">
        <div class="page-h">Mission Preview</div>
        <div class="page-sub">Here is exactly what AegisPT will do. Review, then choose your authorisation level.</div>
        ${renderLanDiscoveryRoutingNotice(state.wizard.data)}
        <section class="preview-box" data-testid="wizard-mission-preview">
          <div class="preview-hd">
            <div class="preview-hd-title">${escapeHtml(heading)}</div>
            <div class="preview-chips">
              <span class="p-chip">🎯 ${escapeHtml(target)}</span>
              <span class="p-chip">⏱ ${escapeHtml(depth.eta)}</span>
              <span class="p-chip">${escapeHtml(depth.phases)}</span>
              <span class="p-chip" data-testid="wizard-preview-execution-lane">${escapeHtml(plan.profileName)} · ${escapeHtml(plan.toolsLabel)}</span>
            </div>
          </div>
          <div class="tgt-bar">
            <span class="tgt-label">Targets</span>
            <span class="tgt-node">🌐 ${escapeHtml(target)}</span>
            <span class="tgt-note">Hosts discovered in Phase 1 are automatically included in later phases.</span>
          </div>
          ${renderGuidedPhaseDiagram(state.wizard.data, depth, plan)}
          ${renderAccessUnlockerGate(state.wizard.data)}
          <div class="auth-area" data-testid="wizard-authorization-selector">
            <div class="auth-title">How far should AegisPT go?</div>
            <div class="auth-grid">
              ${renderGuidedAuthOption("passive", "🔍", "Phases 1 only", "Passive discovery. Stops automatically after Phase 1.")}
              ${renderGuidedAuthOption("active", "⚡", "Phases 1-2", "Discovery and active analysis run as one mission. Manual confirmation is required before intrusive credential or exploit phases.")}
              ${renderGuidedAuthOption("full", "🎯", "Full - all 4 phases", fullAuthCopy.option)}
            </div>
            ${fullAuth ? `
              <div class="confirm-area" data-testid="wizard-full-authorization-confirmation">
                <div class="confirm-text">
                  I confirm I have <strong>written authorisation</strong> from the system owner to run <strong>${escapeHtml(fullAuthCopy.confirmTools)}</strong> against <strong>${escapeHtml(target)}</strong>. AegisPT will execute eligible non-exploitation runners in the authorised phases; exploit confirmation still requires the explicit exploit unlocker and all evidence prerequisites.
                </div>
                <div class="confirm-row">
                  <input id="wizard-full-authorization-input" class="confirm-input" type="text" value="${escapeHtml(state.wizard.data.assessment_mode?.typed_scope_confirmation || "")}" placeholder="Type target to confirm: ${escapeHtml(target)}" aria-label="Typed scope confirmation" data-testid="wizard-full-authorization-input" />
                  <span class="confirm-status ${confirmed ? "ok" : ""}">${escapeHtml(confirmed ? "Confirmed" : "Not confirmed")}</span>
                </div>
              </div>
            ` : ""}
          </div>
        </section>
        <div class="nav-row">
          <button class="btn btn-s" type="button" data-wizard-flow-step="2">← Back</button>
          <button class="btn btn-r" type="button" data-wizard-flow-step="4" ${fullAuth && !confirmed ? "disabled" : ""}>🚀 ${escapeHtml(fullAuth ? "Launch Full Assessment" : "Launch Mission")}</button>
        </div>
        ${renderWizardStepBar(3)}
      </div>
    `;
  }

  function renderAccessUnlockerGate(data = state.wizard.data) {
    const unlockers = normalizeAccessUnlockers(data.access?.prerequisites);
    const options = visibleAccessUnlockerOptions(data);
    const context = accessUnlockerContextForKeys(selectedAssessmentTileKeys(state.wizard), data);
    const selectedLabels = selectedAccessUnlockerKeys(data, options).map(accessUnlockerLabel);
    return `
      <div class="access-unlocker-gate" data-testid="wizard-access-unlockers">
        <div class="access-unlocker-head">
          <div>
            <div class="auth-title">What access or prerequisites do you already have?</div>
            <p>Discovery always starts without credentials. Select extra unlockers now so gated tools can run automatically when their phase is reached.</p>
          </div>
          <span class="q-badge">${escapeHtml(`${selectedLabels.length} selected`)}</span>
        </div>
        <div class="unlocker-grid">
          ${options.map((option) => {
            const selected = Boolean(unlockers[option.key]);
            return `
              <button class="unlocker-card ${escapeHtml(option.className)} ${selected ? "selected" : ""}" type="button" data-wizard-unlocker="${escapeHtml(option.key)}" aria-pressed="${selected ? "true" : "false"}">
                <span class="unlocker-label">${escapeHtml(option.label)}</span>
                <span class="unlocker-copy">${escapeHtml(option.copy)}</span>
                <span class="unlocker-tag">${escapeHtml(accessUnlockerUnlocks(option, context))}</span>
              </button>
            `;
          }).join("")}
        </div>
        ${renderCredentialEntryCta()}
        <p class="access-unlocker-summary">${escapeHtml(buildAccessPrerequisiteLine(data))}</p>
      </div>
    `;
  }

  function renderGuidedAuthOption(value, icon, title, desc) {
    const selected = flowDepthConfig().authorization === value;
    return `
      <button class="a-opt ${selected ? (value === "full" ? "asel-r" : "asel") : ""}" type="button" data-wizard-authorization="${escapeHtml(value)}" data-testid="wizard-authorization-${escapeHtml(value)}" aria-pressed="${selected ? "true" : "false"}">
        <div class="a-icon">${escapeHtml(icon)}</div>
        <div class="a-title">${escapeHtml(title)}</div>
        <div class="a-desc">${escapeHtml(desc)}</div>
      </button>
    `;
  }

  function renderLanDiscoveryRoutingNotice(data = state.wizard.data) {
    const issue = lanDiscoveryRoutingIssue(data);
    if (!issue) return "";
    return `
      <div class="section-note split-top" data-testid="lan-discovery-routing-warning">
        <strong>Internal network profile mismatch</strong>
        <p>${escapeHtml(issue.message)}</p>
        ${renderBadgeList([
          `Current lane ${issue.profileName}`,
          `Tools ${issue.toolsLabel}`,
          "Recommended passive-network-discovery",
        ], "compact-badge-list split-top")}
        <div class="panel-actions split-top">
          <button class="action primary" type="button" data-lan-profile-fix="true" data-testid="lan-profile-fix">
            Switch to Internal Network profile
          </button>
        </div>
      </div>
    `;
  }

  function guidedPhaseFamily(data = state.wizard.data, plan = executionPlanForProfile(estimateMission(data).execution_profile, state.runProfiles)) {
    const keys = selectedAssessmentTileKeys(state.wizard);
    const assessmentType = String(data.assessment_type || "").toLowerCase();
    const profileName = String(plan?.profileName || "").toLowerCase();
    const missionIntent = String(data.intake_preferences?.mission_intent || "").toLowerCase();
    if (
      assessmentType.includes("api") ||
      keys.includes("api-security") ||
      missionIntent.includes("api") ||
      profileName.includes("api")
    ) {
      return "api";
    }
    if (
      assessmentType.includes("llm") ||
      assessmentType.includes("ai") ||
      keys.includes("llm-ai-app") ||
      missionIntent.includes("llm") ||
      missionIntent.includes("prompt")
    ) {
      return "ai";
    }
    if (
      keys.includes("external-infrastructure") ||
      profileName.includes("external-infrastructure") ||
      assessmentType.includes("external ip") ||
      missionIntent.includes("external infrastructure")
    ) {
      return "external-infrastructure";
    }
    if (
      keys.includes("internal-lan") ||
      keys.includes("active-directory") ||
      profileName.includes("network") ||
      assessmentType.includes("internal") ||
      missionIntent.includes("active directory")
    ) {
      return "internal";
    }
    return "web";
  }

  function guidedPhaseLimit(depth = flowDepthConfig()) {
    if (depth.authorization === "passive") return 1;
    if (depth.authorization === "full") return 4;
    return 3;
  }

  function guidedPhaseTemplates(family = "web") {
    const templates = {
      web: [
        { cls: "ph-p", num: "Phase 1 · Auto", name: "🟢 Discovery", tools: ["🌐 HTTP fingerprint", "🔐 TLS/header review", "🧭 Content discovery"], dur: "⏱ ~15 min · no approval" },
        { cls: "ph-a", num: "Phase 2 · 1x approval", name: "🔵 Analysis", tools: ["🎯 nuclei CVE checks", "🕸️ ZAP safe review", "📍 Route/input review"], dur: "⏱ ~30 min · 1 approval" },
        { cls: "ph-c", num: "Phase 3 · 1x approval", name: "🟠 Validation", tools: ["🧪 Targeted validation", "🔑 Auth/session review", "📦 Evidence packaging"], dur: "⏱ ~45 min · 1 approval" },
        { cls: "ph-e", num: "Phase 4 · explicit auth", name: "🔴 Exploitation", tools: ["💥 Controlled exploit proof", "🧯 No persistence", "🛑 Kill switch enforced"], dur: "⏱ ~30 min · full auth" },
      ],
      internal: [
        { cls: "ph-p", num: "Phase 1 · Auto", name: "🟢 Discovery", tools: ["🔍 nmap host discovery", "🩺 Service fingerprint", "📋 Inventory snapshot"], dur: "⏱ ~15 min · no approval" },
        { cls: "ph-a", num: "Phase 2 · 1x approval", name: "🔵 Analysis", tools: ["🎯 nuclei CVE scan", "🖧 SMB/LDAP review", "🗺️ Exposure mapping"], dur: "⏱ ~30 min · 1 approval" },
        { cls: "ph-c", num: "Phase 3 · full auth", name: "🟠 Credential Review", tools: ["📡 Responder on LAN route", "🔑 Kerberos/NTLM if evidence exists", "📦 Protected evidence only"], dur: "⏱ ~45 min · prerequisites shown" },
        { cls: "ph-e", num: "Phase 4 · full auth", name: "🔴 Exploitation", tools: ["💥 Metasploit for allowlisted findings", "🔗 Impacket with credentials", "🛑 Kill switch enforced"], dur: "⏱ ~30 min · prerequisites shown" },
      ],
      "external-infrastructure": [
        { cls: "ph-p", num: "Phase 1 · Auto", name: "🟢 Discovery", tools: ["🌍 Host/service discovery", "🔐 TLS/SSH/RDP fingerprint", "📋 Exposure inventory"], dur: "⏱ ~15 min · no approval" },
        { cls: "ph-a", num: "Phase 2 · 1x approval", name: "🔵 Analysis", tools: ["🎯 Infrastructure CVE checks", "🧱 Service misconfig review", "📈 Exposure scoring"], dur: "⏱ ~30 min · 1 approval" },
        { cls: "ph-c", num: "Phase 3 · 1x approval", name: "🟠 Validation", tools: ["🧪 Targeted safe validation", "🔎 Version proof", "📦 Evidence packaging"], dur: "⏱ ~45 min · 1 approval" },
        { cls: "ph-e", num: "Phase 4 · explicit auth", name: "🔴 Exploitation", tools: ["💥 Controlled exploit proof", "🧯 No persistence", "🛑 Kill switch enforced"], dur: "⏱ ~30 min · full auth" },
      ],
      api: [
        { cls: "ph-p", num: "Phase 1 · Auto", name: "🟢 Discovery", tools: ["🔗 Base URL/spec discovery", "📋 Endpoint inventory", "🔐 Auth surface mapping"], dur: "⏱ ~15 min · no approval" },
        { cls: "ph-a", num: "Phase 2 · 1x approval", name: "🔵 Analysis", tools: ["🎯 API nuclei checks", "🧩 OWASP API review", "📐 Schema/verb review"], dur: "⏱ ~30 min · 1 approval" },
        { cls: "ph-c", num: "Phase 3 · 1x approval", name: "🟠 Validation", tools: ["🧪 Targeted API validation", "🔑 Auth/session checks", "📦 Evidence packaging"], dur: "⏱ ~45 min · 1 approval" },
        { cls: "ph-e", num: "Phase 4 · explicit auth", name: "🔴 Exploitation", tools: ["💥 Controlled abuse-case proof", "🧯 No destructive actions", "🛑 Kill switch enforced"], dur: "⏱ ~30 min · full auth" },
      ],
      ai: [
        { cls: "ph-p", num: "Phase 1 · Auto", name: "🟢 Discovery", tools: ["🧭 App/workflow inventory", "💬 Prompt surface mapping", "🤖 Model/provider context"], dur: "⏱ ~15 min · no approval" },
        { cls: "ph-a", num: "Phase 2 · 1x approval", name: "🔵 Analysis", tools: ["🎯 Prompt injection checks", "🧾 Data leakage review", "🧠 Agent safety review"], dur: "⏱ ~30 min · 1 approval" },
        { cls: "ph-c", num: "Phase 3 · 1x approval", name: "🟠 Validation", tools: ["🧪 Targeted workflow validation", "📦 Evidence packaging", "👀 Safe findings review"], dur: "⏱ ~45 min · 1 approval" },
        { cls: "ph-e", num: "Phase 4 · explicit auth", name: "🔴 Abuse-Case Proof", tools: ["💥 Controlled abuse-case proof", "🧯 No destructive actions", "🛑 Kill switch enforced"], dur: "⏱ ~30 min · full auth" },
      ],
    };
    return templates[family] || templates.web;
  }

  function guidedFullAuthorizationCopy(family = "web") {
    const copy = {
      web: {
        option: "Allows controlled exploit proof for this web target when written authorisation is recorded.",
        confirmTools: "controlled exploit validation and intrusive web checks",
      },
      internal: {
        option: "Allows approved credential and exploitation tooling for this internal environment.",
        confirmTools: "Metasploit, Impacket, and domain-impact validation tooling",
      },
      "external-infrastructure": {
        option: "Allows controlled exploit proof against the authorised exposed services.",
        confirmTools: "controlled infrastructure exploit validation tools",
      },
      api: {
        option: "Allows intrusive API and business-logic validation under written authorisation.",
        confirmTools: "intrusive API and business-logic validation",
      },
      ai: {
        option: "Allows controlled abuse-case validation for the authorised AI workflows.",
        confirmTools: "controlled AI abuse-case validation",
      },
    };
    return copy[family] || copy.web;
  }

  function phaseGridTemplate(count) {
    const columns = [];
    for (let index = 0; index < count; index += 1) {
      columns.push("minmax(0, 1fr)");
      if (index < count - 1) columns.push("auto");
    }
    return columns.join(" ");
  }

  function renderGuidedPhaseDiagram(data = state.wizard.data, depth = flowDepthConfig(), plan = executionPlanForProfile(estimateMission(data).execution_profile, state.runProfiles)) {
    const family = guidedPhaseFamily(data, plan);
    const phases = guidedPhaseTemplates(family).slice(0, guidedPhaseLimit(depth));
    const gridTemplate = phaseGridTemplate(phases.length);
    return `
      <div class="phase-diagram" data-testid="wizard-mission-preview-diagram">
        <div class="phase-row" style="grid-template-columns: ${escapeHtml(gridTemplate)}">
          ${phases.map((phase, index) => `
            <div class="ph-card ${escapeHtml(phase.cls)}">
              <div class="ph-num">${escapeHtml(phase.num)}</div>
              <div class="ph-name">${escapeHtml(phase.name)}</div>
              <div class="ph-tools">${phase.tools.map((tool) => `<div class="ph-tool">${escapeHtml(tool)}</div>`).join("")}</div>
              <div class="ph-dur">${escapeHtml(phase.dur)}</div>
            </div>
            ${index < phases.length - 1 ? `<div class="ph-arrow">→</div>` : ""}
          `).join("")}
        </div>
        <div class="phase-note">AegisPT stores evidence after each phase, keeps approvals explicit, and the kill switch remains available.</div>
      </div>
    `;
  }

  function renderGuidedLaunchStep() {
    const target = flowTargetValue();
    const depth = flowDepthConfig();
    const heading = assessmentSelectionLabel() || "Selected Assessment";
    const estimate = estimateMission(state.wizard.data);
    const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
    const needsAuthorizationConfirmation = needsRoeAuthorizationConfirmation(state.wizard.data);
    return `
      <div class="wizard-flow-step wizard-launch-step" data-testid="conversation-question">
        <div class="launched">
          <div class="launched-icon">🚀</div>
          <div class="page-h">Mission Ready</div>
          <div class="page-sub">Create the queued run dossier, then review the selected work from Mission Control.</div>
          <div class="launch-missions">
            <div class="launch-mission-chip">🎯 ${escapeHtml(heading)}</div>
            <div class="launch-mission-chip">📍 ${escapeHtml(target)}</div>
            <div class="launch-mission-chip">🧭 ${escapeHtml(depth.title)} · ${escapeHtml(plan.profileName)}</div>
          </div>
          ${
            needsAuthorizationConfirmation
              ? `
                <label class="option-card launch-roe-confirmation" data-testid="wizard-roe-authorization-gate">
                  <input id="wizard-roe-authorization-confirmed" data-testid="wizard-roe-authorization-checkbox" type="checkbox" ${state.wizard.data.authorization_confirmed ? "checked" : ""} />
                  <div>
                    <strong>I confirm I have written authorization from the system owner</strong>
                    <p class="micro-copy">This creates an auditable authorization confirmation before the run can start.</p>
                  </div>
                </label>
              `
              : ""
          }
          <div class="launch-actions">
            <button class="btn btn-p" type="button" data-wizard-create-mission="true" ${needsAuthorizationConfirmation && !state.wizard.data.authorization_confirmed ? "disabled" : ""}>Create Mission & Open Mission Control →</button>
            <button class="btn btn-danger-outline" type="button" data-nav-screen="mission-control">⬜ Kill Switch</button>
          </div>
        </div>
        ${renderWizardStepBar(4)}
      </div>
    `;
  }

  function needsRoeAuthorizationConfirmation(data = state.wizard.data) {
    const selectedEngagement = state.wizard.useExistingEngagement
      ? runtime.actions.selectedEngagement?.()
      : null;
    const roeRef = stringValue(selectedEngagement?.roe_ref || data.roe_ref);
    const alreadyConfirmed = Boolean(selectedEngagement?.authorization_confirmed_at);
    return !roeRef && !alreadyConfirmed;
  }

  function renderGuidedWizardFlow(context) {
    const step = flowStep();
    if (step === 2) return renderGuidedTargetStep();
    if (step === 3) return renderGuidedPreviewStep(context);
    if (step === 4) return renderGuidedLaunchStep();
    return renderGuidedAssessmentStep();
  }

  function renderIntentQuestionSurface() {
    const showCustomEntry = Boolean(state.wizard.intake.customAnswerOpen);
    return `
      <div class="wizard-intake-shell" data-testid="conversation-question">
        ${renderRecentMissionRow()}
        <section class="wizard-assessment-surface">
          <div class="wizard-section-head">
            <p class="eyebrow">Assessment Types</p>
          </div>
          ${renderAssessmentTypeTiles()}
          <div class="conversation-manual-entry split-top" data-testid="conversation-manual-entry">
            ${
              showCustomEntry
                ? `
                  <form id="conversation-answer-form" class="conversation-answer-form">
                    <label class="conversation-answer-label" for="wizard-answer-input">Describe the mission</label>
                    <input
                      id="wizard-answer-input"
                      type="text"
                      placeholder="For example: TLS posture for our public site, a narrow API review, or a mixed environment"
                      value="${escapeHtml(state.wizard.intake.draftAnswer || "")}"
                      data-testid="conversation-answer-input"
                    />
                  </form>
                `
                : `
                  <button class="action ghost" type="button" data-intake-custom-entry="intent" data-testid="wizard-custom-answer-toggle">Describe it instead</button>
                  <p class="micro-copy split-top">Use this for narrower workflows like TLS-only validation or other missions that do not fit a single tile.</p>
                `
            }
          </div>
        </section>
        ${renderConversationPathNote(buildConversationContext())}
      </div>
    `;
  }

  function setAssessmentTileSelection(keys, reason = "wizard.assessment.selection") {
    const normalized = normalizeAssessmentTileKeys(keys);
    patchWizardFields(
      {
        intake: {
          ...state.wizard.intake,
          flowMode: "tile",
          selectedAssessmentTileKey: primaryAssessmentTileKey(normalized),
          selectedAssessmentTileKeys: normalized,
        },
      },
      reason
    );
    renderWizard();
  }

  function toggleAssessmentTileSelection(key) {
    const normalizedKey = String(key || "").trim();
    if (normalizedKey === "full-internal") {
      const current = selectedAssessmentTileKeys(state.wizard);
      const comboSelected = current.includes("internal-lan") && current.includes("active-directory");
      setAssessmentTileSelection(comboSelected ? [] : ["internal-lan", "active-directory"], "wizard.assessment.fullInternal");
      return;
    }
    const current = selectedAssessmentTileKeys(state.wizard);
    const next = current.includes(normalizedKey)
      ? current.filter((item) => item !== normalizedKey)
      : [...current, normalizedKey];
    setAssessmentTileSelection(next, "wizard.assessment.toggle");
  }

  function removeAssessmentTileSelection(key) {
    const next = selectedAssessmentTileKeys(state.wizard).filter((item) => item !== String(key || "").trim());
    setAssessmentTileSelection(next, "wizard.assessment.remove");
  }

  async function submitAssessmentSelection() {
    const keys = selectedAssessmentTileKeys(state.wizard);
    if (!keys.length) {
      patchWizardFields({ errors: ["Select at least one assessment type before continuing."] }, "wizard.assessment.required");
      renderWizard();
      return;
    }
    const primaryKey = primaryAssessmentTileKey(keys);
    const label = assessmentSelectionLabel(keys);
    await submitConversationAnswer(label, {
      flowMode: "tile",
      tileKey: primaryKey,
      selectedTileKeys: keys,
      historyText: label,
    });
  }

  function queueRecentMissionScopePrefetch() {
    recentMissionCandidates().forEach((engagement) => {
      const engagementId = String(engagement?.id || "");
      if (!engagementId || RECENT_MISSION_SCOPE_CACHE.has(engagementId) || RECENT_MISSION_SCOPE_REQUESTS.has(engagementId)) {
        return;
      }
      RECENT_MISSION_SCOPE_REQUESTS.add(engagementId);
      api(`/api/v1/engagements/${encodeURIComponent(engagementId)}/scope?optional=true`)
        .then((scope) => {
          const summaryTargets = buildTargetsFromAllowlist(scope?.allowlist_json || {});
          RECENT_MISSION_SCOPE_CACHE.set(engagementId, {
            targetLabel: firstTruthyTargetLabel(summaryTargets),
            allowlist: scope?.allowlist_json || {},
            denylist: scope?.denylist_json || {},
          });
        })
        .catch(() => {
          RECENT_MISSION_SCOPE_CACHE.set(engagementId, { error: true });
        })
        .finally(() => {
          RECENT_MISSION_SCOPE_REQUESTS.delete(engagementId);
          renderWizard();
        });
    });
  }

  async function prefillFromRecentMission(engagementId) {
    const normalizedId = String(engagementId || "").trim();
    if (!normalizedId) return;
    const engagement = state.engagements.find((item) => String(item?.id || "") === normalizedId);
    if (!engagement) return;

    let cached = RECENT_MISSION_PREFILL_CACHE.get(normalizedId);
    if (!cached) {
      const [scope, runs] = await Promise.all([
        api(`/api/v1/engagements/${encodeURIComponent(normalizedId)}/scope?optional=true`).catch(() => null),
        api(`/api/v1/engagements/${encodeURIComponent(normalizedId)}/runs`).catch(() => []),
      ]);
      const latestRun = Array.isArray(runs)
        ? [...runs].sort((left, right) => new Date(right?.created_at || 0).getTime() - new Date(left?.created_at || 0).getTime())[0] || null
        : null;
      const configuration = latestRun?.configuration_json || {};
      cached = { scope, latestRun, configuration };
      RECENT_MISSION_PREFILL_CACHE.set(normalizedId, cached);
    }

    const nextWizard = buildEmptyWizardState();
    const cachedScope = cached.scope?.allowlist_json || RECENT_MISSION_SCOPE_CACHE.get(normalizedId)?.allowlist || {};
    const cachedDenylist = cached.scope?.denylist_json || RECENT_MISSION_SCOPE_CACHE.get(normalizedId)?.denylist || {};
    const configuration = cached.configuration || {};
    const configurationTargets = configuration.targets || {};
    const configurationExclusions = configuration.exclusions || {};

    nextWizard.data.engagement_name = String(engagement.name || "").trim();
    nextWizard.data.client = String(engagement.client || "").trim();
    nextWizard.data.roe_ref = String(engagement.roe_ref || "").trim();
    nextWizard.data.assessment_type =
      String(configuration.assessment_type || "").trim() ||
      inferAssessmentTypeFromTargets(buildTargetsFromAllowlist(cachedScope, configurationTargets)) ||
      nextWizard.data.assessment_type;
    nextWizard.data.targets = buildTargetsFromAllowlist(cachedScope, configurationTargets, nextWizard.data.assessment_type);
    nextWizard.data.exclusions = {
      ...nextWizard.data.exclusions,
      ...buildExclusionsFromDenylist(cachedDenylist, configurationExclusions),
    };
    nextWizard.data.access = {
      ...nextWizard.data.access,
      ...(configuration.access || {}),
    };
    nextWizard.data.intake_preferences = {
      ...nextWizard.data.intake_preferences,
      ...(configuration.intake_preferences || {}),
    };
    nextWizard.data.assessment_mode = {
      ...nextWizard.data.assessment_mode,
      ...(configuration.assessment_mode || {}),
    };
    nextWizard.data.test_profile = String(configuration.test_profile || nextWizard.data.test_profile).trim() || nextWizard.data.test_profile;
    nextWizard.data.modules = {
      ...nextWizard.data.modules,
      ...(configuration.modules || {}),
    };
    nextWizard.data.safety = {
      ...nextWizard.data.safety,
      ...(configuration.safety || {}),
    };
    nextWizard.intake.flowMode = "tile";
    nextWizard.intake.selectedAssessmentTileKey = deriveAssessmentTileKey(nextWizard.data, nextWizard.intake);
    nextWizard.intake.selectedAssessmentTileKeys = normalizeAssessmentTileKeys([nextWizard.intake.selectedAssessmentTileKey]);
    nextWizard.intake.sources.intent = "confirmed";
    nextWizard.intake.sources.target_type = "confirmed";
    if (flattenTargetValues(nextWizard.data.targets).length) {
      nextWizard.intake.sources.scope = "confirmed";
    }
    if (String(nextWizard.data.intake_preferences.primary_goal || "").trim()) {
      nextWizard.intake.sources.goal = "confirmed";
    }
    if (String(nextWizard.data.intake_preferences.output_style || "").trim()) {
      nextWizard.intake.sources.output = "confirmed";
    }
    if (String(nextWizard.data.intake_preferences.auth_strategy || "").trim()) {
      nextWizard.intake.sources.auth = "confirmed";
    }
    if (String(nextWizard.data.intake_preferences.safety_posture || "").trim()) {
      nextWizard.intake.sources.safety = "confirmed";
    }
    if (
      countExplicitExclusions(nextWizard.data.exclusions) ||
      hasBoundaryNotes(nextWizard.data.exclusions) ||
      String(nextWizard.data.intake_preferences.boundary_handling || "").trim()
    ) {
      nextWizard.intake.sources.boundaries = "confirmed";
    }
    nextWizard.intake.activeQuestionId = "scope";
    nextWizard.intake.reviewQuestionId = "scope";
    nextWizard.intake.draftAnswer = flattenTargetValues(nextWizard.data.targets).join("\n");

    patchState({ wizard: nextWizard }, "wizard.recentMission.prefill");
    renderWizard();
    requestAnimationFrame(() => {
      document.getElementById("wizard-answer-input")?.focus();
    });
  }

  function usesCollapsedCustomEntry(question, choiceSurface) {
    return Boolean(choiceSurface) && question.id === "intent";
  }

  function renderConversationPanel(context) {
    const wizard = state.wizard;
    const question = context.question;
    if (question.id === "intent") {
      return renderIntentQuestionSurface();
    }
    const recentHistory = wizard.intake.history.slice(-2);
    const earlierHistory = wizard.intake.history.slice(0, Math.max(0, wizard.intake.history.length - recentHistory.length));
    const introOnly = !wizard.intake.history.some((turn) => turn.role === "user");
    const choiceSurface = renderQuestionChoiceSurface(question);
    const collapsedCustomEntry = usesCollapsedCustomEntry(question, choiceSurface);
    const showTypedAnswerInput = !choiceSurface || !collapsedCustomEntry || wizard.intake.customAnswerOpen;
    return `
      ${renderAssessmentSelectionBar()}
      ${
        earlierHistory.length
          ? renderDisclosure({
              title: "Earlier Intake Context",
              summary: `${wizard.intake.history.length} captured turns`,
              open: false,
              testId: "conversation-history-disclosure",
              body: `<div class="conversation-thread compact">${earlierHistory.map(renderConversationTurn).join("")}</div>`,
            })
          : ""
      }
      <div class="conversation-thread ${recentHistory.length <= 1 ? "compact" : ""} ${introOnly ? "intro-only" : ""}" data-testid="conversation-thread">
        ${recentHistory.map(renderConversationTurn).join("")}
      </div>
      <div class="conversation-question-card ${choiceSurface ? "choice-surface-question" : ""}" data-testid="conversation-question">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Next answer</p>
            <h3>${escapeHtml(question.title)}</h3>
          </div>
          <span class="badge">${escapeHtml(question.badge)}</span>
        </div>
        ${
          question.id === "confirm"
            ? `<p class="micro-copy">Review the planned mission below, revise any topic if needed, or open Advanced Configuration before you create the mission.</p>`
            : question.id === "intent"
              ? ""
              : `<p>${escapeHtml(question.prompt)}</p>`
        }
        ${question.guidance && !["confirm", "intent"].includes(question.id) ? `<p class="micro-copy split-top">${escapeHtml(question.guidance)}</p>` : ""}
        ${choiceSurface ? `<div class="split-top">${choiceSurface}</div>` : ""}
        ${question.recommendation ? `
          <div class="section-note split-top">
            <strong>Recommendation</strong>
            <p>${escapeHtml(question.recommendation)}</p>
          </div>
        ` : ""}
        ${question.quickReplies.length && !choiceSurface ? `
          <div class="chip-row split-top" data-testid="conversation-quick-replies">
            ${question.quickReplies.map((reply) => `
              <button class="action ghost quick-reply-chip" type="button" data-quick-reply="${escapeHtml(reply)}">${escapeHtml(reply)}</button>
            `).join("")}
          </div>
        ` : ""}
        ${question.id === "goal" ? `
          <p class="micro-copy split-top">Choose a depth tile for the fastest common path, or type your own wording below for a custom mission goal.</p>
        ` : question.quickReplies.length && question.id !== "confirm" ? `
          <p class="micro-copy split-top">Use one of the suggested replies for the common path, or type your own wording below if your mission needs more detail.</p>
        ` : ""}
        ${question.id === "confirm" ? `
          ${renderMissionPreviewSurface(context)}
          <div class="detail-surface emphasis-surface split-top" data-testid="wizard-confirmation-summary">
            <h4>Planned Mission</h4>
            <p>${escapeHtml(buildNaturalConfirmationSummary(context.estimate))}</p>
            ${renderConfirmationAuthorizationContext()}
            ${renderConfirmationScopeGuardrails()}
            <p class="micro-copy split-top">${escapeHtml(buildConfirmationSafetyLine(wizard.data, context.estimate.execution_profile))}</p>
          </div>
        ` : `
          ${
            collapsedCustomEntry && !wizard.intake.customAnswerOpen
              ? `
                <div class="conversation-manual-entry split-top" data-testid="conversation-manual-entry">
                  <button class="action ghost" type="button" data-intake-custom-entry="intent" data-testid="wizard-custom-answer-toggle">Describe it instead</button>
                </div>
              `
              : ""
          }
          ${
            showTypedAnswerInput
              ? `
                <form id="conversation-answer-form" class="conversation-answer-form split-top">
                  ${choiceSurface ? `<label class="conversation-answer-label" for="wizard-answer-input">${escapeHtml(question.id === "scope" ? "Target" : question.id === "boundaries" ? "Optional exclusions or notes" : "Describe the mission")}</label>` : ""}
                  ${question.multiline ? `
                    <textarea id="wizard-answer-input" rows="4" placeholder="${escapeHtml(question.placeholder)}" aria-label="${escapeHtml(question.prompt || "Intake answer")}" data-testid="conversation-answer-input">${escapeHtml(wizard.intake.draftAnswer || "")}</textarea>
                  ` : `
                    <input id="wizard-answer-input" type="text" placeholder="${escapeHtml(question.placeholder)}" value="${escapeHtml(wizard.intake.draftAnswer || "")}" aria-label="${escapeHtml(question.prompt || "Intake answer")}" data-testid="conversation-answer-input" />
                  `}
                </form>
              `
              : ""
          }
        `}
        ${renderConversationPathNote(context)}
      </div>
      ${renderConversationEditActions(context)}
      ${renderWizardStepBar(wizardFlowStepIndex(context))}
    `;
  }

  function renderConversationPathNote(context) {
    if (context.question.id === "confirm") {
      return `
        <div class="intake-progress-note ready split-top" data-testid="conversation-path-note">
          <strong>${escapeHtml(context.fullAuthorizationPending ? "Full Authorization Needs Typed Scope Confirmation" : "Confirmation Ready")}</strong>
          <p>${escapeHtml(
            context.fullAuthorizationPending
              ? `All intake topics are resolved. Type ${missionScopeConfirmationToken(state.wizard.data) || "an approved target"} exactly to unlock the full-mission authorization path.`
              : "All required intake topics are resolved. Review the mission summary, revise any topic if needed, then create the mission."
          )}</p>
        </div>
      `;
    }

    if (renderQuestionChoiceSurface(context.question) && context.question.id === "intent") {
      const remainingStillNeededLabels = filterStillNeededLabelsForActiveQuestion(
        context.summary,
        context.question.id,
      );
      const remainingLine =
        remainingStillNeededLabels.length === 0
          ? "Choose the closest assessment shape and AegisPT will ask only the next missing mission details."
          : `Still to confirm in this mission: ${remainingStillNeededLabels.join(", ")}.`;
      return `
        <div class="intake-progress-note review split-top" data-testid="conversation-path-note">
          <strong>Still needed</strong>
          <p>${escapeHtml(remainingLine)}</p>
        </div>
      `;
    }

    if (state.wizard.intake.flowMode === "tile") {
      const needsAuthQuestion =
        questionStillNeedsInput(state.wizard, "auth") ||
        questionStillNeedsInput(state.wizard, "auth-details");
      const tileQuestions = [...new Set(
        activeOrderedQuestions(state.wizard)
          .filter((questionId) => {
            if (["intent", "safety", "output"].includes(questionId)) return false;
            if (!needsAuthQuestion && ["auth", "auth-details"].includes(questionId)) return false;
            return true;
          })
          .map((questionId) => (questionId === "auth-details" ? resolveConversationTopicQuestionId("auth") : questionId))
      )];
      const currentQuestionId =
        context.question.id === "auth-details" ? resolveConversationTopicQuestionId("auth") : context.question.id;
      const tileIndex = tileQuestions.indexOf(currentQuestionId);
      if (tileIndex >= 0) {
        return `
          <div class="intake-progress-note split-top" data-testid="conversation-path-note">
            <strong>Quick Setup</strong>
            <p>Question ${tileIndex + 1} of ${tileQuestions.length}. Keep it short and I will map it into the deterministic run dossier immediately.</p>
          </div>
        `;
      }
    }

    if (context.reviewMode === "earlier") {
      return `
        <div class="intake-progress-note review split-top" data-testid="conversation-path-note">
          <strong>Revising Earlier Topic</strong>
          <p>You are updating an earlier answer. After you apply it, AegisPT recalculates the next required question from the updated mission state.</p>
          <p class="micro-copy split-top">The live summary and deterministic run dossier update immediately when this answer is applied.</p>
        </div>
      `;
    }

    if (context.reviewMode === "later" || context.reviewMode === "other") {
      return `
        <div class="intake-progress-note review split-top" data-testid="conversation-path-note">
          <strong>Reviewing Another Topic</strong>
          <p>You are checking a different mission topic before the main intake reaches it. After you apply this answer, AegisPT returns to the next required topic from the updated mission state.</p>
          <p class="micro-copy split-top">Use this when you want to jump ahead without losing the deterministic intake path.</p>
        </div>
      `;
    }

    const remainingStillNeededLabels = filterStillNeededLabelsForActiveQuestion(
      context.summary,
      context.question.id,
    );
    const remainingLine =
      remainingStillNeededLabels.length === 0
        ? "Answer this to continue. AegisPT will either move straight to confirmation or ask for the next required topic immediately after."
        : `Still to confirm in this mission: ${remainingStillNeededLabels.join(", ")}.`;

    return `
      <div class="intake-progress-note split-top" data-testid="conversation-path-note">
        <strong>Mission Progress</strong>
        <p>${escapeHtml(remainingLine)}</p>
      </div>
    `;
  }

  function activeQuestionFamilyIds(questionId) {
    if (questionId === "auth") {
      return new Set(["auth", "auth-details"]);
    }
    if (
      questionId === "auth-details" &&
      state.wizard.data.intake_preferences.auth_strategy === "advanced-details" &&
      !hasMeaningfulAccessContext(state.wizard.data.access)
    ) {
      return new Set();
    }
    if (questionId === "auth-details") {
      return new Set(["auth", "auth-details"]);
    }
    return new Set([questionId]);
  }

  function labelsResolvedByActiveQuestion(summary, questionId) {
    const activeQuestionIds = activeQuestionFamilyIds(questionId);
    return new Set(
      (summary?.stillNeededDetails || [])
        .filter((item) => item.questionId && activeQuestionIds.has(item.questionId))
        .map((item) => item.label),
    );
  }

  function filterStillNeededLabelsForActiveQuestion(summary, questionId) {
    const suppressedLabels = labelsResolvedByActiveQuestion(summary, questionId);
    return (summary?.stillNeeded || []).filter((label) => !suppressedLabels.has(label));
  }

  function revisableConversationActions(context) {
    const wizard = state.wizard;
    const activeQuestionIds = activeQuestionFamilyIds(context.question.id);
    const confirmedOrOverride = (value) => ["confirmed", "override"].includes(String(value || ""));
    return [
      {
        questionId: "goal",
        label: wizard.intake.flowMode === "tile" ? "Change Depth" : "Change Goal",
        ready: confirmedOrOverride(wizard.intake.sources.goal) && !questionStillNeedsInput(wizard, "goal"),
      },
      {
        questionId: "output",
        label: "Change Output",
        ready: confirmedOrOverride(wizard.intake.sources.output),
      },
      {
        questionId: "scope",
        label: "Change Scope",
        ready: confirmedOrOverride(wizard.intake.sources.scope) && !questionStillNeedsInput(wizard, "scope"),
      },
      {
        questionId: resolveConversationTopicQuestionId("auth"),
        label: "Change Access",
        ready:
          confirmedOrOverride(wizard.intake.sources.auth) &&
          !questionStillNeedsInput(wizard, "auth") &&
          !questionStillNeedsInput(wizard, "auth-details"),
      },
      {
        questionId: "safety",
        label: "Change Safety",
        ready: confirmedOrOverride(wizard.intake.sources.safety) && !questionStillNeedsInput(wizard, "safety"),
      },
      {
        questionId: "boundaries",
        label: "Change Boundaries",
        ready: confirmedOrOverride(wizard.intake.sources.boundaries) && !questionStillNeedsInput(wizard, "boundaries"),
      },
    ].filter((item) => item.ready && !activeQuestionIds.has(item.questionId));
  }

  function renderConversationTurn(turn) {
    return `
      <article class="conversation-turn ${escapeHtml(turn.role)} ${escapeHtml(turn.tone || "neutral")}" data-testid="conversation-turn">
        <p class="eyebrow">${escapeHtml(turn.role === "assistant" ? "AegisPT" : "Operator")}</p>
        <p>${escapeHtml(turn.text)}</p>
        ${turn.questionId && turn.role === "user" ? `<button class="action ghost tiny" type="button" data-edit-question="${escapeHtml(turn.questionId)}">Change</button>` : ""}
      </article>
    `;
  }

  function renderConversationEditActions(context) {
    if (!hasConversationHistory()) return "";
    const actions = revisableConversationActions(context);
    if (!actions.length) return "";
    return renderDisclosure({
      title: "Revise Captured Topic",
      summary: `${actions.length} captured topic${actions.length === 1 ? "" : "s"} can be updated`,
      open: false,
      testId: "conversation-edit-row",
      body: `
        <div class="conversation-edit-row">
          ${actions
            .map(
              ({ questionId, label }) => `
                <button class="action ghost tiny" type="button" data-edit-question="${escapeHtml(questionId)}">${escapeHtml(label)}</button>
              `
            )
            .join("")}
        </div>
        <p class="micro-copy split-top">Only topics already captured in the run dossier are shown here, so later unanswered steps do not add extra noise.</p>
      `,
    });
  }

  function renderAdvancedDrawer(context) {
    const wizard = state.wizard;
    const steps = WIZARD_STEPS.slice(0, 6);
    return `
      <div class="advanced-drawer-shell">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Advanced Configuration</p>
            <h4>Deterministic Run Controls</h4>
          </div>
          <button class="action ghost tiny" type="button" data-advanced-close="true">Hide</button>
        </div>
        <p class="micro-copy">These controls write into the same run configuration that the conversational intake is building.</p>
        ${renderChatGptOAuthCard()}
        <div class="advanced-nav split-top" role="tablist" aria-label="Advanced configuration sections">
          ${steps.map((label, index) => `
            <button class="action ${wizard.advancedStep === index ? "secondary" : "ghost"} tiny" type="button" role="tab" aria-selected="${wizard.advancedStep === index ? "true" : "false"}" data-advanced-step="${index}">${escapeHtml(label)}</button>
          `).join("")}
        </div>
        <div id="wizard-advanced-content" class="advanced-content split-top" data-testid="wizard-advanced-content">
          ${wizardStepContent(wizard.advancedStep, wizard.data, wizard.useExistingEngagement)}
        </div>
      </div>
    `;
  }

  function renderChatGptOAuthCard() {
    const engagementId = selectedEngagementIdForChatGptOAuth();
    const selectedEngagement = runtime.actions.selectedEngagement?.();
    const status = state.chatgptOAuthStatus?.loadedForEngagementId === engagementId
      ? state.chatgptOAuthStatus
      : null;
    const connected = Boolean(status?.connected);
    const loading = Boolean(status?.loading);
    const reusable = Boolean(status?.reusable_session_available && !connected);
    const accountId = status?.account_id || status?.accountId || "";
    const statusLabel = !engagementId
      ? "Select or create an engagement first"
      : loading
        ? "Checking connection"
        : connected
          ? "Connected"
          : status?.error
            ? "Needs attention"
            : status?.pendingAuthorization
              ? "Authorization window opened"
              : "Disconnected";
    const message = !engagementId
      ? "ChatGPT OAuth is stored per engagement so customer contexts stay separated."
      : status?.error
        ? status.error
        : connected
          ? "AegisPT can use this encrypted ChatGPT OAuth session for enabled AI provider features."
          : reusable
            ? `An encrypted ChatGPT session for ${status.reusable_account_id || "another engagement"} is available. Use it here without logging in again.`
          : status?.pendingAuthorization
            ? "Complete the browser login, then refresh this status after the callback returns."
            : "Connect a ChatGPT Plus/Pro account using PKCE. Tokens are encrypted through SecretRef and never rendered here.";
    const buttonLabel = connected ? "Reconnect ChatGPT" : reusable ? "Use Existing ChatGPT Session" : "Connect ChatGPT";
    return `
      <section class="ai-provider-card split-top" data-testid="chatgpt-oauth-card">
        <div>
          <p class="eyebrow">AI Provider</p>
          <h4>ChatGPT OAuth</h4>
          <p>${escapeHtml(message)}</p>
          <div class="chip-row compact split-top">
            <span class="status-chip ${connected ? "success" : status?.error ? "danger" : "neutral"}" data-testid="chatgpt-oauth-status">${escapeHtml(statusLabel)}</span>
            ${accountId ? `<span class="status-chip neutral" data-testid="chatgpt-oauth-account">${escapeHtml(accountId)}</span>` : ""}
            <span class="status-chip neutral">token exposed: no</span>
          </div>
          <p class="micro-copy split-top">${escapeHtml(selectedEngagement?.name ? `Connection scope: ${selectedEngagement.name}` : "Connection scope: selected engagement")}</p>
        </div>
        <div class="ai-provider-actions">
          <button class="action secondary" type="button" data-chatgpt-oauth-connect="true" data-testid="chatgpt-oauth-connect" ${engagementId ? "" : "disabled"}>${escapeHtml(buttonLabel)}</button>
          <button class="action ghost" type="button" data-chatgpt-oauth-refresh="true" data-testid="chatgpt-oauth-refresh" ${engagementId ? "" : "disabled"}>Refresh Status</button>
        </div>
      </section>
    `;
  }

  function selectedEngagementIdForChatGptOAuth() {
    return state.selectedEngagementId || runtime.actions.selectedEngagement?.()?.id || null;
  }

  function queueChatGptOAuthStatusRefresh() {
    const engagementId = selectedEngagementIdForChatGptOAuth();
    if (!engagementId || chatgptOAuthStatusInFlight) return;
    if (state.chatgptOAuthStatus?.loadedForEngagementId === engagementId && !state.chatgptOAuthStatus?.stale) {
      return;
    }
    refreshChatGptOAuthStatus().catch(runtime.actions.handleError || (() => {}));
  }

  async function refreshChatGptOAuthStatus({ force = false } = {}) {
    const engagementId = selectedEngagementIdForChatGptOAuth();
    if (!engagementId) return;
    if (chatgptOAuthStatusInFlight && !force) return;
    chatgptOAuthStatusInFlight = true;
    patchState(
      {
        chatgptOAuthStatus: {
          ...(state.chatgptOAuthStatus || {}),
          loadedForEngagementId: engagementId,
          loading: true,
          stale: false,
          error: null,
        },
      },
      "wizard.chatgptOAuth.status.loading"
    );
    renderWizard();
    try {
      const status = await api(`/api/v1/auth/chatgpt/status?engagement_id=${encodeURIComponent(engagementId)}`);
      patchState(
        {
          chatgptOAuthStatus: {
            ...status,
            loadedForEngagementId: engagementId,
            loading: false,
            stale: false,
            error: null,
          },
        },
        "wizard.chatgptOAuth.status.loaded"
      );
    } catch (error) {
      patchState(
        {
          chatgptOAuthStatus: {
            loadedForEngagementId: engagementId,
            connected: false,
            loading: false,
            stale: false,
            error: error.message || "Unable to read ChatGPT OAuth status.",
            token_exposed: false,
          },
        },
        "wizard.chatgptOAuth.status.failed"
      );
    } finally {
      chatgptOAuthStatusInFlight = false;
      renderWizard();
    }
  }

  async function connectChatGptOAuth() {
    const engagementId = selectedEngagementIdForChatGptOAuth();
    if (!engagementId) return;
    let authWindow = null;
    const canReuse = Boolean(state.chatgptOAuthStatus?.reusable_session_available && !state.chatgptOAuthStatus?.connected);
    if (!canReuse) {
      authWindow = window.open("about:blank", "_blank");
    }
    patchState(
      {
        chatgptOAuthStatus: {
          ...(state.chatgptOAuthStatus || {}),
          loadedForEngagementId: engagementId,
          loading: true,
          stale: false,
          error: null,
        },
      },
      "wizard.chatgptOAuth.connecting"
    );
    renderWizard();
    try {
      const response = await api(`/api/v1/auth/chatgpt/authorize?engagement_id=${encodeURIComponent(engagementId)}`);
      if (response.reused && response.status) {
        authWindow?.close?.();
        patchState(
          {
            chatgptOAuthStatus: {
              ...response.status,
              loadedForEngagementId: engagementId,
              loading: false,
              stale: false,
              pendingAuthorization: false,
              error: null,
              token_exposed: false,
            },
          },
          "wizard.chatgptOAuth.authorization.reused"
        );
        runtime.actions.pushStatus?.(
          "Existing encrypted ChatGPT OAuth session was reused for this engagement.",
          "success"
        );
        return;
      }
      if (!response.authorization_url) {
        authWindow?.close?.();
        throw new Error("ChatGPT OAuth authorization did not return a login URL.");
      }
      if (authWindow) {
        authWindow.location.href = response.authorization_url;
      } else {
        window.open(response.authorization_url, "_blank", "noopener,noreferrer");
      }
      patchState(
        {
          chatgptOAuthStatus: {
            loadedForEngagementId: engagementId,
            connected: false,
            configured: true,
            pendingAuthorization: true,
            authorizationUrl: response.authorization_url,
            loading: false,
            stale: false,
            token_exposed: false,
          },
        },
        "wizard.chatgptOAuth.authorization.opened"
      );
      scheduleChatGptOAuthStatusPolling();
    } catch (error) {
      authWindow?.close?.();
      patchState(
        {
          chatgptOAuthStatus: {
            loadedForEngagementId: engagementId,
            connected: false,
            loading: false,
            stale: false,
            error: error.message || "Unable to start ChatGPT OAuth.",
            token_exposed: false,
          },
        },
        "wizard.chatgptOAuth.authorization.failed"
      );
    } finally {
      renderWizard();
    }
  }

  function scheduleChatGptOAuthStatusPolling() {
    let attempts = 0;
    const poll = async () => {
      attempts += 1;
      const status = await refreshChatGptOAuthStatus({ force: true }).then(() => state.chatgptOAuthStatus).catch(() => null);
      if (status?.connected || attempts >= 12) return;
      window.setTimeout(poll, 5000);
    };
    window.setTimeout(poll, 5000);
  }

  function attachConversationHandlers(context) {
    document.getElementById("conversation-answer-form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      submitConversationAnswer().catch(runtime.actions.handleError || (() => {}));
    });

    document.getElementById("wizard-answer-input")?.addEventListener("input", (event) => {
      patchWizardIntakeFields({ draftAnswer: event.target.value }, "wizard.intake.draftAnswer");
      dom.wizardNextBtn.disabled = !stringValue(event.target.value);
    });

    document.querySelectorAll("[data-assessment-tile-key]").forEach((button) => {
      button.addEventListener("click", () => {
        toggleAssessmentTileSelection(button.dataset.assessmentTileKey);
      });
    });

    document.querySelectorAll("[data-assessment-remove-key]").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        removeAssessmentTileSelection(button.dataset.assessmentRemoveKey);
      });
    });

    document.querySelectorAll("[data-assessment-combo]").forEach((button) => {
      button.addEventListener("click", () => {
        const keys = normalizeAssessmentTileKeys(String(button.dataset.assessmentCombo || "").split(","));
        setAssessmentTileSelection(keys, "wizard.assessment.combo");
        applyGuidedSelectionToData({ step: 2 });
        renderWizard();
      });
    });

    document.querySelectorAll("[data-assessment-submit-selection]").forEach((button) => {
      button.addEventListener("click", () => {
        if (state.wizard.intake.flowMode === "tile") {
          const keys = selectedAssessmentTileKeys(state.wizard);
          if (!keys.length) {
            patchWizardFields({ errors: ["Select at least one assessment type before continuing."] }, "wizard.assessment.required");
            renderWizard();
            return;
          }
          if (state.wizard.intake.sources.scope !== "confirmed") {
            // Use the tile default only when no real scope has already been prefetched or typed.
            state.wizard.data.targets = { domains: [], subdomains: [], urls: [], ip_addresses: [], cidr_ranges: [], api_base_urls: [], wireless_sites: [], ssids: [], bssids: [] };
          }
          applyGuidedSelectionToData({ step: 2 });
          renderWizard();
          return;
        }
        submitAssessmentSelection().catch(runtime.actions.handleError || (() => {}));
      });
    });

    document.querySelectorAll("[data-wizard-step-target]").forEach((button) => {
      button.addEventListener("click", () => {
        const step = Number(button.dataset.wizardStepNumber || 1);
        if (state.wizard.intake.flowMode === "tile") {
          if (step === 1) {
            patchWizardIntakeFields({ flowStep: 1 }, "wizard.flow.step");
            renderWizard();
            return;
          }
          if (step === 2 && selectedAssessmentTileKeys(state.wizard).length) {
            applyGuidedSelectionToData({ step: 2 });
            renderWizard();
            return;
          }
          if (step === 3 && flattenTargetValues(state.wizard.data.targets).length) {
            applyGuidedSelectionToData({ step: 3 });
            renderWizard();
            return;
          }
          if (step === 4 && flattenTargetValues(state.wizard.data.targets).length) {
            applyGuidedSelectionToData({ step: 4 });
            renderWizard();
            return;
          }
        }
        if (step === 4 && !state.wizard.lastCreated) {
          focusQuestion("confirm");
          return;
        }
        focusQuestion(button.dataset.wizardStepTarget);
      });
    });

    document.querySelectorAll("[data-wizard-flow-step]").forEach((button) => {
      button.addEventListener("click", () => {
        const step = Number(button.dataset.wizardFlowStep || 1);
        applyGuidedSelectionToData({ step });
        renderWizard();
      });
    });

    document.querySelectorAll("[data-wizard-target-value]").forEach((button) => {
      button.addEventListener("click", () => {
        applyGuidedSelectionToData({
          targetValue: button.dataset.wizardTargetValue,
          step: 2,
        });
        renderWizard();
      });
    });

    document.getElementById("wizard-target-input")?.addEventListener("input", (event) => {
      applyGuidedSelectionToData({
        targetValue: event.target.value,
        step: 2,
      });
    });

    document.querySelectorAll("[data-wizard-depth-choice]").forEach((button) => {
      button.addEventListener("click", () => {
        applyGuidedSelectionToData({
          targetValue: document.getElementById("wizard-target-input")?.value || flowTargetValue(),
          depthChoice: button.dataset.wizardDepthChoice,
          step: 2,
        });
        renderWizard();
      });
    });

    document.querySelector("[data-wizard-preview]")?.addEventListener("click", () => {
      const targetValue = document.getElementById("wizard-target-input")?.value || flowTargetValue();
      if (containsUnauthorizedExpansion(targetValue)) {
        patchWizardFields(
          {
            errors: ["I need exact authorized targets before I can build a mission preview."],
            intake: {
              ...state.wizard.intake,
              flowMode: "tile",
              flowStep: 2,
            },
          },
          "wizard.guidedFlow.broadScopeRejected"
        );
        renderWizard();
        return;
      }
      applyGuidedSelectionToData({
        targetValue,
        step: 3,
      });
      renderWizard();
    });

    document.querySelectorAll("[data-lan-profile-fix]").forEach((button) => {
      button.addEventListener("click", () => {
        applyLanDiscoveryProfileCorrection();
        renderWizard();
      });
    });

    document.querySelectorAll("[data-wizard-authorization]").forEach((button) => {
      button.addEventListener("click", () => {
        const authorizationLevel = normalizedAuthorizationLevel(button.dataset.wizardAuthorization);
        const depthChoice = authorizationLevel === "full"
          ? "full"
          : authorizationLevel === "passive"
            ? "passive"
            : "active";
        const currentUnlockers = normalizeAccessUnlockers(state.wizard.data.access?.prerequisites);
        const nextUnlockers = authorizationLevel === "full"
          ? {
              ...currentUnlockers,
              unauthenticated_lane: currentUnlockers.unauthenticated_lane || !currentUnlockers.credential_refs,
              intrusive_lan_authorized: true,
              exploit_confirmation_authorized: true,
            }
          : {
              ...currentUnlockers,
              intrusive_lan_authorized: false,
              exploit_confirmation_authorized: false,
            };
        applyGuidedSelectionToData({
          targetValue: flowTargetValue(),
          depthChoice,
          step: 3,
        });
        patchWizardFields(
          {
            data: {
              ...state.wizard.data,
              access: {
                ...state.wizard.data.access,
                prerequisites: nextUnlockers,
              },
              assessment_mode: {
                ...state.wizard.data.assessment_mode,
                authorization_level: authorizationLevel,
              },
            },
            intake: {
              ...state.wizard.intake,
              flowDepthChoice: depthChoice,
            },
          },
          "wizard.flow.authorization"
        );
        renderWizard();
      });
    });

    document.querySelectorAll("[data-wizard-unlocker]").forEach((button) => {
      button.addEventListener("click", () => {
        const key = button.dataset.wizardUnlocker;
        if (!visibleAccessUnlockerOptions(state.wizard.data).some((option) => option.key === key)) return;
        const current = normalizeAccessUnlockers(state.wizard.data.access?.prerequisites);
        const next = { ...current, [key]: !current[key] };
        if (!Object.values(next).some(Boolean)) {
          next.unauthenticated_lane = true;
        }
        if (key === "credential_refs" || key === "hash_or_password_material") {
          next.unauthenticated_lane = false;
        }
        if (key === "unauthenticated_lane" && next.unauthenticated_lane) {
          next.credential_refs = false;
          next.hash_or_password_material = false;
        }
        const needsFullAuthorization = Boolean(next.intrusive_lan_authorized || next.exploit_confirmation_authorized);
        const authorizationLevel = needsFullAuthorization
          ? "full"
          : selectedAuthorizationLevel(state.wizard.data);
        const mode = authorizationLevel === "passive"
          ? state.wizard.data.assessment_mode?.mode || guidedAssessmentModeForSelection({
              keys: selectedAssessmentTileKeys(state.wizard),
              depthChoice: state.wizard.intake.flowDepthChoice || "active",
            }) || ""
          : state.wizard.data.assessment_mode?.mode || guidedAssessmentModeForSelection({
              keys: selectedAssessmentTileKeys(state.wizard),
              depthChoice: authorizationLevel === "full" ? "full" : "active",
            }) || "";
        patchWizardFields(
          {
            data: {
              ...state.wizard.data,
              access: {
                ...state.wizard.data.access,
                prerequisites: next,
              },
              intake_preferences: {
                ...state.wizard.data.intake_preferences,
                auth_strategy: next.credential_refs || next.hash_or_password_material
                  ? "credentialed"
                  : "unauthenticated",
              },
              assessment_mode: {
                ...state.wizard.data.assessment_mode,
                mode,
                authorization_level: authorizationLevel,
              },
            },
          },
          "wizard.accessUnlockers.toggle"
        );
        renderWizard();
      });
    });

    document.querySelector("[data-wizard-create-mission]")?.addEventListener("click", () => {
      submitWizard().catch(runtime.actions.handleError || (() => {}));
    });

    document.getElementById("wizard-roe-authorization-confirmed")?.addEventListener("change", (event) => {
      patchWizardFields(
        {
          data: {
            ...state.wizard.data,
            authorization_confirmed: Boolean(event.target.checked),
          },
        },
        "wizard.roeAuthorization.confirmed"
      );
      renderWizard();
    });

    document.querySelectorAll("[data-quick-reply]").forEach((button) => {
      button.addEventListener("click", () => {
        submitConversationAnswer(button.dataset.quickReply, {
          flowMode: button.dataset.flowMode,
          tileKey: button.dataset.assessmentTileKey,
          depthChoice: button.dataset.depthChoice,
          depthSafety: button.dataset.depthSafety,
          historyText: button.dataset.historyText,
        }).catch(runtime.actions.handleError || (() => {}));
      });
    });

    document.querySelectorAll("[data-edit-question]").forEach((button) => {
      button.addEventListener("click", () => {
        focusQuestion(button.dataset.editQuestion);
      });
    });

    document.querySelectorAll("[data-intake-advanced]").forEach((button) => {
      button.addEventListener("click", () => {
        const requestedStep = Number(button.dataset.intakeAdvancedStep);
        patchWizardFields(
          {
            intake: { ...state.wizard.intake, advancedOpen: true },
            advancedStep: Number.isNaN(requestedStep) ? state.wizard.advancedStep : requestedStep,
          },
          "wizard.intake.openAdvanced"
        );
        renderWizard();
      });
    });

    document.querySelectorAll("[data-intake-custom-entry]").forEach((button) => {
      button.addEventListener("click", () => {
        patchWizardIntakeFields(
          { customAnswerOpen: true },
          "wizard.intake.openCustomEntry"
        );
        renderWizard();
        requestAnimationFrame(() => {
          document.getElementById("wizard-answer-input")?.focus();
        });
      });
    });

    document.querySelectorAll("[data-wizard-clear-assessment]").forEach((button) => {
      button.addEventListener("click", () => {
        const wizard = state.wizard;
        patchWizardFields(
          {
            intake: {
              ...wizard.intake,
              selectedAssessmentTileKey: "",
              selectedAssessmentTileKeys: [],
              draftAnswer: "",
            },
          },
          "wizard.assessment.clearSelection"
        );
        renderWizard();
      });
    });

    document.querySelectorAll("[data-recent-engagement-prefill]").forEach((button) => {
      button.addEventListener("click", () => {
        prefillFromRecentMission(button.dataset.recentEngagementPrefill).catch(runtime.actions.handleError || (() => {}));
      });
    });

    const advancedToggle = document.getElementById("wizard-advanced-toggle");
    if (advancedToggle) {
      advancedToggle.onclick = () => {
        patchWizardIntakeFields(
          { advancedOpen: !state.wizard.intake.advancedOpen },
          "wizard.intake.toggleAdvanced"
        );
        renderWizard();
      };
    }

    const restartButton = document.getElementById("wizard-restart-btn");
    if (restartButton) {
      restartButton.onclick = () => {
        restartConversation();
      };
    }

    document.querySelectorAll("[data-authorization-level]").forEach((button) => {
      button.addEventListener("click", () => {
        if (!chainAuthorizationAvailable(state.wizard.data)) return;
        patchWizardFields(
          {
            data: {
              ...state.wizard.data,
              assessment_mode: {
                ...state.wizard.data.assessment_mode,
                authorization_level: normalizedAuthorizationLevel(button.dataset.authorizationLevel),
              },
            },
          },
          "wizard.confirm.authorizationLevel"
        );
        renderWizard();
      });
    });

    document.getElementById("wizard-full-authorization-input")?.addEventListener("input", (event) => {
      patchWizardFields(
        {
          data: {
            ...state.wizard.data,
            assessment_mode: {
              ...state.wizard.data.assessment_mode,
              typed_scope_confirmation: event.target.value,
            },
          },
        },
        "wizard.confirm.fullAuthorizationTypedScope"
      );
      const fullAuthorizationReady = hasValidFullAuthorizationConfirmation(state.wizard.data);
      const launchButton = document.querySelector('[data-wizard-flow-step="4"]');
      const launchStatus = document.querySelector(".confirm-status");
      if (launchButton) {
        launchButton.disabled = !fullAuthorizationReady;
      }
      if (launchStatus) {
        launchStatus.textContent = fullAuthorizationReady ? "Confirmed" : "Not confirmed";
        launchStatus.classList.toggle("ok", fullAuthorizationReady);
      }
      dom.wizardConfirmBtn.disabled = state.wizard.submitting || !fullAuthorizationReady;
      dom.wizardConfirmBtn.textContent = fullAuthorizationReady
        ? "Authorize Full Mission & Open Mission Control"
        : "Type Target To Unlock Full Authorization";
    });
  }

  function attachAdvancedHandlers() {
    document.querySelectorAll("[data-advanced-step]").forEach((button) => {
      button.addEventListener("click", () => {
        patchWizardFields(
          { advancedStep: Number(button.dataset.advancedStep || 0) },
          "wizard.advanced.step"
        );
        renderWizard();
      });
    });

    document.querySelector('[data-advanced-close="true"]')?.addEventListener("click", () => {
      patchWizardIntakeFields({ advancedOpen: false }, "wizard.intake.closeAdvanced");
      renderWizard();
    });

    document.querySelector('[data-chatgpt-oauth-connect="true"]')?.addEventListener("click", () => {
      connectChatGptOAuth().catch(runtime.actions.handleError || (() => {}));
    });

    document.querySelector('[data-chatgpt-oauth-refresh="true"]')?.addEventListener("click", () => {
      refreshChatGptOAuthStatus({ force: true }).catch(runtime.actions.handleError || (() => {}));
    });

    const advancedRoot = document.getElementById("wizard-advanced-content");
    if (!advancedRoot) return;

    advancedRoot.querySelectorAll("input, textarea, select").forEach((element) => {
      element.addEventListener("input", onAdvancedInput);
      element.addEventListener("change", onAdvancedInput);
    });

    advancedRoot.querySelector("#wizard-add-account-btn")?.addEventListener("click", () => {
      syncWizardStepFromDom();
      patchWizardAccessAccounts(
        [...state.wizard.data.access.accounts, buildEmptyAccount()],
        "wizard.access.addAccount"
      );
      markAdvancedOverrideForStep(state.wizard.advancedStep);
      renderWizard();
    });

    advancedRoot.querySelectorAll(".wizard-remove-account-btn").forEach((button) => {
      button.addEventListener("click", () => {
        syncWizardStepFromDom();
        const index = Number(button.dataset.accountRemove);
        const accounts = state.wizard.data.access.accounts.filter((_, accountIndex) => accountIndex !== index);
        patchWizardAccessAccounts(accounts.length ? accounts : [buildEmptyAccount()], "wizard.access.removeAccount");
        markAdvancedOverrideForStep(state.wizard.advancedStep);
        renderWizard();
      });
    });
  }

  function submitConversationAnswer(answerOverride, submitOptions = {}) {
    syncWizardStepFromDom();
    const wizard = state.wizard;
    const context = buildConversationContext();
    const question = context.question;
    const answer = stringValue(answerOverride ?? wizard.intake.draftAnswer ?? document.getElementById("wizard-answer-input")?.value);
    const historyText = stringValue(submitOptions.historyText || answer);

    if (question.id === "confirm") {
      return Promise.resolve();
    }

    if (!answer) {
      wizard.errors = ["Enter an answer or use a quick reply."];
      renderWizard();
      return Promise.resolve();
    }

    if (handleConversationCommand(answer)) {
      return Promise.resolve();
    }

    wizard.errors = [];
    const result = applyConversationAnswer(question.id, answer, submitOptions);
    wizard.intake.history.push({
      role: "user",
      questionId: question.id,
      text: historyText || answer,
    });
    wizard.intake.draftAnswer = "";
    wizard.intake.customAnswerOpen = false;

    if (!result.ok) {
      wizard.errors = [result.error];
      wizard.intake.history.push({
        role: "assistant",
        questionId: question.id,
        tone: "warning",
        text: result.error,
      });
      renderWizard();
      return Promise.resolve();
    }

    wizard.intake.history.push({
      role: "assistant",
      questionId: question.id,
      text: result.message,
    });
    wizard.intake.reviewQuestionId = null;
    syncConversationMetadataFromData();
    ensureConversationDefaults();
    wizard.intake.activeQuestionId = recommendedQuestionId(wizard);
    wizard.errors = transitionValidationErrorsForQuestion(wizard, wizard.intake.activeQuestionId);
    renderWizard();
    return Promise.resolve();
  }

  function goBackConversation() {
    const previousUserTurn = [...state.wizard.intake.history]
      .reverse()
      .find((turn) => turn.role === "user" && turn.questionId);
    if (!previousUserTurn) return;
    focusQuestion(resolveConversationTopicQuestionId(previousUserTurn.questionId));
  }

  function focusQuestion(questionId) {
    if (!questionId) return;
    state.wizard.intake.activeQuestionId = questionId;
    state.wizard.intake.reviewQuestionId = questionId;
    state.wizard.intake.draftAnswer = draftAnswerForQuestion(questionId);
    state.wizard.intake.customAnswerOpen =
      questionId === "intent" && Boolean(state.wizard.intake.draftAnswer);
    state.wizard.errors = validationErrorsForQuestion(state.wizard, questionId);
    renderWizard();
  }

  function restartConversation() {
    state.wizard = buildEmptyWizardState();
    renderWizard();
  }

  function hasConversationHistory() {
    return state.wizard.intake.history.some((turn) => turn.role === "user");
  }

  function resolveConversationTopicQuestionId(questionId) {
    if (questionId !== "auth") return questionId;
    const preferredQuestionId = preferredAuthRevisionQuestionId(state.wizard.data);
    const accessTurn = [...state.wizard.intake.history]
      .reverse()
      .find((turn) => turn.role === "user" && ["auth", "auth-details"].includes(turn.questionId));
    if (accessTurn?.questionId && accessTurn.questionId !== preferredQuestionId) {
      return preferredQuestionId;
    }
    if (accessTurn?.questionId) {
      return accessTurn.questionId;
    }
    return preferredQuestionId;
  }

  function buildQuestion(questionId, estimate) {
    const wizard = state.wizard;
    const assessmentType = wizard.data.assessment_type;
    const goal = wizard.data.intake_preferences.primary_goal;
    const questionMap = {
      intent: {
        id: "intent",
        badge: "Assessment",
        title: "Assessment types",
        prompt: "",
        placeholder: "Example: My LAN network, our customer portal, our public API, our external domain",
        quickReplies: [],
        multiline: false,
        allowSubmission: true,
      },
      goal: {
        id: "goal",
        badge: "Depth",
        title: "What is your main goal for this assessment?",
        prompt: "How deep should we go? This depth choice replaces the old open-ended main goal step and sets the run profile, safety posture, and likely follow-up path.",
        placeholder: "Example: Inventory first, a standard assessment, deep validation, authenticated review, or adaptive customer-specific testing",
        quickReplies: goalQuickRepliesForAssessment(assessmentType),
        multiline: false,
        allowSubmission: true,
      },
      output: {
        id: "output",
        badge: "Output",
        title: "What reporting style should I use?",
        prompt: "This changes only the mission handoff and reporting preference. It does not change scope, safety, or execution lane.",
        placeholder: "Example: Detailed per item, balanced technical, technical detail, or executive summary",
        quickReplies: ["Detailed per item", "Balanced technical", "Technical detail", "Executive summary"],
        multiline: false,
        allowSubmission: true,
      },
      scope: {
        id: "scope",
        badge: "Scope",
        title: scopeQuestionTitle(assessmentType),
        prompt: scopeQuestionPrompt(assessmentType),
        guidance: "Only include explicitly authorized targets. I will not broaden scope from vague phrases like “look around” or “scan anything public”.",
        placeholder: scopePlaceholder(assessmentType),
        quickReplies: scopeQuickRepliesForAssessment(assessmentType),
        multiline: true,
        allowSubmission: true,
      },
      auth: {
        id: "auth",
        badge: "Access",
        title: "Should this stay unauthenticated, or do you have access I should use?",
        prompt: "If you already know this should stay unauthenticated, say so. If you have accounts, tokens, or sessions, I can prepare for them now and you can add the details in Advanced Configuration.",
        placeholder: "Example: Keep it unauthenticated, I have a portal account, I have API keys, or I will add credentials in advanced settings",
        quickReplies: ["Keep it unauthenticated", "I have portal/app accounts", "I have API tokens or keys", "I will add access in advanced settings"],
        multiline: false,
        allowSubmission: true,
      },
      "auth-details": {
        id: "auth-details",
        badge: "Access Detail",
        title: "What access context should I record?",
        prompt: "You can paste a username, role, token reference, or session reference. Keep it concise if you want to finish quickly, use Advanced Configuration for full detail, or say that access should be withdrawn if you want to remove authenticated context.",
        placeholder: "Example: analyst@example.com role Analyst secret vault://prod/app/user or api-key vault://prod/api/key",
        quickReplies: ["I will add the full details in advanced settings"],
        multiline: true,
        allowSubmission: true,
      },
      safety: {
        id: "safety",
        badge: "Safety",
        title: "Should I keep this conservative or more thorough?",
        prompt: "I will explain any change that makes the run more invasive before I enable it.",
        recommendation: goal === "inventory-first"
          ? "I recommend a conservative posture because you asked for visibility first."
          : (goal === "deep-assessment" ? "I recommend a balanced but guarded posture unless you explicitly want active validation." : ""),
        placeholder: "Example: Conservative, balanced, thorough, passive only, or aggressive with approval",
        quickReplies: ["Conservative", "Balanced", "Thorough", "Passive only", "Aggressive with approval"],
        multiline: false,
        allowSubmission: true,
      },
      boundaries: boundaryQuestionConfig(assessmentType),
      confirm: {
        id: "confirm",
        badge: "Confirm",
        title: "I have enough to prepare the mission.",
        prompt: buildNaturalConfirmationSummary(estimate),
        guidance: "Confirm to create the engagement and run, revise any topic, or open Advanced Configuration for the full deterministic controls.",
        quickReplies: [],
        multiline: false,
        allowSubmission: false,
      },
    };
    return questionMap[questionId] || questionMap.intent;
  }

function isInternalRangeAssessment(assessmentType) {
  return String(assessmentType || "").trim() === "Internal Range / LAN";
}

function boundaryQuestionConfig(assessmentType) {
  if (isInternalRangeAssessment(assessmentType)) {
    return {
      id: "boundaries",
      badge: "Boundaries",
      title: "Any targets, systems, or internal edges to exclude?",
      prompt: "Use this for exclusions, sensitive internal systems, or how to handle adjacent ranges if they become visible. Are there systems, behaviors, or internal edges I must avoid or handle carefully?",
      guidance: "For internal expansion I stay inside your configured scope. I can report adjacent reachable ranges, but I do not scan newly discovered ranges without explicit authorization.",
      placeholder: "Example: Avoid 10.0.20.10, report adjacent internal ranges only, do not touch production payment hosts",
      quickReplies: ["No extra exclusions", "Report adjacent internal ranges only", "I need custom exclusions"],
      multiline: true,
      allowSubmission: true,
    };
  }

  return {
    id: "boundaries",
    badge: "Boundaries",
    title: "Any targets or flows to exclude?",
    prompt: "Use this for exclusions, sensitive workflows, maintenance windows, or any scope notes that must stay explicit. Are there systems, behaviors, or boundaries I must avoid or handle carefully?",
    guidance: "I stay inside the exact approved scope. I do not broaden coverage, change target classes, or expand into related systems without explicit authorization.",
    placeholder: "Example: Avoid billing flows, do not touch production payment hosts, no after-hours testing",
    quickReplies: ["No extra exclusions", "I need custom exclusions"],
    multiline: true,
    allowSubmission: true,
  };
}

function boundaryNotesIntro(assessmentType) {
  if (isInternalRangeAssessment(assessmentType)) {
    return "Use these fields when the engagement has explicit denylist targets or when internal range handling needs notes that should stay visible in the run configuration and report scope snapshot.";
  }
  return "Use these fields when the engagement has explicit denylist targets or when scope assumptions and sensitive flows need notes that should stay visible in the run configuration and report scope snapshot.";
}

function boundaryNotesPlaceholder(assessmentType) {
  if (isInternalRangeAssessment(assessmentType)) {
    return "Report adjacent internal ranges only, avoid production payment hosts, no after-hours testing";
  }
  return "Avoid billing flows, do not touch production payment hosts, no after-hours testing";
}

function goalQuickRepliesForAssessment(assessmentType) {
  if (assessmentType === "Internal Range / LAN") {
    return ["Inventory first", "Visibility with clear per-item detail", "Standard internal assessment", "Deep internal validation"];
  }
  if (assessmentType === "External IP / WAN") {
    return [
      "Quick perimeter overview",
      "Inventory first",
      "Perimeter review",
      "Deep follow-up after discovery",
      "Adaptive follow-up after discovery",
    ];
  }
  if (assessmentType === "Authenticated App") {
    return ["Authenticated review", "Standard assessment", "Deep assessment", "Inventory first"];
  }
    if (assessmentType === "API") {
      return ["Inventory first", "Authenticated API review", "Deep API assessment", "Adaptive customer-specific testing"];
    }
    if (assessmentType === "SSL/TLS Only") {
      return ["Quick overview", "Standard assessment"];
    }
    return ["Quick overview", "Inventory first", "Standard assessment", "Deep assessment", "Adaptive customer-specific testing"];
  }

  function scopeQuestionTitle(assessmentType) {
    if (assessmentType === "Internal Range / LAN") return "What exact CIDR range or internal hosts may I use?";
    if (assessmentType === "External IP / WAN") return "What exact IPs or CIDR ranges are authorized?";
    if (assessmentType === "API") return "What API base URLs or application URLs may I use?";
    if (assessmentType === "SSL/TLS Only") return "What hostnames, URLs, or IPs should I validate for TLS only?";
    return "What exact targets are authorized for this assessment?";
  }

  function scopeQuestionPrompt(assessmentType) {
    if (assessmentType === "Internal Range / LAN") {
      return "Enter one or more approved internal CIDRs or hosts. I will keep discovery inside that scope and only report adjacent ranges unless you later authorize more.";
    }
    if (assessmentType === "API") {
      return "Enter the approved API base URLs or related application URLs. I will classify them into API and application scope automatically where possible.";
    }
    return "Enter the exact authorized domains, URLs, IPs, or CIDRs that belong in scope.";
  }

  function scopePlaceholder(assessmentType) {
    if (assessmentType === "Internal Range / LAN") return "Example: 10.0.20.0/24";
    if (assessmentType === "API") return "Example: https://api.example.com/v1";
    if (assessmentType === "External IP / WAN") return "Example: 203.0.113.10 or 203.0.113.0/28";
    return "Example: https://portal.example.com or app.example.com";
  }

  function operatorSettingValue(key) {
    const sections = Array.isArray(state.operatorSettings?.sections) ? state.operatorSettings.sections : [];
    for (const section of sections) {
      const settings = Array.isArray(section?.settings) ? section.settings : [];
      const match = settings.find((setting) => String(setting?.key || "") === String(key || ""));
      if (match) {
        return match.value;
      }
    }
    return null;
  }

  function scopeQuickRepliesForAssessment(assessmentType) {
    if (assessmentType !== "Internal Range / LAN") return [];
    const lanCidr = String(operatorSettingValue("network.default_lan_cidr") || "").trim();
    const vlanValue = operatorSettingValue("network.default_vlan_cidrs");
    const vlanCidrs = Array.isArray(vlanValue) ? vlanValue : [];
    return [lanCidr, ...vlanCidrs.map((item) => String(item || "").trim())]
      .filter(Boolean)
      .slice(0, 4);
  }

  function recommendedQuestionId(wizard) {
    const orderedQuestions = activeOrderedQuestions(wizard);
    for (const questionId of orderedQuestions) {
      if (questionStillNeedsInput(wizard, questionId)) return questionId;
    }
    if (wizard.intake.flowMode === "legacy" && questionStillNeedsInput(wizard, "safety")) {
      return "safety";
    }
    return "confirm";
  }

  function buildSummaryBuckets(wizard, estimate) {
    const data = wizard.data;
    const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
    const goalLabel = wizard.intake.flowMode === "tile" ? "Depth" : "Goal";
    const scopeLabel = wizard.intake.flowMode === "tile" ? "Target" : "Scope";
    const engagementRoute = currentEngagementRouteContext(data);
    const deferAccessUntilRelevant =
      wizard.intake.sources.intent === "still-needed" &&
      wizard.intake.sources.auth === "still-needed" &&
      !shouldAskAuthQuestion(data) &&
      !String(data.intake_preferences.auth_strategy || "").trim() &&
      !hasMeaningfulAccessContext(data.access) &&
      !wizard.intake.overrides.access;
    const deferOutputUntilGoalContext =
      questionStillNeedsInput(wizard, "goal") &&
      wizard.intake.sources.output === "inferred" &&
      !wizard.intake.overrides.profile &&
      !wizard.intake.overrides.modules &&
      !wizard.intake.overrides.safety;
    const effectiveGoalSource = questionStillNeedsInput(wizard, "goal") ? "still-needed" : wizard.intake.sources.goal;
    const effectiveScopeSource = questionStillNeedsInput(wizard, "scope") ? "still-needed" : wizard.intake.sources.scope;
    const effectiveAccessSource =
      deferAccessUntilRelevant
        ? "deferred"
        : questionStillNeedsInput(wizard, "auth") || questionStillNeedsInput(wizard, "auth-details")
        ? "still-needed"
        : wizard.intake.sources.auth;
    const effectiveSafetySource = questionStillNeedsInput(wizard, "safety")
      ? "still-needed"
      : wizard.intake.sources.safety;
    const effectiveBoundarySource = questionStillNeedsInput(wizard, "boundaries")
      ? "still-needed"
      : wizard.intake.sources.boundaries;
    const effectiveOutputSource = deferOutputUntilGoalContext
      ? "deferred"
      : wizard.intake.sources.output;
    const confirmed = [];
    const inferred = [];
    const stillNeeded = [];
    const stillNeededDetails = [];
    const addToBucket = (source, label, value, stillNeededDetail = null) => {
      if (!value) return;
      if (source === "deferred") return;
      if (source === "confirmed" || source === "override") {
        confirmed.push(`${label}: ${value}${source === "override" ? " (advanced override)" : ""}`);
      } else if (source === "inferred") {
        inferred.push(`${label}: ${value}`);
      } else {
        stillNeeded.push(label);
        if (stillNeededDetail) stillNeededDetails.push(stillNeededDetail);
      }
    };

    if (engagementRoute.mode === "reuse-selected-engagement") {
      confirmed.push(`Engagement Route: ${engagementRoute.summaryLabel}`);
    }
    addToBucket(wizard.intake.sources.target_type, "Target Type", data.assessment_type, {
      key: "target-type",
      label: "Target Type",
      questionId: "intent",
    });
    if (String(data.assessment_mode?.mode || "").trim()) {
      confirmed.push(
        `Assessment Mode: ${humanizeAssessmentMode(data.assessment_mode.mode)}${
          effectiveAssessmentModeAutoAdvance(data)
            ? " · auto-advance enabled"
            : " · boundary approvals only"
        } · ${authorizationOption(selectedAuthorizationLevel(data)).label.toLowerCase()} authorization`
      );
    }
    addToBucket(effectiveGoalSource, goalLabel, humanizeGoal(data.intake_preferences.primary_goal), {
      key: "goal",
      label: goalLabel,
      questionId: "goal",
    });
    addToBucket(effectiveScopeSource, scopeLabel, renderTargetSummary(data.targets), {
      key: "scope",
      label: scopeLabel,
      questionId: "scope",
    });
    const accessStillNeededDetail =
      data.intake_preferences.auth_strategy === "advanced-details" &&
      !hasMeaningfulAccessContext(data.access)
        ? {
            key: "access",
            label: "Access",
            action: "advanced",
            advancedStep: 2,
          }
        : {
            key: "access",
            label: "Access",
            questionId: "auth",
          };
    addToBucket(effectiveAccessSource, "Access", summarizeAuthStrategy(data), accessStillNeededDetail);
    addToBucket(
      effectiveSafetySource,
      "Safety",
      `${humanizeSafetyPosture(data.intake_preferences.safety_posture)} · ${humanizeCheckMode(data.safety.active_checks)}`,
      {
        key: "safety",
        label: "Safety",
        questionId: "safety",
      }
    );
    addToBucket(effectiveBoundarySource, "Boundaries", summarizeBoundaries(data), {
      key: "boundaries",
      label: "Boundaries",
      questionId: "boundaries",
    });
    addToBucket(effectiveOutputSource, "Output", humanizeOutputStyle(data.intake_preferences.output_style), {
      key: "output",
      label: "Output",
      questionId: "output",
    });

    if (!data.engagement_name) {
      stillNeeded.push("Mission record name");
      stillNeededDetails.push({
        key: "mission-record-name",
        label: "Mission record name",
        action: "advanced",
        advancedStep: 0,
      });
    }

    return {
      confirmed,
      inferred,
      stillNeeded,
      stillNeededDetails,
      plan,
    };
  }

  function applyConversationAnswer(questionId, answer, submitOptions = {}) {
    const normalized = String(answer || "").trim();
    if (questionId === "intent") return applyIntentAnswer(normalized, submitOptions);
    if (questionId === "goal") return applyGoalAnswer(normalized, submitOptions);
    if (questionId === "output") return applyOutputAnswer(normalized);
    if (questionId === "scope") return applyScopeAnswer(normalized);
    if (questionId === "auth") return applyAuthAnswer(normalized);
    if (questionId === "auth-details") return applyAuthDetailsAnswer(normalized);
    if (questionId === "safety") return applySafetyAnswer(normalized);
    if (questionId === "boundaries") return applyBoundariesAnswer(normalized);
    return { ok: true, message: "Understood." };
  }

  function applyIntentAnswer(answer, submitOptions = {}) {
    const wizard = state.wizard;
    const previousNameContext = snapshotEngagementNameContext(wizard.data);
    let inferredGoal = null;
    wizard.data.intake_preferences.mission_intent = answer;
    wizard.intake.sources.intent = "confirmed";

    const selectedTileKeysValue = normalizeAssessmentTileKeys(submitOptions.selectedTileKeys || []);
    const selectedTileKey = String(submitOptions.tileKey || primaryAssessmentTileKey(selectedTileKeysValue)).trim();
    const selectedTile = assessmentTileByKey(selectedTileKey);
    const inferredType = selectedTile?.assessmentType || inferAssessmentType(answer);
    if (selectedTile) {
      wizard.intake.flowMode = "tile";
      wizard.intake.selectedAssessmentTileKey = selectedTile.key;
      wizard.intake.selectedAssessmentTileKeys = selectedTileKeysValue.length ? selectedTileKeysValue : [selectedTile.key];
    } else if (submitOptions.flowMode === "tile") {
      wizard.intake.flowMode = "tile";
    } else {
      wizard.intake.flowMode = "legacy";
      wizard.intake.selectedAssessmentTileKey = deriveAssessmentTileKey(wizard.data, wizard.intake);
      wizard.intake.selectedAssessmentTileKeys = [];
    }

    if (inferredType) {
      wizard.data.assessment_type = inferredType;
      if (!wizard.intake.overrides.profile && !wizard.intake.overrides.modules && !wizard.intake.overrides.safety) {
        applyAssessmentTypePreset(inferredType);
      }
      wizard.intake.sources.target_type = "confirmed";
    }

    if (!selectedTile) {
      inferredGoal = inferPrimaryGoal(answer);
      if (inferredGoal) {
        setGoalRecommendation(inferredGoal, "confirmed");
      }

      const outputStyle = inferOutputStyle(answer);
      if (outputStyle) {
        wizard.data.intake_preferences.output_style = outputStyle;
        wizard.intake.sources.output = "confirmed";
      }

      const authStrategy = inferAuthStrategy(answer);
      if (authStrategy) {
        wizard.data.intake_preferences.auth_strategy = authStrategy;
        wizard.intake.sources.auth = "confirmed";
      }

      const lateral = inferLateralDiscovery(answer);
      if (lateral) {
        wizard.data.intake_preferences.lateral_discovery = lateral;
        wizard.data.intake_preferences.boundary_handling = "";
        wizard.intake.sources.boundaries = "still-needed";
      }
      wizard.intake.selectedAssessmentTileKey = deriveAssessmentTileKey(wizard.data, wizard.intake);
      wizard.intake.selectedAssessmentTileKeys = normalizeAssessmentTileKeys([wizard.intake.selectedAssessmentTileKey]);
    } else {
      wizard.data.intake_preferences.primary_goal = "";
      wizard.data.intake_preferences.safety_posture = "";
      wizard.intake.sources.safety = "still-needed";
      wizard.intake.sources.goal = "still-needed";
      wizard.intake.sources.scope = "still-needed";
      wizard.intake.sources.boundaries = "still-needed";
    }

    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, wizard.data);
    return {
      ok: true,
      message: `Understood. I am preparing a ${wizard.data.assessment_type.toLowerCase()} intake${inferredGoal ? ` with a ${humanizeGoal(inferredGoal).toLowerCase()} goal` : ""}.`,
    };
  }

  function applyGoalAnswer(answer, submitOptions = {}) {
    const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
    const currentTile = selectedAssessmentTile(state.wizard);
    const goal =
      inferPrimaryGoal(answer) ||
      inferGoalFromDepthAnswer(answer, state.wizard.data.assessment_type, currentTile?.key || "");
    if (!goal) {
      return {
        ok: false,
        error: "Choose a depth such as Passive only, Active scan, or Full including exploitation, or enter a custom mission goal.",
      };
    }
    const compatibility = setGoalRecommendation(goal, "confirmed");
    const depthChoice = String(submitOptions.depthChoice || depthChoiceKeyForGoal(goal)).trim();
    const depthSafety =
      String(submitOptions.depthSafety || "").trim() ||
      depthChoiceOptions(state.wizard.data.assessment_type, currentTile?.key || "").find((option) => option.key === depthChoice)?.safetyPosture ||
      "";
    const outputStyle = inferOutputStyle(answer);
    if (outputStyle) {
      state.wizard.data.intake_preferences.output_style = outputStyle;
      state.wizard.intake.sources.output = "confirmed";
    }
    if (state.wizard.intake.flowMode === "tile" && !state.wizard.intake.overrides.safety) {
      const safetyPosture = depthSafety || (goal === "internal-validation" ? "thorough" : "balanced");
      state.wizard.data.intake_preferences.safety_posture = safetyPosture;
      applySafetyPreference(safetyPosture);
      enforceDiscoveryFirstSafetyGuardrails(state.wizard.data);
      state.wizard.intake.sources.safety = "confirmed";
    }
    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
    return {
      ok: true,
      message: compatibility.changed && compatibility.reason
        ? compatibility.reason
        : `I will shape this as a ${humanizeGoal(goal).toLowerCase()} and keep the execution lane aligned with that intent.`,
    };
  }

  function applyOutputAnswer(answer) {
    const outputStyle = inferOutputStyle(answer);
    if (!outputStyle) {
      return {
        ok: false,
        error: "Tell me whether you want detailed per-item, balanced technical, technical detail, or executive-summary output.",
      };
    }
    state.wizard.data.intake_preferences.output_style = outputStyle;
    state.wizard.intake.sources.output = "confirmed";
    return {
      ok: true,
      message: `I will use ${humanizeOutputStyle(outputStyle).toLowerCase()} reporting for this mission.`,
    };
  }

  function applyScopeAnswer(answer) {
    const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
    const previousAssessmentType = state.wizard.data.assessment_type;
    const previousBoundaryRequirement = requiresExplicitBoundaryConfirmation(state.wizard.data);
    const previousBoundaryHandling = effectiveBoundaryHandling(state.wizard.data);
    const previousLateralDiscovery = state.wizard.data.intake_preferences.lateral_discovery;
    const previousHasExplicitBoundaryScope =
      countExplicitExclusions(state.wizard.data.exclusions || {}) > 0 ||
      hasBoundaryNotes(state.wizard.data.exclusions || {});
    if (containsUnauthorizedExpansion(answer)) {
      return {
        ok: false,
        error: "I need exact authorized targets. I will not expand to arbitrary public scope or “anything reachable” without explicit approved targets.",
      };
    }

    const parsed = parseTargetsFromText(answer);
    if (!flattenTargetValues(parsed).length) {
      return {
        ok: false,
        error: "I could not find a valid URL, domain, IP, CIDR, or API base URL in that answer. Please enter the exact approved targets.",
      };
    }

    state.wizard.data.targets = parsed;
    const inferredType = inferAssessmentTypeFromTargets(parsed);
    if (inferredType) {
      const changedType = inferredType !== state.wizard.data.assessment_type;
      if (changedType && !shouldPreserveAssessmentType(state.wizard.data.assessment_type, inferredType)) {
        state.wizard.data.assessment_type = inferredType;
        if (!state.wizard.intake.overrides.profile && !state.wizard.intake.overrides.modules && !state.wizard.intake.overrides.safety) {
          applyAssessmentTypePreset(inferredType);
        }
      }
      state.wizard.intake.sources.target_type = state.wizard.intake.sources.target_type === "still-needed" ? "inferred" : state.wizard.intake.sources.target_type;
    }
    const compatibility = reconcileGoalCompatibility("inferred");
    if (
      inferredType &&
      !state.wizard.intake.overrides.profile &&
      !state.wizard.intake.overrides.modules &&
      !state.wizard.intake.overrides.safety
    ) {
      applyGoalDrivenPlanDefaults();
    }
    resetBoundaryConfirmationAfterScopeChange({
      previousAssessmentType,
      previousBoundaryRequirement,
      previousBoundaryHandling,
      previousLateralDiscovery,
      previousHasExplicitBoundaryScope,
    });
    state.wizard.intake.selectedAssessmentTileKey = deriveAssessmentTileKey(state.wizard.data, state.wizard.intake);
    if (!selectedAssessmentTileKeys(state.wizard).length) {
      state.wizard.intake.selectedAssessmentTileKeys = normalizeAssessmentTileKeys([state.wizard.intake.selectedAssessmentTileKey]);
    }
    state.wizard.intake.sources.scope = "confirmed";
    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
    return {
      ok: true,
      message: compatibility.changed && compatibility.reason
        ? `Scope recorded as ${renderTargetSummary(state.wizard.data.targets)}. ${compatibility.reason}`
        : `Scope recorded as ${renderTargetSummary(state.wizard.data.targets)}.`,
    };
  }

  function applyAuthAnswer(answer) {
    const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
    const strategy = inferAuthStrategy(answer);
    if (!strategy) {
      return {
        ok: false,
        error: "Tell me whether this should stay unauthenticated, whether you have accounts, whether you have API keys/tokens, or whether you will add access in advanced settings.",
      };
    }
    state.wizard.data.intake_preferences.auth_strategy = strategy;
    state.wizard.intake.sources.auth = "confirmed";
    if (strategy === "unauthenticated") {
      clearAccessContext();
      const downgraded = alignPlanForUnauthenticatedAccess();
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
      return {
        ok: true,
        message: downgraded
          ? "I will keep the assessment unauthenticated, clear the prior access context, and downgrade the mission to a compatible unauthenticated plan unless you add access later."
          : "I will keep the assessment unauthenticated unless you change that later.",
      };
    }
    if (strategy === "advanced-details") {
      const compatibility = reconcileGoalCompatibility("inferred");
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
      return {
        ok: true,
        message: compatibility.changed && compatibility.reason
          ? `${compatibility.reason} Add the account, token, or session details in Advanced Configuration and I will keep the conversational summary synchronized.`
          : "Understood. Add the account, token, or session details in Advanced Configuration and I will keep the conversational summary synchronized.",
      };
    }
    const compatibility = reconcileGoalCompatibility("inferred");
    state.wizard.intake.activeQuestionId = "auth-details";
    refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
    return {
      ok: true,
      message: compatibility.changed && compatibility.reason
        ? `${compatibility.reason} I will capture the access context next so the run and replay lane know what to use.`
        : "Understood. I will capture the access context next so the run and replay lane know what to use.",
    };
  }

  function applyAuthDetailsAnswer(answer) {
    const strategy = inferAuthStrategy(answer);
    // At the detail step, only a true withdrawal back to unauthenticated should
    // bypass detail parsing. Token/session keywords may legitimately appear
    // inside the secret reference itself (for example `vault://.../updated-token`).
    if (strategy === "unauthenticated") {
      return applyAuthAnswer(answer);
    }

    if (/advanced settings/i.test(answer)) {
      state.wizard.data.intake_preferences.auth_strategy = "advanced-details";
      state.wizard.intake.advancedOpen = true;
      state.wizard.advancedStep = 2;
      return {
        ok: true,
        message: "Understood. I opened Advanced Configuration on Access so you can add the required detail before confirmation.",
      };
    }

    const existingAccess = state.wizard.data.access || {};
    const meaningfulAccounts = (existingAccess.accounts || []).filter((account) =>
      hasMeaningfulAccount([account]),
    );
    const sharedManualOnlyRoute =
      !meaningfulAccounts.length &&
      String(state.wizard.data.intake_preferences.auth_strategy || "").trim() === "credentialed" &&
      stringValue(existingAccess.manual_auth_steps);
    const sharedSessionOnlyRoute =
      !meaningfulAccounts.length &&
      String(state.wizard.data.intake_preferences.auth_strategy || "").trim() === "session-access" &&
      stringValue(existingAccess.cookie_notes);
    const noteOnlyRevisionAnswer = !looksLikeStructuredAccessDetail(answer);
    if (sharedManualOnlyRoute && noteOnlyRevisionAnswer) {
      state.wizard.data.access.accounts = [];
      state.wizard.data.access.manual_auth_steps = stringValue(answer);
      state.wizard.data.access.cookie_notes = "";
      state.wizard.intake.sources.auth = "confirmed";
      const compatibility = reconcileGoalCompatibility("inferred");
      return {
        ok: true,
        message: compatibility.changed && compatibility.reason
          ? `Shared manual auth guidance updated. ${compatibility.reason}`
          : "Shared manual auth guidance updated.",
      };
    }
    if (sharedSessionOnlyRoute && noteOnlyRevisionAnswer) {
      state.wizard.data.access.accounts = [];
      state.wizard.data.access.manual_auth_steps = "";
      state.wizard.data.access.cookie_notes = stringValue(answer);
      state.wizard.intake.sources.auth = "confirmed";
      const compatibility = reconcileGoalCompatibility("inferred");
      return {
        ok: true,
        message: compatibility.changed && compatibility.reason
          ? `Shared session guidance updated. ${compatibility.reason}`
          : "Shared session guidance updated.",
      };
    }
    const account = buildAccountFromFreeText(answer);
    if (!hasMeaningfulAccount([account])) {
      return {
        ok: false,
        error: "I still need at least a username, token reference, session reference, or password reference for an authenticated run.",
      };
    }
    state.wizard.data.access.accounts = [account];
    state.wizard.data.intake_preferences.auth_strategy =
      account.api_key_ref || account.bearer_token_ref
        ? "api-access"
        : account.session_ref
          ? "session-access"
          : "credentialed";
    state.wizard.intake.sources.auth = "confirmed";
    const compatibility = reconcileGoalCompatibility("inferred");
    return {
      ok: true,
      message: compatibility.changed && compatibility.reason
        ? `Access context recorded for ${account.label || account.username || "the provided account"}. ${compatibility.reason}`
        : `Access context recorded for ${account.label || account.username || "the provided account"}.`,
    };
  }

function applySafetyAnswer(answer) {
  const repeatedAuthStrategy = inferAuthStrategy(answer);
  if (repeatedAuthStrategy) {
    const currentAuthStrategy = String(state.wizard.data.intake_preferences.auth_strategy || "").trim();
    const currentAccessSummary =
      currentAuthStrategy === "unauthenticated"
        ? "unauthenticated"
        : summarizeAuthStrategy(state.wizard.data).toLowerCase();
    return {
      ok: false,
      error:
        repeatedAuthStrategy === currentAuthStrategy
          ? `Access is already set to ${currentAccessSummary}. Next I need a safety choice such as Conservative, Balanced, Thorough, Passive only, or Aggressive with approval.`
          : "That answer changes access, but the current question is about safety. Use Change Access if you want to revise access, or answer Conservative, Balanced, Thorough, Passive only, or Aggressive with approval.",
    };
  }
  const posture = inferSafetyPosture(answer);
  if (!posture) {
    return {
      ok: false,
        error: "Tell me whether this should stay conservative, balanced, thorough, passive only, or aggressive with approval.",
      };
    }
    state.wizard.data.intake_preferences.safety_posture = posture;
    applySafetyPreference(posture);
    enforceDiscoveryFirstSafetyGuardrails(state.wizard.data);
    state.wizard.intake.sources.safety = "confirmed";
    const stagedDiscoveryPlan = stagedDiscoveryCompatibility(state.wizard.data);
    return {
      ok: true,
      message: posture === "aggressive"
        ? "I will mark this as an approval-aware aggressive posture. Active checks still remain bounded by the configured lane and authorized scope."
        : stagedDiscoveryPlan?.profile === "External Surface Only"
          ? `I will keep the perimeter discovery run ${humanizeSafetyPosture(posture).toLowerCase()} while the first run remains passive discovery only.`
        : `I will keep the run ${humanizeSafetyPosture(posture).toLowerCase()}.`,
    };
  }

  function applyBoundariesAnswer(answer) {
    const repeatedAuthStrategy = inferAuthStrategy(answer);
    if (repeatedAuthStrategy) {
      const currentAuthStrategy = String(state.wizard.data.intake_preferences.auth_strategy || "").trim();
      const currentAccessSummary =
        currentAuthStrategy === "unauthenticated"
          ? "unauthenticated"
          : summarizeAuthStrategy(state.wizard.data).toLowerCase();
      const boundaryGuidance = summarizeBoundaryReplyOptions(state.wizard.data.assessment_type);
      return {
        ok: false,
        error:
          repeatedAuthStrategy === currentAuthStrategy
            ? `Access is already set to ${currentAccessSummary}. Next I need boundary guidance such as ${boundaryGuidance}.`
            : `That answer changes access, but the current question is about boundaries. Use Change Access if you want to revise access, or answer ${boundaryGuidance}.`,
      };
    }

    const repeatedSafety = inferStandaloneSafetyAnswer(answer);
    if (repeatedSafety) {
      const currentSafety = String(state.wizard.data.intake_preferences.safety_posture || "").trim();
      const boundaryGuidance = summarizeBoundaryReplyOptions(state.wizard.data.assessment_type);
      return {
        ok: false,
        error:
          repeatedSafety === currentSafety
            ? `Safety is already set to ${humanizeSafetyPosture(repeatedSafety).toLowerCase()}. Next I need boundary guidance such as ${boundaryGuidance}.`
            : `That answer changes safety, but the current question is about boundaries. Use Change Safety if you want to revise safety, or answer ${boundaryGuidance}.`,
      };
    }

    if (/no extra exclusions|no exclusions|nothing extra/i.test(answer)) {
      state.wizard.data.exclusions = buildEmptyExclusions();
      state.wizard.data.intake_preferences.boundary_handling = "standard-scope-only";
      state.wizard.data.intake_preferences.lateral_discovery = "not-requested";
      state.wizard.intake.sources.boundaries = "confirmed";
      return {
        ok: true,
        message: "Understood. I will keep the mission inside the exact approved scope with no extra exclusions.",
      };
    }

    if (/adjacent internal|report adjacent|reachable internal ranges|lateral/i.test(answer)) {
      state.wizard.data.exclusions = buildEmptyExclusions();
      state.wizard.data.intake_preferences.boundary_handling = "report-adjacent-ranges-only";
      state.wizard.data.intake_preferences.lateral_discovery = "report-only";
      state.wizard.intake.sources.boundaries = "confirmed";
      return {
        ok: true,
        message: "Understood. I will keep discovery inside the approved scope and only report adjacent reachable internal ranges for explicit follow-up approval.",
      };
    }

    const exclusions = parseTargetsFromText(answer);
    const hasStructuredExclusions = flattenTargetValues(exclusions).length > 0;
    state.wizard.data.exclusions = {
      ...buildEmptyExclusions(),
      ...exclusions,
      notes: answer,
    };
    state.wizard.data.intake_preferences.boundary_handling = hasStructuredExclusions ? "custom-exclusions" : "notes-only-boundaries";
    state.wizard.data.intake_preferences.lateral_discovery = "not-requested";
    state.wizard.intake.sources.boundaries = "confirmed";
    return {
      ok: true,
      message: hasStructuredExclusions
        ? "Understood. I recorded structured exclusions and boundary notes."
        : "Understood. I recorded those boundary notes for confirmation and reporting context.",
    };
  }

  function parseConversationCommand(answer) {
    const normalized = String(answer || "").trim().toLowerCase().replace(/\s+/g, " ");
    const cleaned = normalized.replace(/[.!?]+$/g, "").trim();
    const politeTrimmed = cleaned
      .replace(/^please\s+/, "")
      .replace(/\s+please$/, "")
      .trim();

    if (["go back", "undo", "previous", "change that"].includes(politeTrimmed)) {
      return { type: "back" };
    }

    const revisionMatch = politeTrimmed.match(/^(change|edit|revise)\s+([a-z -]+)$/);
    if (!revisionMatch) return null;

    const target = revisionMatch[2].trim();
    const targetGroups = [
      ["scope", ["scope", "target", "targets"]],
      ["goal", ["goal", "depth", "profile"]],
      ["output", ["output", "output style", "reporting", "reporting style", "report", "report style", "format"]],
      ["auth", ["access", "auth", "credential", "credentials", "token", "tokens", "session", "sessions"]],
      ["safety", ["safety", "careful", "conservative", "aggressive", "thorough"]],
      ["boundaries", ["exclude", "excludes", "exclusion", "exclusions", "boundary", "boundaries", "avoid", "lateral"]],
    ];
    const matchedGroup = targetGroups.find(([, aliases]) => aliases.includes(target));
    if (!matchedGroup) return null;

    return { type: "focus", questionId: matchedGroup[0] };
  }

  function handleConversationCommand(answer) {
    const command = parseConversationCommand(answer);
    if (!command) return false;
    if (command.type === "back") {
      goBackConversation();
      return true;
    }
    if (command.type === "focus") {
      focusQuestion(resolveConversationTopicQuestionId(command.questionId));
      return true;
    }
    return false;
  }

  function markAdvancedOverrideForStep(step) {
    const overrides = state.wizard.intake.overrides;
    if (step === 0) {
      overrides.mission = true;
      overrides.assessment_type = true;
      state.wizard.intake.sources.intent = "override";
      state.wizard.intake.sources.target_type = "override";
    } else if (step === 1) {
      overrides.scope = true;
      overrides.boundaries = true;
      state.wizard.intake.sources.scope = "override";
      state.wizard.intake.sources.boundaries = "override";
    } else if (step === 2) {
      overrides.access = true;
      state.wizard.intake.sources.auth = "override";
    } else if (step === 3) {
      overrides.profile = true;
      state.wizard.intake.sources.goal = "override";
    } else if (step === 4) {
      overrides.modules = true;
      state.wizard.intake.sources.goal = "override";
    } else if (step === 5) {
      overrides.safety = true;
      state.wizard.intake.sources.safety = "override";
    }
  }

  function markMissionContextOverrideOnly() {
    state.wizard.intake.overrides.mission = true;
  }

  function onAdvancedInput(event) {
    if (state.wizard.advancedStep === 0 && event.target.name === "wizard-assessment-type") {
      const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
      syncWizardStepFromDom();
      if (!state.wizard.intake.overrides.profile && !state.wizard.intake.overrides.modules && !state.wizard.intake.overrides.safety) {
        applyAssessmentTypePreset(state.wizard.data.assessment_type);
      }
      markAdvancedOverrideForStep(0);
      state.wizard.intake.selectedAssessmentTileKey = deriveAssessmentTileKey(state.wizard.data, state.wizard.intake);
      state.wizard.intake.selectedAssessmentTileKeys = normalizeAssessmentTileKeys([state.wizard.intake.selectedAssessmentTileKey]);
      syncConversationMetadataFromData();
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
      realignConversationAfterAdvancedChange();
      state.wizard.errors = validationErrorsForQuestion(
        state.wizard,
        state.wizard.intake.activeQuestionId || recommendedQuestionId(state.wizard),
      );
      renderWizard();
      return;
    }
    if (
      state.wizard.advancedStep === 0 &&
      (event.target.id === "wizard-use-existing" ||
        ["wizard-engagement-name", "wizard-client", "wizard-roe-ref"].includes(event.target.id))
    ) {
      syncWizardStepFromDom();
      markMissionContextOverrideOnly();
      syncConversationMetadataFromData();
      dom.wizardSummary.innerHTML = renderWizardSummary(state.wizard, estimateMission(state.wizard.data), buildConversationContext());
      return;
    }
    if (state.wizard.advancedStep === 3 && event.target.name === "wizard-test-profile") {
      const previousNameContext = snapshotEngagementNameContext(state.wizard.data);
      syncWizardStepFromDom();
      if (!state.wizard.intake.overrides.modules && !state.wizard.intake.overrides.safety) {
        applyProfilePreset(state.wizard.data.test_profile);
      }
      markAdvancedOverrideForStep(3);
      syncConversationMetadataFromData();
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
      realignConversationAfterAdvancedChange();
      state.wizard.errors = validationErrorsForQuestion(
        state.wizard,
        state.wizard.intake.activeQuestionId || recommendedQuestionId(state.wizard),
      );
      renderWizard();
      return;
    }
    const previousNameContext = state.wizard.advancedStep === 1
      ? snapshotEngagementNameContext(state.wizard.data)
      : null;
    syncWizardStepFromDom();
    markAdvancedOverrideForStep(state.wizard.advancedStep);
    syncConversationMetadataFromData();
    if (previousNameContext) {
      refreshSuggestedEngagementNameIfAutomatic(previousNameContext, state.wizard.data);
    }
    realignConversationAfterAdvancedChange();
    state.wizard.errors = validationErrorsForQuestion(
      state.wizard,
      state.wizard.intake.activeQuestionId || recommendedQuestionId(state.wizard),
    );
    if (state.wizard.intake.flowMode === "tile") {
      if (
        event.type === "change" ||
        ["SELECT", "OPTION"].includes(event.target.tagName) ||
        ["checkbox", "radio"].includes(event.target.type)
      ) {
        renderWizard();
      }
      return;
    }
    dom.wizardSummary.innerHTML = renderWizardSummary(state.wizard, estimateMission(state.wizard.data), buildConversationContext());
  }

  function draftAnswerForQuestion(questionId) {
    const data = state.wizard.data;
    if (questionId === "intent") return data.intake_preferences.mission_intent || "";
    if (questionId === "goal") return humanizeGoal(data.intake_preferences.primary_goal);
    if (questionId === "output") return humanizeOutputStyle(data.intake_preferences.output_style);
    if (questionId === "scope") return flattenTargetValues(data.targets).join("\n");
    if (questionId === "auth") return draftAuthStrategyText(data);
    if (questionId === "auth-details") return draftAuthDetailsText(data.access);
    if (questionId === "safety") return humanizeSafetyPosture(data.intake_preferences.safety_posture);
    if (questionId === "boundaries") return draftBoundariesText(data);
    return "";
  }

  function wizardStepContent(step, data, useExistingEngagement) {
    if (step === 0) {
      const selectedEngagement = runtime.actions.selectedEngagement?.();
      const selectedAssessmentMode = String(data.assessment_mode?.mode || "");
      return `
        <div class="wizard-panel-grid">
          <div class="stack-form">
            <label class="field">
              ${fieldLabel(
                "Mission Mode",
                "Choose whether this wizard should create a brand-new engagement dossier or add a new run under the engagement already selected in the left rail."
              )}
              <div class="option-card">
                <input id="wizard-use-existing" data-testid="wizard-use-existing" type="checkbox" ${useExistingEngagement ? "checked" : ""} ${state.engagements.length ? "" : "disabled"} />
                <div>
                  <strong>Use the selected engagement dossier</strong>
                  <p class="micro-copy">Reuse the engagement selected in the rail and create a new run under it.</p>
                </div>
              </div>
            </label>
            ${useExistingEngagement ? `
              <div class="detail-surface">
                <h4>Selected Engagement</h4>
                <p>${escapeHtml(selectedEngagement?.name || "No engagement selected")}</p>
                <p class="micro-copy">${escapeHtml(selectedEngagement?.client || "Client not set")}</p>
              </div>
            ` : `
              <label class="field">
                ${fieldLabel(
                  "Engagement Name",
                  "Use a name a human can immediately recognize later in Explorer, Reports, and History. Example: customer plus scope or objective."
                )}
                <input id="wizard-engagement-name" data-testid="wizard-engagement-name" type="text" value="${escapeHtml(data.engagement_name)}" placeholder="Acme External Validation" />
                ${fieldHelp("Give the mission a recognizable dossier name, for example customer plus scope or objective.")}
              </label>
              <label class="field">
                ${fieldLabel(
                  "Customer",
                  "This appears in dossiers and report headers so operators and recipients can see which customer the run belongs to."
                )}
                <input id="wizard-client" data-testid="wizard-client" type="text" value="${escapeHtml(data.client)}" placeholder="Acme Corp" />
                ${fieldHelp("Used in the customer dossier and in generated report headers.")}
              </label>
              <label class="field">
                ${fieldLabel(
                  "ROE Reference",
                  "Link this run back to the Rules of Engagement, ticket, or approval reference so later reviews can see under which authorization the work happened."
                )}
                <input id="wizard-roe-ref" data-testid="wizard-roe-ref" type="text" value="${escapeHtml(data.roe_ref)}" placeholder="ROE-2026-200" />
                ${fieldHelp("Point to the Rules of Engagement, approval ticket, or engagement reference for auditability.")}
              </label>
            `}
          </div>
          <div class="stack-form">
            ${fieldLabel(
              "Assessment Type",
              "This controls which scope inputs are shown next and which execution lane is likely to be selected later.",
              "What changes?"
            )}
            <div class="toggle-grid">
              ${ASSESSMENT_TYPES.map((type) => `
                <label class="option-card">
                  <input type="radio" name="wizard-assessment-type" value="${escapeHtml(type)}" ${data.assessment_type === type ? "checked" : ""} />
                  <div>
                    <strong>${escapeHtml(type)}</strong>
                    <p class="micro-copy">${escapeHtml(assessmentTypeCopy(type))}</p>
                  </div>
                </label>
              `).join("")}
            </div>
            <div class="detail-surface split-top" data-testid="wizard-assessment-mode-panel">
              <h4>Assessment Mode</h4>
              <p class="micro-copy">Optional phase chaining for operators who want one approval per tier instead of launching each follow-up run by hand.</p>
              <div class="toggle-grid split-top">
                ${ASSESSMENT_MODE_OPTIONS.map((option) => `
                  <label class="option-card">
                    <input type="radio" name="wizard-assessment-mode" value="${escapeHtml(option.value)}" ${selectedAssessmentMode === option.value ? "checked" : ""} />
                    <div>
                      <strong>${escapeHtml(option.label)}</strong>
                      <p class="micro-copy">${escapeHtml(option.copy)}</p>
                    </div>
                  </label>
                `).join("")}
              </div>
              <label class="option-card split-top">
                <input id="wizard-assessment-mode-auto-advance" type="checkbox" ${data.assessment_mode?.auto_advance_on_phase_complete !== false ? "checked" : ""} ${selectedAssessmentMode ? "" : "disabled"} />
                <div>
                  <strong>Auto-advance at safe phase boundaries</strong>
                  <p class="micro-copy">AegisPT moves into the next phase automatically when the previous phase finishes cleanly. Exploitation phases still never auto-start.</p>
                </div>
              </label>
              <p class="micro-copy split-top">The final preview step lets you pick the actual phase authorization level: Passive only, Active, or Full.</p>
            </div>
          </div>
        </div>
      `;
    }

    if (step === 1) {
      const visibleGroups = visibleTargetGroups(data.assessment_type);
      return `
        <div class="stack-zone">
          <div class="detail-surface">
            <h4>Scope and Boundaries</h4>
            <p>These fields stay synchronized with the conversational intake. Use the top section for approved scope, and the lower section for exclusions or internal boundary notes.</p>
          </div>
          <div class="wizard-panel-grid">
          ${visibleGroups.includes("domains") ? textareaField("wizard-target-domains", "Domains", data.targets.domains, "example.com\nshop.example.com", "Enter bare hostnames without protocol. Use this for DNS and domain-scoped discovery.", "Bare domain names only, without https:// or paths.") : ""}
          ${visibleGroups.includes("subdomains") ? textareaField("wizard-target-subdomains", "Subdomains", data.targets.subdomains, "api.example.com\nadmin.example.com", "List known subdomains you already want in scope so discovery starts from explicit assets.", "Known child hostnames such as api.example.com or admin.example.com.") : ""}
          ${visibleGroups.includes("urls") ? textareaField("wizard-target-urls", "URLs", data.targets.urls, "https://example.com\nhttps://example.com/login", "Use full URLs including protocol when you want page or route level web validation.", "Full application or page URLs, including https:// and optional path.") : ""}
          ${visibleGroups.includes("ip_addresses") ? textareaField("wizard-target-ip-addresses", "IP Addresses", data.targets.ip_addresses, "203.0.113.5\n203.0.113.8", "Use individual hosts when the scope is defined as explicit IPs rather than a whole range.", "One host per line. Use this for explicit WAN or LAN hosts.") : ""}
          ${visibleGroups.includes("cidr_ranges") ? textareaField("wizard-target-cidrs", "CIDR Ranges", data.targets.cidr_ranges, "10.10.0.0/24", "Use only approved network blocks here. CIDR ranges drive network discovery breadth and can increase runtime quickly.", "Only enter ranges that are explicitly allowed in scope, for example 10.10.0.0/24.") : ""}
          ${visibleGroups.includes("api_base_urls") ? textareaField("wizard-target-api", "API Base URLs", data.targets.api_base_urls, "https://api.example.com/v1", "Use the base URL that API crawling and validation should start from, not every individual endpoint.", "Start point for API coverage, for example https://api.example.com/v1.") : ""}
          ${visibleGroups.includes("wireless_sites") ? textareaField("wizard-target-wireless-sites", "Wireless Sites", data.targets.wireless_sites || [], "HQ-Amsterdam\nWarehouse-2", "Name the exact authorized physical site or location for passive wireless observation.", "Site names must be explicit because wireless evidence is location-bound.") : ""}
          ${visibleGroups.includes("ssids") ? textareaField("wizard-target-ssids", "Approved SSIDs", data.targets.ssids || [], "CorpWiFi\nGuestWiFi", "List only SSIDs explicitly approved for this assessment.", "SSID names are treated as allowlist values, not discovery expansion.") : ""}
          ${visibleGroups.includes("bssids") ? textareaField("wizard-target-bssids", "Approved BSSIDs", data.targets.bssids || [], "aa:bb:cc:dd:ee:ff", "Known AP BSSIDs make rogue/unknown AP review more precise. Leave blank when unknown.", "BSSIDs are optional only if at least one approved SSID is listed.") : ""}
          ${visibleGroups.includes("wireless_sites") ? `
            <label>Wireless Adapter / Interface
              <input id="wizard-wireless-adapter" type="text" value="${escapeHtml(data.wireless?.adapter || "")}" placeholder="wlan0" />
              ${fieldHelp("Required adapter context for evidence provenance. This foundation does not enable monitor mode automatically.")}
            </label>
            <label class="check-row">
              <input id="wizard-wireless-roe" type="checkbox" ${data.wireless?.roe_acknowledged ? "checked" : ""} />
              <span>I confirm the wireless site, SSIDs/BSSIDs, adapter context, and passive-only ROE are authorized.</span>
            </label>
          ` : ""}
        </div>
          <div class="detail-surface split-top">
            <h4>Exclusions and boundary handling</h4>
            <p class="micro-copy">${escapeHtml(boundaryNotesIntro(data.assessment_type))}</p>
          </div>
          <div class="wizard-panel-grid">
            ${visibleGroups.includes("domains") ? textareaField("wizard-exclude-domains", "Excluded Domains", data.exclusions.domains, "old.example.com", "Explicit domains that must stay out of scope even if operators mention them conversationally.", "Denied domains remain visible in the scope snapshot and confirmation summary.") : ""}
            ${visibleGroups.includes("urls") ? textareaField("wizard-exclude-urls", "Excluded URLs", data.exclusions.urls, "https://example.com/admin", "Specific URLs or app paths that should not be touched during this run.", "Useful for maintenance pages, admin consoles, or sensitive user journeys.") : ""}
            ${visibleGroups.includes("ip_addresses") ? textareaField("wizard-exclude-ip-addresses", "Excluded IP Addresses", data.exclusions.ip_addresses, "10.0.20.10", "Individual hosts that must be avoided even when they sit inside an approved network block.", "Denied IPs are carried into the denylist scope snapshot.") : ""}
            ${visibleGroups.includes("cidr_ranges") ? textareaField("wizard-exclude-cidrs", "Excluded CIDR Ranges", data.exclusions.cidr_ranges, "10.0.21.0/24", "Internal ranges that must not be scanned or expanded into.", "Use this for known restricted network segments.") : ""}
            ${visibleGroups.includes("api_base_urls") ? textareaField("wizard-exclude-api", "Excluded API Base URLs", data.exclusions.api_base_urls, "https://api.example.com/internal", "API roots or prefixes that are explicitly out of scope.", "These stay visible to operators and report consumers as deliberate exclusions.") : ""}
            <label class="field">
              ${fieldLabel("Boundary Notes", "Use notes for maintenance-sensitive systems, approved internal-expansion handling where applicable, or scope assumptions that should remain human-readable.")}
              <textarea id="wizard-boundary-notes" rows="4" placeholder="${escapeHtml(boundaryNotesPlaceholder(data.assessment_type))}">${escapeHtml(data.exclusions.notes || "")}</textarea>
              ${fieldHelp("These notes appear in the conversational confirmation summary and can be carried into the run configuration and reports.")}
            </label>
          </div>
        </div>
      `;
    }

    if (step === 2) {
      return `
        <div class="stack-zone">
          <div class="detail-surface">
            <h4>What to provide here</h4>
            <p>Enter credentials for authenticated scanning. Fields left empty are skipped.</p>
            <p>Only add the identities, tokens, sessions, or manual auth notes the run really needs. Leave fields empty if they do not apply.</p>
            <p class="micro-copy">Direct secrets are accepted and converted to protected bindings when the run is created.</p>
          </div>
          ${data.access.accounts.map((account, index) => `
            <div class="account-card" data-account-card="${index}">
              <div class="panel-head">
                <div>
                  <p class="eyebrow">Account ${index + 1}</p>
                  <h4>${escapeHtml(account.label || `Account ${index + 1}`)}</h4>
                </div>
                <button class="action ghost wizard-remove-account-btn" type="button" data-account-remove="${index}" ${data.access.accounts.length === 1 ? "disabled" : ""}>Remove</button>
              </div>
              <div class="wizard-panel-grid">
                <label class="field">
                  ${fieldLabel("Label", "Human-friendly name for this identity inside the UI and report context, for example Analyst, Admin, or Read Only API User.")}
                  <input data-account-field="label" data-account-index="${index}" type="text" value="${escapeHtml(account.label)}" placeholder="Primary User" />
                  ${fieldHelp("Give the identity a short human label such as Analyst, Admin, or API User.")}
                </label>
                <label class="field">
                  ${fieldLabel("Username", "Optional if you only have a token or session. Fill it in when the operator should know which account is being used.")}
                  <input data-account-field="username" data-account-index="${index}" type="text" value="${escapeHtml(account.username)}" placeholder="username or email" />
                  ${fieldHelp("Optional if you are authenticating with a token or session instead of a username/password.")}
                </label>
                <label class="field">
                  ${fieldLabel("Role", "Describe the privilege level this identity represents so findings and replay are easier to interpret later.")}
                  <input data-account-field="role" data-account-index="${index}" type="text" value="${escapeHtml(account.role)}" placeholder="Admin" />
                  ${fieldHelp("Examples: User, Analyst, Admin, Billing, Read Only API.")}
                </label>
                <label class="field">
                  ${fieldLabel("Password or secret ref", "Use a direct password only when necessary. Prefer an external pointer such as vault:// or env:// when your workflow already has one.")}
                  <input data-account-field="secret_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.secret_ref)}" placeholder="vault://prod/app/admin or direct secret" />
                  ${fieldHelp("Direct secrets are protected after creation. External references are preserved as references.")}
                </label>
                <label class="field">
                  ${fieldLabel("API Key Reference or Value", "Use this when the application or API authenticates with a static key instead of a user login.")}
                  <input data-account-field="api_key_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.api_key_ref)}" placeholder="vault://prod/api/key or direct key" />
                  ${fieldHelp("Fill only if the target uses API key authentication.")}
                </label>
                <label class="field">
                  ${fieldLabel("Bearer Token Reference or Value", "Use this for JWTs or bearer tokens that should seed authenticated API or application checks.")}
                  <input data-account-field="bearer_token_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.bearer_token_ref)}" placeholder="vault://prod/api/bearer or direct token" />
                  ${fieldHelp("Use this when you already have a bearer token and do not want the run to log in first.")}
                </label>
                <label class="field">
                  ${fieldLabel("Cookie / Session Reference or Material", "Use this when access depends on a captured session rather than a fresh login flow.")}
                  <input data-account-field="session_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.session_ref)}" placeholder="session-bundle-A or direct cookie material" />
                  ${fieldHelp("Helpful for SSO, handoff logins, or test accounts that rely on an existing browser session.")}
                </label>
                <label class="field">
                  ${fieldLabel("MFA Notes / Manual Auth Steps", "Document anything a human operator may need to complete before replay or authenticated validation works.")}
                  <textarea data-account-field="mfa_notes" data-account-index="${index}" rows="3" placeholder="Manual OTP or SSO handoff notes">${escapeHtml(account.mfa_notes)}</textarea>
                  ${fieldHelp("Examples: approve push notification, complete SSO handoff, or copy OTP from secure channel.")}
                </label>
              </div>
            </div>
          `).join("")}
          <div class="action-row">
            <button id="wizard-add-account-btn" class="action ghost" type="button">Add Account / Role</button>
          </div>
          <label class="field">
            ${fieldLabel("Shared Manual Auth Steps", "Use this for login choreography that applies to the whole run rather than to one specific account.")}
            <textarea id="wizard-manual-auth-steps" rows="3" placeholder="Manual login, device trust, or MFA sequencing">${escapeHtml(data.access.manual_auth_steps)}</textarea>
            ${fieldHelp("Examples: first visit must trust a device, or analyst must complete SSO before the session can be reused.")}
          </label>
          <label class="field">
            ${fieldLabel("Cookie / Session Notes", "Capture any notes about how the session was obtained, how long it stays valid, or when it must be refreshed.")}
            <textarea id="wizard-cookie-notes" rows="3" placeholder="Session capture notes or cookie replay guidance">${escapeHtml(data.access.cookie_notes)}</textarea>
            ${fieldHelp("Useful when the run depends on an imported cookie jar or a short-lived session.")}
          </label>
        </div>
      `;
    }

    if (step === 3) {
      return `
        <div class="stack-zone">
          <div class="detail-surface">
            <h4>Profile Presets</h4>
            <p>Changing the operator profile resets the module and safety defaults for that profile. You can fine-tune both in the next two steps.</p>
          </div>
          <div class="toggle-grid">
            ${TEST_PROFILES.map((profile) => `
              <label class="option-card">
                <input type="radio" name="wizard-test-profile" value="${escapeHtml(profile)}" ${data.test_profile === profile ? "checked" : ""} />
                <div>
                  <strong>${escapeHtml(profile)}</strong>
                  <p class="micro-copy">${escapeHtml(testProfileCopy(profile))}</p>
                </div>
              </label>
            `).join("")}
          </div>
        </div>
      `;
    }

    if (step === 4) {
      const estimate = estimateMission(data);
      const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
      return `
        <div class="stack-zone">
          <div class="detail-surface">
            <h4>Coverage Intent vs Runtime Lane</h4>
            <p>These toggles capture the coverage you want reflected in the mission record, UI summaries, and reports.</p>
            <p class="micro-copy">The enforced runtime lane for this mission is currently <strong>${escapeHtml(plan.profileName)}</strong> using ${escapeHtml(plan.toolsLabel)}.</p>
          </div>
          <div class="toggle-grid">
            ${MODULES.map(([key, label]) => `
              <label class="toggle-card">
                <input type="checkbox" data-module-key="${key}" ${data.modules[key] ? "checked" : ""} />
                <div>
                  <strong>${escapeHtml(label)}</strong>
                  <p class="micro-copy">${escapeHtml(moduleCopy(key))}</p>
                </div>
              </label>
            `).join("")}
          </div>
        </div>
      `;
    }

    if (step === 5) {
      return `
        <div class="wizard-panel-grid">
          <label class="field">
            ${fieldLabel("Rate Limit (requests / second)", "The maximum pace the run should maintain against the target. Lower values are safer for fragile or shared environments.")}
            <input id="wizard-rate-limit" type="number" min="1" max="20" value="${escapeHtml(String(data.safety.rate_limit_rps))}" />
            ${fieldHelp("Set this lower when the environment is sensitive or the customer expects a cautious pace.")}
          </label>
          <label class="field">
            ${fieldLabel("Concurrency", "How many validations AegisPT may work on at once. Higher concurrency finishes faster but increases target load and log volume.")}
            <input id="wizard-concurrency" type="number" min="1" max="10" value="${escapeHtml(String(data.safety.concurrency))}" />
            ${fieldHelp("Use low concurrency for fragile apps, narrow maintenance windows, or sensitive internal segments.")}
          </label>
          <label class="field">
            ${fieldLabel("Time Budget (minutes)", "The expected operator-approved time envelope for this run before you review progress or stop it.")}
            <input id="wizard-time-budget" type="number" min="15" max="1440" value="${escapeHtml(String(data.safety.time_budget_minutes))}" />
            ${fieldHelp("This helps keep the run aligned with the engagement window and the ETA model.")}
          </label>
          <label class="field">
            ${fieldLabel("Active Checks", "Choose how invasive the run is allowed to become. Passive only observes. Guarded permits safer validation. Active allows deeper probing where approved.")}
            <select id="wizard-active-checks">
              ${[
                ["passive-only", "Passive Only"],
                ["guarded", "Guarded Active"],
                ["active", "Active Validation"],
              ].map(([value, label]) => `<option value="${value}" ${data.safety.active_checks === value ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}
            </select>
            ${fieldHelp("Use Passive Only for reconnaissance and low-risk review, Guarded Active for common web validation, and Active Validation only when the ROE allows it.")}
          </label>
          <label class="field">
            ${fieldLabel("Adaptive Generation", "Allow AegisPT to prepare customer-specific pack proposals after inventory and relevance analysis, before deeper validation starts.")}
            <select id="wizard-adaptive-generation">
              <option value="true" ${data.safety.adaptive_generation ? "selected" : ""}>Enabled</option>
              <option value="false" ${!data.safety.adaptive_generation ? "selected" : ""}>Disabled</option>
            </select>
            ${fieldHelp("Enable this when you want inventory-driven pack planning. Disable it for fixed, baseline-only runs.")}
          </label>
          <label class="field">
            ${fieldLabel("Maximum Validation Depth", "Sets how far the run may go when the profile and safety posture still allow more coverage.")}
            <select id="wizard-max-depth">
              ${[
                ["light", "Light"],
                ["standard", "Standard"],
                ["deep", "Deep"],
              ].map(([value, label]) => `<option value="${value}" ${data.safety.max_validation_depth === value ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}
            </select>
            ${fieldHelp("Light keeps validation short and cautious. Standard fits most work. Deep allows broader follow-up within the approved profile.")}
          </label>
        </div>
      `;
    }

    const estimate = estimateMission(data);
    const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
    const moduleLabels = enabledModules(data.modules);
    const accessSummary = renderAccessContextSummary(data.access);
    const accessContextCount = countMeaningfulAccessContexts(data.access);
    const assessmentModeLabel = String(data.assessment_mode?.mode || "").trim()
      ? humanizeAssessmentMode(data.assessment_mode.mode)
      : "";
    return `
      <div class="stack-zone" data-testid="wizard-review">
        <div class="detail-surface">
          <h4>Mission Review</h4>
          <p>${escapeHtml(data.assessment_type)} with the ${escapeHtml(data.test_profile)} operator profile will use the ${escapeHtml(plan.profileName)} execution lane.</p>
          <p>${escapeHtml(estimate.summary)}</p>
          ${renderLanDiscoveryRoutingNotice(data)}
          ${renderBadgeList([
            renderTargetSummary(data.targets),
            `${accessContextCount} access context${accessContextCount === 1 ? "" : "s"}`,
            `${moduleLabels.length} enabled module${moduleLabels.length === 1 ? "" : "s"}`,
            `RPS ${data.safety.rate_limit_rps}`,
            `${humanizeCheckMode(data.safety.active_checks)}`,
            assessmentModeLabel
              ? `${assessmentModeLabel}${effectiveAssessmentModeAutoAdvance(data) ? " · auto-advance" : ""} · ${authorizationOption(selectedAuthorizationLevel(data)).label.toLowerCase()} authorization`
              : null,
            `${estimate.confidence} ETA confidence`,
          ], "compact-badge-list split-top")}
        </div>
        <div class="disclosure-grid">
          ${renderDisclosure({
            title: "Targets & Access",
            summary: `${renderTargetSummary(data.targets)} · ${accessSummary}`,
            open: true,
            body: `
              <div class="compact-definition-grid">
                <div><span>Targets</span><strong>${escapeHtml(renderTargetSummary(data.targets))}</strong></div>
                <div><span>Access</span><strong>${escapeHtml(accessSummary)}</strong></div>
                <div><span>Manual Auth</span><strong>${escapeHtml(data.access.manual_auth_steps || "Not provided")}</strong></div>
                <div><span>Session Notes</span><strong>${escapeHtml(data.access.cookie_notes || "Not provided")}</strong></div>
              </div>
            `,
          })}
          ${renderDisclosure({
            title: "Execution Lane & Coverage",
            summary: `${plan.profileName} · ${plan.toolsLabel} · ${moduleLabels.length} modules`,
            open: true,
            testId: "wizard-execution-lane",
            body: `
              <div class="compact-definition-grid">
                <div><span>Execution Lane</span><strong>${escapeHtml(plan.profileName)}</strong></div>
                <div><span>Planned Tools</span><strong>${escapeHtml(plan.toolsLabel)}</strong></div>
                <div><span>Approvals</span><strong>${escapeHtml(String(plan.requiredApprovals))}</strong></div>
                <div><span>Assessment Mode</span><strong>${escapeHtml(
                  assessmentModeLabel
                    ? `${assessmentModeLabel}${effectiveAssessmentModeAutoAdvance(data) ? " · auto-advance" : ""} · ${authorizationOption(selectedAuthorizationLevel(data)).label.toLowerCase()} authorization`
                    : "Disabled"
                )}</strong></div>
                <div><span>Coverage Intent</span><strong>${escapeHtml(moduleLabels.join(", ") || "None")}</strong></div>
              </div>
              <p class="micro-copy split-top">${escapeHtml(plan.description)}</p>
            `,
          })}
          ${renderDisclosure({
            title: "Safety & Launch Handoff",
            summary: `Budget ${data.safety.time_budget_minutes}m · depth ${humanizeDepthLabel(data.safety.max_validation_depth)} · adaptive ${data.safety.adaptive_generation ? "enabled" : "disabled"}`,
            open: true,
            body: `
              <div class="compact-definition-grid">
                <div><span>Rate Limit</span><strong>${escapeHtml(`${data.safety.rate_limit_rps} RPS`)}</strong></div>
                <div><span>Concurrency</span><strong>${escapeHtml(String(data.safety.concurrency))}</strong></div>
                <div><span>Time Budget</span><strong>${escapeHtml(`${data.safety.time_budget_minutes} minutes`)}</strong></div>
                <div><span>Check Mode</span><strong>${escapeHtml(humanizeCheckMode(data.safety.active_checks))}</strong></div>
                <div><span>Maximum Depth</span><strong>${escapeHtml(humanizeDepthLabel(data.safety.max_validation_depth))}</strong></div>
                <div><span>Adaptive Generation</span><strong>${escapeHtml(data.safety.adaptive_generation ? "Enabled" : "Disabled")}</strong></div>
              </div>
              <p class="micro-copy split-top">${escapeHtml(
                assessmentModeLabel
                  ? "Confirming creates or reuses the engagement, stores this wizard configuration on the run record, seeds inventory, launches the first phase run, and opens Mission Control with the assessment chain armed."
                  : "Confirming creates or reuses the engagement, stores this wizard configuration on the run record, seeds the inventory model from the reviewed scope, and opens Mission Control."
              )}</p>
              <p class="micro-copy">${escapeHtml(
                assessmentModeLabel
                  ? "Mission Control will show which phases were pre-authorized at launch, which ones auto-advance, and which gates still need credentials, evidence, scope, or exploitation approval."
                  : "After Mission Control opens, press Start Queued Checks only if the run is still queued; active runs continue automatically."
              )}</p>
            `,
          })}
        </div>
      </div>
    `;
  }

  function renderWizardSummary(wizard, estimate, context = buildConversationContext()) {
    const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
    const targetSummary = renderTargetSummary(wizard.data.targets);
    const targetDetails = flattenTargetValues(wizard.data.targets).join(", ") || "No targets recorded";
    const accessSummary = renderAccessContextSummary(wizard.data.access);
    const moduleLabels = enabledModules(wizard.data.modules);
    const accessContextCount = countMeaningfulAccessContexts(wizard.data.access);
    const summary = context.summary || buildSummaryBuckets(wizard, estimate);
    if (!summary.confirmed.length && !wizard.lastCreated) {
      return "";
    }
    const confirmedItems = summary.confirmed.length ? summary.confirmed.slice(0, 6) : [];
    const stillNeededItems = summary.stillNeeded.length
      ? summary.stillNeeded
      : [context.confirmationReady ? "Nothing blocking confirmation" : "Continue the intake to confirm remaining assumptions"];
    const stillNeededActions = summary.stillNeededDetails || [];
    const currentQuestionIds = activeQuestionFamilyIds(context.question.id);
    const visibleStillNeededActions = stillNeededActions.filter((item) =>
      item.action === "advanced" || !currentQuestionIds.has(item.questionId)
    );
    const currentQuestionStillNeededLabels = labelsResolvedByActiveQuestion(summary, context.question.id);
    const visibleStillNeededActionLabels = new Set(visibleStillNeededActions.map((item) => item.label));
    const remainingStillNeededBadges = stillNeededItems
      .slice(1)
      .filter((item) => !visibleStillNeededActionLabels.has(item) && !currentQuestionStillNeededLabels.has(item));
    const advancedMissionOpen = wizard.intake.advancedOpen && wizard.advancedStep === 0;
    const advancedPlanningOpen = wizard.intake.advancedOpen && [0, 3, 4, 5].includes(wizard.advancedStep);
    const advancedLaneOpen = wizard.intake.advancedOpen && [3, 4, 5].includes(wizard.advancedStep);
    const targetTypeMeaningful =
      wizard.intake.sources.target_type !== "still-needed" ||
      wizard.intake.overrides.mission ||
      advancedMissionOpen;
    const profileMeaningful =
      wizard.intake.sources.goal !== "still-needed" ||
      advancedPlanningOpen ||
      wizard.intake.overrides.mission ||
      wizard.intake.overrides.profile ||
      wizard.intake.overrides.modules ||
      wizard.intake.overrides.safety;
    const safetyMeaningful =
      wizard.intake.sources.safety !== "still-needed" ||
      advancedMissionOpen ||
      advancedLaneOpen ||
      wizard.intake.overrides.mission ||
      wizard.intake.overrides.profile ||
      wizard.intake.overrides.modules ||
      wizard.intake.overrides.safety;
    const essentialsBadges = [];
    if (targetTypeMeaningful) essentialsBadges.push(wizard.data.assessment_type);
    if (profileMeaningful) {
      essentialsBadges.push(`${wizard.data.test_profile} profile`);
      essentialsBadges.push(plan.profileName);
    }
    if (targetTypeMeaningful && profileMeaningful && safetyMeaningful) {
      essentialsBadges.push(
        `${estimate.estimated_total_minutes}m ETA`,
        `${estimate.estimated_impact} impact`,
        `${estimate.confidence} confidence`,
      );
    }
    const essentialsMicrocopy = context.confirmationReady
      ? "Everything required for deterministic run creation is present."
      : essentialsBadges.length
        ? "The intake is updating the real run model in place while advanced overrides stay available."
        : "Mission type, profile, execution lane, and ETA appear here once the intake has enough confirmed or safely inferred context.";
    const coverageDetailsReady = profileMeaningful;
    const laneDetailsReady = targetTypeMeaningful && profileMeaningful;
    const coverageSummary = coverageDetailsReady
      ? `${wizard.data.test_profile === "Deep" ? "Deep Assessment" : `${wizard.data.test_profile} profile`} · ${humanizeCheckMode(wizard.data.safety.active_checks)} · Modules ${moduleLabels.length}`
      : "Waiting for mission shape";
    const coverageBody = coverageDetailsReady
      ? `
          <div class="compact-definition-grid">
            <div><span>Execution Lane</span><strong>${escapeHtml(plan.profileName)}</strong></div>
            <div><span>Planned Tools</span><strong>${escapeHtml(plan.toolsLabel)}</strong></div>
            <div><span>Modules</span><strong>${escapeHtml(moduleLabels.join(", ") || "No modules enabled")}</strong></div>
            <div><span>Access Contexts</span><strong>${escapeHtml(String(accessContextCount))}</strong></div>
            <div><span>Rate / Concurrency</span><strong>${escapeHtml(`${wizard.data.safety.rate_limit_rps} RPS · ${wizard.data.safety.concurrency}`)}</strong></div>
            <div><span>Budget</span><strong>${escapeHtml(`${wizard.data.safety.time_budget_minutes} minutes`)}</strong></div>
            <div><span>Check Mode</span><strong>${escapeHtml(humanizeCheckMode(wizard.data.safety.active_checks))}</strong></div>
            <div><span>Adaptive</span><strong>${escapeHtml(wizard.data.safety.adaptive_generation ? "Enabled" : "Disabled")}</strong></div>
            <div><span>Goal</span><strong>${escapeHtml(humanizeGoal(wizard.data.intake_preferences.primary_goal))}</strong></div>
            <div><span>Output</span><strong>${escapeHtml(humanizeOutputStyle(wizard.data.intake_preferences.output_style))}</strong></div>
          </div>
        `
      : "<p class='micro-copy'>Coverage posture, execution lane, and ETA stay hidden here until the intake has enough confirmed or safely inferred mission context.</p>";
    const laneSummary = laneDetailsReady && safetyMeaningful
      ? `${plan.profileName} · approvals ${plan.requiredApprovals} · ${estimate.estimated_total_minutes}m`
      : "Waiting for mission shape";
    const laneBody = laneDetailsReady && safetyMeaningful
      ? `
          <div class="compact-definition-grid">
            <div><span>Execution Lane</span><strong>${escapeHtml(plan.profileName)}</strong></div>
            <div><span>Approvals</span><strong>${escapeHtml(String(plan.requiredApprovals))}</strong></div>
            <div><span>Planned Tools</span><strong>${escapeHtml(plan.toolsLabel)}</strong></div>
            <div><span>ETA</span><strong>${escapeHtml(`${estimate.estimated_total_minutes} minutes`)}</strong></div>
            <div><span>Impact</span><strong>${escapeHtml(estimate.estimated_impact)}</strong></div>
            <div><span>Confidence</span><strong>${escapeHtml(estimate.confidence)}</strong></div>
          </div>
          <p class="micro-copy split-top">${escapeHtml(plan.description)}</p>
        `
      : "<p class='micro-copy'>AegisPT only surfaces the execution lane, approvals, ETA, impact, and confidence here once the intake has enough confirmed or safely inferred mission context.</p>";
    return `
      <div class="wizard-inline-head">
        <div>
          <p class="eyebrow">Mission Context</p>
          <h3>Confirmed intake context</h3>
        </div>
        <span class="badge">${escapeHtml(`${summary.confirmed.length} confirmed`)}</span>
      </div>
      <div class="list-card" data-testid="wizard-summary-current">
        <h4>Current Essentials</h4>
        <p>${escapeHtml(readinessSummary(wizard.data))}</p>
        <p class="micro-copy">${escapeHtml(essentialsMicrocopy)}</p>
        ${renderBadgeList(essentialsBadges, "compact-badge-list split-top")}
      </div>
      <div class="detail-surface emphasis-surface wizard-summary-focus" data-testid="wizard-summary-needed">
        <h4>${escapeHtml(context.confirmationReady ? "Ready to Create" : "What Still Needs Confirmation")}</h4>
        <p>${escapeHtml(stillNeededItems[0])}</p>
        ${
          visibleStillNeededActions.length
            ? `<div class="chip-row split-top" data-testid="wizard-needed-actions">${visibleStillNeededActions.map((item) => item.action === "advanced"
                ? `<button class="action ghost quick-reply-chip" type="button" data-intake-advanced="true" ${item.advancedStep !== undefined ? `data-intake-advanced-step="${escapeHtml(String(item.advancedStep))}"` : ""} data-testid="wizard-needed-action-${escapeHtml(item.key)}">${escapeHtml(item.label)}</button>`
                : `<button class="action ghost quick-reply-chip" type="button" data-edit-question="${escapeHtml(item.questionId)}" data-testid="wizard-needed-action-${escapeHtml(item.key)}">${escapeHtml(item.label)}</button>`
              ).join("")}</div>`
            : ""
        }
        ${
          remainingStillNeededBadges.length
            ? `${renderBadgeList(remainingStillNeededBadges, "compact-badge-list split-top")}<p class="micro-copy split-top">The remaining items still need confirmation before the mission can be created cleanly.</p>`
            : visibleStillNeededActions.length
              ? `<p class="micro-copy split-top">Use the remaining quick actions to revise the other missing mission topics without losing the current intake path.</p>`
            : `<p class="micro-copy split-top">${escapeHtml(context.confirmationReady ? "Nothing blocking confirmation. You can confirm now or revise any topic first." : "This topic still needs confirmation before the mission can be created cleanly.")}</p>`
        }
      </div>
      <div class="detail-surface" data-testid="wizard-summary-confirmed">
        <h4>Mission Brief</h4>
        <p>${escapeHtml(summary.confirmed.length ? `${summary.confirmed.length} items are already locked into the deterministic run dossier.` : "Nothing confirmed yet.")}</p>
        ${
          confirmedItems.length
            ? `<div class="compact-definition-grid split-top">${confirmedItems.map((item, index) => `<div><span>Locked ${index + 1}</span><strong>${escapeHtml(item)}</strong></div>`).join("")}</div>`
            : "<p class='micro-copy split-top'>Confirmed intake items appear here as soon as the conversation or advanced configuration resolves them.</p>"
        }
        ${
          summary.confirmed.length > confirmedItems.length
            ? `<p class="micro-copy split-top">${escapeHtml(`${summary.confirmed.length - confirmedItems.length} additional confirmed item${summary.confirmed.length - confirmedItems.length === 1 ? "" : "s"} remain available in the detailed disclosures below.`)}</p>`
            : ""
        }
      </div>
      ${renderDisclosure({
        title: "Inferred",
        summary: summary.inferred.length ? `${summary.inferred.length} safe defaults proposed` : "No safe inferences active",
        open: false,
        testId: "wizard-summary-inferred",
        body: summary.inferred.length
          ? `<div class="compact-definition-grid">${summary.inferred.map((item, index) => `<div><span>Inference ${index + 1}</span><strong>${escapeHtml(item)}</strong></div>`).join("")}</div>`
          : "<p class='micro-copy'>When the intake can safely infer a profile, safety posture, or output style, it will show up here until you confirm or override it.</p>",
      })}
      ${wizard.lastCreated ? renderDisclosure({
        title: "Last Mission Created",
        summary: `${wizard.lastCreated.engagementName} · ${wizard.lastCreated.runId}`,
        open: false,
        body: `
          <div class="compact-definition-grid">
            <div><span>Engagement</span><strong>${escapeHtml(wizard.lastCreated.engagementName)}</strong></div>
            <div><span>Run</span><strong>${escapeHtml(wizard.lastCreated.runId)}</strong></div>
          </div>
        `,
      }) : ""}
      ${renderDisclosure({
        title: "Targets & Access",
        summary: `${targetSummary} · ${accessSummary}`,
        open: false,
        testId: "wizard-summary-targets",
        body: `
          <div class="compact-definition-grid">
            <div><span>Targets</span><strong>${escapeHtml(targetSummary)}</strong></div>
            <div><span>Target Detail</span><strong>${escapeHtml(targetDetails)}</strong></div>
            <div><span>Access Context</span><strong>${escapeHtml(accessSummary)}</strong></div>
            <div><span>Boundary Notes</span><strong>${escapeHtml(wizard.data.exclusions.notes || "Not provided")}</strong></div>
            <div><span>Denylist</span><strong>${escapeHtml(renderExclusionSummary(wizard.data.exclusions))}</strong></div>
            <div><span>Shared Auth Notes</span><strong>${escapeHtml(wizard.data.access.manual_auth_steps || "Not provided")}</strong></div>
            <div><span>Session Notes</span><strong>${escapeHtml(wizard.data.access.cookie_notes || "Not provided")}</strong></div>
          </div>
        `,
      })}
      ${renderDisclosure({
        title: "Coverage & Safety",
        summary: coverageSummary,
        open: false,
        testId: "wizard-summary-coverage",
        body: coverageBody,
      })}
      ${renderDisclosure({
        title: "Execution Lane & ETA",
        summary: laneSummary,
        open: false,
        testId: "wizard-summary-lane",
        body: laneBody,
      })}
    `;
  }

  function attachWizardHandlers() {
    dom.wizardPanel.querySelectorAll("input, textarea, select").forEach((element) => {
      element.addEventListener("input", onWizardInput);
      element.addEventListener("change", onWizardInput);
    });

    const addAccountButton = document.getElementById("wizard-add-account-btn");
    if (addAccountButton) {
      addAccountButton.addEventListener("click", () => {
        syncWizardStepFromDom();
        patchWizardAccessAccounts(
          [...state.wizard.data.access.accounts, buildEmptyAccount()],
          "wizard.legacyAccess.addAccount"
        );
        renderWizard();
      });
    }

    dom.wizardPanel.querySelectorAll(".wizard-remove-account-btn").forEach((button) => {
      button.addEventListener("click", () => {
        syncWizardStepFromDom();
        const index = Number(button.dataset.accountRemove);
        patchWizardAccessAccounts(
          state.wizard.data.access.accounts.filter((_, accountIndex) => accountIndex !== index),
          "wizard.legacyAccess.removeAccount"
        );
        renderWizard();
      });
    });
  }

  function onWizardInput(event) {
    if (state.wizard.step === 0 && event.target.name === "wizard-assessment-type") {
      syncWizardStepFromDom();
      applyAssessmentTypePreset(state.wizard.data.assessment_type);
      renderWizard();
      return;
    }
    if (state.wizard.step === 3 && event.target.name === "wizard-test-profile") {
      syncWizardStepFromDom();
      applyProfilePreset(state.wizard.data.test_profile);
      renderWizard();
      return;
    }
    syncWizardStepFromDom();
    if (
      (state.wizard.step === 0 && event.target.id === "wizard-use-existing") ||
      (state.wizard.step === 2 && event.target.dataset.accountField === "label")
    ) {
      renderWizard();
    } else {
      dom.wizardSummary.innerHTML = renderWizardSummary(state.wizard, estimateMission(state.wizard.data));
    }
  }

  function syncWizardStepFromDom(stepOverride = null) {
    const wizard = state.wizard;
    const data = wizard.data;
    const currentStep = stepOverride ?? currentWizardFormStep();
    const advancedContent = document.getElementById("wizard-advanced-content");
    if (
      state.wizard.intake.flowMode === "tile" &&
      currentStep >= 1 &&
      currentStep <= 5 &&
      (!advancedContent || !state.wizard.intake.advancedOpen)
    ) {
      return;
    }
    const formRoot = advancedContent || dom.wizardPanel || document;

    if (currentStep === 0) {
      const useExisting = document.getElementById("wizard-use-existing");
      wizard.useExistingEngagement = Boolean(useExisting?.checked);
      data.engagement_name = stringValue(document.getElementById("wizard-engagement-name")?.value);
      data.client = stringValue(document.getElementById("wizard-client")?.value);
      data.roe_ref = stringValue(document.getElementById("wizard-roe-ref")?.value);
      data.assessment_type =
        document.querySelector('input[name="wizard-assessment-type"]:checked')?.value || data.assessment_type;
      const selectedAssessmentMode =
        document.querySelector('input[name="wizard-assessment-mode"]:checked')?.value ||
        data.assessment_mode?.mode ||
        "";
      data.assessment_mode = {
        ...data.assessment_mode,
        mode: selectedAssessmentMode,
        auto_advance_on_phase_complete: Boolean(
          document.getElementById("wizard-assessment-mode-auto-advance")?.checked
        ),
        authorization_level: selectedAssessmentMode
          ? normalizedAuthorizationLevel(data.assessment_mode?.authorization_level)
          : "passive",
        typed_scope_confirmation: selectedAssessmentMode
          ? String(data.assessment_mode?.typed_scope_confirmation || "")
          : "",
      };
      return;
    }
    if (currentStep === 1) {
      data.targets = {
        domains: splitLines(document.getElementById("wizard-target-domains")?.value),
        subdomains: splitLines(document.getElementById("wizard-target-subdomains")?.value),
        urls: splitLines(document.getElementById("wizard-target-urls")?.value),
        ip_addresses: splitLines(document.getElementById("wizard-target-ip-addresses")?.value),
        cidr_ranges: splitLines(document.getElementById("wizard-target-cidrs")?.value),
        api_base_urls: splitLines(document.getElementById("wizard-target-api")?.value),
        wireless_sites: splitLines(document.getElementById("wizard-target-wireless-sites")?.value),
        ssids: splitLines(document.getElementById("wizard-target-ssids")?.value),
        bssids: splitLines(document.getElementById("wizard-target-bssids")?.value),
      };
      data.exclusions = {
        domains: splitLines(document.getElementById("wizard-exclude-domains")?.value),
        urls: splitLines(document.getElementById("wizard-exclude-urls")?.value),
        ip_addresses: splitLines(document.getElementById("wizard-exclude-ip-addresses")?.value),
        cidr_ranges: splitLines(document.getElementById("wizard-exclude-cidrs")?.value),
        api_base_urls: splitLines(document.getElementById("wizard-exclude-api")?.value),
        ssids: splitLines(document.getElementById("wizard-exclude-ssids")?.value),
        bssids: splitLines(document.getElementById("wizard-exclude-bssids")?.value),
        notes: stringValue(document.getElementById("wizard-boundary-notes")?.value),
      };
      data.wireless = {
        ...(data.wireless || {}),
        site: data.targets.wireless_sites[0] || "",
        adapter: stringValue(document.getElementById("wizard-wireless-adapter")?.value),
        approved_ssids: [...data.targets.ssids],
        approved_bssids: [...data.targets.bssids],
        excluded_ssids: [...data.exclusions.ssids],
        excluded_bssids: [...data.exclusions.bssids],
        roe_acknowledged: Boolean(document.getElementById("wizard-wireless-roe")?.checked),
        passive_only: true,
        rf_disruptive_actions: false,
        handshake_capture: false,
        credential_harvesting: false,
        wps_pin_testing: false,
        evil_twin: false,
        jamming: false,
      };
      const exclusionCount = countExplicitExclusions(data.exclusions);
      if (exclusionCount) {
        data.intake_preferences.boundary_handling = "custom-exclusions";
      } else if (hasBoundaryNotes(data.exclusions)) {
        data.intake_preferences.boundary_handling = "notes-only-boundaries";
      } else if (["custom-exclusions", "notes-only-boundaries"].includes(String(data.intake_preferences.boundary_handling || "").trim())) {
        data.intake_preferences.boundary_handling = "standard-scope-only";
      }
      return;
    }
    if (currentStep === 2) {
      const accounts = Array.from(formRoot.querySelectorAll("[data-account-card]")).map((card) => {
        const index = Number(card.dataset.accountCard);
        return {
          label: stringValue(card.querySelector('[data-account-field="label"]')?.value),
          username: stringValue(card.querySelector('[data-account-field="username"]')?.value),
          role: stringValue(card.querySelector('[data-account-field="role"]')?.value),
          secret_ref: stringValue(card.querySelector('[data-account-field="secret_ref"]')?.value),
          api_key_ref: stringValue(card.querySelector('[data-account-field="api_key_ref"]')?.value),
          bearer_token_ref: stringValue(card.querySelector('[data-account-field="bearer_token_ref"]')?.value),
          session_ref: stringValue(card.querySelector('[data-account-field="session_ref"]')?.value),
          mfa_notes: stringValue(card.querySelector('[data-account-field="mfa_notes"]')?.value),
          _index: index,
        };
      }).sort((left, right) => left._index - right._index).map(({ _index, ...account }) => account);
      data.access.accounts = accounts.length ? accounts : [buildEmptyAccount()];
      data.access.manual_auth_steps = stringValue(document.getElementById("wizard-manual-auth-steps")?.value);
      data.access.cookie_notes = stringValue(document.getElementById("wizard-cookie-notes")?.value);
      return;
    }
    if (currentStep === 3) {
      data.test_profile = document.querySelector('input[name="wizard-test-profile"]:checked')?.value || data.test_profile;
      return;
    }
    if (currentStep === 4) {
      MODULES.forEach(([key]) => {
        data.modules[key] = Boolean(formRoot.querySelector(`[data-module-key="${key}"]`)?.checked);
      });
      return;
    }
    if (currentStep === 5) {
      data.safety.rate_limit_rps = numberValue(document.getElementById("wizard-rate-limit")?.value, DEFAULT_SAFETY.rate_limit_rps);
      data.safety.concurrency = numberValue(document.getElementById("wizard-concurrency")?.value, DEFAULT_SAFETY.concurrency);
      data.safety.time_budget_minutes = numberValue(document.getElementById("wizard-time-budget")?.value, DEFAULT_SAFETY.time_budget_minutes);
      data.safety.active_checks = document.getElementById("wizard-active-checks")?.value || DEFAULT_SAFETY.active_checks;
      data.safety.adaptive_generation = (document.getElementById("wizard-adaptive-generation")?.value || "true") === "true";
      data.safety.max_validation_depth = document.getElementById("wizard-max-depth")?.value || DEFAULT_SAFETY.max_validation_depth;
    }
  }

  function validateWizardStep(step) {
    const data = state.wizard.data;
    if (step === 0) {
      const errors = [];
      if (state.wizard.useExistingEngagement && !state.selectedEngagementId) {
        errors.push("Select an existing engagement or create a new one.");
      }
      if (!state.wizard.useExistingEngagement && !data.engagement_name.trim()) {
        errors.push("Enter an engagement name.");
      }
      if (!data.assessment_type) {
        errors.push("Choose an assessment type.");
      }
      return errors;
    }
    if (step === 1) {
      const targets = flattenTargetValues(data.targets);
      const errors = [];
      if (!targets.length) {
        errors.push("Add at least one target in scope.");
      }
      if (data.assessment_type === "WiFi / Wireless") {
        if (!(data.targets.wireless_sites || []).length) errors.push("Add the authorized wireless site/location.");
        if (!(data.targets.ssids || []).length && !(data.targets.bssids || []).length) errors.push("Add at least one approved SSID or BSSID.");
        if (!stringValue(data.wireless?.adapter)) errors.push("Add the wireless adapter/interface context.");
        if (!data.wireless?.roe_acknowledged) errors.push("Confirm passive wireless ROE before launch.");
      }
      data.targets.urls.forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid URL: ${value}`);
      });
      data.targets.api_base_urls.forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid API base URL: ${value}`);
      });
      data.targets.ip_addresses.forEach((value) => {
        if (!isLikelyIp(value)) errors.push(`Invalid IP address: ${value}`);
      });
      data.targets.cidr_ranges.forEach((value) => {
        if (!isLikelyCidr(value)) errors.push(`Invalid CIDR range: ${value}`);
      });
      data.targets.domains.forEach((value) => {
        if (!isLikelyDomain(value)) errors.push(`Invalid domain: ${value}`);
      });
      data.targets.subdomains.forEach((value) => {
        if (!isLikelyDomain(value)) errors.push(`Invalid subdomain: ${value}`);
      });
      data.exclusions.urls.forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid excluded URL: ${value}`);
      });
      data.exclusions.api_base_urls.forEach((value) => {
        if (!isLikelyUrl(value)) errors.push(`Invalid excluded API base URL: ${value}`);
      });
      data.exclusions.ip_addresses.forEach((value) => {
        if (!isLikelyIp(value)) errors.push(`Invalid excluded IP address: ${value}`);
      });
      data.exclusions.cidr_ranges.forEach((value) => {
        if (!isLikelyCidr(value)) errors.push(`Invalid excluded CIDR range: ${value}`);
      });
      data.exclusions.domains.forEach((value) => {
        if (!isLikelyDomain(value)) errors.push(`Invalid excluded domain: ${value}`);
      });
      return [...new Set(errors)];
    }
    if (step === 2) {
      if (requiresCredentials(data) && !hasMeaningfulAccessContext(data.access)) {
        return ["This assessment profile needs at least one access context, shared manual-auth note, or session note."];
      }
      return [];
    }
    if (step === 3) {
      return data.test_profile ? [] : ["Choose a test profile."];
    }
    if (step === 4) {
      return enabledModules(data.modules).length ? [] : ["Enable at least one test module."];
    }
    if (step === 5) {
      const errors = [];
      if (data.safety.rate_limit_rps < 1) errors.push("Rate limit must be at least 1 request per second.");
      if (data.safety.concurrency < 1) errors.push("Concurrency must be at least 1.");
      if (data.safety.time_budget_minutes < 15) errors.push("Time budget must be at least 15 minutes.");
      return errors;
    }
    return validateEntireWizard();
  }

  function validateEntireWizard() {
    const allErrors = [];
    for (let step = 0; step < WIZARD_STEPS.length - 1; step += 1) {
      allErrors.push(...validateWizardStep(step));
    }
    return [...new Set(allErrors)];
  }

  async function submitWizard() {
    syncWizardStepFromDom();
    const errors = validateEntireWizard();
    const authorizationErrors = [];
    if (needsRoeAuthorizationConfirmation(state.wizard.data) && !state.wizard.data.authorization_confirmed) {
      authorizationErrors.push("Confirm written authorization before launching this mission.");
    }
    if (
      chainAuthorizationAvailable(state.wizard.data) &&
      selectedAuthorizationLevel(state.wizard.data) === "full" &&
      !hasValidFullAuthorizationConfirmation(state.wizard.data)
    ) {
      authorizationErrors.push(
        `Type ${missionScopeConfirmationToken(state.wizard.data) || "an approved target"} exactly to unlock Full authorization.`
      );
    }
    if (errors.length || authorizationErrors.length) {
      const nextIntake = authorizationErrors.length && state.wizard.intake.flowMode === "tile"
        ? { ...state.wizard.intake, flowStep: 3 }
        : state.wizard.intake;
      patchWizardFields({ errors: [...errors, ...authorizationErrors], intake: nextIntake }, "wizard.submit.validationFailed");
      renderWizard();
      return;
    }

    patchWizardFields({ submitting: true, errors: [] }, "wizard.submit.start");
    runtime.actions.pushStatus?.("Creating mission dossier and run configuration.", "info");
    renderWizard();

    try {
      const estimate = estimateMission(state.wizard.data);
      const configuration = buildRunConfiguration(state.wizard.data, estimate);
      let engagement = state.wizard.useExistingEngagement
        ? runtime.actions.selectedEngagement?.()
        : await api("/api/v1/engagements", {
            method: "POST",
            body: {
              name: state.wizard.data.engagement_name,
              client: valueOrNull(state.wizard.data.client),
              roe_ref: valueOrNull(state.wizard.data.roe_ref),
            },
          });
      if (
        engagement &&
        !valueOrNull(engagement.roe_ref) &&
        state.wizard.data.authorization_confirmed &&
        !engagement.authorization_confirmed_at
      ) {
        const authorization = await api(`/api/v1/engagements/${engagement.id}/confirm-authorization`, {
          method: "PATCH",
        });
        engagement = {
          ...engagement,
          authorization_confirmed_by: authorization.authorization_confirmed_by,
          authorization_confirmed_at: authorization.authorization_confirmed_at,
        };
      }
      if (configuration.intake?.engagement_context) {
        configuration.intake.engagement_context = {
          ...configuration.intake.engagement_context,
          engagement_id: engagement.id,
          engagement_name: engagement.name,
          client: engagement.client || configuration.intake.engagement_context.client || null,
          roe_ref: engagement.roe_ref || configuration.intake.engagement_context.roe_ref || null,
        };
      }

      const scopePayload = {
        allowlist_json: buildAllowlistFromWizard(state.wizard.data.targets),
        denylist_json: buildDenylistFromWizard(state.wizard.data.exclusions),
      };
      await api(`/api/v1/engagements/${engagement.id}/scope`, {
        method: "POST",
        body: scopePayload,
      });

      const inventorySnapshot = await api("/api/v1/inventory/runs", {
        method: "POST",
        body: buildInventorySeedPayload(engagement.id, state.wizard.data),
      });

      const run = await api(`/api/v1/engagements/${engagement.id}/runs`, {
        method: "POST",
        body: {
          profile_name: estimate.execution_profile,
          source_inventory_snapshot_id: inventorySnapshot.id,
          configuration_json: configuration,
          assessment_mode: state.wizard.data.assessment_mode?.mode || null,
          assessment_auto_advance_on_phase_complete:
            state.wizard.data.assessment_mode?.mode
              ? configuration.assessment_mode?.auto_advance_on_phase_complete !== false
              : null,
          dispatch_after_create: true,
        },
      });

      runtime.actions.pushStatus?.(
        state.wizard.data.assessment_mode?.mode
          ? `Mission ${engagement.name} created with ${humanizeAssessmentMode(state.wizard.data.assessment_mode.mode).toLowerCase()} enabled. Mission Control now tracks the phase chain.`
          : `Mission ${engagement.name} created and dispatched through the existing runtime boundary.`,
        "success"
      );
      const wizardData = state.wizard.data;
      const useExistingEngagement = state.wizard.useExistingEngagement;
      const selectedRun = {
        ...run,
        profile: run.profile || { name: estimate.execution_profile },
        tasks: Array.isArray(run.tasks) ? run.tasks : [],
        configuration_json: run.configuration_json || configuration,
      };
      const selectedTask = selectedRun.tasks[0] || null;
      const sameExistingEngagement =
        useExistingEngagement &&
        String(runtime.actions.selectedEngagement?.()?.id || "") === String(engagement.id);
      const nextWizard = {
        ...buildEmptyWizardState(),
        lastCreated: {
          engagementName: engagement.name,
          runId: run.id,
        },
      };
      await showMissionLaunchOverlay({
        engagementName: engagement.name,
        profileName: estimate.execution_profile,
        targetSummary: `${flattenTargetValues(wizardData.targets).length} target signal${flattenTargetValues(wizardData.targets).length === 1 ? "" : "s"}`,
      });
      patchState(
        {
          engagements: useExistingEngagement
            ? state.engagements
            : [
                engagement,
                ...state.engagements.filter((item) => String(item.id) !== String(engagement.id)),
              ],
          selectedEngagementId: engagement.id,
          selectedRunId: run.id,
          selectedRun,
          selectedTaskId: selectedTask?.id || null,
          selectedTask,
          selectedFindingId: null,
          selectedFindingTheater: null,
          selectedFindingEvidence: null,
          reportCatalog: [],
          reportDraft: null,
          selectedPackBundle: null,
          selectedCodexContext: null,
          selectedCodexResult: null,
          mission: {
            scope: {
              allowlist_json: buildAllowlistFromWizard(wizardData.targets),
              denylist_json: buildDenylistFromWizard(wizardData.exclusions),
            },
            inventory: inventorySnapshot ? [inventorySnapshot] : [],
            relevance: [],
            packs: sameExistingEngagement ? state.mission.packs : [],
            runs: [selectedRun],
            internalValidations: sameExistingEngagement ? state.mission.internalValidations : [],
            findingsByRun: {
              [run.id]: [],
            },
          },
          wizard: nextWizard,
          activeScreen: "mission-control",
          activePhase: "execution",
          missionLaunch: {
            runId: run.id,
            createdAt: Date.now(),
          },
        },
        "wizard.submit.createdRun"
      );
      runtime.actions.renderAll?.();
      await runtime.actions.refreshShell?.();
      // Force-navigate to Mission Control in case refreshShell reset the active screen
      if (state.activeScreen !== "mission-control") {
        runtime.actions.navigateToScreen?.("mission-control");
      }
    } catch (error) {
      patchWizardFields(
        { submitting: false, errors: [error.message || "Wizard submission failed."] },
        "wizard.submit.failed"
      );
      renderWizard();
      throw error;
    }
  }

  return {
    goBackConversation,
    renderWizard,
    submitConversationAnswer,
    syncWizardStepFromDom,
    validateWizardStep,
    submitWizard,
  };
}

export function buildRunConfiguration(data, estimate) {
  const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
  const engagementRoute = currentEngagementRouteContext(data);
  const assessmentMode = String(data.assessment_mode?.mode || "").trim();
  const authorizationLevel = selectedAuthorizationLevel(data);
  const authorizationScopeToken = missionScopeConfirmationToken(data);
  const authorizationScopeSummary = missionScopeConfirmationSummary(data);
  const effectiveAutoAdvance = effectiveAssessmentModeAutoAdvance(data);
  return {
    assessment_type: data.assessment_type,
    test_profile: data.test_profile,
    execution_profile: estimate.execution_profile,
    execution_plan: {
      profile_name: plan.profileName,
      run_class: plan.runClass,
      planned_tools: plan.tools,
      required_approvals: plan.requiredApprovals,
      description: plan.description,
    },
    targets: data.targets,
    exclusions: data.exclusions,
    access: {
      accounts: data.access.accounts
        .filter((account) => hasMeaningfulAccount([account]))
        .map((account) => ({
          label: account.label,
          username: account.username,
          role: account.role,
          secret_ref: account.secret_ref || null,
          api_key_ref: account.api_key_ref || null,
          bearer_token_ref: account.bearer_token_ref || null,
          session_ref: account.session_ref || null,
          mfa_notes: account.mfa_notes || null,
        })),
      manual_auth_steps: valueOrNull(data.access.manual_auth_steps),
      cookie_notes: valueOrNull(data.access.cookie_notes),
      prerequisites: normalizeAccessUnlockers(data.access?.prerequisites),
    },
    modules: data.modules,
    safety: data.safety,
    wireless: data.assessment_type === "WiFi / Wireless"
      ? {
          site: data.wireless?.site || data.targets?.wireless_sites?.[0] || null,
          adapter: data.wireless?.adapter || null,
          approved_ssids: [...(data.wireless?.approved_ssids || data.targets?.ssids || [])],
          approved_bssids: [...(data.wireless?.approved_bssids || data.targets?.bssids || [])],
          excluded_ssids: [...(data.wireless?.excluded_ssids || data.exclusions?.ssids || [])],
          excluded_bssids: [...(data.wireless?.excluded_bssids || data.exclusions?.bssids || [])],
          roe_acknowledged: Boolean(data.wireless?.roe_acknowledged),
          passive_only: true,
          rf_disruptive_actions: false,
          handshake_capture: false,
          credential_harvesting: false,
          wps_pin_testing: false,
          evil_twin: false,
          jamming: false,
        }
      : undefined,
    intake: {
      mode: "conversational-ai-guided",
      engagement_route: engagementRoute.mode,
      engagement_context: engagementRoute.configContext,
      preferences: data.intake_preferences,
      sources: state.wizard?.intake?.sources || {},
      advanced_overrides: state.wizard?.intake?.overrides || {},
      confirmation_summary: buildNaturalConfirmationSummary(estimate, data),
    },
    assessment_mode: assessmentMode
      ? {
          enabled: true,
          mode: assessmentMode,
          auto_advance_on_phase_complete: effectiveAutoAdvance,
          authorization_level: authorizationLevel,
          confirmed_scope: authorizationScopeSummary,
          confirmation_target: authorizationScopeToken || null,
          intrusive_lan_authorized: Boolean(
            normalizeAccessUnlockers(data.access?.prerequisites).intrusive_lan_authorized
          ),
          exploit_confirmation_authorized: Boolean(
            normalizeAccessUnlockers(data.access?.prerequisites).exploit_confirmation_authorized
          ),
          typed_scope_confirmation:
            authorizationLevel === "full"
              ? valueOrNull(data.assessment_mode?.typed_scope_confirmation)
              : null,
        }
      : {
          enabled: false,
        },
    eta: estimate,
  };
}

function buildAllowlistFromWizard(targets) {
  return {
    domains: [...targets.domains, ...targets.subdomains].filter(Boolean),
    urls: [...targets.urls, ...targets.api_base_urls].filter(Boolean),
    hosts: [...targets.ip_addresses].filter(Boolean),
    cidrs: [...targets.cidr_ranges].filter(Boolean),
    wireless_sites: [...(targets.wireless_sites || [])].filter(Boolean),
    ssids: [...(targets.ssids || [])].filter(Boolean),
    bssids: [...(targets.bssids || [])].filter(Boolean),
  };
}

function buildDenylistFromWizard(exclusions) {
  return {
    domains: [...(exclusions?.domains || [])].filter(Boolean),
    urls: [...(exclusions?.urls || []), ...(exclusions?.api_base_urls || [])].filter(Boolean),
    hosts: [...(exclusions?.ip_addresses || [])].filter(Boolean),
    cidrs: [...(exclusions?.cidr_ranges || [])].filter(Boolean),
    notes: exclusions?.notes ? [exclusions.notes] : [],
  };
}

function currentEngagementRouteContext(data = state.wizard?.data || {}) {
  const selectedEngagement = state.wizard?.useExistingEngagement
    ? runtime.actions.selectedEngagement?.()
    : null;
  if (state.wizard?.useExistingEngagement) {
    const engagementName = selectedEngagement?.name || data.engagement_name || "Selected engagement";
    return {
      mode: "reuse-selected-engagement",
      summaryLabel: `Reuse existing dossier · ${engagementName}`,
      configContext: {
        source: "selected-engagement",
        engagement_id: selectedEngagement?.id || null,
        engagement_name: engagementName,
        client: selectedEngagement?.client || null,
        roe_ref: selectedEngagement?.roe_ref || null,
      },
    };
  }
  const engagementName = data.engagement_name || suggestedEngagementName(data);
  return {
    mode: "create-new-engagement",
    summaryLabel: `Create new dossier · ${engagementName}`,
    configContext: {
      source: "wizard-created-engagement",
      engagement_id: null,
      engagement_name: engagementName,
      client: valueOrNull(data.client),
      roe_ref: valueOrNull(data.roe_ref),
    },
  };
}

function buildInventorySeedPayload(engagementId, data) {
  const hosts = [...data.targets.domains, ...data.targets.subdomains, ...data.targets.ip_addresses];
  const urls = [...data.targets.urls, ...data.targets.api_base_urls];
  return {
    engagement_id: engagementId,
    source_tools: ["wizard-input"],
    observations: [
      {
        tool: "wizard-input",
        kind: "inventory-seed",
        data: {
          hosts,
          urls,
          endpoints: urls.map((url) => ({
            url,
            methods: [],
            status_code: null,
            title: "Wizard-seeded target",
          })),
          auth_mechanisms: data.access.accounts.filter((account) => hasMeaningfulAccount([account])).map((account) => ({
            type: account.session_ref ? "session-context" : "credential-reference",
            location: account.role || null,
            confidence: 0.7,
          })),
          api_types: data.targets.api_base_urls.map((url) => ({ type: "rest", base_url: url, confidence: 0.7 })),
          wireless_networks: (data.targets.ssids || []).map((ssid) => ({
            ssid,
            bssid_count: (data.targets.bssids || []).length,
            bssids: [...(data.targets.bssids || [])],
            encryption: "unknown",
            auth_modes: [],
            wps: false,
            pmf: ["unknown"],
            confidence: 0.4,
          })),
          tls: data.assessment_type === "SSL/TLS Only"
            ? { protocols: ["tls"], issues: [], confidence: 0.8 }
            : undefined,
          confidence: 0.72,
        },
      },
    ],
    environment_notes: [
      `Wizard seeded assessment type: ${data.assessment_type}`,
      `Wizard profile: ${data.test_profile}`,
      `Conversation goal: ${humanizeGoal(data.intake_preferences.primary_goal)}`,
      `Safety posture: ${humanizeSafetyPosture(data.intake_preferences.safety_posture)}`,
      `Output style: ${humanizeOutputStyle(data.intake_preferences.output_style)}`,
      data.exclusions.notes ? `Boundary notes: ${data.exclusions.notes}` : "No boundary notes provided.",
    ],
    assumptions: [
      "Seed inventory was created from operator-reviewed wizard input before active discovery.",
      data.intake_preferences.boundary_handling
        ? `Boundary handling: ${data.intake_preferences.boundary_handling}`
        : "Boundary handling not explicitly set.",
      data.intake_preferences.lateral_discovery
        ? `Lateral discovery posture: ${data.intake_preferences.lateral_discovery}`
        : "Lateral discovery not requested.",
      data.access.manual_auth_steps ? `Manual auth note: ${data.access.manual_auth_steps}` : "No shared manual auth note provided.",
    ],
  };
}

export function estimateMission(data) {
  const targetsCount = flattenTargetValues(data.targets).length;
  const moduleCount = enabledModules(data.modules).length;
  const accessContextCount = countMeaningfulAccessContexts(data.access);
  const profileMultipliers = {
    "Light": 0.7,
    "Standard": 1,
    "Deep": 1.5,
    "External Surface Only": 0.85,
    "Authenticated Only": 1.15,
    "SSL/TLS Only": 0.65,
    "Internal Validation": 1.85,
    "Adaptive Customer-Specific Mode": 1.55,
  };
  const base = 24 + targetsCount * 9 + moduleCount * 4 + accessContextCount * 10 + (data.safety.adaptive_generation ? 14 : 0);
  const estimated_total_minutes = Math.round(base * (profileMultipliers[data.test_profile] || 1));
  const execution_profile = resolveExecutionProfile(data);
  const estimated_impact = data.safety.active_checks === "active" || data.test_profile === "Internal Validation"
    ? "high"
    : data.test_profile === "Deep" || data.test_profile === "Authenticated Only"
      ? "medium"
      : "low";
  const confidence = targetsCount >= 2 ? "medium" : "low";
  return {
    estimated_total_minutes,
    estimated_impact,
    confidence,
    execution_profile,
    summary: `Estimated duration ${estimated_total_minutes} minutes with ${estimated_impact} expected impact under ${execution_profile}.`,
  };
}

function resolveExecutionProfile(data) {
  const selectedTileKeys = selectedAssessmentTileKeys(state.wizard);
  const selectedTileKey = deriveAssessmentTileKey(data, state.wizard?.intake || {});
  if (data.assessment_type === "API" || selectedTileKey === "api-security" || selectedTileKeys.includes("api-security")) {
    return data.safety.active_checks === "passive-only" ? "passive-web-baseline" : "active-api-assessment";
  }
  if (selectedTileKey === "llm-ai-app" || selectedTileKeys.includes("llm-ai-app")) {
    return data.safety.active_checks === "passive-only" ? "passive-web-baseline" : "active-llm-application-probe";
  }
  if (selectedTileKey === "wifi-wireless" || selectedTileKeys.includes("wifi-wireless") || data.assessment_type === "WiFi / Wireless") {
    return "passive-wifi-survey";
  }
  if (selectedTileKey === "ssl-tls" || selectedTileKeys.includes("ssl-tls") || data.assessment_type === "SSL/TLS Only") {
    return "passive-web-baseline";
  }
  if (selectedTileKey === "authenticated-app" || selectedTileKeys.includes("authenticated-app") || data.assessment_type === "Authenticated App") {
    return data.safety.active_checks === "passive-only" ? "passive-web-baseline" : "active-web-safe";
  }
  if (targetsContainPrivateNetwork(data.targets)) {
    return "passive-network-discovery";
  }
  const externalIpWanScope =
    data.assessment_type === "External IP / WAN" &&
    flattenTargetValues(data.targets).some((value) => isLikelyIp(value) || isLikelyCidr(value));
  if (data.assessment_type === "Internal Range / LAN" || data.assessment_type === "External IP / WAN") {
    if (
      data.assessment_type === "External IP / WAN" &&
      (
        selectedTileKey === "external-infrastructure" ||
        selectedTileKeys.includes("external-infrastructure") ||
        externalIpWanScope
      )
    ) {
      if (data.safety.active_checks !== "passive-only" && data.modules.nuclei_checks) {
        return "active-external-infrastructure";
      }
      return "passive-external-infrastructure";
    }
    if (data.test_profile === "Internal Validation") return "passive-network-discovery";
    return "passive-network-discovery";
  }
  if (data.test_profile === "Internal Validation") return "intrusive-validation";
  if (data.safety.active_checks === "active" && data.modules.zap_active_checks) return "active-web-zap-active";
  if (
    data.safety.active_checks !== "passive-only" &&
    (
      data.test_profile === "Deep" ||
      data.test_profile === "Authenticated Only" ||
      data.test_profile === "Adaptive Customer-Specific Mode" ||
      data.assessment_type === "Authenticated App" ||
      data.modules.zap_active_checks
    )
  ) {
    return "active-web-safe";
  }
  if (data.test_profile === "SSL/TLS Only") return "passive-web-baseline";
  if (data.test_profile === "Standard" && data.modules.nuclei_checks) return "passive-web-nuclei-audit";
  if (data.test_profile === "Light" || data.test_profile === "External Surface Only") return "passive-web-baseline";
  return "passive-web-baseline";
}

function moduleState(enabledKeys = []) {
  const modules = Object.fromEntries(
    Object.keys(DEFAULT_MODULE_STATE).map((key) => [key, false])
  );
  enabledKeys.forEach((key) => {
    if (Object.hasOwn(modules, key)) {
      modules[key] = true;
    }
  });
  return modules;
}

function profileModulePreset(profile) {
  const presets = {
    "Light": moduleState(["discovery", "web_crawling", "nuclei_checks", "ssl_tls_analysis"]),
    "Standard": { ...DEFAULT_MODULE_STATE },
    "Deep": moduleState([
      "discovery",
      "web_crawling",
      "auth_flows",
      "content_discovery",
      "nuclei_checks",
      "zap_active_checks",
      "ssl_tls_analysis",
      "business_logic_testing",
      "adaptive_ai_generated_tests",
    ]),
    "External Surface Only": moduleState([
      "discovery",
      "web_crawling",
      "content_discovery",
      "nuclei_checks",
      "ssl_tls_analysis",
    ]),
    "Authenticated Only": moduleState([
      "web_crawling",
      "auth_flows",
      "content_discovery",
      "nuclei_checks",
      "ssl_tls_analysis",
      "business_logic_testing",
    ]),
    "SSL/TLS Only": moduleState(["ssl_tls_analysis"]),
    "Internal Validation": moduleState([
      "discovery",
      "auth_flows",
      "nuclei_checks",
      "zap_active_checks",
      "business_logic_testing",
      "internal_validation_modules",
    ]),
    "Adaptive Customer-Specific Mode": moduleState([
      "discovery",
      "web_crawling",
      "auth_flows",
      "content_discovery",
      "nuclei_checks",
      "ssl_tls_analysis",
      "business_logic_testing",
      "adaptive_ai_generated_tests",
    ]),
  };
  return { ...(presets[profile] || DEFAULT_MODULE_STATE) };
}

function profileSafetyPreset(profile) {
  const presets = {
    "Light": {
      ...DEFAULT_SAFETY,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    },
    "Deep": {
      ...DEFAULT_SAFETY,
      active_checks: "guarded",
      adaptive_generation: true,
      max_validation_depth: "deep",
    },
    "External Surface Only": {
      ...DEFAULT_SAFETY,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    },
    "Authenticated Only": {
      ...DEFAULT_SAFETY,
      active_checks: "guarded",
      adaptive_generation: false,
      max_validation_depth: "standard",
    },
    "SSL/TLS Only": {
      ...DEFAULT_SAFETY,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    },
    "Internal Validation": {
      ...DEFAULT_SAFETY,
      active_checks: "active",
      adaptive_generation: false,
      max_validation_depth: "deep",
    },
    "Adaptive Customer-Specific Mode": {
      ...DEFAULT_SAFETY,
      active_checks: "guarded",
      adaptive_generation: true,
      max_validation_depth: "deep",
    },
  };
  return { ...(presets[profile] || DEFAULT_SAFETY) };
}

function assessmentTypeProfileRecommendation(assessmentType) {
  const mapping = {
    "Website / Web App": "Standard",
    "Domain / Domains": "External Surface Only",
    "External IP / WAN": "External Surface Only",
    "Internal Range / LAN": "Standard",
    "WiFi / Wireless": "Standard",
    "API": "Standard",
    "SSL/TLS Only": "SSL/TLS Only",
    "Authenticated App": "Authenticated Only",
    "Mixed Assessment": "Adaptive Customer-Specific Mode",
  };
  return mapping[assessmentType] || "Standard";
}

function applyProfilePreset(profile) {
  const modules = profileModulePreset(profile);
  const safety = profileSafetyPreset(profile);
  Object.assign(state.wizard.data.modules, modules);
  Object.assign(state.wizard.data.safety, safety);
}

function applyAssessmentTypePreset(assessmentType) {
  const recommendation = assessmentTypeProfileRecommendation(assessmentType);
  state.wizard.data.test_profile = recommendation;
  applyProfilePreset(recommendation);

  if (assessmentType === "External IP / WAN") {
    Object.assign(state.wizard.data.modules, moduleState(["discovery", "ssl_tls_analysis"]));
    Object.assign(state.wizard.data.safety, {
      ...state.wizard.data.safety,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    });
    return;
  }

  if (assessmentType === "WiFi / Wireless") {
    state.wizard.data.test_profile = "Standard";
    Object.assign(state.wizard.data.modules, moduleState(["discovery"]));
    Object.assign(state.wizard.data.safety, {
      ...state.wizard.data.safety,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    });
    return;
  }

  if (assessmentType === "Internal Range / LAN") {
    Object.assign(state.wizard.data.modules, moduleState(["discovery"]));
    Object.assign(state.wizard.data.safety, {
      ...state.wizard.data.safety,
      active_checks: "passive-only",
      adaptive_generation: false,
      max_validation_depth: "light",
    });
    return;
  }

  if (assessmentType === "API") {
    Object.assign(
      state.wizard.data.modules,
      moduleState([
        "discovery",
        "nuclei_checks",
        "ssl_tls_analysis",
        "adaptive_ai_generated_tests",
      ])
    );
    return;
  }

  if (assessmentType === "Mixed Assessment") {
    Object.assign(
      state.wizard.data.modules,
      moduleState([
        "discovery",
        "web_crawling",
        "content_discovery",
        "nuclei_checks",
        "ssl_tls_analysis",
        "adaptive_ai_generated_tests",
      ])
    );
  }
}

function wizardStepLead(step) {
  const leads = [
    {
      title: "Choose the mission shape",
      body: "Set whether you are launching a new mission dossier or adding a new mission to an existing engagement, then choose the assessment type that best matches the target surface.",
      ask: "Name the engagement and choose the assessment type that best matches the surface you want to validate.",
      why: "This decides what scope fields appear next, how the run is classified, and which execution lane is most likely to be used.",
    },
    {
      title: "Define exactly what is in scope",
      body: "Add only the targets that should enter inventory and validation. The wizard validates core formats before anything becomes part of the mission record.",
      ask: "Provide the domains, URLs, IPs, CIDRs, or API base URLs that are explicitly allowed in scope.",
      why: "These values seed inventory, target selection, and later evidence and reporting. Over-scoping here creates noisy or risky validation later.",
    },
    {
      title: "Record access context safely",
      body: "Store operator-facing references or direct secrets. Sensitive values are moved behind protected secret bindings when the run is created.",
      ask: "Add only the credentials, sessions, or manual auth notes needed for the selected assessment profile.",
      why: "Authenticated context changes what the run can see, which findings are reachable, and how replay works later.",
    },
    {
      title: "Pick the right depth",
      body: "The test profile shapes execution safety, likely ETA, and how much adaptive testing or active validation the mission is allowed to perform.",
      ask: "Choose how deep or specialized the run should be: light, standard, deep, authenticated, TLS-only, or adaptive.",
      why: "This is the fastest way to align coverage depth with customer appetite, target sensitivity, and the expected run duration.",
    },
    {
      title: "Enable only the modules that matter",
      body: "Turn on the validation lanes you actually want. The module set directly feeds run configuration, mission progress, ETA, and reporting coverage.",
      ask: "Keep the modules that matter for this engagement and disable anything that is out of scope or not worth the runtime cost.",
      why: "Cleaner module selection produces clearer progress, less noise, and more explainable reports for the operator and customer.",
    },
    {
      title: "Set guardrails before launch",
      body: "Tune rate, concurrency, validation depth, and active-check posture so the mission stays controlled and aligned with the rules of engagement.",
      ask: "Set the pace, allowed aggressiveness, adaptive behavior, and maximum depth the run may use.",
      why: "These controls make the run safer, easier to explain, and easier to stop before it exceeds the engagement intent.",
    },
    {
      title: "Confirm what will happen next",
      body: "Review the full mission configuration before confirmation. AegisPT will create or reuse the engagement, seed inventory, create the mission record, and open Mission Control.",
      ask: "Check that the targets, access, modules, and safety settings match what you actually want to run.",
      why: "This is the last point where a human can spot a wrong target, too much depth, or the wrong access context before work is queued.",
    },
  ];
  return leads[step] || leads[0];
}

function renderWizardGuidance(lead) {
  if (!lead.ask && !lead.why) return "";
  return `
    <div class="wizard-guidance">
      <div class="guidance-card">
        <h4>What This Step Asks For</h4>
        <p>${escapeHtml(lead.ask || "Review the visible fields and provide only what this mission needs.")}</p>
      </div>
      <div class="guidance-card">
        <h4>Why It Matters</h4>
        <p>${escapeHtml(lead.why || "This input affects later execution, reporting, and evidence handling.")}</p>
      </div>
    </div>
  `;
}

function assessmentTypeCopy(type) {
  const mapping = {
    "Website / Web App": "Crawlable browser-facing surface with standard page and workflow discovery.",
    "Domain / Domains": "Domain-scoped recon and service discovery across named targets.",
    "External IP / WAN": "Perimeter validation against explicit WAN IP targets.",
    "Internal Range / LAN": "Internal network range validation with scope-controlled depth.",
    "WiFi / Wireless": "Passive wireless site, SSID/BSSID, adapter, and AP security posture review.",
    "API": "API-first assessment with base URLs, auth context, and protocol-aware testing.",
    "SSL/TLS Only": "Certificate, protocol, and crypto posture validation only.",
    "Authenticated App": "Application validation where session or credentialed access is central.",
    "Mixed Assessment": "Combined web, API, network, auth, and adaptive workflows.",
  };
  return mapping[type] || "Assessment type";
}

function testProfileCopy(profile) {
  const mapping = {
    "Light": "Faster low-impact coverage with emphasis on passive discovery and fingerprinting.",
    "Standard": "Balanced baseline suited for most scoped engagements.",
    "Deep": "Broader active depth with more validation time and review overhead.",
    "External Surface Only": "Focus on exposed surface and perimeter posture without deeper auth flows.",
    "Authenticated Only": "Prioritize account-context workflows, auth paths, and role behavior.",
    "SSL/TLS Only": "Only certificate and transport protection analysis.",
    "Internal Validation": "Approval-heavy validation for controlled internal adversary simulation.",
    "Adaptive Customer-Specific Mode": "Inventory-informed plus adaptive pack generation before deeper validation.",
  };
  return mapping[profile] || "Profile";
}

function moduleCopy(key) {
  const mapping = {
    discovery: "Resolve targets, fingerprints, and accessible surface safely.",
    web_crawling: "Build page and route coverage for browser-facing applications.",
    auth_flows: "Exercise login, session, and role-aware access paths.",
    content_discovery: "Enumerate discoverable content and hidden application routes.",
    nuclei_checks: "Run templated security probes through the managed validation lane.",
    zap_active_checks: "Use approval-aware ZAP active checks where safety allows.",
    ssl_tls_analysis: "Inspect certificate and transport security posture.",
    business_logic_testing: "Investigate workflow abuse and privilege or process edge cases.",
    adaptive_ai_generated_tests: "Enable customer-specific adaptive checks from Pack Forge.",
    internal_validation_modules: "Prepare internal validation modules and scenarios.",
  };
  return mapping[key] || key;
}

function visibleTargetGroups(assessmentType) {
  const base = ["domains", "urls"];
  if (assessmentType === "WiFi / Wireless") return ["wireless_sites", "ssids", "bssids"];
  if (assessmentType === "API") return ["api_base_urls", "urls", "domains"];
  if (assessmentType === "SSL/TLS Only") return ["domains", "urls", "ip_addresses"];
  if (assessmentType === "External IP / WAN") return ["ip_addresses", "cidr_ranges"];
  if (assessmentType === "Internal Range / LAN") return ["cidr_ranges", "ip_addresses"];
  if (assessmentType === "Domain / Domains") return ["domains", "subdomains", "urls"];
  if (assessmentType === "Authenticated App") return ["urls", "domains", "api_base_urls"];
  if (assessmentType === "Mixed Assessment") return ["domains", "subdomains", "urls", "ip_addresses", "cidr_ranges", "api_base_urls"];
  return [...base, "subdomains"];
}

function currentWizardFormStep() {
  const advancedStep = Number(state.wizard?.advancedStep);
  if (Number.isInteger(advancedStep) && advancedStep >= 0) return advancedStep;
  const step = Number(state.wizard?.step);
  return Number.isInteger(step) && step >= 0 ? step : 0;
}

function snapshotEngagementNameContext(data) {
  return {
    engagement_name: stringValue(data.engagement_name),
    assessment_type: data.assessment_type,
    targets: {
      domains: [...(data.targets?.domains || [])],
      subdomains: [...(data.targets?.subdomains || [])],
      urls: [...(data.targets?.urls || [])],
      ip_addresses: [...(data.targets?.ip_addresses || [])],
      cidr_ranges: [...(data.targets?.cidr_ranges || [])],
      api_base_urls: [...(data.targets?.api_base_urls || [])],
      wireless_sites: [...(data.targets?.wireless_sites || [])],
      ssids: [...(data.targets?.ssids || [])],
      bssids: [...(data.targets?.bssids || [])],
    },
    intake_preferences: {
      primary_goal: data.intake_preferences?.primary_goal || "",
    },
    test_profile: data.test_profile,
  };
}

function refreshSuggestedEngagementNameIfAutomatic(previousContext, data = state.wizard?.data) {
  const previousName = stringValue(previousContext?.engagement_name);
  const previousSuggestedName = suggestedEngagementName(previousContext || data);
  if (!previousName || previousName === previousSuggestedName) {
    data.engagement_name = suggestedEngagementName(data);
  }
}

function suggestedEngagementName(data) {
  const firstTarget = flattenTargetValues(data.targets)[0];
  const base = firstTarget
    ? String(firstTarget).replace(/^https?:\/\//i, "").replace(/[^a-z0-9./:-]+/gi, " ").trim()
    : humanizeAssessmentTypeShort(data.assessment_type);
  const goal = humanizeGoal(data.intake_preferences.primary_goal || goalForProfile(data.test_profile)).replace(/\s+/g, " ");
  return `${base || "Mission"} ${goal}`.trim();
}

function humanizeAssessmentTypeShort(value) {
  const mapping = {
    "Website / Web App": "Web App",
    "Domain / Domains": "Domain",
    "External IP / WAN": "External Surface",
    "Internal Range / LAN": "Internal Range",
    "WiFi / Wireless": "WiFi",
    "API": "API",
    "SSL/TLS Only": "TLS",
    "Authenticated App": "Authenticated App",
    "Mixed Assessment": "Mixed Surface",
  };
  return mapping[value] || String(value || "Mission");
}

function humanizeGoal(value) {
  const mapping = {
    "quick-overview": "Quick Overview",
    "inventory-first": "Inventory First",
    "standard-assessment": "Standard Assessment",
    "deep-assessment": "Deep Assessment",
    "authenticated-review": "Authenticated Review",
    "adaptive-coverage": "Adaptive Customer-Specific Testing",
    "internal-validation": "Internal Validation",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function humanizeOutputStyle(value) {
  const mapping = {
    "detailed-per-item": "Detailed Per Item",
    "balanced-technical": "Balanced Technical",
    "technical-detail": "Technical Detail",
    "executive-summary": "Executive Summary",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function humanizeBoundaryHandling(value) {
  const mapping = {
    "standard-scope-only": "Standard Scope Only",
    "report-adjacent-ranges-only": "Report Adjacent Ranges Only",
    "approved-lateral-discovery": "Approved Lateral Discovery",
    "custom-exclusions": "Custom Exclusions Recorded",
    "notes-only-boundaries": "Boundary Notes Recorded",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function humanizeSafetyPosture(value) {
  const mapping = {
    conservative: "Conservative",
    balanced: "Balanced",
    thorough: "Thorough",
    "passive-only": "Passive Only",
    aggressive: "Aggressive with Approval",
  };
  return mapping[String(value || "").trim()] || String(value || "Not set");
}

function summarizeAuthStrategy(data) {
  const strategy = String(data.intake_preferences.auth_strategy || "").trim();
  const accessSummary = renderAccessContextSummary(data.access);
  const mapping = {
    unauthenticated: "Unauthenticated",
    credentialed: accessSummary !== "No account context recorded" ? accessSummary : "Credentialed access planned",
    "api-access": accessSummary !== "No account context recorded" ? accessSummary : "API token or key access planned",
    "session-access": accessSummary !== "No account context recorded" ? accessSummary : "Session-based access planned",
    "advanced-details": "Access details to be finalized in Advanced Configuration",
  };
  return mapping[strategy] || accessSummary;
}

function summarizeBoundaries(data) {
  const exclusionSummary = renderExclusionSummary(data.exclusions);
  const notes = stringValue(data.exclusions.notes);
  const lateral = data.intake_preferences.lateral_discovery;
  const lateralSummary = lateral === "requested"
    ? "Lateral discovery requested within approved internal limits"
    : lateral === "report-only"
      ? "Adjacent internal ranges reported only"
      : "No lateral expansion";
  if (notes && exclusionSummary !== "No denylist recorded") {
    return `${exclusionSummary} · ${notes}`;
  }
  if (notes) return `${lateralSummary} · ${notes}`;
  if (exclusionSummary !== "No denylist recorded") return `${lateralSummary} · ${exclusionSummary}`;
  return lateralSummary;
}

function renderExclusionSummary(exclusions) {
  const count = countExplicitExclusions(exclusions);
  if (!count && !hasBoundaryNotes(exclusions)) return "No denylist recorded";
  if (!count) return "Boundary notes only";
  return `${count} explicit exclusion${count === 1 ? "" : "s"}`;
}

function countExplicitExclusions(exclusions) {
  return flattenTargetValues({
    domains: exclusions?.domains || [],
    urls: exclusions?.urls || [],
    ip_addresses: exclusions?.ip_addresses || [],
    cidr_ranges: exclusions?.cidr_ranges || [],
    api_base_urls: exclusions?.api_base_urls || [],
  }).length;
}

function hasBoundaryNotes(exclusions) {
  return Boolean(stringValue(exclusions?.notes));
}

function clearAccessContext() {
  state.wizard.data.access = {
    accounts: [buildEmptyAccount()],
    manual_auth_steps: "",
    cookie_notes: "",
  };
}

function unauthenticatedProfileRecommendation(assessmentType) {
  const mapping = {
    "Website / Web App": "Standard",
    "Domain / Domains": "External Surface Only",
    "External IP / WAN": "External Surface Only",
    "Internal Range / LAN": "Standard",
    "API": "Standard",
    "SSL/TLS Only": "SSL/TLS Only",
    "Authenticated App": "Standard",
    "Mixed Assessment": "Standard",
  };
  return mapping[assessmentType] || "Standard";
}

function alignPlanForUnauthenticatedAccess() {
  const data = state.wizard.data;
  const intake = state.wizard.intake;
  let changed = false;

  if (data.intake_preferences.primary_goal === "authenticated-review") {
    data.intake_preferences.primary_goal = "standard-assessment";
    if (intake.sources.goal !== "still-needed") {
      intake.sources.goal = "inferred";
    }
    changed = true;
  }

  if (data.test_profile === "Authenticated Only") {
    const fallbackProfile = unauthenticatedProfileRecommendation(data.assessment_type);
    if (fallbackProfile !== data.test_profile) {
      data.test_profile = fallbackProfile;
      intake.overrides.profile = false;
      changed = true;
      if (!intake.overrides.modules && !intake.overrides.safety) {
        applyProfilePreset(fallbackProfile);
      } else {
        if (!intake.overrides.modules) {
          Object.assign(data.modules, profileModulePreset(fallbackProfile));
        }
        if (!intake.overrides.safety) {
          Object.assign(data.safety, profileSafetyPreset(fallbackProfile));
        }
      }
    }
  }

  data.modules.auth_flows = false;
  return changed;
}

function buildEmptyExclusions() {
  return {
    domains: [],
    urls: [],
    ip_addresses: [],
    cidr_ranges: [],
    api_base_urls: [],
    notes: "",
  };
}

function effectiveBoundaryHandling(data = state.wizard.data) {
  const explicit = String(data?.intake_preferences?.boundary_handling || "").trim();
  if (explicit) return explicit;
  const exclusions = data?.exclusions || {};
  if (countExplicitExclusions(exclusions)) return "custom-exclusions";
  if (hasBoundaryNotes(exclusions)) return "notes-only-boundaries";
  return "standard-scope-only";
}

function requiresExplicitBoundaryConfirmation(data = state.wizard.data) {
  const assessmentType = String(data?.assessment_type || "").trim();
  const goal = String(data?.intake_preferences?.primary_goal || "").trim();
  const authStrategy = String(data?.intake_preferences?.auth_strategy || "").trim();
  const supportedAssessmentTypes = new Set([
    "Website / Web App",
    "Domain / Domains",
    "External IP / WAN",
    "Internal Range / LAN",
    "API",
    "SSL/TLS Only",
    "Authenticated App",
    "Mixed Assessment",
  ]);

  if (supportedAssessmentTypes.has(assessmentType)) return true;
  if (assessmentType === "Internal Range / LAN" || goal === "internal-validation") return true;
  if (assessmentType === "SSL/TLS Only") return true;
  if (assessmentType === "Mixed Assessment") return true;
  if (goal === "adaptive-coverage") return true;
  if (["credentialed", "api-access", "session-access", "advanced-details"].includes(authStrategy)) return true;
  return false;
}

function resetBoundaryConfirmationAfterScopeChange({
  previousAssessmentType,
  previousBoundaryRequirement,
  previousBoundaryHandling,
  previousLateralDiscovery,
  previousHasExplicitBoundaryScope,
}) {
  const assessmentChanged = previousAssessmentType !== state.wizard.data.assessment_type;
  const currentBoundaryRequirement = requiresExplicitBoundaryConfirmation(state.wizard.data);
  const boundaryRequirementChanged = previousBoundaryRequirement !== currentBoundaryRequirement;
  const currentAssessmentType = String(state.wizard.data.assessment_type || "").trim();
  const shouldClearInternalLateralScope =
    currentAssessmentType !== "Internal Range / LAN" &&
    !previousHasExplicitBoundaryScope &&
    (
      previousBoundaryHandling === "report-adjacent-ranges-only" ||
      ["requested", "report-only", "authorized-allowlist-only"].includes(String(previousLateralDiscovery || "").trim())
    );

  if (shouldClearInternalLateralScope) {
    state.wizard.data.intake_preferences.boundary_handling = "";
    state.wizard.data.intake_preferences.lateral_discovery = "not-requested";
    state.wizard.intake.sources.boundaries = currentBoundaryRequirement ? "still-needed" : "inferred";
    return;
  }

  if (!assessmentChanged && !boundaryRequirementChanged) return;
  if (previousHasExplicitBoundaryScope) return;
  if (previousBoundaryHandling !== "standard-scope-only") return;

  state.wizard.data.intake_preferences.boundary_handling = "";
  state.wizard.intake.sources.boundaries = currentBoundaryRequirement ? "still-needed" : "inferred";
}

function shouldAskAuthQuestion(data) {
  if (["Authenticated App", "API", "Mixed Assessment"].includes(data.assessment_type)) return true;
  if (["authenticated-review", "internal-validation"].includes(data.intake_preferences.primary_goal)) return true;
  if (data.test_profile === "Authenticated Only") return true;
  if (
    data.modules.auth_flows &&
    ["Internal Range / LAN"].includes(String(data.assessment_type || "").trim())
  ) {
    return true;
  }
  return false;
}

function needsAuthDetails(data) {
  const strategy = String(data.intake_preferences.auth_strategy || "").trim();
  if (!strategy || ["unauthenticated", "advanced-details"].includes(strategy)) return false;
  return !hasMeaningfulAccessContext(data.access);
}

function inferAssessmentType(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(active directory|domain controller|ldap|kerberos|bloodhound|sharphound)\b/.test(normalized)) return "Internal Range / LAN";
  if (/\b(cloud|aws|azure|gcp|subscription|tenant)\b/.test(normalized)) return "Mixed Assessment";
  if (/\b(wifi|wi-fi|wireless|ssid|bssid|wlan)\b/.test(normalized)) return "WiFi / Wireless";
  if (/\b(llm|ai app|ai application|prompt injection|agentic)\b/.test(normalized)) return "Website / Web App";
  if (/\b(mixed|hybrid|both web and api|web and api)\b/.test(normalized)) return "Mixed Assessment";
  if (/\b(api|graphql|swagger|openapi)\b/.test(normalized)) return "API";
  if (/\b(wan|public ip|external ip|perimeter|internet-facing ip)\b/.test(normalized)) return "External IP / WAN";
  if (/\b(lan|internal|subnet|cidr|network|range)\b/.test(normalized)) return "Internal Range / LAN";
  if (/\b(tls|ssl|certificate|cipher)\b/.test(normalized)) return "SSL/TLS Only";
  if (/\b(authenticated app|portal with login|logged[- ]in portal)\b/.test(normalized)) return "Authenticated App";
  if (/\b(customer|client|member|partner|admin)\s+portal\b/.test(normalized)) return "Authenticated App";
  if (/\bportal\b.*\b(login|sign[- ]?in|account|accounts|dashboard)\b/.test(normalized)) return "Authenticated App";
  if (/\b(domain|domains|dns)\b/.test(normalized)) return "Domain / Domains";
  if (/\b(app|portal|website|site|web application|web app)\b/.test(normalized)) return "Website / Web App";
  return null;
}

function shouldPreserveAssessmentType(currentType, inferredType) {
  const preserveMap = {
    "SSL/TLS Only": ["Domain / Domains", "Website / Web App"],
    "Authenticated App": ["Website / Web App", "Domain / Domains"],
  };
  return (preserveMap[currentType] || []).includes(inferredType);
}

function inferAssessmentTypeFromTargets(parsed) {
  if ((parsed.wireless_sites || []).length || (parsed.ssids || []).length || (parsed.bssids || []).length) return "WiFi / Wireless";
  const hasDomains = parsed.domains.length || parsed.subdomains.length;
  const hasUrls = parsed.urls.length;
  const hasApi = parsed.api_base_urls.length;
  const hasIps = parsed.ip_addresses.length;
  const hasCidrs = parsed.cidr_ranges.length;

  if ((hasCidrs || hasIps) && !(hasDomains || hasUrls || hasApi)) {
    const privateOnly = [...parsed.ip_addresses, ...parsed.cidr_ranges.map((item) => item.split("/")[0])]
      .every((value) => isPrivateIp(value));
    return privateOnly ? "Internal Range / LAN" : "External IP / WAN";
  }
  if (hasApi && (hasDomains || hasUrls || hasIps || hasCidrs)) return "Mixed Assessment";
  if (hasApi) return "API";
  if (hasUrls) return "Website / Web App";
  if (hasDomains) return "Domain / Domains";
  return null;
}

function inferPrimaryGoal(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(passive only|passive)\b/.test(normalized)) return "inventory-first";
  if (/\b(active scan|active)\b/.test(normalized)) return "standard-assessment";
  if (/\b(full including exploitation|full)\b/.test(normalized)) return "deep-assessment";
  if (/\b(quick perimeter overview|perimeter overview)\b/.test(normalized)) return "quick-overview";
  if (/\b(quick|overview|high level|light)\b/.test(normalized)) return "quick-overview";
  if (/\b(perimeter review)\b/.test(normalized)) return "standard-assessment";
  if (/\b(inventory|visibility|enumeration|per[- ]item|asset list)\b/.test(normalized)) return "inventory-first";
  if (/\b(authenticated|portal account|logged[- ]in|role[- ]based)\b/.test(normalized)) return "authenticated-review";
  if (/\b(adaptive follow[- ]up after discovery|adaptive follow[- ]up)\b/.test(normalized)) return "adaptive-coverage";
  if (/\b(adaptive|customer-specific|custom pack|codex|ai-generated)\b/.test(normalized)) return "adaptive-coverage";
  if (/\b(internal validation|adversary|lateral|privilege escalation)\b/.test(normalized)) return "internal-validation";
  if (/\b(deep follow[- ]up after discovery|deep follow[- ]up)\b/.test(normalized)) return "deep-assessment";
  if (/\b(deep|thorough|full test|full pentest|in-depth)\b/.test(normalized)) return "deep-assessment";
  if (/\b(standard|normal|balanced)\b/.test(normalized)) return "standard-assessment";
  return null;
}

function inferOutputStyle(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(per item|each item|clear information per found item|detailed visibility)\b/.test(normalized)) return "detailed-per-item";
  if (/\b(technical|deep detail|full detail)\b/.test(normalized)) return "technical-detail";
  if (/\b(executive|leadership|summary)\b/.test(normalized)) return "executive-summary";
  if (/\b(balanced|normal)\b/.test(normalized)) return "balanced-technical";
  return null;
}

function inferAuthStrategy(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(unauthenticated|unauth|no auth|without auth|guest only|keep it unauthenticated|no credentials)\b/.test(normalized)) return "unauthenticated";
  if (/\b(advanced settings|advanced config|i will add.*advanced)\b/.test(normalized)) return "advanced-details";
  if (/\b(token|tokens|api key|api keys|apikey|apikeys|bearer)\b/.test(normalized)) return "api-access";
  if (/\b(cookie|cookies|session|sessions)\b/.test(normalized)) return "session-access";
  if (/\b(account|accounts|username|password|portal account|portal accounts|credentials|login)\b/.test(normalized)) return "credentialed";
  return null;
}

function inferLateralDiscovery(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(report adjacent|report reachable|report only)\b/.test(normalized)) return "report-only";
  if (/\b(reach other internal|discover other internal|lateral|adjacent internal)\b/.test(normalized)) return "requested";
  return null;
}

function inferSafetyPosture(answer) {
  const normalized = String(answer || "").toLowerCase();
  if (/\b(passive only|passive)\b/.test(normalized)) return "passive-only";
  if (/\b(conservative|careful|cautious|safe)\b/.test(normalized)) return "conservative";
  if (/\b(aggressive|intrusive|exploit)\b/.test(normalized)) return "aggressive";
  if (/\b(thorough|deep)\b/.test(normalized)) return "thorough";
  if (/\b(balanced|standard|normal|guarded)\b/.test(normalized)) return "balanced";
  return null;
}

function inferStandaloneSafetyAnswer(answer) {
  const normalized = String(answer || "").trim().toLowerCase();
  if (/^(passive only|passive)(?:[.!])?$/.test(normalized)) return "passive-only";
  if (/^(conservative|careful|cautious|safe)(?:[.!])?$/.test(normalized)) return "conservative";
  if (/^(aggressive|intrusive|exploit|aggressive with approval)(?:[.!])?$/.test(normalized)) return "aggressive";
  if (/^(thorough|deep)(?:[.!])?$/.test(normalized)) return "thorough";
  if (/^(balanced|standard|normal|guarded)(?:[.!])?$/.test(normalized)) return "balanced";
  return null;
}

function summarizeBoundaryReplyOptions(assessmentType) {
  const quickReplies = assessmentType === "Internal Range / LAN"
    ? ["No extra exclusions", "Report adjacent internal ranges only"]
    : ["No extra exclusions"];
  const customOption = "custom exclusions / boundary notes";
  if (!quickReplies.length) return customOption;
  if (quickReplies.length === 1) return `${quickReplies[0]} or ${customOption}`;
  return `${quickReplies.join(", ")}, or ${customOption}`;
}

function containsUnauthorizedExpansion(answer) {
  const normalized = String(answer || "").toLowerCase();
  const riskyBroadPhrases = [
    "scan the internet",
    "anything reachable",
    "anything public",
    "whatever you can find",
    "all public websites",
    "look around everywhere",
    "scan random public targets",
  ];
  return riskyBroadPhrases.some((phrase) => normalized.includes(phrase));
}

function parseTargetsFromText(answer) {
  const text = String(answer || "");
  const isScopeRevision = state.wizard.intake.reviewQuestionId === "scope";
  const urls = [...text.matchAll(/https?:\/\/[^\s,;]+/gi)].map((match) => match[0].replace(/[.)]+$/, ""));
  const cidrs = [...text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}\b/g)].map((match) => match[0]);
  const ips = [...text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)]
    .map((match) => match[0])
    .filter((value) => !cidrs.some((cidr) => cidr.startsWith(`${value}/`)));
  const domains = [...text.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi)]
    .map((match) => match[0].toLowerCase())
    .filter((value) => !urls.some((url) => {
      try {
        return new URL(url).hostname.toLowerCase() === value;
      } catch {
        return false;
      }
    }));

  const parsed = {
    domains: [],
    subdomains: [],
    urls: [],
    ip_addresses: [],
    cidr_ranges: [],
    api_base_urls: [],
  };
  const seen = {
    domains: new Set(),
    subdomains: new Set(),
    urls: new Set(),
    ip_addresses: new Set(),
    cidr_ranges: new Set(),
    api_base_urls: new Set(),
  };

  cidrs.forEach((value) => addUniqueTarget(parsed, seen, "cidr_ranges", value));
  ips.forEach((value) => addUniqueTarget(parsed, seen, "ip_addresses", value));
  urls.forEach((value) => {
    const preserveApiUrlBias =
      state.wizard.data.assessment_type === "API" &&
      !isScopeRevision;
    if (looksLikeApiUrl(value) || preserveApiUrlBias) {
      addUniqueTarget(parsed, seen, "api_base_urls", value);
      return;
    }
    addUniqueTarget(parsed, seen, "urls", value);
  });
  domains.forEach((value) => {
    const key = value.split(".").length > 2 ? "subdomains" : "domains";
    addUniqueTarget(parsed, seen, key, value);
  });
  return parsed;
}

function addUniqueTarget(parsed, seen, key, value) {
  const normalized = String(value || "").trim();
  if (!normalized || seen[key].has(normalized)) return;
  seen[key].add(normalized);
  parsed[key].push(normalized);
}

function looksLikeApiUrl(value) {
  try {
    const url = new URL(value);
    return /^api\./i.test(url.hostname) || /\/(api|graphql|v\d+)(\/|$)/i.test(url.pathname);
  } catch {
    return false;
  }
}

function buildAccountFromFreeText(answer) {
  const account = buildEmptyAccount();
  const usernameMatch = answer.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i) || answer.match(/\buser(name)?[:=]?\s*([^\s,;]+)/i);
  const labelMatch = !usernameMatch
    ? answer.match(/^\s*([^,\n]+?)\s+role[:=]?\s+/i)
    : null;
  const roleMatch = answer.match(
    /\brole[:=]?\s+([a-z0-9 _-]+?)(?=\s+(secret|password|api[- ]?key|key|bearer|session|cookie)\b|\s+(vault:\/\/|env:\/\/|secret:\/\/)|$)/i
  );
  const secretMatch = answer.match(/\b(secret|password)[:=]?\s+([^\s,;]+)/i);
  const apiKeyMatch = answer.match(/\b(api[- ]?key|key)[:=]?\s+([^\s,;]+)/i);
  const bearerMatch = answer.match(/\bbearer[:=]?\s+([^\s,;]+)/i);
  const sessionMatch = answer.match(/\b(session|cookie)[:=]?\s+(?!role\b)([^\s,;]+)/i);

  account.username = usernameMatch ? (usernameMatch[2] || usernameMatch[0]) : "";
  account.role = roleMatch ? roleMatch[1].trim() : account.role;
  account.secret_ref = secretMatch ? secretMatch[2].trim() : "";
  account.api_key_ref = apiKeyMatch ? apiKeyMatch[2].trim() : "";
  account.bearer_token_ref = bearerMatch ? bearerMatch[1].trim() : "";
  account.session_ref = sessionMatch ? sessionMatch[2].trim() : "";
  account.label = labelMatch?.[1]?.trim() || account.role || account.username || "Primary Account";

  if (!account.secret_ref && !account.api_key_ref && !account.bearer_token_ref && !account.session_ref) {
    const vaultLike = answer.match(/\b(vault:\/\/[^\s,;]+|env:\/\/[^\s,;]+|secret:\/\/[^\s,;]+)\b/i);
    if (vaultLike) {
      account.secret_ref = vaultLike[1];
    }
  }
  return account;
}

function looksLikeStructuredAccessDetail(answer) {
  const text = String(answer || "");
  if (!text.trim()) return false;
  if (/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(text)) return true;
  if (/\buser(name)?[:=]?\s*[^\s,;]+/i.test(text)) return true;
  if (/\brole[:=]?\s+[a-z0-9 _-]+/i.test(text)) return true;
  if (/\b(secret|password|api[- ]?key|key|bearer)[:=]?\s+[^\s,;]+/i.test(text)) return true;
  if (/\b(vault:\/\/[^\s,;]+|env:\/\/[^\s,;]+|secret:\/\/[^\s,;]+)\b/i.test(text)) return true;
  if (/\b(session|cookie)[:=]\s*[^\s,;]+/i.test(text)) return true;
  if (/\b(session|cookie)\s+[^\s,;=]+=[^\s,;]+/i.test(text)) return true;
  return false;
}

function draftAuthDetailsText(access) {
  const meaningfulAccounts = (access?.accounts || []).filter((account) => hasMeaningfulAccount([account]));
  const lines = meaningfulAccounts.map((account) => {
    const parts = [];
    const labelOnly =
      !account.username &&
      stringValue(account.label) &&
      account.label !== account.role &&
      account.label !== "Primary Account";
    if (account.username) parts.push(account.username);
    else if (labelOnly) parts.push(account.label);
    if (account.role) parts.push(`role ${account.role}`);
    if (account.secret_ref) parts.push(`secret ${account.secret_ref}`);
    if (account.api_key_ref) parts.push(`api-key ${account.api_key_ref}`);
    if (account.bearer_token_ref) parts.push(`bearer ${account.bearer_token_ref}`);
    if (account.session_ref) parts.push(`session ${account.session_ref}`);
    return parts.join(" ").trim();
  }).filter(Boolean);

  if (lines.length) return lines.join("\n");
  if (stringValue(access?.manual_auth_steps)) return access.manual_auth_steps.trim();
  if (stringValue(access?.cookie_notes)) return access.cookie_notes.trim();
  return "";
}

function preferredAuthRevisionQuestionId(data) {
  const strategy = String(data?.intake_preferences?.auth_strategy || "").trim();
  const hasCapturedAccessDetail = hasMeaningfulAccessContext(data?.access || {});
  if (
    ["credentialed", "api-access", "session-access"].includes(strategy) &&
    (hasCapturedAccessDetail || needsAuthDetails(data))
  ) {
    return "auth-details";
  }
  return "auth";
}

function draftAuthStrategyText(data) {
  const strategy = String(data?.intake_preferences?.auth_strategy || "").trim();
  if (strategy === "unauthenticated") return "Keep it unauthenticated";
  if (strategy === "advanced-details") return "I will add access in advanced settings";
  if (strategy === "api-access") return "I have API tokens or keys";
  if (strategy === "session-access") return "I have a session reference";
  if (strategy === "credentialed") return "I have portal/app accounts";
  return summarizeAuthStrategy(data);
}

function draftBoundariesText(data) {
  const notes = stringValue(data?.exclusions?.notes);
  const explicitExclusions = flattenTargetValues(data?.exclusions || {});
  const boundaryHandling = String(data?.intake_preferences?.boundary_handling || "").trim();
  const lateral = String(data?.intake_preferences?.lateral_discovery || "").trim();

  if (
    boundaryHandling === "report-adjacent-ranges-only" ||
    ["requested", "report-only", "authorized-allowlist-only"].includes(lateral)
  ) {
    return "Report adjacent internal ranges only";
  }
  if (!notes && !explicitExclusions.length) {
    return "No extra exclusions";
  }
  if (notes) return notes;
  return explicitExclusions.join("\n");
}

function normalizeGoalForAssessmentType(goal, assessmentType) {
  if (goal === "internal-validation" && assessmentType !== "Internal Range / LAN") {
    return {
      goal: "deep-assessment",
      changed: true,
      reason: `Internal validation stays reserved for approved internal ranges. With the current ${assessmentType.toLowerCase()} scope I will shape this as a deep assessment unless you switch the mission back to an internal CIDR.`,
    };
  }
  if (assessmentType === "SSL/TLS Only") {
    if (goal === "inventory-first") {
      return {
        goal: "quick-overview",
        changed: true,
        reason: "TLS-only missions stay limited to certificate, protocol, and crypto posture. I will shape this as a quick overview unless you switch to a broader web, API, or network assessment.",
      };
    }
    if (["deep-assessment", "adaptive-coverage", "authenticated-review", "internal-validation"].includes(goal)) {
      return {
        goal: "standard-assessment",
        changed: true,
        reason: "TLS-only missions stay limited to certificate, protocol, and crypto posture. I will shape this as a standard TLS-only assessment unless you switch to a broader application or network mission.",
      };
    }
  }
  return { goal, changed: false, reason: "" };
}

function internalDiscoveryFirstCompatibility(data) {
  if (data.assessment_type !== "Internal Range / LAN") return null;

  const goal = String(data.intake_preferences.primary_goal || "").trim();
  const strategy = String(data.intake_preferences.auth_strategy || "").trim();
  const hasAccessPlan = Boolean(strategy && strategy !== "unauthenticated");

  if (goal === "authenticated-review" && hasAccessPlan) {
    return {
      profile: "Standard",
      reason:
        "Authenticated review against an internal range starts with staged discovery. I will keep the planned access context attached to this mission and begin with a discovery-first internal run until reachable services are confirmed.",
      confirmationLine:
        "I will begin with live network discovery under the Standard profile, keep the planned access context attached to this mission, and surface credential-aware follow-up options once reachable services are confirmed.",
    };
  }

  if (goal === "deep-assessment") {
    return {
      profile: "Standard",
      reason: hasAccessPlan
        ? "Deep assessment against an internal range starts with staged discovery. I will keep the planned access context attached to this mission, begin with a discovery-first internal run, and surface deeper follow-up validation once reachable hosts and services are confirmed."
        : "Deep assessment against an internal range starts with staged discovery. I will begin with a discovery-first internal run and surface deeper follow-up validation once reachable hosts and services are confirmed.",
      confirmationLine: hasAccessPlan
        ? "I will begin with live network discovery under the Standard profile, keep the planned access context attached to this mission, and surface deeper follow-up validation once reachable hosts and services are confirmed."
        : "I will begin with live network discovery under the Standard profile and surface deeper follow-up validation once reachable hosts and services are confirmed.",
    };
  }

  if (goal === "adaptive-coverage") {
    return {
      profile: "Standard",
      reason: hasAccessPlan
        ? "Adaptive customer-specific testing against an internal range starts with staged discovery. I will keep the planned access context attached to this mission, begin with a discovery-first internal run, and surface adaptive follow-up coverage once the reachable inventory is confirmed."
        : "Adaptive customer-specific testing against an internal range starts with staged discovery. I will begin with a discovery-first internal run and surface adaptive follow-up coverage once the reachable inventory is confirmed.",
      confirmationLine: hasAccessPlan
        ? "I will begin with live network discovery under the Standard profile, keep the planned access context attached to this mission, and surface adaptive customer-specific follow-up coverage once the reachable inventory is confirmed."
        : "I will begin with live network discovery under the Standard profile and surface adaptive customer-specific follow-up coverage once the reachable inventory is confirmed.",
    };
  }

  return null;
}

function externalPerimeterDiscoveryCompatibility(data) {
  if (data.assessment_type !== "External IP / WAN") return null;

  const goal = String(data.intake_preferences.primary_goal || "").trim();
  const strategy = String(data.intake_preferences.auth_strategy || "").trim();
  const hasAccessPlan = Boolean(strategy && strategy !== "unauthenticated");

  if (goal === "authenticated-review" && hasAccessPlan) {
    return {
      profile: "External Surface Only",
      reason:
        "Authenticated review against explicit WAN IP scope starts with staged perimeter discovery. I will keep the planned access context attached to this mission, begin with a passive perimeter discovery run, and surface access-aware follow-up options once reachable services and protected application surfaces are confirmed.",
      confirmationLine:
        "I will begin with passive perimeter discovery under the External Surface Only profile, keep the planned access context attached to this mission, and surface access-aware follow-up options once reachable services and protected application surfaces are confirmed.",
    };
  }

  if (goal === "deep-assessment") {
    return {
      profile: "External Surface Only",
      reason:
        "Deep assessment against explicit WAN IP scope starts with staged perimeter discovery. I will begin with a passive perimeter discovery run and surface deeper service-aware follow-up validation once reachable hosts and services are confirmed.",
      confirmationLine:
        "I will begin with passive perimeter discovery under the External Surface Only profile and surface deeper service-aware follow-up validation once reachable hosts and services are confirmed.",
    };
  }

  if (goal === "adaptive-coverage") {
    return {
      profile: "External Surface Only",
      reason:
        "Adaptive customer-specific testing against explicit WAN IP scope starts with staged perimeter discovery. I will begin with a passive perimeter discovery run and surface adaptive customer-specific follow-up coverage once reachable hosts and services are confirmed.",
      confirmationLine:
        "I will begin with passive perimeter discovery under the External Surface Only profile and surface adaptive customer-specific follow-up coverage once reachable hosts and services are confirmed.",
    };
  }

  if (!goal || goal === "standard-assessment") {
    return {
      profile: "External Surface Only",
      reason:
        "External IP scope starts with staged perimeter discovery. I will begin with passive perimeter discovery and only surface deeper service-aware follow-up once reachable hosts and services are confirmed.",
      confirmationLine:
        "I will begin with passive perimeter discovery under the External Surface Only profile and surface deeper follow-up validation once reachable hosts and services are confirmed.",
    };
  }

  return null;
}

function stagedDiscoveryCompatibility(data) {
  return internalDiscoveryFirstCompatibility(data) || externalPerimeterDiscoveryCompatibility(data);
}

function reconcileGoalCompatibility(sourceWhenNormalized = "inferred") {
  const data = state.wizard.data;
  const intake = state.wizard.intake;
  const normalized = normalizeGoalForAssessmentType(
    data.intake_preferences.primary_goal,
    data.assessment_type,
  );
  let changed = normalized.changed;
  let reason = normalized.reason;

  if (normalized.changed) {
    data.intake_preferences.primary_goal = normalized.goal;
    if (intake.sources.goal !== "still-needed") {
      intake.sources.goal = sourceWhenNormalized;
    }
  }

  if (!intake.overrides.profile) {
    const stagedDiscoveryPlan = stagedDiscoveryCompatibility(data);
    const compatibleProfile = stagedDiscoveryPlan?.profile || recommendedProfileForGoal(
      data.intake_preferences.primary_goal,
      data.assessment_type,
    );
    if (!reason && stagedDiscoveryPlan?.reason) {
      reason = stagedDiscoveryPlan.reason;
    }
    if (compatibleProfile && compatibleProfile !== data.test_profile) {
      data.test_profile = compatibleProfile;
      changed = true;
      if (!intake.overrides.modules && !intake.overrides.safety) {
        applyProfilePreset(compatibleProfile);
      } else {
        if (!intake.overrides.modules) {
          Object.assign(data.modules, profileModulePreset(compatibleProfile));
        }
        if (!intake.overrides.safety) {
          Object.assign(data.safety, profileSafetyPreset(compatibleProfile));
        }
      }
    }
  }

  return {
    goal: data.intake_preferences.primary_goal,
    changed,
    reason,
  };
}

function setGoalRecommendation(goal, source = "confirmed") {
  state.wizard.data.intake_preferences.primary_goal = goal;
  state.wizard.intake.sources.goal = source;
  const compatibility = reconcileGoalCompatibility(source === "confirmed" ? "inferred" : source);

  if (state.wizard.intake.overrides.profile || state.wizard.intake.overrides.modules || state.wizard.intake.overrides.safety) {
    return compatibility;
  }

  applyGoalDrivenPlanDefaults();
  return compatibility;
}

function applyGoalDrivenPlanDefaults() {
  const stagedDiscoveryPlan = stagedDiscoveryCompatibility(state.wizard.data);
  const profile = stagedDiscoveryPlan?.profile || recommendedProfileForGoal(
    state.wizard.data.intake_preferences.primary_goal,
    state.wizard.data.assessment_type,
  );
  state.wizard.data.test_profile = profile;
  applyProfilePreset(profile);

  if (state.wizard.data.intake_preferences.primary_goal === "inventory-first" || state.wizard.data.intake_preferences.primary_goal === "quick-overview") {
    applyInventoryGoalTuning(state.wizard.data.intake_preferences.primary_goal);
  }
  if (state.wizard.data.intake_preferences.primary_goal === "authenticated-review" && !state.wizard.data.modules.auth_flows) {
    state.wizard.data.modules.auth_flows = true;
  }
  if (state.wizard.data.intake_preferences.safety_posture) {
    applySafetyPreference(state.wizard.data.intake_preferences.safety_posture);
  }
  enforceDiscoveryFirstSafetyGuardrails(state.wizard.data);
}

function recommendedProfileForGoal(goal, assessmentType) {
  if (goal === "quick-overview") return assessmentType === "External IP / WAN" ? "External Surface Only" : "Light";
  if (goal === "inventory-first") {
    if (assessmentType === "Internal Range / LAN") return "Standard";
    if (assessmentType === "External IP / WAN") return "External Surface Only";
    if (assessmentType === "SSL/TLS Only") return "SSL/TLS Only";
    return "Light";
  }
  if (goal === "deep-assessment") return "Deep";
  if (goal === "authenticated-review") return "Authenticated Only";
  if (goal === "adaptive-coverage") return "Adaptive Customer-Specific Mode";
  if (goal === "internal-validation") return "Internal Validation";
  return assessmentTypeProfileRecommendation(assessmentType);
}

function goalForProfile(profile) {
  const mapping = {
    "Light": "quick-overview",
    "Standard": "standard-assessment",
    "Deep": "deep-assessment",
    "External Surface Only": "inventory-first",
    "Authenticated Only": "authenticated-review",
    "SSL/TLS Only": "inventory-first",
    "Internal Validation": "internal-validation",
    "Adaptive Customer-Specific Mode": "adaptive-coverage",
  };
  return mapping[profile] || "standard-assessment";
}

function applyInventoryGoalTuning(goal) {
  const networkAssessment = ["Internal Range / LAN", "External IP / WAN"].includes(state.wizard.data.assessment_type);
  if (networkAssessment) {
    Object.assign(state.wizard.data.modules, moduleState(["discovery"]));
  } else {
    Object.assign(state.wizard.data.modules, moduleState(["discovery", "web_crawling", "ssl_tls_analysis", "nuclei_checks"]));
  }
  state.wizard.data.safety.active_checks = "passive-only";
  state.wizard.data.safety.adaptive_generation = goal === "inventory-first" ? false : state.wizard.data.safety.adaptive_generation;
  state.wizard.data.safety.max_validation_depth = "light";
}

function enforceDiscoveryFirstSafetyGuardrails(data) {
  if (!externalPerimeterDiscoveryCompatibility(data)) return;
  Object.assign(data.safety, {
    active_checks: "passive-only",
    max_validation_depth: "light",
  });
}

function applySafetyPreference(posture) {
  const safety = state.wizard.data.safety;
  if (posture === "passive-only") {
    Object.assign(safety, {
      rate_limit_rps: Math.min(safety.rate_limit_rps, 2),
      concurrency: 1,
      active_checks: "passive-only",
      max_validation_depth: "light",
    });
    return;
  }
  if (posture === "conservative") {
    Object.assign(safety, {
      rate_limit_rps: Math.min(safety.rate_limit_rps, 2),
      concurrency: Math.min(safety.concurrency, 2),
      active_checks: "passive-only",
      max_validation_depth: "light",
    });
    return;
  }
  if (posture === "balanced") {
    Object.assign(safety, {
      rate_limit_rps: Math.max(2, safety.rate_limit_rps),
      concurrency: Math.max(2, safety.concurrency),
      active_checks: "guarded",
      max_validation_depth: "standard",
    });
    return;
  }
  if (posture === "thorough") {
    Object.assign(safety, {
      rate_limit_rps: Math.max(3, safety.rate_limit_rps),
      concurrency: Math.max(2, safety.concurrency),
      active_checks: "guarded",
      max_validation_depth: "deep",
    });
    return;
  }
  if (posture === "aggressive") {
    Object.assign(safety, {
      rate_limit_rps: Math.max(4, safety.rate_limit_rps),
      concurrency: Math.max(3, safety.concurrency),
      active_checks: "active",
      max_validation_depth: "deep",
    });
  }
}

function deriveSafetyPostureFromConfig(data) {
  if (data.safety.active_checks === "active") return "aggressive";
  if (data.safety.active_checks === "passive-only") {
    return data.safety.max_validation_depth === "light" ? "conservative" : "passive-only";
  }
  if (data.safety.max_validation_depth === "deep") return "thorough";
  return "balanced";
}

function syncConversationMetadataFromData() {
  const { data, intake } = state.wizard;
  if ((!data.intake_preferences.primary_goal && intake.overrides.profile) || intake.sources.goal === "override") {
    data.intake_preferences.primary_goal = goalForProfile(data.test_profile);
  }
  if ((!data.intake_preferences.safety_posture && intake.overrides.safety) || intake.sources.safety === "override") {
    data.intake_preferences.safety_posture = deriveSafetyPostureFromConfig(data);
  }
  const inferredAuthStrategy = inferAuthStrategyFromAccess(data.access);
  if (
    inferredAuthStrategy &&
    (
      !data.intake_preferences.auth_strategy ||
      data.intake_preferences.auth_strategy === "advanced-details" ||
      intake.overrides.access
    )
  ) {
    data.intake_preferences.auth_strategy = inferredAuthStrategy;
  }
  if (flattenTargetValues(data.targets).length && intake.sources.scope === "still-needed") {
    intake.sources.scope = "inferred";
  }
  if (data.assessment_type && intake.sources.target_type === "still-needed") {
    intake.sources.target_type = "inferred";
  }
  if (data.intake_preferences.primary_goal && intake.sources.goal === "still-needed") {
    intake.sources.goal = "inferred";
  }
  if (data.intake_preferences.auth_strategy && intake.sources.auth === "still-needed") {
    intake.sources.auth = "inferred";
  }
  if (renderExclusionSummary(data.exclusions) !== "No denylist recorded" && intake.sources.boundaries === "still-needed") {
    intake.sources.boundaries = "inferred";
  }
  syncAdvancedSharedAccessHistoryFromData();
}

function syncAdvancedSharedAccessHistoryFromData() {
  const wizard = state.wizard;
  const preservedHistory = wizard.intake.history.filter((turn) => !isSyntheticSharedAccessTurn(turn));
  const hasAuthenticAuthDetailsTurn = preservedHistory.some(
    (turn) => turn.role === "user" && turn.questionId === "auth-details"
  );

  if (hasAuthenticAuthDetailsTurn) {
    wizard.intake.history = preservedHistory;
    return;
  }

  const sharedAccessHistory = buildAdvancedSharedAccessHistoryEntry(wizard.data.access);
  if (!sharedAccessHistory) {
    wizard.intake.history = preservedHistory;
    return;
  }

  wizard.intake.history = [
    ...preservedHistory,
    {
      role: "user",
      questionId: "auth-details",
      text: sharedAccessHistory.userText,
      syncKey: "advanced-shared-access-user",
    },
    {
      role: "assistant",
      questionId: "auth-details",
      text: sharedAccessHistory.assistantText,
      syncKey: "advanced-shared-access-assistant",
    },
  ];
}

function isSyntheticSharedAccessTurn(turn) {
  return [
    "advanced-shared-access-user",
    "advanced-shared-access-assistant",
  ].includes(String(turn?.syncKey || ""));
}

function buildAdvancedSharedAccessHistoryEntry(access) {
  if (hasMeaningfulAccount(access?.accounts || [])) return null;

  const manualAuthSteps = stringValue(access?.manual_auth_steps);
  const cookieNotes = stringValue(access?.cookie_notes);

  if (manualAuthSteps && !cookieNotes) {
    return {
      userText: manualAuthSteps,
      assistantText: "Advanced shared manual-auth guidance recorded in the mission configuration.",
    };
  }

  if (cookieNotes && !manualAuthSteps) {
    return {
      userText: cookieNotes,
      assistantText: "Advanced shared session guidance recorded in the mission configuration.",
    };
  }

  return null;
}

function humanizeProfileName(value) {
  return String(value || "")
    .split("-")
    .filter(Boolean)
    .map((part) => capitalizeWord(part))
    .join(" ") || "Planned Runner";
}

function previewTierStyle(tier) {
  return PHASE_TIER_STYLES[String(tier || "").trim()] || PHASE_TIER_STYLES.passive;
}

function targetGroupLabel(group) {
  const mapping = {
    network: "Network",
    domain: "Domain",
    web: "Web",
    api: "API",
    directory: "Identity",
    ai: "AI",
    summary: "Scope",
  };
  return mapping[String(group || "").trim()] || "Scope";
}

function buildMissionPreviewTargets(targets = state.wizard.data.targets) {
  const normalized = typeof targets === "object" && targets !== null ? targets : {};
  const rawTargets = [
    ...(normalized.cidr_ranges || []).map((value) => ({ label: value, group: "network" })),
    ...(normalized.ip_addresses || []).map((value) => ({ label: value, group: "network" })),
    ...(normalized.domains || []).map((value) => ({ label: value, group: "domain" })),
    ...(normalized.subdomains || []).map((value) => ({ label: value, group: "domain" })),
    ...(normalized.urls || []).map((value) => ({ label: value, group: "web" })),
    ...(normalized.api_base_urls || []).map((value) => ({ label: value, group: "api" })),
  ];
  const seen = new Set();
  const deduped = rawTargets.filter((target) => {
    const key = `${target.group}:${target.label}`;
    if (!target.label || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  const visibleTargets = deduped.slice(0, 5);
  if (deduped.length > visibleTargets.length) {
    visibleTargets.push({
      label: `+${deduped.length - visibleTargets.length} more`,
      group: "summary",
      summary: true,
    });
  }
  return visibleTargets.length
    ? visibleTargets
    : [{ label: "Approved scope", group: "summary", summary: true }];
}

function missionPreviewDefinition(data = state.wizard.data, estimate = estimateMission(data)) {
  const configuredMode = String(data.assessment_mode?.mode || "").trim().toUpperCase();
  if (configuredMode && MISSION_PREVIEW_DEFINITIONS[configuredMode]) {
    return MISSION_PREVIEW_DEFINITIONS[configuredMode];
  }
  const executionPlan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
  const tier = executionPlan.runClass === "intrusive"
    ? "intrusive-exploitation"
    : executionPlan.runClass === "active"
      ? "active"
      : "passive";
  return {
    mode: "",
    label: "Single Run Mission",
    phases: [
      {
        key: "single-run",
        label: "Planned Validation Run",
        tier,
        icon: "RUN",
        estimatedMinutes: estimate.estimated_total_minutes,
        findingCopy: executionPlan.description,
        profiles: [estimate.execution_profile],
      },
    ],
  };
}

function buildMissionPreviewPhases(data = state.wizard.data, estimate = estimateMission(data)) {
  return missionPreviewDefinition(data, estimate).phases.map((phase) => ({
    ...phase,
    tools: phase.profiles.map((profileName) => {
      const plan = executionPlanForProfile(profileName, state.runProfiles);
      const primaryTool = plan.tools[0] || "runner";
      return {
        profileName,
        label: humanizeProfileName(profileName),
        icon: TOOL_ICON_LABELS[primaryTool] || primaryTool.slice(0, 5).toUpperCase(),
        toolLabel: primaryTool,
        description: PROFILE_EXPECTATION_COPY[profileName] || plan.description,
        targetGroups: PROFILE_TARGET_GROUPS[profileName] || ["network", "domain", "web", "api", "directory", "ai"],
      };
    }),
  }));
}

function missionPreviewTargetIndexes(tool, targets) {
  const groups = Array.isArray(tool?.targetGroups) ? tool.targetGroups : [];
  const matches = targets.reduce((indexes, target, index) => {
    if (target.summary || groups.includes(target.group) || groups.includes("all")) {
      indexes.push(index);
    }
    if (groups.includes("web") && target.group === "domain") {
      indexes.push(index);
    }
    return indexes;
  }, []);
  return [...new Set(matches)].length ? [...new Set(matches)] : targets.map((_, index) => index);
}

function renderMissionPreviewSvg(data = state.wizard.data, estimate = estimateMission(data)) {
  const phases = buildMissionPreviewPhases(data, estimate);
  const targets = buildMissionPreviewTargets(data.targets);
  const width = 1120;
  const cardX = 150;
  const cardWidth = 820;
  const targetStartX = 130;
  const targetSpacing = targets.length > 1 ? (width - (targetStartX * 2)) / (targets.length - 1) : 0;
  const targetY = 82;
  const phaseGap = 30;
  let cursorY = 156;
  const phaseLayouts = phases.map((phase) => {
    const toolRows = Math.max(1, Math.ceil((phase.tools?.length || 0) / 4));
    const cardHeight = 132 + (toolRows - 1) * 34;
    const layout = { ...phase, y: cursorY, height: cardHeight };
    cursorY += cardHeight + phaseGap;
    return layout;
  });
  const height = cursorY + 24;

  const targetLayouts = targets.map((target, index) => ({
    ...target,
    x: targets.length === 1 ? width / 2 : targetStartX + (targetSpacing * index),
    y: targetY,
  }));

  const connectionLines = [];
  const toolCards = [];
  const phaseCards = phaseLayouts.map((phase, phaseIndex) => {
    const style = previewTierStyle(phase.tier);
    const toolHeight = 24;
    const toolWidth = 176;
    const toolGap = 12;
    const toolsPerRow = 4;
    const toolStartX = cardX + 26;
    const toolStartY = phase.y + 52;
    (phase.tools || []).forEach((tool, toolIndex) => {
      const row = Math.floor(toolIndex / toolsPerRow);
      const column = toolIndex % toolsPerRow;
      const x = toolStartX + (column * (toolWidth + toolGap));
      const y = toolStartY + (row * 34);
      const midX = x + (toolWidth / 2);
      const targetIndexes = missionPreviewTargetIndexes(tool, targetLayouts);
      targetIndexes.forEach((targetIndex) => {
        const target = targetLayouts[targetIndex];
        connectionLines.push(`
          <line
            x1="${midX}"
            y1="${y}"
            x2="${target.x}"
            y2="${target.y + 18}"
            stroke="${style.stroke}"
            stroke-width="1.5"
            stroke-dasharray="4 5"
            opacity="0.34"
          />
        `);
      });
      toolCards.push(`
        <g>
          <rect x="${x}" y="${y}" width="${toolWidth}" height="${toolHeight}" rx="8" fill="#ffffff" stroke="${style.accent}" />
          <rect x="${x + 7}" y="${y + 5}" width="38" height="14" rx="7" fill="${style.badge}" />
          <text x="${x + 26}" y="${y + 15}" text-anchor="middle" font-size="9" font-weight="700" fill="${style.text}">${escapeHtml(tool.icon)}</text>
          <text x="${x + 54}" y="${y + 15}" font-size="11" font-weight="600" fill="#15233b">${escapeHtml(tool.label)}</text>
        </g>
      `);
    });
    const connectorLine = phaseIndex < phaseLayouts.length - 1
      ? `<line x1="${width / 2}" y1="${phase.y + phase.height}" x2="${width / 2}" y2="${phaseLayouts[phaseIndex + 1].y}" stroke="${style.stroke}" stroke-width="2" stroke-dasharray="6 6" opacity="0.5" />`
      : "";
    return `
      ${connectorLine}
      <g>
        <rect x="${cardX}" y="${phase.y}" width="${cardWidth}" height="${phase.height}" rx="16" fill="${style.fill}" stroke="${style.stroke}" stroke-width="2" />
        <rect x="${cardX + 18}" y="${phase.y + 18}" width="64" height="24" rx="12" fill="${style.badge}" />
        <text x="${cardX + 50}" y="${phase.y + 34}" text-anchor="middle" font-size="11" font-weight="700" fill="${style.text}">${escapeHtml(phase.icon)}</text>
        <text x="${cardX + 96}" y="${phase.y + 34}" font-size="18" font-weight="700" fill="#15233b">${escapeHtml(phase.label)}</text>
        <rect x="${cardX + cardWidth - 118}" y="${phase.y + 18}" width="96" height="24" rx="12" fill="#ffffff" stroke="${style.accent}" />
        <text x="${cardX + cardWidth - 70}" y="${phase.y + 34}" text-anchor="middle" font-size="11" font-weight="700" fill="#233655">${escapeHtml(`~${phase.estimatedMinutes}m`)}</text>
        <text x="${cardX + 26}" y="${phase.y + phase.height - 22}" font-size="12" fill="#44566f">${escapeHtml(phase.findingCopy)}</text>
      </g>
    `;
  }).join("");

  const targetNodes = targetLayouts.map((target) => `
    <g>
      <line x1="${target.x}" y1="44" x2="${target.x}" y2="${target.y - 16}" stroke="#c8d5e3" stroke-width="1" />
      <circle cx="${target.x}" cy="${target.y}" r="18" fill="#ffffff" stroke="#7f9ab5" stroke-width="2" />
      <text x="${target.x}" y="${target.y + 4}" text-anchor="middle" font-size="9" font-weight="700" fill="#173049">${escapeHtml(targetGroupLabel(target.group).slice(0, 4).toUpperCase())}</text>
      <text x="${target.x}" y="${target.y + 36}" text-anchor="middle" font-size="11" font-weight="600" fill="#15233b">${escapeHtml(target.label.length > 24 ? `${target.label.slice(0, 21)}...` : target.label)}</text>
    </g>
  `).join("");

  return `
    <div class="mission-preview-canvas" data-testid="wizard-mission-preview-diagram">
      <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Mission preview diagram">
        <rect x="0" y="0" width="${width}" height="${height}" rx="22" fill="#f8fbfd" />
        <text x="42" y="38" font-size="12" font-weight="700" letter-spacing="0.18em" fill="#6a7f96">SCOPE BAR</text>
        <line x1="88" y1="82" x2="${width - 88}" y2="82" stroke="#d8e2ec" stroke-width="3" stroke-linecap="round" />
        ${connectionLines.join("")}
        ${phaseCards}
        ${toolCards.join("")}
        ${targetNodes}
      </svg>
    </div>
  `;
}

function renderMissionAuthorizationSelector(data = state.wizard.data) {
  const authorizationEnabled = chainAuthorizationAvailable(data);
  const selectedLevel = selectedAuthorizationLevel(data);
  const expectedToken = missionScopeConfirmationToken(data);
  const scopeSummary = missionScopeConfirmationSummary(data);
  return `
    <section class="mission-preview-authorization split-top">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Authorization</p>
          <h4>Phase Boundary Approval</h4>
        </div>
        <span class="badge">${escapeHtml(authorizationEnabled ? "Assessment mode armed" : "Assessment mode disabled")}</span>
      </div>
      <div class="authorization-card-grid" data-testid="wizard-authorization-selector">
        ${AUTHORIZATION_LEVEL_OPTIONS.map((option) => `
          <button
            class="authorization-card ${selectedLevel === option.value ? "selected" : ""}"
            type="button"
            data-authorization-level="${escapeHtml(option.value)}"
            data-testid="wizard-authorization-${escapeHtml(option.value)}"
            ${authorizationEnabled ? "" : "disabled"}
          >
            <strong>${escapeHtml(option.label)}</strong>
            <span>${escapeHtml(option.copy)}</span>
            <span class="authorization-card-note">${escapeHtml(option.boundaryCopy)}</span>
          </button>
        `).join("")}
      </div>
      <p class="micro-copy split-top">${escapeHtml(
        authorizationEnabled
          ? "The kill switch remains available in Mission Control at every phase boundary and during active execution."
          : "Enable Assessment Mode in Advanced Configuration if you want multi-phase authorization instead of a single-run launch."
      )}</p>
      ${
        authorizationEnabled && selectedLevel === "full"
          ? `
            <div class="detail-surface split-top authorization-confirm-box" data-testid="wizard-full-authorization-confirmation">
              <h4>Typed Full Authorization</h4>
              <p>${escapeHtml(`I confirm I have written authorisation to run the full non-exploitation chain against ${scopeSummary}. Exploitation tools including Metasploit and Impacket still require the exploit unlocker, prerequisite evidence, and an explicit gate in Mission Control if that unlocker was not selected.`)}</p>
              <label class="field split-top">
                ${fieldLabel("Type the primary approved target exactly", "This prevents accidental one-click approval of the exploitation tier.")}
                <input id="wizard-full-authorization-input" type="text" value="${escapeHtml(data.assessment_mode?.typed_scope_confirmation || "")}" placeholder="${escapeHtml(expectedToken || "approved target")}" aria-label="Typed scope confirmation" data-testid="wizard-full-authorization-input" />
                ${fieldHelp(expectedToken ? `Type ${expectedToken} exactly to unlock Full authorization.` : "Add scope first so Full authorization has a concrete confirmation target.")}
              </label>
            </div>
          `
          : ""
      }
    </section>
  `;
}

function renderMissionAccessUnlockerGate(data = state.wizard.data) {
  const unlockers = normalizeAccessUnlockers(data.access?.prerequisites);
  const options = visibleAccessUnlockerOptions(data);
  const context = accessUnlockerContextForKeys(selectedAssessmentTileKeys(state.wizard), data);
  return `
    <section class="mission-preview-access split-top" data-testid="wizard-access-unlockers">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Access Prerequisites</p>
          <h4>What can AegisPT use during the run?</h4>
        </div>
        <span class="badge">${escapeHtml(`${selectedAccessUnlockerKeys(data, options).length} selected`)}</span>
      </div>
      <p class="micro-copy">${escapeHtml("Discovery always starts without credentials. Extra context is declared here so gated checks can run when the selected authorization tier allows them.")}</p>
      <div class="unlocker-grid split-top">
        ${options.map((option) => `
          <button class="unlocker-card ${escapeHtml(option.className)} ${unlockers[option.key] ? "selected" : ""}" type="button" data-wizard-unlocker="${escapeHtml(option.key)}" aria-pressed="${unlockers[option.key] ? "true" : "false"}">
            <span class="unlocker-label">${escapeHtml(option.label)}</span>
            <span class="unlocker-copy">${escapeHtml(option.copy)}</span>
            <span class="unlocker-tag">${escapeHtml(accessUnlockerUnlocks(option, context))}</span>
          </button>
        `).join("")}
      </div>
      ${renderCredentialEntryCta()}
      <p class="access-unlocker-summary">${escapeHtml(buildAccessPrerequisiteLine(data))}</p>
    </section>
  `;
}

function renderCredentialEntryCta() {
  return `
    <div class="credential-entry-cta split-top" data-testid="wizard-credential-entry-cta">
      <span>Need authenticated coverage?</span>
      <button class="action secondary tiny" type="button" data-intake-advanced="true" data-intake-advanced-step="2">
        Add credentials in Advanced Configuration -&gt;
      </button>
    </div>
  `;
}

function renderMissionPreviewSurface(context) {
  const definition = missionPreviewDefinition(state.wizard.data, context.estimate);
  const targetCount = flattenTargetValues(state.wizard.data.targets).length;
  const selectedAuth = authorizationOption(selectedAuthorizationLevel(state.wizard.data));
  return `
    <section class="mission-preview-surface split-top" data-testid="wizard-mission-preview">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Mission Preview</p>
          <h4>${escapeHtml(definition.label)}</h4>
        </div>
        <span class="badge">Static SVG</span>
      </div>
      <p class="micro-copy">This preview is generated from the configured scope and planned execution path. It does not depend on live runtime state.</p>
      <div class="chip-row compact split-top">
        <span class="status-chip neutral">${escapeHtml(`${targetCount} target${targetCount === 1 ? "" : "s"}`)}</span>
        <span class="status-chip neutral">${escapeHtml(`${definition.phases.length} phase${definition.phases.length === 1 ? "" : "s"}`)}</span>
        <span class="status-chip neutral">${escapeHtml(`${context.estimate.estimated_total_minutes} min ETA`)}</span>
        <span class="status-chip neutral">${escapeHtml(`Authorization: ${selectedAuth.label}`)}</span>
      </div>
      ${renderMissionPreviewSvg(state.wizard.data, context.estimate)}
      ${renderMissionAccessUnlockerGate(state.wizard.data)}
      ${renderMissionAuthorizationSelector(state.wizard.data)}
    </section>
  `;
}

function buildNaturalConfirmationSummary(estimate, data = state.wizard.data) {
  const engagementRoute = currentEngagementRouteContext(data);
  const assessmentLead =
    data.assessment_type === "Mixed Assessment"
      ? "a mixed assessment"
      : `${data.assessment_type === "Internal Range / LAN"
          ? "an"
          : /^[AEIOU]/i.test(data.assessment_type) ? "an" : "a"} ${data.assessment_type.toLowerCase()} assessment`;
  const scopePieces = flattenTargetValues(data.targets);
  const scopeText = scopePieces.length > 3
    ? `${scopePieces.slice(0, 3).join(", ")}, plus ${scopePieces.length - 3} more approved target${scopePieces.length - 3 === 1 ? "" : "s"}`
    : (scopePieces.join(", ") || "the approved scope");
  const stagedInternalValidation = data.assessment_type === "Internal Range / LAN" && data.test_profile === "Internal Validation";
  const stagedDiscoveryPlan = stagedDiscoveryCompatibility(data);
  const outputLine = data.intake_preferences.output_style === "detailed-per-item"
    ? "I will keep the output detailed per discovered item."
    : data.intake_preferences.output_style
      ? `I will bias reporting toward ${humanizeOutputStyle(data.intake_preferences.output_style).toLowerCase()}.`
      : "";
  const lateralLine = data.intake_preferences.lateral_discovery === "requested"
    ? "I will only consider lateral discovery inside your authorized internal environment and configured limits."
    : data.intake_preferences.lateral_discovery === "report-only"
      ? "I will report adjacent reachable internal ranges but will not expand into them without explicit follow-up approval."
      : "";
  const engagementRouteLine = engagementRoute.mode === "reuse-selected-engagement"
    ? `I will attach this run to the existing engagement dossier "${engagementRoute.configContext.engagement_name}" instead of creating a new customer dossier.`
    : `I will create a new engagement dossier named "${engagementRoute.configContext.engagement_name}" before this run begins.`;
  const authorizationLine = buildAuthorizationContextLine(engagementRoute.configContext);
  const phaseAuthorizationLine = String(data.assessment_mode?.mode || "").trim()
    ? `Phase authorization: ${authorizationOption(selectedAuthorizationLevel(data)).label}. ${authorizationOption(selectedAuthorizationLevel(data)).boundaryCopy}`
    : "";
  const accessPrerequisiteLine = buildAccessPrerequisiteLine(data);
  const scopeGuardrailLine = buildScopeGuardrailLine(data);
  return [
    `I am going to run ${assessmentLead} against ${scopeText}.`,
    stagedInternalValidation
      ? `I will begin with live network discovery under the ${data.test_profile} profile, then surface controlled follow-up validation options once hosts and services are confirmed.`
      : stagedDiscoveryPlan?.confirmationLine
      ? stagedDiscoveryPlan.confirmationLine
      : `I will prioritize ${humanizeGoal(data.intake_preferences.primary_goal).toLowerCase()} with the ${data.test_profile} profile and the ${estimate.execution_profile} execution lane.`,
    engagementRouteLine,
    authorizationLine,
    accessPrerequisiteLine,
    phaseAuthorizationLine,
    scopeGuardrailLine,
    outputLine,
    lateralLine,
    `Estimated duration: ${estimate.estimated_total_minutes} minutes with ${estimate.confidence} ETA confidence.`,
  ].filter(Boolean).join(" ");
}

function buildAuthorizationContextLine(engagementContext = {}) {
  const client = stringValue(engagementContext.client);
  const roeRef = stringValue(engagementContext.roe_ref);
  if (!client && !roeRef) return "";
  if (client && roeRef) return `Authorization context: ${client} under ${roeRef}.`;
  if (client) return `Authorization context: ${client}.`;
  return `Authorization context: ${roeRef}.`;
}

function renderConfirmationAuthorizationContext(data = state.wizard.data) {
  const engagementContext = currentEngagementRouteContext(data).configContext || {};
  const client = stringValue(engagementContext.client);
  const roeRef = stringValue(engagementContext.roe_ref);
  if (!client && !roeRef) return "";
  return `
    <div class="compact-definition-grid split-top" data-testid="wizard-authorization-context">
      <div><span>Customer</span><strong>${escapeHtml(client || "Not recorded")}</strong></div>
      <div><span>ROE Reference</span><strong>${escapeHtml(roeRef || "Not recorded")}</strong></div>
    </div>
  `;
}

function buildScopeGuardrailLine(data = state.wizard.data) {
  const exclusions = data.exclusions || {};
  const exclusionSummary = renderExclusionSummary(exclusions);
  const boundaryHandling = humanizeBoundaryHandling(effectiveBoundaryHandling(data));
  const exclusionCount = countExplicitExclusions(exclusions);
  if (!exclusionCount && hasBoundaryNotes(exclusions)) {
    return `Scope guardrails: ${boundaryHandling}. The recorded boundary note stays in force unless you revise the approved scope.`;
  }
  if (exclusionSummary === "No denylist recorded") {
    if (boundaryHandling === "Standard Scope Only") return "";
    return `Scope guardrails: ${boundaryHandling}.`;
  }
  const exclusionVerb = exclusionCount === 1 ? "remains" : "remain";
  return `Scope guardrails: ${boundaryHandling}. ${exclusionSummary} ${exclusionVerb} outside this mission unless you revise the approved scope.`;
}

function renderConfirmationScopeGuardrails(data = state.wizard.data) {
  const exclusionSummary = renderExclusionSummary(data.exclusions);
  const boundaryHandling = humanizeBoundaryHandling(effectiveBoundaryHandling(data));
  const outputStyle = humanizeOutputStyle(data.intake_preferences.output_style);
  const boundaryNotes = stringValue(data.exclusions.notes) || "Not recorded";
  return `
    <div class="compact-definition-grid split-top" data-testid="wizard-scope-guardrails">
      <div><span>Output Style</span><strong>${escapeHtml(outputStyle)}</strong></div>
      <div><span>Boundary Handling</span><strong>${escapeHtml(boundaryHandling)}</strong></div>
      <div><span>Exclusions</span><strong>${escapeHtml(exclusionSummary)}</strong></div>
      <div><span>Boundary Notes</span><strong>${escapeHtml(boundaryNotes)}</strong></div>
    </div>
  `;
}

function buildConfirmationSafetyLine(data = state.wizard.data, executionProfile = estimateMission(data).execution_profile) {
  const stagedInternalValidation = data.assessment_type === "Internal Range / LAN" && data.test_profile === "Internal Validation";
  if (stagedInternalValidation) {
    const boundaryLine = data.exclusions.notes
      ? `Boundary note: ${data.exclusions.notes}`
      : "No extra boundary note is currently recorded.";
    return `This mission starts with passive discovery across the approved range. Deeper internal validation stays gated behind the follow-up lane, your configured safety posture, and explicit operator action. ${boundaryLine}`;
  }
  const executionPlan = executionPlanForProfile(executionProfile, state.runProfiles);
  const activeLine = executionPlan.runClass === "passive"
    ? `This mission stays in the ${executionPlan.profileName} execution lane, so active exploitation-style checks are not enabled in this run.`
    : data.safety.active_checks === "active"
      ? "Active exploitation-style checks are enabled only within the approved scope and current safety limits."
      : data.safety.active_checks === "guarded"
        ? "Guarded active validation is enabled, but the run remains bounded by the configured rate, concurrency, and approval lane."
        : "Active exploitation-style checks are not enabled.";
  const boundaryLine = data.exclusions.notes
    ? `Boundary note: ${data.exclusions.notes}`
    : "No extra boundary note is currently recorded.";
  return `${activeLine} ${boundaryLine}`;
}

function isPrivateIp(value) {
  const normalized = String(value || "").trim();
  if (!isLikelyIp(normalized)) return false;
  const octets = normalized.split(".").map(Number);
  return octets[0] === 10 ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168);
}

function isPrivateCidr(value) {
  const normalized = String(value || "").trim();
  if (!isLikelyCidr(normalized)) return false;
  return isPrivateIp(normalized.split("/")[0]);
}

function targetsContainPrivateNetwork(targets = {}) {
  const privateIps = Array.isArray(targets.ip_addresses)
    ? targets.ip_addresses.some((value) => isPrivateIp(value))
    : false;
  const privateCidrs = Array.isArray(targets.cidr_ranges)
    ? targets.cidr_ranges.some((value) => isPrivateCidr(value))
    : false;
  return privateIps || privateCidrs;
}

function lanDiscoveryRoutingIssue(data = state.wizard.data) {
  if (!targetsContainPrivateNetwork(data.targets)) return null;
  const estimate = estimateMission(data);
  const selectedKeys = selectedAssessmentTileKeys(state.wizard);
  const selectionMatchesLan =
    data.assessment_type === "Internal Range / LAN" ||
    selectedKeys.includes("internal-lan") ||
    selectedKeys.includes("active-directory");
  const alreadyInLanLane = LAN_DISCOVERY_EXECUTION_PROFILES.has(estimate.execution_profile);
  if (selectionMatchesLan && alreadyInLanLane) return null;
  const plan = executionPlanForProfile(estimate.execution_profile, state.runProfiles);
  return {
    profileName: plan.profileName,
    toolsLabel: plan.toolsLabel,
    message: alreadyInLanLane
      ? "This looks like an internal network. Keep it classified as Internal Range / LAN so scope, reporting, and follow-up phases use the LAN discovery model. Switch to passive-network-discovery before launch."
      : "This looks like an internal network. The current lane is not the LAN discovery lane and may miss host and service truth. Switch to passive-network-discovery before launch.",
  };
}

function applyLanDiscoveryProfileCorrection() {
  const data = state.wizard.data;
  const previousNameContext = snapshotEngagementNameContext(data);
  data.assessment_type = "Internal Range / LAN";
  data.test_profile = "Standard";
  data.intake_preferences.primary_goal = "inventory-first";
  data.intake_preferences.safety_posture = "passive-only";
  data.assessment_mode = {
    ...data.assessment_mode,
    mode: "",
    authorization_level: normalizedAuthorizationLevel(data.assessment_mode?.authorization_level || "passive"),
  };
  Object.assign(data.modules, moduleState(["discovery"]));
  Object.assign(data.safety, {
    ...data.safety,
    active_checks: "passive-only",
    adaptive_generation: false,
    max_validation_depth: "light",
  });
  state.wizard.intake.overrides.profile = false;
  state.wizard.intake.overrides.modules = false;
  state.wizard.intake.overrides.safety = false;
  state.wizard.intake.sources.target_type = "inferred";
  state.wizard.intake.sources.goal = "inferred";
  state.wizard.intake.sources.safety = "inferred";
  state.wizard.intake.selectedAssessmentTileKey = "internal-lan";
  state.wizard.intake.selectedAssessmentTileKeys = normalizeAssessmentTileKeys(["internal-lan"]);
  refreshSuggestedEngagementNameIfAutomatic(previousNameContext, data);
}
