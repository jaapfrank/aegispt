import {
  Bot,
  Braces,
  Building2,
  Cloud,
  Globe2,
  KeyRound,
  Landmark,
  LockKeyhole,
  Network,
  Radio,
  Router,
  Server,
  Settings2,
  type LucideIcon,
} from 'lucide-react';

export type AssessmentTileKey =
  | 'external-web'
  | 'external-infrastructure'
  | 'internal-lan'
  | 'active-directory'
  | 'full-internal'
  | 'smart-home-lan'
  | 'wifi-wireless'
  | 'cloud'
  | 'api-security'
  | 'llm-ai-app'
  | 'custom'
  | 'ssl-tls'
  | 'authenticated-app';

export type PhaseTagTone = 'passive' | 'active' | 'credential' | 'proof' | 'custom';

export type AssessmentTile = {
  key: AssessmentTileKey;
  label: string;
  icon: LucideIcon;
  badge?: string;
  phaseTags: Array<{ label: string; tone: PhaseTagTone }>;
  description: string;
  assessmentType: string;
  quickReply: string;
  recommended?: boolean;
};

export const ASSESSMENT_TILES: AssessmentTile[] = [
  {
    key: 'external-web',
    label: 'External Web',
    icon: Globe2,
    badge: 'Popular',
    phaseTags: [
      { label: 'passive', tone: 'passive' },
      { label: 'active', tone: 'active' },
    ],
    description: 'Websites, web apps, and public application surfaces reachable from the internet.',
    assessmentType: 'Website / Web App',
    quickReply: 'Our web application',
    recommended: true,
  },
  {
    key: 'external-infrastructure',
    label: 'External IPs',
    icon: Server,
    badge: 'New',
    phaseTags: [
      { label: 'passive', tone: 'passive' },
      { label: 'active', tone: 'active' },
    ],
    description: 'External IP ranges, exposed services, SSH/RDP/VPN endpoints, and non-web internet-facing hosts.',
    assessmentType: 'External IP / WAN',
    quickReply: 'Our external infrastructure',
    recommended: true,
  },
  {
    key: 'internal-lan',
    label: 'Internal LAN',
    icon: Network,
    badge: 'Popular',
    phaseTags: [
      { label: 'passive', tone: 'passive' },
      { label: 'active', tone: 'active' },
      { label: 'credential', tone: 'credential' },
    ],
    description: 'Internal network ranges, subnets, office segments, and on-premise servers.',
    assessmentType: 'Internal Range / LAN',
    quickReply: 'My LAN network',
    recommended: true,
  },
  {
    key: 'active-directory',
    label: 'Active Directory',
    icon: Landmark,
    badge: 'AD',
    phaseTags: [
      { label: 'passive', tone: 'passive' },
      { label: 'active', tone: 'active' },
      { label: 'credential', tone: 'credential' },
      { label: 'proof', tone: 'proof' },
    ],
    description: 'Domain controllers, AD identities, trust edges, and directory attack paths.',
    assessmentType: 'Internal Range / LAN',
    quickReply: 'Active Directory',
  },
  {
    key: 'full-internal',
    label: 'Full Internal',
    icon: Router,
    badge: 'Complete',
    phaseTags: [
      { label: 'P1', tone: 'passive' },
      { label: 'P2', tone: 'active' },
      { label: 'P3', tone: 'credential' },
      { label: 'P4', tone: 'proof' },
    ],
    description: 'Broader internal validation across LAN, identity, and deeper follow-up workflows.',
    assessmentType: 'Internal Range / LAN',
    quickReply: 'Full internal assessment',
  },
  {
    key: 'smart-home-lan',
    label: 'Smart Home / IoT LAN',
    icon: Building2,
    badge: 'IoT',
    phaseTags: [
      { label: 'P1', tone: 'passive' },
      { label: 'P2', tone: 'active' },
      { label: 'P3', tone: 'active' },
      { label: 'P6', tone: 'credential' },
    ],
    description: 'Smart home hubs, IP cameras, consumer IoT, gateways, SNMP devices, segmentation, and IPv6 on an internal LAN.',
    assessmentType: 'Internal Range / LAN',
    quickReply: 'Smart home / IoT LAN',
    recommended: true,
  },
  {
    key: 'wifi-wireless',
    label: 'WiFi / Wireless',
    icon: Radio,
    badge: 'Passive',
    phaseTags: [{ label: 'passive', tone: 'passive' }],
    description: 'Authorized wireless sites, SSIDs, BSSIDs, adapter context, and passive AP posture review.',
    assessmentType: 'WiFi / Wireless',
    quickReply: 'WiFi assessment',
    recommended: true,
  },
  {
    key: 'cloud',
    label: 'Cloud',
    icon: Cloud,
    phaseTags: [
      { label: 'passive', tone: 'passive' },
      { label: 'active', tone: 'active' },
    ],
    description: 'Cloud infrastructure, IAM exposure, and tenant-facing control plane review.',
    assessmentType: 'Mixed Assessment',
    quickReply: 'Cloud environment',
  },
  {
    key: 'api-security',
    label: 'API Security',
    icon: Braces,
    phaseTags: [
      { label: 'passive', tone: 'passive' },
      { label: 'active', tone: 'active' },
    ],
    description: 'REST, GraphQL, gRPC, and other endpoint-centric application surfaces.',
    assessmentType: 'API',
    quickReply: 'Our API',
    recommended: true,
  },
  {
    key: 'llm-ai-app',
    label: 'LLM / AI App',
    icon: Bot,
    badge: 'New',
    phaseTags: [{ label: 'active', tone: 'active' }],
    description: 'Prompt injection, model misuse, agent behavior, and AI-assisted app workflows.',
    assessmentType: 'Website / Web App',
    quickReply: 'LLM / AI application',
  },
  {
    key: 'custom',
    label: 'Custom',
    icon: Settings2,
    phaseTags: [{ label: 'fine-tune', tone: 'custom' }],
    description: 'Build a custom combination and refine the exact run model in later advanced controls.',
    assessmentType: 'Mixed Assessment',
    quickReply: 'A mixed environment',
  },
  {
    key: 'ssl-tls',
    label: 'SSL/TLS Only',
    icon: LockKeyhole,
    badge: 'TLS',
    phaseTags: [{ label: 'passive', tone: 'passive' }],
    description: 'Certificate, protocol, cipher, and transport-security posture for a hostname, URL, or IP.',
    assessmentType: 'SSL/TLS Only',
    quickReply: 'TLS posture review',
    recommended: true,
  },
  {
    key: 'authenticated-app',
    label: 'Authenticated App',
    icon: KeyRound,
    badge: 'Access',
    phaseTags: [
      { label: 'active', tone: 'active' },
      { label: 'credential', tone: 'credential' },
    ],
    description: 'Application testing where login, session, API token, or role context is central.',
    assessmentType: 'Authenticated App',
    quickReply: 'Authenticated app',
    recommended: true,
  },
];
