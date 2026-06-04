import type { Finding, Run, RunReportCatalogItem } from '../api/types';
import type { ReportTruthModel } from './reportTruth';

export type ManagementReportStandardState = 'used' | 'mapped';

export interface ManagementReportStandardBadge {
  badge: string;
  label: string;
  meaning: string;
  state: ManagementReportStandardState;
}

export interface ManagementReportRouteStep {
  key: string;
  label: string;
  detail: string;
  tone: 'scope' | 'good' | 'info' | 'proof' | 'outcome';
}

export interface ManagementReportTechnique {
  label: string;
  plain: string;
  basis: string;
}

export interface ManagementReportAction {
  owner: string;
  action: string;
  doneWhen: string;
}

export interface ManagementReportProofModel {
  isManagementReady: boolean;
  exportReadiness: string;
  storyHeadline: string;
  testedScope: string;
  evidenceBasis: string;
  notClaimed: string[];
  standards: ManagementReportStandardBadge[];
  route: ManagementReportRouteStep[];
  techniques: ManagementReportTechnique[];
  actions: ManagementReportAction[];
}

const STANDARD_BADGES: Array<Omit<ManagementReportStandardBadge, 'state'>> = [
  {
    badge: '[PTES]',
    label: 'PTES',
    meaning: 'Assessment route: scope, discovery, proof, and reporting.',
  },
  {
    badge: '[WSTG]',
    label: 'OWASP WSTG',
    meaning: 'Web application checks and evidence expectations.',
  },
  {
    badge: '[NIST]',
    label: 'NIST SP 800-115',
    meaning: 'Professional testing method and reporting boundaries.',
  },
  {
    badge: '[ASVS]',
    label: 'OWASP ASVS',
    meaning: 'Application requirements findings can map back to.',
  },
];

export function buildManagementReportProof(
  report: RunReportCatalogItem,
  truth: ReportTruthModel,
  findings: Finding[],
  run: Run | null,
): ManagementReportProofModel {
  const highPlus = truth.canonicalHighPlus;
  const reportable = truth.canonicalTotal;
  const exportReady = report.export_allowed && truth.countStatus !== 'mismatch' && !truth.internalCopyWarning;
  const strongest = strongestFinding(findings);
  const scope = testedScopeLabel(report, findings, run);
  const techniqueRows = managementTechniqueRows(findings);
  const leadingIssue = strongest ? managementFindingTitle(strongest) : 'geen reportbare bevinding';

  return {
    isManagementReady: exportReady,
    exportReadiness: exportReady ? 'Ready for management export' : 'Review before export',
    storyHeadline:
      reportable > 0
        ? `The report explains how the test moved from scope to proof and why ${highPlus} high-risk item${highPlus === 1 ? '' : 's'} need attention.`
        : 'The report explains what was checked and why no reportable finding was saved.',
    testedScope: scope,
    evidenceBasis:
      truth.evidenceVerified
        ? `${reportable} canonical finding${reportable === 1 ? '' : 's'} with linked evidence status.`
        : `${reportable} canonical finding${reportable === 1 ? '' : 's'}; evidence status needs review before management export.`,
    notClaimed: truth.excludedBullets,
    standards: STANDARD_BADGES.map((standard) => ({
      ...standard,
      state: standardUsed(standard.label, report, findings) ? 'used' : 'mapped',
    })),
    route: [
      { key: 'scope', label: 'Scope', detail: scope, tone: 'scope' },
      { key: 'recon', label: 'Discovery', detail: `${truth.includedInventory} asset${truth.includedInventory === 1 ? '' : 's'} in scope`, tone: 'good' },
      {
        key: 'techniques',
        label: 'Techniques',
        detail: `${techniqueRows.length} plain-language explanation${techniqueRows.length === 1 ? '' : 's'}`,
        tone: 'info',
      },
      { key: 'proof', label: 'Proof', detail: leadingIssue, tone: highPlus > 0 ? 'proof' : 'info' },
      { key: 'decision', label: 'Decision', detail: exportReady ? 'report ready' : 'review needed', tone: 'outcome' },
    ],
    techniques: techniqueRows,
    actions: managementActionRows(findings, highPlus),
  };
}

function testedScopeLabel(report: RunReportCatalogItem, findings: Finding[], run: Run | null): string {
  const target = findings.find((finding) => finding.target_id.trim())?.target_id;
  if (target) return target;
  const profile = report.source_scope_profile.run_profile;
  if (typeof profile === 'string' && profile.trim()) return profile;
  return run?.profile.name ?? 'selected run';
}

function strongestFinding(findings: Finding[]): Finding | null {
  return [...findings].sort((left, right) => severityRank(right.severity) - severityRank(left.severity))[0] ?? null;
}

function severityRank(severity: string): number {
  const normalized = severity.toLowerCase();
  if (normalized === 'critical') return 5;
  if (normalized === 'high') return 4;
  if (normalized === 'medium') return 3;
  if (normalized === 'low') return 2;
  return 1;
}

function managementFindingTitle(finding: Finding): string {
  const title = finding.title.toLowerCase();
  if (title.includes('xss')) return 'Input and data handling';
  if (title.includes('sql')) return 'Database input control';
  if (title.includes('header') || title.includes('hsts')) return 'Security headers';
  if (title.includes('openapi') || title.includes('schema') || title.includes('docs')) return 'Public API information';
  if (title.includes('flag') || title.includes('proof')) return 'Proven attack path';
  return finding.title;
}

function managementTechniqueRows(findings: Finding[]): ManagementReportTechnique[] {
  const rows = new Map<string, ManagementReportTechnique>();
  for (const finding of findings) {
    const title = finding.title.toLowerCase();
    const tags = finding.methodology_tags.join(' ').toLowerCase();
    if (title.includes('xss') || title.includes('sql') || tags.includes('input')) {
      rows.set('input', {
        label: 'Input and data handling',
        plain: 'The test checked whether submitted text or parameters are handled safely.',
        basis: finding.wstg_id || finding.owasp_reference || 'OWASP WSTG input validation',
      });
    }
    if (title.includes('header') || title.includes('hsts') || tags.includes('configuration')) {
      rows.set('config', {
        label: 'Configuration check',
        plain: 'The test checked whether protective settings are visible and active.',
        basis: finding.wstg_id || finding.owasp_reference || 'OWASP WSTG configuration',
      });
    }
    if (title.includes('openapi') || title.includes('schema') || title.includes('docs') || tags.includes('api')) {
      rows.set('api', {
        label: 'API information exposure',
        plain: 'The test checked which technical blueprints are publicly visible.',
        basis: finding.wstg_id || finding.owasp_reference || 'OWASP WSTG information gathering',
      });
    }
    if (finding.severity.toLowerCase() === 'critical' || title.includes('flag') || title.includes('proof')) {
      rows.set('proof', {
        label: 'Controlled proof step',
        plain: 'Only saved proof counts as a management risk.',
        basis: finding.evidence_ref || 'canonical finding evidence',
      });
    }
  }
  if (rows.size === 0) {
    rows.set('baseline', {
      label: 'Connectivity check',
      plain: 'The test recorded whether the selected system was reachable.',
      basis: 'run evidence baseline',
    });
  }
  return [...rows.values()].slice(0, 4);
}

function managementActionRows(findings: Finding[], highPlus: number): ManagementReportAction[] {
  const hasInputRisk = findings.some((finding) => {
    const title = finding.title.toLowerCase();
    return title.includes('xss') || title.includes('sql') || finding.methodology_tags.join(' ').toLowerCase().includes('input');
  });
  const hasConfigRisk = findings.some((finding) => {
    const title = finding.title.toLowerCase();
    return title.includes('header') || title.includes('hsts') || title.includes('openapi') || title.includes('docs');
  });
  return [
    {
      owner: 'Management',
      action: highPlus > 0 ? 'Prioritize the highest risks and assign an owner.' : 'Keep the report as a baseline and schedule a retest.',
      doneWhen: highPlus > 0 ? 'Risk owner, deadline, and retest moment are recorded.' : 'New test date and scope are confirmed.',
    },
    {
      owner: 'Engineering',
      action: hasInputRisk ? 'Fix input validation and authorization on the proven route.' : 'Implement code and configuration fixes for confirmed findings.',
      doneWhen: 'Retest shows the same route no longer works.',
    },
    {
      owner: 'IT/Ops',
      action: hasConfigRisk ? 'Tighten public exposure, headers, and access rules.' : 'Check monitoring and configuration around the scope.',
      doneWhen: 'Production configuration and logging show the new protection.',
    },
  ];
}

function standardUsed(label: string, report: RunReportCatalogItem, findings: Finding[]): boolean {
  const haystack = [
    ...report.methodology_references,
    ...findings.flatMap((finding) => [
      finding.owasp_framework,
      finding.owasp_reference,
      finding.wstg_id,
      finding.ptes_phase,
      finding.nist_phase,
      finding.asvs_reference,
      ...finding.methodology_tags,
    ]),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  if (label === 'PTES') return haystack.includes('ptes') || findings.some((finding) => Boolean(finding.ptes_phase));
  if (label === 'OWASP WSTG') return haystack.includes('wstg') || haystack.includes('owasp');
  if (label === 'NIST SP 800-115') return haystack.includes('nist');
  if (label === 'OWASP ASVS') return haystack.includes('asvs');
  return false;
}
