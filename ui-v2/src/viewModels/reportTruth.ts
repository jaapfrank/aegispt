import type { Finding, RunReportCatalogItem } from '../api/types';

export type ReportStage = 'evidence' | 'scope' | 'findings' | 'variant' | 'export';
export type ReportCountStatus = 'match' | 'mismatch' | 'unknown' | 'loading';

export interface ReportTruthModel {
  canonicalTotal: number;
  canonicalHighPlus: number;
  includedTotal: number | null;
  includedInventory: number;
  countStatus: ReportCountStatus;
  evidenceVerified: boolean;
  internalCopyWarning: boolean;
  severityData: Array<{ label: string; value: number; color: string }>;
  includedBullets: string[];
  excludedBullets: string[];
}

export function buildReportTruth(
  report: RunReportCatalogItem | null,
  findings: Finding[],
  loading: boolean,
): ReportTruthModel {
  const severityCounts = new Map<string, number>();
  for (const finding of findings) {
    const severity = finding.severity.toLowerCase();
    severityCounts.set(severity, (severityCounts.get(severity) ?? 0) + 1);
  }
  const canonicalTotal = findings.length;
  const includedTotal = report ? includedFindingTotal(report.included_findings) : null;
  const countStatus: ReportCountStatus = loading
    ? 'loading'
    : includedTotal === null
      ? 'unknown'
      : includedTotal === canonicalTotal
        ? 'match'
        : 'mismatch';
  const includedInventory = report ? includedInventoryTotal(report.included_inventory) : 0;
  const evidenceVerified = report ? evidenceStatusVerified(report.evidence_status) : false;
  const internalCopyWarning = report ? reportHasInternalCustomerCopy(report) : false;
  const severityData = SEVERITY_ORDER.map((severity) => ({
    label: severity === 'informational' ? 'Info' : severity[0].toUpperCase() + severity.slice(1),
    value: severityCounts.get(severity) ?? 0,
    color: severityColor(severity),
  }));
  return {
    canonicalTotal,
    canonicalHighPlus: (severityCounts.get('critical') ?? 0) + (severityCounts.get('high') ?? 0),
    includedTotal,
    includedInventory,
    countStatus,
    evidenceVerified,
    internalCopyWarning,
    severityData,
    includedBullets: reportIncludedBullets(report, canonicalTotal, includedTotal, includedInventory, evidenceVerified),
    excludedBullets: reportExcludedBullets(internalCopyWarning),
  };
}

export function stageDetailCopy(stage: ReportStage, report: RunReportCatalogItem, truth: ReportTruthModel) {
  const included = truth.includedTotal === null ? 'not listed' : `${truth.includedTotal}`;
  const formats = report.available_formats.join(', ') || 'no export format';
  const map = {
    evidence: {
      label: 'Evidence',
      title: truth.evidenceVerified ? 'Stored proof is attached' : 'Evidence needs review',
      items: [
        truth.evidenceVerified ? 'The catalog marks the report evidence as verified.' : 'Open Evidence Replay before treating this as export-ready.',
        'Report text must be backed by saved findings and artifact references.',
      ],
    },
    scope: {
      label: 'Scope',
      title: `${truth.includedInventory} assets listed`,
      items: [
        'The report only claims the scope returned by the catalog.',
        'Anything outside that scope stays unclaimed, even when the scan ran nearby tools.',
      ],
    },
    findings: {
      label: 'Findings',
      title: `${truth.canonicalTotal} canonical / ${included} included`,
      items: [
        `Count check: ${countStatusLabel(truth.countStatus)}.`,
        `${truth.canonicalHighPlus} canonical high-or-critical finding${truth.canonicalHighPlus === 1 ? '' : 's'} are visible before export.`,
      ],
    },
    variant: {
      label: 'Variant',
      title: humanizeReportValue(report.variant),
      items: [
        report.description || 'No variant description was supplied by the catalog.',
        truth.internalCopyWarning ? 'Customer-facing copy contains internal-looking words and needs review.' : 'Selected metadata is clear of internal lab markers.',
      ],
    },
    export: {
      label: 'Export',
      title: report.export_allowed ? 'Ready to generate' : 'Blocked by catalog',
      items: [
        `Available formats: ${formats}.`,
        report.availability_reason || 'No additional availability reason was supplied.',
      ],
    },
  } satisfies Record<ReportStage, { label: string; title: string; items: string[] }>;
  return map[stage];
}

export function countStatusLabel(status: ReportCountStatus): string {
  if (status === 'loading') return 'loading canonical truth';
  if (status === 'match') return 'matches canonical';
  if (status === 'mismatch') return 'count mismatch';
  return 'count not listed';
}

export function countStatusTone(status: ReportCountStatus): 'cyan' | 'green' | 'amber' | 'red' | 'muted' {
  if (status === 'match') return 'green';
  if (status === 'mismatch') return 'red';
  if (status === 'loading') return 'amber';
  return 'muted';
}

function severityColor(severity: string): string {
  if (severity === 'critical') return '#ef4444';
  if (severity === 'high') return '#f59e0b';
  if (severity === 'medium') return '#fde047';
  if (severity === 'low') return '#5ecfff';
  return '#8ebfe4';
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

function reportIncludedBullets(
  report: RunReportCatalogItem | null,
  canonicalTotal: number,
  includedTotal: number | null,
  includedInventory: number,
  evidenceVerified: boolean,
): string[] {
  if (!report) return ['Select a report variant to see what will be included.'];
  return [
    `${canonicalTotal} canonical finding${canonicalTotal === 1 ? '' : 's'} loaded from the run context.`,
    includedTotal === null
      ? 'The catalog does not list a finding total for this variant.'
      : `${includedTotal} finding${includedTotal === 1 ? '' : 's'} listed inside the selected report catalog entry.`,
    `${includedInventory} scoped asset${includedInventory === 1 ? '' : 's'} listed for this report.`,
    evidenceVerified ? 'Evidence status is marked verified by the report catalog.' : 'Evidence status is not marked verified yet.',
  ];
}

function reportExcludedBullets(internalCopyWarning: boolean): string[] {
  return [
    'Tool output that never became a saved finding stays out of the report.',
    'Untested scope is not treated as safe or clean.',
    internalCopyWarning
      ? 'Internal benchmark or lab wording must be cleaned before customer export.'
      : 'No internal benchmark or lab marker is visible in selected report metadata.',
  ];
}

function includedFindingTotal(payload: Record<string, unknown>): number | null {
  const direct = numberFromRecord(payload, ['total', 'count', 'finding_count', 'findings', 'included', 'included_count']);
  if (direct !== null) return direct;
  const severitySum = SEVERITY_ORDER.reduce((sum, severity) => sum + (numberFromUnknown(payload[severity]) ?? 0), 0);
  return severitySum > 0 ? severitySum : null;
}

function includedInventoryTotal(payload: Record<string, unknown>): number {
  const direct = numberFromRecord(payload, ['total', 'assets', 'asset_count', 'targets', 'target_count']);
  if (direct !== null) return direct;
  const inventoryKeys = ['hosts', 'services', 'http_endpoints', 'endpoints', 'ports'];
  return inventoryKeys.reduce((sum, key) => sum + (numberFromUnknown(payload[key]) ?? 0), 0);
}

function numberFromRecord(payload: Record<string, unknown>, keys: string[]): number | null {
  for (const key of keys) {
    const value = numberFromUnknown(payload[key]);
    if (value !== null) return value;
  }
  return null;
}

function numberFromUnknown(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Number(value);
  if (Array.isArray(value)) return value.length;
  return null;
}

function evidenceStatusVerified(payload: Record<string, unknown>): boolean {
  if (payload.verified === true) return true;
  const status = `${payload.status ?? payload.integrity ?? payload.evidence_status ?? ''}`.toLowerCase();
  return ['verified', 'complete', 'trusted'].includes(status);
}

function reportHasInternalCustomerCopy(report: RunReportCatalogItem): boolean {
  const customerFacing = `${report.variant} ${report.title}`.toLowerCase();
  const isCustomerVariant = /(executive|management|board|customer|client|summary|compliance|iso|soc|pci)/.test(customerFacing);
  if (!isCustomerVariant) return false;
  const haystack = [
    report.variant,
    report.title,
    report.description,
    report.availability_reason,
    report.version_label,
    ...report.methodology_references,
  ].join(' ').toLowerCase();
  return /(xben|benchmark|fixture|smoke|debug|internal|localhost|127\.0\.0\.1)/.test(haystack);
}

function humanizeReportValue(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
