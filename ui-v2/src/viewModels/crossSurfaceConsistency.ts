import type { Finding, Run, RunReportCatalogItem } from '../api/types';

export type CrossSurfaceCheckStatus = 'match' | 'warning' | 'mismatch' | 'unknown' | 'loading';
export type CrossSurfaceOverallStatus = 'consistent' | 'review' | 'mismatch' | 'loading' | 'unknown';

export interface CrossSurfaceCheck {
  id: 'run-summary' | 'report-catalog' | 'report-preview' | 'evidence-links';
  label: string;
  status: CrossSurfaceCheckStatus;
  expected: string;
  observed: string;
  detail: string;
}

export interface CrossSurfaceConsistencyModel {
  status: CrossSurfaceOverallStatus;
  headline: string;
  detail: string;
  canonicalTotal: number;
  canonicalHighPlus: number;
  evidenceLinkedTotal: number;
  runSummaryTotal: number | null;
  selectedReportTotal: number | null;
  previewTotal: number | null;
  checks: CrossSurfaceCheck[];
}

export interface BuildCrossSurfaceConsistencyInput {
  run: Run | null;
  findings: Finding[];
  reports: RunReportCatalogItem[];
  selectedReport: RunReportCatalogItem | null;
  markdownPreview: string | null;
  loadingFindings: boolean;
  loadingReports: boolean;
}

export function buildCrossSurfaceConsistency({
  run,
  findings,
  reports,
  selectedReport,
  markdownPreview,
  loadingFindings,
  loadingReports,
}: BuildCrossSurfaceConsistencyInput): CrossSurfaceConsistencyModel {
  const severityCounts = findingSeverityCounts(findings);
  const canonicalTotal = findings.length;
  const canonicalHighPlus = (severityCounts.critical ?? 0) + (severityCounts.high ?? 0);
  const evidenceLinkedTotal = findings.filter((finding) => String(finding.evidence_ref || '').trim()).length;
  const runSummaryTotal = run ? numberFromUnknown(run.findings?.finding_count) : null;
  const selectedReportTotal = selectedReport ? includedFindingTotal(selectedReport.included_findings) : null;
  const previewTotal = markdownPreview ? previewFindingTotal(markdownPreview) : null;
  const catalogMismatches = reports.filter((report) => {
    const total = includedFindingTotal(report.included_findings);
    return total !== null && total !== canonicalTotal;
  });

  const checks: CrossSurfaceCheck[] = [
    buildRunSummaryCheck({ canonicalTotal, runSummaryTotal, loadingFindings, hasRun: run !== null }),
    buildReportCatalogCheck({ canonicalTotal, selectedReportTotal, catalogMismatches, loadingReports, hasReport: selectedReport !== null }),
    buildReportPreviewCheck({ canonicalTotal, previewTotal, markdownPreview, loadingReports }),
    buildEvidenceLinksCheck({ canonicalTotal, evidenceLinkedTotal, selectedReport, loadingFindings }),
  ];

  const status = overallStatus(checks);
  return {
    status,
    headline: headlineForStatus(status),
    detail: detailForStatus(status, checks),
    canonicalTotal,
    canonicalHighPlus,
    evidenceLinkedTotal,
    runSummaryTotal,
    selectedReportTotal,
    previewTotal,
    checks,
  };
}

function buildRunSummaryCheck({
  canonicalTotal,
  runSummaryTotal,
  loadingFindings,
  hasRun,
}: {
  canonicalTotal: number;
  runSummaryTotal: number | null;
  loadingFindings: boolean;
  hasRun: boolean;
}): CrossSurfaceCheck {
  if (loadingFindings) {
    return {
      id: 'run-summary',
      label: 'Run summary',
      status: 'loading',
      expected: `${canonicalTotal} canonical`,
      observed: 'loading',
      detail: 'Canonical findings are still loading.',
    };
  }
  if (!hasRun || runSummaryTotal === null) {
    return {
      id: 'run-summary',
      label: 'Run summary',
      status: 'unknown',
      expected: `${canonicalTotal} canonical`,
      observed: 'not listed',
      detail: 'No run-local finding summary is available for comparison.',
    };
  }
  if (runSummaryTotal !== canonicalTotal) {
    return {
      id: 'run-summary',
      label: 'Run summary',
      status: 'warning',
      expected: `${canonicalTotal} canonical`,
      observed: `${runSummaryTotal} run-local`,
      detail: 'Run-local summary differs; customer/report surfaces should use canonical findings.',
    };
  }
  return {
    id: 'run-summary',
    label: 'Run summary',
    status: 'match',
    expected: `${canonicalTotal} canonical`,
    observed: `${runSummaryTotal} run-local`,
    detail: 'Run-local summary and canonical findings agree.',
  };
}

function buildReportCatalogCheck({
  canonicalTotal,
  selectedReportTotal,
  catalogMismatches,
  loadingReports,
  hasReport,
}: {
  canonicalTotal: number;
  selectedReportTotal: number | null;
  catalogMismatches: RunReportCatalogItem[];
  loadingReports: boolean;
  hasReport: boolean;
}): CrossSurfaceCheck {
  if (loadingReports) {
    return {
      id: 'report-catalog',
      label: 'Report catalog',
      status: 'loading',
      expected: `${canonicalTotal} canonical`,
      observed: 'loading',
      detail: 'Report catalog is still loading.',
    };
  }
  if (!hasReport || selectedReportTotal === null) {
    return {
      id: 'report-catalog',
      label: 'Report catalog',
      status: 'unknown',
      expected: `${canonicalTotal} canonical`,
      observed: 'not listed',
      detail: 'The selected catalog entry does not list an included finding total.',
    };
  }
  if (selectedReportTotal !== canonicalTotal || catalogMismatches.length > 0) {
    const variants = catalogMismatches.map((report) => report.variant).join(', ');
    return {
      id: 'report-catalog',
      label: 'Report catalog',
      status: 'mismatch',
      expected: `${canonicalTotal} canonical`,
      observed: `${selectedReportTotal} selected`,
      detail: variants
        ? `Catalog mismatch in ${variants}; export readiness needs review.`
        : 'Selected report count does not match canonical findings.',
    };
  }
  return {
    id: 'report-catalog',
    label: 'Report catalog',
    status: 'match',
    expected: `${canonicalTotal} canonical`,
    observed: `${selectedReportTotal} selected`,
    detail: 'Selected report and catalog variants match canonical findings.',
  };
}

function buildReportPreviewCheck({
  canonicalTotal,
  previewTotal,
  markdownPreview,
  loadingReports,
}: {
  canonicalTotal: number;
  previewTotal: number | null;
  markdownPreview: string | null;
  loadingReports: boolean;
}): CrossSurfaceCheck {
  if (loadingReports) {
    return {
      id: 'report-preview',
      label: 'Export preview',
      status: 'loading',
      expected: `${canonicalTotal} canonical`,
      observed: 'loading',
      detail: 'Preview state follows the selected report catalog.',
    };
  }
  if (!markdownPreview) {
    return {
      id: 'report-preview',
      label: 'Export preview',
      status: 'unknown',
      expected: `${canonicalTotal} canonical`,
      observed: 'not generated',
      detail: 'Generate a preview to compare exported markdown claims.',
    };
  }
  if (previewTotal === null) {
    return {
      id: 'report-preview',
      label: 'Export preview',
      status: 'unknown',
      expected: `${canonicalTotal} canonical`,
      observed: 'count not found',
      detail: 'Preview loaded, but no canonical finding count was found in the markdown.',
    };
  }
  if (previewTotal !== canonicalTotal) {
    return {
      id: 'report-preview',
      label: 'Export preview',
      status: 'mismatch',
      expected: `${canonicalTotal} canonical`,
      observed: `${previewTotal} preview`,
      detail: 'Markdown preview claims a different finding count than canonical findings.',
    };
  }
  return {
    id: 'report-preview',
    label: 'Export preview',
    status: 'match',
    expected: `${canonicalTotal} canonical`,
    observed: `${previewTotal} preview`,
    detail: 'Markdown preview finding count matches canonical findings.',
  };
}

function buildEvidenceLinksCheck({
  canonicalTotal,
  evidenceLinkedTotal,
  selectedReport,
  loadingFindings,
}: {
  canonicalTotal: number;
  evidenceLinkedTotal: number;
  selectedReport: RunReportCatalogItem | null;
  loadingFindings: boolean;
}): CrossSurfaceCheck {
  if (loadingFindings) {
    return {
      id: 'evidence-links',
      label: 'Evidence links',
      status: 'loading',
      expected: `${canonicalTotal} linked`,
      observed: 'loading',
      detail: 'Evidence references are still loading with canonical findings.',
    };
  }
  const catalogLinked = selectedReport ? numberFromUnknown(selectedReport.evidence_status.linked_findings) : null;
  if (canonicalTotal > 0 && evidenceLinkedTotal < canonicalTotal) {
    return {
      id: 'evidence-links',
      label: 'Evidence links',
      status: 'warning',
      expected: `${canonicalTotal} linked`,
      observed: `${evidenceLinkedTotal} linked`,
      detail: 'Some canonical findings have no evidence reference attached yet.',
    };
  }
  if (catalogLinked !== null && catalogLinked !== evidenceLinkedTotal) {
    return {
      id: 'evidence-links',
      label: 'Evidence links',
      status: 'mismatch',
      expected: `${evidenceLinkedTotal} canonical linked`,
      observed: `${catalogLinked} catalog linked`,
      detail: 'Catalog evidence-link count differs from canonical findings.',
    };
  }
  return {
    id: 'evidence-links',
    label: 'Evidence links',
    status: 'match',
    expected: `${canonicalTotal} linked`,
    observed: `${evidenceLinkedTotal} linked`,
    detail: canonicalTotal === 0
      ? 'No canonical findings require evidence links for this run.'
      : 'Every canonical finding has an evidence reference available for reports.',
  };
}

function overallStatus(checks: CrossSurfaceCheck[]): CrossSurfaceOverallStatus {
  if (checks.some((check) => check.status === 'loading')) return 'loading';
  if (checks.some((check) => check.status === 'mismatch')) return 'mismatch';
  if (checks.some((check) => check.status === 'warning')) return 'review';
  if (checks.every((check) => check.status === 'unknown')) return 'unknown';
  return 'consistent';
}

function headlineForStatus(status: CrossSurfaceOverallStatus): string {
  if (status === 'loading') return 'Loading consistency checks';
  if (status === 'mismatch') return 'Report truth needs review';
  if (status === 'review') return 'Canonical surfaces agree with a noted caveat';
  if (status === 'unknown') return 'Not enough data to compare surfaces';
  return 'Report surfaces agree';
}

function detailForStatus(status: CrossSurfaceOverallStatus, checks: CrossSurfaceCheck[]): string {
  if (status === 'loading') return 'The checker is waiting for findings or report catalog data.';
  if (status === 'mismatch') return checks.find((check) => check.status === 'mismatch')?.detail ?? 'At least one surface disagrees.';
  if (status === 'review') return checks.find((check) => check.status === 'warning')?.detail ?? 'One caveat needs operator review.';
  if (status === 'unknown') return 'Generate a preview or load a report catalog to complete the comparison.';
  return 'Canonical findings, report catalog, evidence links, and generated preview are aligned where data is available.';
}

function findingSeverityCounts(findings: Finding[]): Record<string, number> {
  return findings.reduce<Record<string, number>>((counts, finding) => {
    const severity = String(finding.severity || 'unknown').toLowerCase();
    counts[severity] = (counts[severity] ?? 0) + 1;
    return counts;
  }, {});
}

function includedFindingTotal(payload: Record<string, unknown>): number | null {
  const direct = numberFromRecord(payload, ['total', 'count', 'finding_count', 'findings', 'included', 'included_count']);
  if (direct !== null) return direct;
  const severityBuckets = ['critical', 'high', 'medium', 'low', 'info', 'informational'];
  const severitySum = severityBuckets.reduce((sum, key) => sum + (numberFromUnknown(payload[key]) ?? 0), 0);
  return severitySum > 0 ? severitySum : null;
}

function previewFindingTotal(markdown: string): number | null {
  const patterns = [
    /Canonical Findings:\s*(\d+)/i,
    /Evidence-backed Findings:\s*(\d+)/i,
    /Bevindingen:\s*(\d+)/i,
    /Totaal bevindingen\s*(?:\||:)?\s*(\d+)/i,
  ];
  for (const pattern of patterns) {
    const match = markdown.match(pattern);
    if (match?.[1]) return Number(match[1]);
  }
  return null;
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
