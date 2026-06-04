import type { RunReportCatalogItem } from '../api/types';

export type ReportPreviewTone = 'cyan' | 'green' | 'amber' | 'red' | 'muted';

export interface ReportPreviewMetadata {
  variantLabel: string;
  availabilityLabel: string;
  availabilityTone: ReportPreviewTone;
  preview: {
    loaded: boolean;
    label: string;
    tone: ReportPreviewTone;
    detail: string;
    lineCount: number;
    sectionCount: number;
    claimedFindingTotal: number | null;
  };
  export: {
    ready: boolean;
    label: string;
    tone: ReportPreviewTone;
    formatsLabel: string;
    primaryDownloadName: string;
    contentHash: string;
    shortHash: string;
    reason: string;
  };
  readinessData: Array<{ label: 'Preview' | 'Export' | 'Draft'; value: number; color: string }>;
}

export function buildReportPreviewMetadata(
  report: RunReportCatalogItem,
  markdown: string | null,
): ReportPreviewMetadata {
  const lineCount = markdown ? markdown.split(/\r?\n/).filter((line) => line.trim()).length : 0;
  const sectionCount = markdown ? markdown.split(/\r?\n/).filter((line) => /^#{1,3}\s+/.test(line)).length : 0;
  const claimedFindingTotal = markdown ? previewFindingTotal(markdown) : null;
  const availabilityTone = availabilityToneFor(report.availability_status);
  const exportFormats = report.available_formats.filter((format) => format.trim());
  const primaryFormat = preferredFormat(exportFormats);
  const primaryDownloadName =
    report.download_names[primaryFormat] ?? `aegispt-report-${report.source_run_id.slice(0, 8)}-${report.variant}.${primaryFormat}`;

  return {
    variantLabel: humanizeReportValue(report.variant),
    availabilityLabel: report.availability_label || humanizeReportValue(report.availability_status || 'unknown'),
    availabilityTone,
    preview: {
      loaded: Boolean(markdown),
      label: markdown ? 'loaded' : 'not loaded',
      tone: markdown ? 'green' : report.preview_allowed ? 'muted' : 'amber',
      detail: markdown
        ? previewDetail(lineCount, sectionCount, claimedFindingTotal)
        : report.preview_allowed
          ? 'Generate a Markdown preview to compare exported claims before download.'
          : report.availability_reason || 'Preview is not available for this report.',
      lineCount,
      sectionCount,
      claimedFindingTotal,
    },
    export: {
      ready: report.export_allowed,
      label: report.export_allowed ? 'ready' : 'blocked',
      tone: report.export_allowed ? 'green' : 'red',
      formatsLabel: exportFormats.join(' / ') || 'no format',
      primaryDownloadName,
      contentHash: report.content_sha256,
      shortHash: shortHash(report.content_sha256),
      reason: report.availability_reason || 'No additional availability reason was supplied.',
    },
    readinessData: [
      { label: 'Preview', value: report.preview_allowed ? 1 : 0, color: report.preview_allowed ? '#5ecfff' : '#475569' },
      { label: 'Export', value: report.export_allowed ? 1 : 0, color: report.export_allowed ? '#34d399' : '#475569' },
      { label: 'Draft', value: report.draft_allowed ? 1 : 0, color: report.draft_allowed ? '#d06bff' : '#475569' },
    ],
  };
}

function previewDetail(lineCount: number, sectionCount: number, claimedFindingTotal: number | null): string {
  const findingLabel = claimedFindingTotal === null
    ? 'no finding-count claim found'
    : `${claimedFindingTotal} finding${claimedFindingTotal === 1 ? '' : 's'} claimed`;
  return `${lineCount} non-empty lines, ${sectionCount} section${sectionCount === 1 ? '' : 's'}, ${findingLabel}.`;
}

function preferredFormat(formats: string[]): string {
  if (formats.includes('pdf')) return 'pdf';
  if (formats.includes('html')) return 'html';
  if (formats.includes('markdown')) return 'markdown';
  return formats[0] ?? 'md';
}

function shortHash(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return 'not listed';
  if (trimmed.length <= 14) return trimmed;
  return `${trimmed.slice(0, 8)}...${trimmed.slice(-6)}`;
}

function availabilityToneFor(status: string): ReportPreviewTone {
  if (status === 'export_ready') return 'green';
  if (status === 'generating' || status === 'draft_only') return 'amber';
  if (status === 'blocked' || status === 'unavailable') return 'red';
  return 'muted';
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

function humanizeReportValue(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
