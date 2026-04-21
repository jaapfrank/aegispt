# Report PDF Pipeline

## Purpose

AegisPT now exposes a dedicated PDF export path on top of the existing report service so Executive, Technical, Evidence, and Retest reports can be downloaded directly as deterministic PDFs without creating a second reporting domain model.

## Implementation choice

The pipeline reuses the existing HTML report renderer and finalizes the document with Playwright Chromium in `api/app/services/report_pdf.py`.

Why this path was chosen:

- additive to the current reporting model
- preserves Prompt 1 methodology structure and Prompt 2 provenance fields
- keeps report semantics in one place
- reliable layout and pagination without a parallel template stack

## Flow

1. `api/app/services/reports.py` builds the report context and catalog.
2. `api/app/routers/runs.py` accepts `format=pdf`.
3. `api/app/services/report_pdf.py`:
   - renders the existing HTML report
   - injects print-safe base URL and PDF CSS
   - applies headers/footers
   - emits an A4 tagged PDF through Playwright Chromium

The HTML template is also tuned for print readability so the PDF stays:

- easy to scan section by section
- readable in grayscale or low-color print workflows
- explicit about run, customer, and profile context
- less likely to break long evidence references or code-like values across the page

## Supported outputs

- Executive Report
- Technical Report
- Evidence Appendix
- Retest / Verification Report

All variants continue to use the same run/customer/project/methodology/evidence context already defined in the existing reporting layer.

## Operational notes

- Playwright Chromium must be installed:

```bash
python -m playwright install chromium
```

- the export endpoint remains:

```text
GET /api/v1/runs/{run_id}/report?format=pdf&variant={variant}
```

- `scripts/export_run_report.sh` now supports `pdf`

## Validation

- `api/tests/test_reports.py` validates markdown, HTML, and PDF export
- PDF validation confirms:
  - response type is `application/pdf`
  - bytes are parseable as a PDF
  - expected report text is present
