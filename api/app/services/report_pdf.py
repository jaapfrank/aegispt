from __future__ import annotations

from html import escape

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from api.app.config import Settings
from api.app.models import Run
from api.app.services.reports import (
    REPORT_VARIANT_LABELS,
    _render_management_nl_html,
    normalize_report_variant,
    render_html_report,
    report_context,
)


def _inject_pdf_base_and_styles(html: str, *, base_url: str) -> str:
    base_tag = f'<base href="{escape(base_url.rstrip("/") + "/")}">'
    pdf_styles = """
    <style>
      @page {
        size: A4;
        margin: 18mm 14mm 18mm 14mm;
      }
      body {
        margin: 0;
        background: #ffffff !important;
        font-size: 13px;
        line-height: 1.58;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
      h1 {
        font-size: 22px;
      }
      h2 {
        font-size: 15px;
      }
      .panel,
      .finding,
      .task,
      table,
      pre {
        break-inside: avoid;
        page-break-inside: avoid;
      }
      a {
        color: #9a3412;
        text-decoration: underline;
      }
      .pdf-cover {
        padding: 0 0 1.5rem 0;
        border-bottom: 2px solid #d1d5db;
        margin-bottom: 1.5rem;
      }
      .pdf-cover h1 {
        margin-bottom: 0.35rem;
      }
      .pdf-cover p {
        color: #4b5563;
        margin: 0.2rem 0;
      }
      .report-context {
        display: flex;
        flex-wrap: wrap;
        gap: 0.35rem;
        margin-top: 0.75rem;
      }
      .context-chip {
        padding: 0.28rem 0.48rem;
        border-radius: 999px;
        border: 1px solid #d1d5db;
        background: #fcfcfd;
        color: #374151;
        font-size: 8.5px;
      }
      code,
      pre {
        overflow-wrap: anywhere;
        word-break: break-word;
        white-space: pre-wrap;
      }
    </style>
    """
    with_head = html.replace("</head>", f"{base_tag}{pdf_styles}</head>", 1)
    return with_head


def render_pdf_report(
    run: Run,
    *,
    variant: str,
    settings: Settings,
    framework: str | None = None,
    context: dict[str, object] | None = None,
) -> bytes:
    ctx = context or report_context(run)
    if str(variant or "").strip().lower() == "management_nl":
        html = _render_management_nl_html(run, ctx)
    else:
        html = render_html_report(run, variant=variant, framework=framework, context=ctx)
    prepared_html = _inject_pdf_base_and_styles(html, base_url=settings.app_public_base_url)
    title = REPORT_VARIANT_LABELS.get(normalize_report_variant(variant), "AegisPT Report")
    header_template = f"""
      <div style="width:100%; font-size:8px; padding:0 12px; color:#6b7280; font-family:Segoe UI, Helvetica Neue, sans-serif;">
        <span>{escape(title)} · {escape(run.engagement.name if run.engagement is not None else 'Unknown engagement')}</span>
      </div>
    """
    footer_template = """
      <div style="width:100%; font-size:8px; padding:0 12px; color:#6b7280; font-family:Segoe UI, Helvetica Neue, sans-serif; display:flex; justify-content:space-between;">
        <span>AegisPT evidence-first export</span>
        <span><span class="pageNumber"></span>/<span class="totalPages"></span></span>
      </div>
    """

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 960})
            page.set_content(prepared_html, wait_until="load")
            pdf = page.pdf(
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template=header_template,
                footer_template=footer_template,
                margin={"top": "22mm", "right": "14mm", "bottom": "18mm", "left": "14mm"},
                prefer_css_page_size=True,
                tagged=True,
            )
            browser.close()
            return pdf
    except PlaywrightError as exc:
        raise RuntimeError(
            "PDF export requires Playwright Chromium. Install it with `python -m playwright install chromium`."
        ) from exc
