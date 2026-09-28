# modules/reporting/pdf_report.py
# =============================================================================
# CyberToolkit Pro — PDF Report Generator
# =============================================================================

import os
import datetime
from typing import Any, Dict
from core.models import ToolResult, Severity

TOOL_INFO = {
    "name": "pdf_report",
    "category": "reporting",
    "description": "Generates professional PDF security audit and vulnerability reports",
    "author": "CyberToolkit Pro Team",
    "version": "1.0.0",
    "arguments": [
        {"name": "output_file", "description": "Output PDF path (default: reports/audit_report.pdf)", "arg_type": "str", "default": "reports/audit_report.pdf"},
        {"name": "title", "description": "Report title", "arg_type": "str", "default": "CyberToolkit Pro Security Audit Report"},
    ],
    "tags": ["reporting", "pdf", "export", "executive", "audit"],
}

def _generate_minimal_pdf(output_path: str, title: str, findings: list):
    """Fallback pure-Python PDF generator if ReportLab is not available."""
    content_lines = [
        "%PDF-1.4",
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj",
        "5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    ]
    
    # Stream text
    stream_lines = [
        "BT",
        "/F1 18 Tf",
        "50 740 Td",
        f"({title}) Tj",
        "/F1 10 Tf",
        "0 -25 Td",
        f"(Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} by CyberToolkit Pro) Tj",
        "0 -30 Td",
        f"(Total Findings: {len(findings)}) Tj",
        "0 -20 Td",
    ]
    
    y = 665
    for idx, f in enumerate(findings[:25], 1):
        sev = getattr(f, "severity", "INFO")
        sev_str = sev.value.upper() if hasattr(sev, "value") else str(sev).upper()
        ftitle = getattr(f, "title", "Finding")
        clean_title = ftitle.replace("(", "[").replace(")", "]")
        stream_lines.extend([
            "0 -15 Td",
            f"({idx}. [{sev_str}] {clean_title[:60]}) Tj",
        ])
    
    stream_lines.append("ET")
    stream_content = "\n".join(stream_lines)
    
    stream_obj = f"4 0 obj << /Length {len(stream_content)} >> stream\n{stream_content}\nendstream\nendobj"
    content_lines.append(stream_obj)
    
    # Cross reference table
    xref_offset = sum(len(line) + 1 for line in content_lines)
    xref = [
        f"xref",
        "0 6",
        "0000000000 65535 f ",
        "0000000010 00000 n ",
        "0000000060 00000 n ",
        "0000000115 00000 n ",
        f"{xref_offset:010d} 00000 n ",
        "0000000240 00000 n ",
        "trailer << /Size 6 /Root 1 0 R >>",
        f"startxref\n{xref_offset}\n%%EOF"
    ]
    
    with open(output_path, "wb") as pdf:
        pdf.write("\n".join(content_lines + xref).encode("latin1"))

def run(args: Dict[str, Any]) -> ToolResult:
    out_file = args.get("output_file", "reports/audit_report.pdf")
    title = args.get("title", "CyberToolkit Pro Security Audit Report")
    findings = args.get("findings", [])

    os.makedirs(os.path.dirname(os.path.abspath(out_file)), exist_ok=True)

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        doc = SimpleDocTemplate(out_file, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#00ffff'),
            spaceAfter=20
        )

        story.append(Paragraph(title, title_style))
        story.append(Paragraph(f"<b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 15))

        # Findings table
        table_data = [["#", "Severity", "Finding Title", "Target"]]
        for i, f in enumerate(findings, 1):
            sev = getattr(f, "severity", "INFO")
            sev_str = sev.value.upper() if hasattr(sev, "value") else str(sev).upper()
            table_data.append([
                str(i),
                sev_str,
                getattr(f, "title", "Finding")[:40],
                getattr(f, "target", "")[:30]
            ])

        if len(table_data) > 1:
            t = Table(table_data, colWidths=[30, 80, 250, 150])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f2937')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No findings recorded in this audit session.", styles['Normal']))

        doc.build(story)
    except ImportError:
        # Fallback to minimal PDF
        _generate_minimal_pdf(out_file, title, findings)

    return ToolResult(
        tool_name="pdf_report",
        status="success",
        data={"pdf_path": out_file, "filesize": os.path.getsize(out_file) if os.path.exists(out_file) else 0}
    )
