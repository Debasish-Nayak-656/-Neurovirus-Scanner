"""
/api/report  –  Generate downloadable PDF/JSON reports for a completed scan.

GET /api/report/<scan_id>/json   → raw JSON
GET /api/report/<scan_id>/pdf    → PDF report (requires reportlab)
"""

import io
import json
import time
import logging
from flask import Blueprint, jsonify, send_file, current_app

from routes.scan import _scan_cache   # shared in-process cache

logger    = logging.getLogger("neurovirus.report")
report_bp = Blueprint("report", __name__)


@report_bp.route("/<scan_id>/json", methods=["GET"])
def report_json(scan_id: str):
    data = _scan_cache.get(scan_id)
    if not data:
        return jsonify({"error": "Scan ID not found"}), 404
    return jsonify(data), 200


@report_bp.route("/<scan_id>/pdf", methods=["GET"])
def report_pdf(scan_id: str):
    data = _scan_cache.get(scan_id)
    if not data:
        return jsonify({"error": "Scan ID not found"}), 404

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
    except ImportError:
        return jsonify({"error": "reportlab not installed; run: pip install reportlab"}), 500

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # Title
    title_style = ParagraphStyle("title", parent=styles["Title"], textColor=colors.HexColor("#00ff88"))
    story.append(Paragraph("NeuroVirus Scan Report", title_style))
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(f"Scan ID: {scan_id}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {data.get('timestamp', 'N/A')}", styles["Normal"]))
    story.append(Spacer(1, 0.6*cm))

    # Summary table
    summary = data.get("summary", {})
    s_data  = [
        ["Metric", "Value"],
        ["Total Files Scanned", str(summary.get("total_files", 0))],
        ["Threats Found",       str(summary.get("total_threats", 0))],
        ["Max Threat Score",    str(summary.get("max_score", 0)) + "/100"],
        ["Critical",            str(summary.get("threat_counts", {}).get("CRITICAL", 0))],
        ["High",                str(summary.get("threat_counts", {}).get("HIGH", 0))],
        ["Moderate",            str(summary.get("threat_counts", {}).get("MODERATE", 0))],
        ["Safe",                str(summary.get("threat_counts", {}).get("SAFE", 0))],
    ]
    t = Table(s_data, colWidths=[10*cm, 6*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#020b14")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.HexColor("#00ff88")),
        ("GRID",       (0, 0), (-1,-1), 0.5, colors.HexColor("#0a2a3a")),
        ("FONTNAME",   (0, 0), (-1, 0), "Courier-Bold"),
        ("FONTNAME",   (0, 1), (-1,-1), "Courier"),
        ("FONTSIZE",   (0, 0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1,-1), [colors.white, colors.HexColor("#f0f8ff")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.6*cm))

    # Per-file results
    for r in data.get("results", []):
        story.append(Paragraph(f"File: {r.get('file_name','?')}", styles["Heading2"]))
        story.append(Paragraph(f"Threat Level: {r.get('threat_level','?')}  |  Score: {r.get('threat_score',0)}/100", styles["Normal"]))
        story.append(Paragraph(f"SHA256: {r.get('sha256','?')}", styles["Code"]))
        story.append(Paragraph(f"MD5: {r.get('md5','?')}", styles["Code"]))

        # ClamAV
        clam = r.get("clamav", {})
        story.append(Paragraph("ClamAV: " + (clam.get("virus_name") or "CLEAN"), styles["Normal"]))

        # YARA hits
        yara_hits = r.get("yara", {}).get("matches", [])
        if yara_hits:
            story.append(Paragraph("YARA Matches:", styles["Normal"]))
            for hit in yara_hits:
                story.append(Paragraph(f"  • {hit}", styles["Normal"]))

        # VirusTotal
        vt = r.get("virustotal", {})
        if vt.get("found"):
            story.append(Paragraph(
                f"VirusTotal: {vt.get('positives',0)}/{vt.get('total',0)} engines flagged",
                styles["Normal"]
            ))

        story.append(Spacer(1, 0.4*cm))

    doc.build(story)
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True, download_name=f"neurovirus_report_{scan_id}.pdf")
