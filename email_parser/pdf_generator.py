from django.http import HttpResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import io

def generate_pdf(request):
    """Generate a structured PDF report of the email analysis results"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph("<b>Email Security Analysis Report</b>", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Email Information
    email_info = request.session.get("email_info", {})
    if email_info:
        elements.append(Paragraph("<b>Email Information:</b>", styles["Heading2"]))
        for key, value in email_info.items():
            elements.append(Paragraph(f"<b>{key}:</b> {value}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    # Vendor Details (New Section)
    vendor_details = request.session.get("vendor_details", {})
    if vendor_details:
        elements.append(Paragraph("<b>Vendor Details:</b>", styles["Heading2"]))
        for key, value in vendor_details.items():
            elements.append(Paragraph(f"<b>{key}:</b> {value}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    # URL Scans
    url_scans = request.session.get("url_scans", [])
    if url_scans:
        elements.append(Paragraph("<b>URL Scans:</b>", styles["Heading2"]))
        for scan in url_scans:
            elements.append(Paragraph(f"URL: {scan.get('url', 'N/A')}", styles["Normal"]))
            elements.append(Paragraph(f"Reputation: {scan.get('reputation', 0)}", styles["Normal"]))
            elements.append(Paragraph(f"Malicious: {scan.get('malicious', 0)}", styles["Normal"]))
            elements.append(Spacer(1, 6))

    # Attachment Scans
    attachment_scans = request.session.get("attachment_scans", [])
    if attachment_scans:
        elements.append(Paragraph("<b>Attachment Scans:</b>", styles["Heading2"]))
        for attachment in attachment_scans:
            elements.append(Paragraph(f"Filename: {attachment.get('filename', 'N/A')}", styles["Normal"]))
            elements.append(Paragraph(f"MD5: {attachment.get('scan_result', {}).get('md5', 'N/A')}", styles["Normal"]))
            elements.append(Paragraph(f"Malicious: {attachment.get('scan_result', {}).get('malicious', 0)}", styles["Normal"]))
            elements.append(Spacer(1, 6))

    # Generate PDF
    doc.build(elements)

    buffer.seek(0)
    response = HttpResponse(buffer, content_type="application/pdf")
    response["Content-Disposition"] = "attachment; filename=email_analysis_report.pdf"

    return response
