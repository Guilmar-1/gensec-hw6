import json
import csv
import io
from flask import Blueprint, Response, flash, redirect, url_for, render_template
from models.scan_model import ScanModel
from models.vulnerability_model import VulnerabilityModel

report_bp = Blueprint('report', __name__)

@report_bp.route('/scan/<int:scan_id>/report/json')
def export_json(scan_id):
    scan = ScanModel.get_scan(scan_id)
    if not scan:
        flash("Scan not found.", "warning")
        return redirect(url_for('dashboard.index'))

    vulns = VulnerabilityModel.get_vulnerabilities_by_scan(scan_id)
    report_data = {
        "scan": dict(scan),
        "vulnerabilities": [dict(v) for v in vulns]
    }

    return Response(
        json.dumps(report_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=scan_{scan_id}_report.json"}
    )

@report_bp.route('/scan/<int:scan_id>/report/csv')
def export_csv(scan_id):
    scan = ScanModel.get_scan(scan_id)
    if not scan:
        flash("Scan not found.", "warning")
        return redirect(url_for('dashboard.index'))

    vulns = VulnerabilityModel.get_vulnerabilities_by_scan(scan_id)
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['ID', 'Name', 'Severity', 'Description', 'Evidence', 'Remediation'])
    for v in vulns:
        writer.writerow([v['id'], v['name'], v['severity'], v['description'], v['evidence'], v['remediation']])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=scan_{scan_id}_report.csv"}
    )

@report_bp.route('/scan/<int:scan_id>/report/html')
def export_html(scan_id):
    scan = ScanModel.get_scan(scan_id)
    if not scan:
        flash("Scan not found.", "warning")
        return redirect(url_for('dashboard.index'))

    vulns = VulnerabilityModel.get_vulnerabilities_by_scan(scan_id)
    rendered_html = render_template('scan_detail.html', scan=scan, vulnerabilities=vulns, print_mode=True)
    
    return Response(
        rendered_html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment;filename=scan_{scan_id}_report.html"}
    )
