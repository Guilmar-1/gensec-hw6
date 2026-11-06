from flask import Blueprint, request, redirect, url_for, render_template, flash
from models.scan_model import ScanModel
from models.vulnerability_model import VulnerabilityModel
from scanner.validator import URLValidator
from scanner.engine import ScannerEngine

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scan/start', methods=['POST'])
def start_scan():
    target_url = request.form.get('target_url', '').strip()

    is_valid, message = URLValidator.validate_url(target_url)
    if not is_valid:
        flash(f"Invalid scan target: {message}", "danger")
        return redirect(url_for('dashboard.index'))

    scan_id = ScanModel.create_scan(target_url)
    
    engine = ScannerEngine()
    engine.run_scan(scan_id, target_url)

    flash("Scan completed successfully.", "success")
    return redirect(url_for('scan.view_scan', scan_id=scan_id))

@scan_bp.route('/scan/<int:scan_id>')
def view_scan(scan_id):
    scan = ScanModel.get_scan(scan_id)
    if not scan:
        flash("Scan record not found.", "warning")
        return redirect(url_for('dashboard.index'))

    vulnerabilities = VulnerabilityModel.get_vulnerabilities_by_scan(scan_id)
    return render_template('scan_detail.html', scan=scan, vulnerabilities=vulnerabilities)

@scan_bp.route('/scans')
def scan_history():
    scans = ScanModel.get_all_scans()
    return render_template('history.html', scans=scans)

@scan_bp.route('/scan/<int:scan_id>/delete', methods=['POST'])
def delete_scan(scan_id):
    ScanModel.delete_scan(scan_id)
    flash("Scan record deleted.", "info")
    return redirect(url_for('scan.scan_history'))
