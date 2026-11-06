from flask import Blueprint, render_template
from models.scan_model import ScanModel
from config import Config

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def index():
    scans = ScanModel.get_all_scans()
    return render_template('index.html', scans=scans, default_target=Config.DEFAULT_TARGET)
