"""Page routes - Serve HTML templates."""
from flask import Blueprint, render_template

pages_bp = Blueprint('pages', __name__)


@pages_bp.route('/')
def index():
    return render_template('index.html')


@pages_bp.route('/login')
def login_page():
    return render_template('login.html')


@pages_bp.route('/intranet')
def intranet_page():
    return render_template('intranet.html')


@pages_bp.route('/apn-int')
def apn_int_page():
    return render_template('apn_int.html')


@pages_bp.route('/apn-mali')
def apn_mali_page():
    return render_template('apn_mali.html')


@pages_bp.route('/ptmp')
def ptmp_page():
    return render_template('ptmp.html')


@pages_bp.route('/mpls-vpls')
def mpls_vpls_page():
    return render_template('mpls_vpls.html')


@pages_bp.route('/config-wizard')
def config_wizard_page():
    return render_template('config_wizard.html')


@pages_bp.route('/config-both')
def config_both_page():
    return render_template('config_both.html')


@pages_bp.route('/reserve-lan')
def reserve_lan_page():
    return render_template('reserve_lan.html')


@pages_bp.route('/db-manager')
def db_manager_page():
    return render_template('db_manager.html')


@pages_bp.route('/service-management')
def service_management_page():
    return render_template('service_management.html')


@pages_bp.route('/shared-files')
def shared_files_page():
    return render_template('shared_files.html')


@pages_bp.route('/reports')
def reports_page():
    return render_template('reports.html')


@pages_bp.route('/network-map')
def network_map_page():
    return render_template('network_map.html')


@pages_bp.route('/nat-diagram')
def nat_diagram_page():
    return render_template('nat_diagram.html')
