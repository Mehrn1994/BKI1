"""Export routes - CSV, Excel, PDF exports for all tables."""
import io
import csv
from datetime import datetime
from flask import Blueprint, jsonify, request, Response

from app.config import Config
from app.database import get_db_readonly, log_audit
from app.security import sanitize_error

export_bp = Blueprint('export', __name__)


def _csv_response(output, filename):
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={filename}'})


@export_bp.route('/api/export/lan-ips', methods=['GET'])
def export_lan_ips():
    username = request.args.get('username', '')
    if username != Config.DB_ADMIN_USER:
        return jsonify({'error': 'Admin only'}), 403
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT octet2, octet3, branch_name, province, wan_ip, username, reservation_date, status
                FROM lan_ips WHERE branch_name IS NOT NULL AND branch_name != ''
                ORDER BY province, branch_name
            """)
            rows = cursor.fetchall()

        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.writer(output)
        writer.writerow(['IP LAN', 'Branch', 'Province', 'WAN IP', 'User', 'Date', 'Status'])
        for r in rows:
            writer.writerow([f"10.{r['octet2']}.{r['octet3']}.0/24", r['branch_name'] or '',
                             r['province'] or '', r['wan_ip'] or '', r['username'] or '',
                             r['reservation_date'] or '', r['status'] or 'Active'])

        log_audit('export', 'LAN IPs CSV export', username, 'export', ip_address=request.remote_addr)
        return _csv_response(output, 'lan_ips_export.csv')
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@export_bp.route('/api/export/reservations', methods=['GET'])
def export_reservations():
    username = request.args.get('username', '')
    if username != Config.DB_ADMIN_USER:
        return jsonify({'error': 'Admin only'}), 403
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reserved_ips ORDER BY reservation_date DESC")
            rows = cursor.fetchall()

        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.writer(output)
        writer.writerow(['IP LAN', 'Province', 'Branch', 'Type', 'Request#', 'User', 'Date', 'Expiry', 'Status'])
        for r in rows:
            writer.writerow([f"10.{r['octet2']}.{r['octet3']}.0/24", r['province'] or '',
                             r['branch_name'] or '', r['point_type'] or '', r['request_number'] or '',
                             r['username'] or '', r['reservation_date'] or '', r['expiry_date'] or '',
                             r['status'] or 'reserved'])

        log_audit('export', 'Reservations CSV export', username, 'export', ip_address=request.remote_addr)
        return _csv_response(output, 'reservations_export.csv')
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@export_bp.route('/api/export/apn-int', methods=['GET'])
def export_apn_int():
    username = request.args.get('username', '')
    if username != Config.DB_ADMIN_USER:
        return jsonify({'error': 'Admin only'}), 403
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, branch_name, province, type, lan_ip, ip_wan_apn, username, reservation_date
                FROM apn_ips WHERE username IS NOT NULL AND username != ''
                ORDER BY reservation_date DESC
            """)
            rows = cursor.fetchall()
        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.writer(output)
        writer.writerow(['ID', 'Branch', 'Province', 'Type', 'LAN IP', 'WAN IP', 'User', 'Date'])
        for r in rows:
            writer.writerow([r['id'], r['branch_name'] or '', r['province'] or '', r['type'] or '',
                             r['lan_ip'] or '', r['ip_wan_apn'] or '', r['username'] or '',
                             r['reservation_date'] or ''])
        log_audit('export', 'APN INT CSV export', username, 'export', ip_address=request.remote_addr)
        return _csv_response(output, 'apn_int_export.csv')
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@export_bp.route('/api/export/apn-mali', methods=['GET'])
def export_apn_mali():
    username = request.args.get('username', '')
    if username != Config.DB_ADMIN_USER:
        return jsonify({'error': 'Admin only'}), 403
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, branch_name, province, type, lan_ip, ip_wan, username, reservation_date
                FROM apn_mali WHERE username IS NOT NULL AND username != ''
                ORDER BY reservation_date DESC
            """)
            rows = cursor.fetchall()
        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.writer(output)
        writer.writerow(['ID', 'Branch', 'Province', 'Type', 'LAN IP', 'WAN IP', 'User', 'Date'])
        for r in rows:
            writer.writerow([r['id'], r['branch_name'] or '', r['province'] or '', r['type'] or '',
                             r['lan_ip'] or '', r['ip_wan'] or '', r['username'] or '',
                             r['reservation_date'] or ''])
        log_audit('export', 'APN Mali CSV export', username, 'export', ip_address=request.remote_addr)
        return _csv_response(output, 'apn_mali_export.csv')
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@export_bp.route('/api/export/intranet', methods=['GET'])
def export_intranet():
    username = request.args.get('username', '')
    if username != Config.DB_ADMIN_USER:
        return jsonify({'error': 'Admin only'}), 403
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ip_address, tunnel_name, ip_lan, ip_intranet, description, province, status, reserved_by, reserved_at
                FROM intranet_tunnels WHERE LOWER(status)='reserved'
                ORDER BY reserved_at DESC
            """)
            rows = cursor.fetchall()
        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.writer(output)
        writer.writerow(['IP', 'Tunnel Name', 'IP LAN', 'IP Intranet', 'Description', 'Province', 'Status', 'User', 'Date'])
        for r in rows:
            writer.writerow([r['ip_address'] or '', r['tunnel_name'] or '', r['ip_lan'] or '',
                             r['ip_intranet'] or '', r['description'] or '', r['province'] or '',
                             r['status'] or '', r['reserved_by'] or '', r['reserved_at'] or ''])
        log_audit('export', 'Intranet CSV export', username, 'export', ip_address=request.remote_addr)
        return _csv_response(output, 'intranet_export.csv')
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500


@export_bp.route('/api/export/audit-log', methods=['GET'])
def export_audit_log():
    username = request.args.get('username', '')
    if username != Config.DB_ADMIN_USER:
        return jsonify({'error': 'Admin only'}), 403
    try:
        with get_db_readonly() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 5000")
            rows = cursor.fetchall()
        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.writer(output)
        writer.writerow(['ID', 'Timestamp', 'User', 'Action', 'Category', 'Details', 'IP', 'Table', 'Target ID'])
        for r in rows:
            writer.writerow([r['id'], r['timestamp'], r['username'], r['action'],
                             r['category'] or '', r['details'] or '', r['ip_address'] or '',
                             r['target_table'] or '', r['target_id'] or ''])
        return _csv_response(output, 'audit_log_export.csv')
    except Exception as e:
        return jsonify({'error': sanitize_error(e)}), 500
