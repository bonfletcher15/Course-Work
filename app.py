import requests
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, session
from werkzeug.utils import secure_filename
import time
from flask_sqlalchemy import SQLAlchemy
import hashlib
from io import BytesIO
from datetime import datetime
import json
import os
from urllib.parse import urlparse
import re

with open('config.json') as config_file:
    config = json.load(config_file)

VIRUSTOTAL_API_KEY = config.get('virustotal_api_key')

app = Flask(__name__)
app.secret_key = 'roberto_bilbao'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///analysis_results.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    input_value = db.Column(db.String(256), unique=True, nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    vt_link = db.Column(db.String(512))
    stats_json = db.Column(db.Text)
    details_json = db.Column(db.Text)

    file_analysis = db.relationship('FileAnalysis', backref='scan_result', uselist=False)
    other_analyses = db.relationship('OtherAnalysis', backref='scan_result', lazy=True)

class FileAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(256))
    file_size = db.Column(db.Integer)
    file_path = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'))

class OtherAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan_result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'))

def scan_file_with_virustotal(file_content, filename):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    files = {
        'file': (filename, file_content)
    }
    response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers, files=files)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def get_virustotal_results(scan_id, timeout=60, interval=5):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    elapsed = 0
    while elapsed < timeout:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            status = result.get('data', {}).get('attributes', {}).get('status')
            if status == 'completed':
                return result
        time.sleep(interval)
        elapsed += interval
    return None

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False

def scan_url_with_virustotal(url):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    data = {'url': url}
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    return None

def get_url_analysis_results(scan_id, timeout=120, interval=5):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    elapsed = 0
    while elapsed < timeout:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result.get('data', {}).get('attributes', {}).get('status') == 'completed':
                return result
        time.sleep(interval)
        elapsed += interval
    return None

def is_sha256(s):
    return bool(re.fullmatch(r'[A-Fa-f0-9]{64}', s))

def is_sha1(s):
    return bool(re.fullmatch(r'[A-Fa-f0-9]{40}', s))

def is_md5(s):
    return bool(re.fullmatch(r'[A-Fa-f0-9]{32}', s))

def is_ip(s):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, s):
        return False
    parts = s.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

def is_domain(s):
    pattern = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$'
    return bool(re.match(pattern, s))

def calculate_severity(stats: dict) -> str:
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    if malicious > 0:
        return 'malicious'
    elif suspicious > 0:
        return 'suspicious'
    else:
        return 'clean'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('home'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('home'))

    filename = secure_filename(file.filename)
    file_content = file.read()
    file_hash = hashlib.sha256(file_content).hexdigest()

    scan_result = ScanResult.query.filter_by(input_value=file_hash).first()
    file_analysis = FileAnalysis.query.filter_by(scan_result_id=scan_result.id).first() if scan_result else None

    if not scan_result:
        vt_response = scan_file_with_virustotal(file_content, filename)
        if vt_response:
            scan_id = vt_response.get('data', {}).get('id')
            analysis = get_virustotal_results(scan_id)
            if analysis:
                stats = analysis.get('data', {}).get('attributes', {}).get('stats')
                details = analysis.get('meta', {}).get('file_info', {})
                severity = calculate_severity(stats)
                permalink = f"https://www.virustotal.com/gui/file/{file_hash}"

                scan_result = ScanResult(
                    input_value=file_hash,
                    severity=severity,
                    vt_link=permalink,
                    stats_json=json.dumps(stats),
                    details_json=json.dumps(details)
                )
                db.session.add(scan_result)
                db.session.commit()

                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                with open(save_path, 'wb') as f:
                    f.write(file_content)

                file_analysis = FileAnalysis(
                    file_name=filename,
                    file_size=len(file_content),
                    file_path=save_path,
                    created_at=datetime.utcnow(),
                    scan_result_id=scan_result.id
                )
                db.session.add(file_analysis)
                db.session.commit()

    return render_template(
        'index.html',
        active_tab='file',
        filename=filename,
        vt_results=json.loads(scan_result.stats_json),
        vt_details=json.loads(scan_result.details_json),
        severity=scan_result.severity,
        scan_link=scan_result.vt_link,
        scan_result=scan_result,
        created_at=file_analysis.created_at if file_analysis else None
)

@app.route('/scan_url', methods=['POST'])
def scan_url():
    url_input = request.form.get('url_input')
    if not is_valid_url(url_input):
        error = "Please enter a valid URL."
        return render_template('index.html', error_message=error, active_tab='url')

    scan_result = ScanResult.query.filter_by(input_value=url_input).first()

    if not scan_result:
        vt_response = scan_url_with_virustotal(url_input)
        if vt_response:
            scan_id = vt_response.get('data', {}).get('id')
            analysis = get_url_analysis_results(scan_id)
            if analysis:
                stats = analysis.get('data', {}).get('attributes', {}).get('stats')
                severity = calculate_severity(stats)
                permalink = f"https://www.virustotal.com/gui/url/{scan_id}"

                scan_result = ScanResult(
                    input_value=url_input,
                    severity=severity,
                    vt_link=permalink,
                    stats_json=json.dumps(stats),
                    details_json=json.dumps(analysis.get('meta', {}))
                )
                db.session.add(scan_result)
                db.session.commit()

                other_analysis = OtherAnalysis(
                    type='url',
                    scan_result_id=scan_result.id
                )
                db.session.add(other_analysis)
                db.session.commit()

    vt_results = json.loads(scan_result.stats_json)
    vt_details = json.loads(scan_result.details_json)

    return render_template(
        'index.html',
        active_tab='url',
        url_input=url_input,
        vt_results=vt_results,
        vt_details=vt_details,
        severity=scan_result.severity,
        scan_link=scan_result.vt_link,
        scan_result=scan_result
    )

@app.route('/scan_other', methods=['POST'])
def scan_other():
    query = request.form.get('search_input', '').strip()
    active_tab = 'search'

    if not query:
        error = "Please enter a search query."
        return render_template('index.html', error_message=error, active_tab=active_tab)

    if is_sha256(query) or is_sha1(query) or is_md5(query):
        vt_endpoint = f"https://www.virustotal.com/api/v3/files/{query}"
        analysis_type = 'file_hash'
    elif is_ip(query):
        vt_endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
        analysis_type = 'ip'
    elif is_domain(query):
        vt_endpoint = f"https://www.virustotal.com/api/v3/domains/{query}"
        analysis_type = 'domain'
    elif is_valid_url(query):
        vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{query}"
        analysis_type = 'url'
    else:
        error = "Input is not recognized as valid hash, IP, domain, or URL."
        return render_template('index.html', error_message=error, active_tab=active_tab)

    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(vt_endpoint, headers=headers)

    if response.status_code != 200:
        error = "Could not retrieve data from VirusTotal for the given input."
        return render_template('index.html', error_message=error, active_tab=active_tab)

    data = response.json()
    attributes = data.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})
    severity = calculate_severity(stats)
    permalink = f"https://www.virustotal.com/gui/{analysis_type}/{query}"

    scan_result = ScanResult.query.filter_by(input_value=query).first()
    if not scan_result:
        scan_result = ScanResult(
            input_value=query,
            severity=severity,
            vt_link=permalink,
            stats_json=json.dumps(stats),
            details_json=json.dumps(attributes)
        )
        db.session.add(scan_result)
        db.session.commit()

        other_analysis = OtherAnalysis(
            type=analysis_type,
            scan_result_id=scan_result.id
        )
        db.session.add(other_analysis)
        db.session.commit()

    return render_template(
        'index.html',
        active_tab=active_tab,
        search_input=query,
        vt_results=json.loads(scan_result.stats_json),
        vt_details=json.loads(scan_result.details_json),
        severity=scan_result.severity,
        scan_link=scan_result.vt_link
    )

@app.route('/download_report_txt/<path:input_value>')
def download_report_txt(input_value):
    scan = ScanResult.query.filter_by(input_value=input_value).first()
    if not scan:
        return "Scan not found", 404

    session['report_counter'] = session.get('report_counter', 0) + 1
    report_number = session['report_counter']

    stats = json.loads(scan.stats_json)
    details = json.loads(scan.details_json)

    content = f"""Scan Report for: {input_value}
Severity: {scan.severity}
VirusTotal Link: {scan.vt_link}

--- Summary ---
"""
    for k, v in stats.items():
        content += f"{k.capitalize()}: {v}\n"

    content += "\n--- Details ---\n"
    for k, v in details.items():
        content += f"{k.replace('_', ' ').capitalize()}: {v}\n"

    filename = f"report{report_number}.txt"

    return Response(
        content,
        mimetype='text/plain',
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route('/api/scans')
def api_scans():
    scans = ScanResult.query.order_by(ScanResult.id.desc()).all()
    scan_list = []
    for scan in scans:
        if scan.file_analysis:
            scan_type = 'file'
        elif scan.other_analyses:
            scan_type = scan.other_analyses[0].type
        else:
            scan_type = 'unknown'
        scan_list.append({
            'input_value': scan.input_value,
            'severity': scan.severity,
            'type': scan_type
        })
    return jsonify(scan_list)

@app.route('/view_scan/<path:input_value>')
def view_scan(input_value):
    scan = ScanResult.query.filter_by(input_value=input_value).first()
    if not scan:
        return "Scan not found", 404

    return render_template(
        'index.html',
        active_tab='search',
        search_input=input_value,
        vt_results=json.loads(scan.stats_json),
        vt_details=json.loads(scan.details_json),
        severity=scan.severity,
        scan_link=scan.vt_link
    )

@app.route('/api/delete_scan/<path:input_value>', methods=['DELETE'])
def delete_scan(input_value):
    scan = ScanResult.query.filter_by(input_value=input_value).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404

    FileAnalysis.query.filter_by(scan_result_id=scan.id).delete()
    OtherAnalysis.query.filter_by(scan_result_id=scan.id).delete()
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/recent_scans')
def recent_scans():
    scans = ScanResult.query.order_by(ScanResult.id.desc()).limit(10).all()
    return jsonify([
        {
            'input_value': s.input_value,
            'severity': s.severity,
            'type': 'file' if s.file_analysis else 'url'
        }
        for s in scans
    ])

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)