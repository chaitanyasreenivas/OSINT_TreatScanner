from flask import Flask, render_template, request, redirect, url_for
from scanner import Orchestrator
from flask_sqlalchemy import SQLAlchemy
import json
from datetime import datetime
import mistune
from dashboard_fetchers import get_threat_news, get_top_attackers
from collections import Counter # New import

app = Flask(__name__)
# --- DATABASE CONFIGURATION ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Add mistune as a Jinja filter ---
app.jinja_env.filters['markdown'] = mistune.html

# --- DATABASE MODEL ---
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(200), nullable=False)
    target_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results_json = db.Column(db.Text, nullable=False)

# --- UPDATED DASHBOARD ROUTE ---
@app.route('/')
def dashboard():
    """Renders the new intelligence dashboard with KPIs and Map data."""
    threat_news = get_threat_news()
    top_attackers = get_top_attackers()

    # --- NEW: Process data for KPIs and Map ---
    kpis = {
        'total_attackers': 0,
        'countries_involved': 0,
        'top_country': 'N/A',
        'intel_articles': len(threat_news)
    }
    country_counts = {}

    if top_attackers and 'error' not in top_attackers[0]:
        kpis['total_attackers'] = len(top_attackers)
        
        # Count occurrences of each country code
        country_codes = [attacker['country'] for attacker in top_attackers]
        country_counts = dict(Counter(country_codes))
        
        kpis['countries_involved'] = len(country_counts)
        if country_counts:
            # Find the country with the highest count
            top_country_code = max(country_counts, key=country_counts.get)
            kpis['top_country'] = top_country_code
    
    return render_template('dashboard.html', 
                           news=threat_news, 
                           attackers=top_attackers,
                           kpis=kpis,
                           map_data=json.dumps(country_counts))

# --- UNCHANGED ROUTES ---
@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    orchestrator = Orchestrator(target)
    scan_results = orchestrator.run_scans()
    
    new_scan = Scan(
        target=target,
        target_type=orchestrator.target_type,
        results_json=json.dumps(scan_results)
    )
    db.session.add(new_scan)
    db.session.commit()
    
    return redirect(url_for('view_report', scan_id=new_scan.id))

@app.route('/report/view/<int:scan_id>')
def view_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    results = json.loads(scan.results_json)
    return render_template('results.html', scan=scan, results=results)

@app.route('/history')
def history():
    all_scans = Scan.query.order_by(Scan.timestamp.desc()).all()
    return render_template('history.html', scans=all_scans)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)