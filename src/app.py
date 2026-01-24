# src/app.py
from flask import Flask, render_template, jsonify
from netids.models import SessionLocal, Alert
from sqlalchemy import desc
import datetime

app = Flask(__name__, template_folder="dashboard/templates", static_folder="dashboard/static")

# Helper to classify alerts
def get_layer(alert_type):
    layer1_types = ["port-scan", "dos", "blacklist", "insecure-protocol"]
    # If it's a known network attack, it's Layer 1. Otherwise, it's Layer 2 (Anomaly/ML).
    if any(x in alert_type.lower() for x in layer1_types):
        return "Layer 1 (Network)"
    return "Layer 2 (Insider/ML)"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/data")
def get_data():
    session = SessionLocal()
    try:
        # Fetch last 50 alerts
        alerts_query = session.query(Alert).order_by(desc(Alert.timestamp)).limit(50).all()
        
        data = []
        stats = {
            "total": 0,
            "layer1": 0,
            "layer2": 0,
            "critical": 0
        }

        for a in alerts_query:
            layer_name = get_layer(a.alert_type)
            
            # Update stats
            stats["total"] += 1
            if "Layer 1" in layer_name:
                stats["layer1"] += 1
            else:
                stats["layer2"] += 1
            
            if a.severity >= 4:
                stats["critical"] += 1

            # Format timestamp for display
            ts_str = a.timestamp.strftime("%H:%M:%S")
            
            data.append({
                "id": a.id,
                "time": ts_str,
                "src": a.src_ip,
                "dst": a.dst_ip,
                "type": a.alert_type,
                "layer": layer_name,
                "severity": a.severity,
                "desc": a.description
            })
            
        return jsonify({"alerts": data, "stats": stats})
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        session.close()

if __name__ == "__main__":
    print("[SERVER] Smart Farm IDS Dashboard running on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)