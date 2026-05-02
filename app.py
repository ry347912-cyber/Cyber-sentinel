from flask import Flask, jsonify, request
from flask_cors import CORS
import random, time
from datetime import datetime

app = Flask(__name__)
CORS(app)

ATTACK_TYPES = ["DDoS","Port Scan","SQL Injection","Brute Force","XSS","ARP Spoof","MITM","DNS Flood"]
PROTOCOLS = ["TCP","UDP","ICMP","HTTP","HTTPS","DNS","SSH"]
SEVERITIES = ["LOW","MEDIUM","HIGH","CRITICAL"]
FAKE_IPS = ["192.168.1.","10.0.0.","185.220.101.","203.0.113.","45.33.32."]
start_time = time.time()

def rand_ip():
    return random.choice(FAKE_IPS) + str(random.randint(1,254))

def fake_alert():
    return {"type":random.choice(ATTACK_TYPES),"src_ip":rand_ip(),"dst_ip":rand_ip(),
            "severity":random.choice(SEVERITIES),"protocol":random.choice(PROTOCOLS),
            "port":random.randint(1,65535),"packets":random.randint(100,9999),
            "time":datetime.now().isoformat()}

def uptime():
    s=int(time.time()-start_time); return f"{s//3600}h {(s%3600)//60}m {s%60}s"

@app.route("/")
def home():
    return jsonify({"project":"CyberSentinel IDS","status":"running","author":"Rupesh Yadav","github":"https://github.com/ry347912-cyber/Cyber-sentinel"})

@app.route("/api/status")
def status():
    return jsonify({"status":"running","ml_enabled":True,"capturing":True,"uptime":uptime(),"total_packets":847293+random.randint(50,400),"total_attacks":1247,"blocked_ips":1183})

@app.route("/api/alerts")
def alerts():
    return jsonify([fake_alert() for _ in range(20)])

@app.route("/api/traffic")
def traffic():
    return jsonify([{"time":f"{i}s","packets":random.randint(200,1200),"attacks":random.randint(0,80),"normal":random.randint(150,1100)} for i in range(30)])

@app.route("/api/stats")
def stats():
    return jsonify({"total_packets":847293,"attacks_detected":1247,"blocked_count":1183,"uptime":uptime(),"severity_counts":{"LOW":120,"MEDIUM":280,"HIGH":190,"CRITICAL":85},"attack_type_counts":{t:random.randint(10,200) for t in ATTACK_TYPES}})

@app.route("/api/block", methods=["POST"])
def block():
    ip=(request.get_json() or {}).get("ip","unknown")
    return jsonify({"success":True,"blocked_ip":ip})

@app.route("/api/settings", methods=["GET","POST"])
def settings():
    return jsonify({"ml_enabled":True,"deep_inspect":False,"auto_block":True,"threshold":500})

if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
