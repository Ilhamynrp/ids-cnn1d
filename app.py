from flask import Flask, request, jsonify, render_template, redirect, url_for
from datetime import datetime
import threading
import os
import sys
import subprocess

app = Flask(__name__)
log_data = []
block_list = set()
data_lock = threading.Lock()

CRITICAL_TYPES = {"SQL Injection", "RCE", "Brute Force", "SYN Flood", "DoS ICMP"}
MONITORING_TYPES = {"Port Scan"}

@app.route("/")
def dashboard():
    with data_lock:
        attack_logs = [e for e in log_data if e.get("attack") == True]
        blocked_ips = [{
            "ip": ip,
            "first_detected": min(e['timestamp'] for e in log_data if e.get('src') == ip),
            "last_attack": max(e['timestamp'] for e in log_data if e.get('src') == ip),
            "attack_count": sum(1 for e in log_data if e.get('src') == ip),
            "attack_type": next((e['attack_type'] for e in reversed(log_data) if e.get('src') == ip), "Unknown")
        } for ip in block_list]
        critical_count = sum(1 for e in attack_logs if e.get("attack_type") in CRITICAL_TYPES)
        monitoring_count = sum(1 for e in attack_logs if e.get("attack_type") in MONITORING_TYPES)
        return render_template("dashboard.html", data=attack_logs, blocks=blocked_ips,
                               critical_count=critical_count, monitoring_count=monitoring_count)

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    with data_lock:
        if data:
            print("[RECEIVED]", data)
            log_data.append(data)
            if len(log_data) > 1000:
                log_data.pop(0)
            atype = data.get("attack_type")
            if atype in CRITICAL_TYPES and data.get("src"):
                block_list.add(data["src"])
        else:
            print("[ERROR] Bad data")
    return jsonify({"status": "received"})

@app.route("/data")
def get_data():
    with data_lock:
        return jsonify([e for e in log_data if e.get("attack") == True])

@app.route("/blocked")
def get_blocked():
    with data_lock:
        return jsonify([{
            "ip": ip,
            "first_detected": min(e['timestamp'] for e in log_data if e.get('src') == ip),
            "last_attack": max(e['timestamp'] for e in log_data if e.get('src') == ip),
            "attack_count": sum(1 for e in log_data if e.get('src') == ip),
            "attack_type": next((e['attack_type'] for e in reversed(log_data) if e.get('src') == ip), "Unknown")
        } for ip in block_list])

# ✅ Fix nama fungsi agar tidak duplikat
@app.route("/unblock/<ip>")
def unblock_page(ip):
    with data_lock:
        block_list.discard(ip)
        print(f"[UNBLOCKED] {ip}")
    try:
        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
    except Exception as e:
        print(f"[ERROR] Failed to unblock IP {ip} from iptables: {e}")
    return redirect(url_for('dashboard'))

@app.route("/unblock", methods=["POST"])
def unblock_ip():
    data = request.get_json()
    ip = data.get("ip")
    if ip:
        try:
            # Hapus SEMUA rule DROP yang cocok
            while True:
                # Dapatkan nomor rule untuk IP itu
                result = subprocess.check_output(
                    f"iptables -L INPUT -n --line-numbers | grep 'DROP' | grep '{ip}' | awk '{{print $1}}'",
                    shell=True
                ).decode().strip().split("\n")
                # Cek apakah sudah tidak ada rule untuk IP tsb
                result = [r for r in result if r.strip()]
                if not result:
                    break
                # Selalu hapus rule dengan nomor terkecil (rule nomor berubah setelah 1 baris dihapus!)
                subprocess.run(['iptables', '-D', 'INPUT', result[0]], check=True)
            block_list.discard(ip)
            return jsonify({"status": "success", "msg": f"{ip} unblocked"})
        except Exception as e:
            return jsonify({"status": "fail", "msg": str(e)}), 500
    return jsonify({"status": "fail", "msg": "No IP"}), 400


# ✅ Jalankan sniff.py di background
def start_sniffer():
    python_path = sys.executable
    sniff_script_path = os.path.join(os.getcwd(), "sniff.py")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    subprocess.Popen([python_path, sniff_script_path], env=env)

if __name__ == "__main__":
    threading.Thread(target=start_sniffer).start()
    app.run(host="0.0.0.0", port=5000)
