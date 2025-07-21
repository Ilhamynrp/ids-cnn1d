from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import deque, Counter
import time
import pandas as pd
import numpy as np
import joblib
import socket
import subprocess
from tensorflow.keras.models import load_model
import requests
import fcntl
import struct
from rules import apply_rules

def get_host_ip(interface='eth0'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(
            fcntl.ioctl(
                s.fileno(),
                0x8915,
                struct.pack('256s', interface[:15].encode('utf-8'))
            )[20:24]
        )
    except Exception:
        return None

HOST_IP = get_host_ip('eth0') or '127.0.0.1'
print(f"[INFO] Host IP (eth0): {HOST_IP}")

scaler = joblib.load('scaler.pkl')
model = load_model('cnn1d_model.h5', compile=False)

target_features = [
    'Protocol_TCP','Protocol_UDP','Protocol_ICMP',
    'Flags_S','Flags_FA','Flags_PA','Flags_A','Flags_R',
    'PayloadEntropy','Flag_S_Count','PacketRate','Pkt_last1s',
    'PayloadLen','TotalFwdPackets','EntropyPorts'
]

pkt_buffer = deque(maxlen=1000)
flag_counter = Counter()
recent_alerts = {}
cooldown = {}
COOLDOWN_SEC = 10
last_reset = time.time()
last_time = time.time()

def entropy(data):
    if not data:
        return 0.0
    vals, counts = np.unique(np.frombuffer(data, dtype=np.uint8), return_counts=True)
    p = counts / counts.sum()
    return -np.sum(p * np.log2(p))

def should_alert(src, dst, atype, now):
    key = (src, dst, atype)
    if key not in recent_alerts or now - recent_alerts[key] > 5:
        recent_alerts[key] = now
        return True
    return False

def get_syn_burst(pkt_buffer, now):
    burst_counter = {}
    for t, sport, dport, flags in reversed(pkt_buffer):
        if now - t > 1.0:
            break
        if flags & 0x02:  # 0x02 = SYN
            burst_counter[dport] = burst_counter.get(dport, 0) + 1
    return max(burst_counter.values(), default=0)

def extract(pkt):
    global last_time, last_reset
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if ip.dst != HOST_IP:
        return None
    now = time.time()
    feat = dict.fromkeys(target_features, 0)

    feat['Protocol_TCP'] = int(ip.proto == 6)
    feat['Protocol_UDP'] = int(ip.proto == 17)
    feat['Protocol_ICMP'] = int(ip.proto == 1)

    if ip.proto == 6 and TCP in pkt:
        flags = pkt[TCP].flags
        s = 'S' in flags
        feat['Flags_S'] = int(s)
        feat['Flags_A'] = int('A' in flags)
        feat['Flags_FA'] = int('F' in flags)
        feat['Flags_PA'] = int('P' in flags and 'A' in flags)
        feat['Flags_R'] = int('R' in flags)
        if s:
            flag_counter['S'] += 1

    feat['Flag_S_Count'] = flag_counter['S']

    raw = bytes(ip.payload)
    feat['PayloadLen'] = len(raw)
    feat['PayloadEntropy'] = entropy(raw)
    
    feat['SynBurst'] = get_syn_burst(pkt_buffer, now)

    if now - last_reset > 1.0:
        flag_counter['S'] = 0
        last_reset = now

    sport = getattr(pkt, 'sport', 0)
    dport = getattr(pkt, 'dport', 0)
    flags = pkt[TCP].flags if TCP in pkt else 0
    pkt_buffer.append((now, sport, dport, flags))

    # PATCH: hanya dst port (dport) untuk entropy dan unique port scan
    window = [t for t, _, _, _ in pkt_buffer if now - t <= 1.0]
    feat['Pkt_last1s'] = len(window)
    feat['PacketRate'] = len(pkt_buffer) / max(1e-6, now - last_time)
    last_time = now
    feat['TotalFwdPackets'] = sum(1 for _, s, _, _ in pkt_buffer if s < dport)

    # --- PATCH: Hanya gunakan dport, bukan src+dst ---
    dport_window = [d for t, _, d, _ in pkt_buffer if now - t <= 1.0]
    feat['EntropyPorts'] = entropy(np.array(dport_window, dtype=np.uint16).tobytes())
    feat['UniqueDports'] = len(set(dport_window))
    feat['DstPort'] = dport   # Tambahkan ini!

    if now - last_reset > 1.0:
        flag_counter['S'] = 0
        last_reset = now

    return feat

def handle(pkt):
    try:
        if IP in pkt:
            src_ip = pkt[IP].src
            if src_ip != '10.88.35.5':
                return  # abaikan paket dari IP lain
                
        feat = extract(pkt)
        if not feat:
            return
        print(feat)
        df = pd.DataFrame([feat])[target_features]
        Xs = scaler.transform(df).reshape((1, 1, len(target_features)))
        pred = float(model.predict(Xs, verbose=0)[0][0])
        rule_score, atype = apply_rules(feat)
        final = (rule_score * 0.7) + (pred * 0.3)

        if atype is not None and rule_score > 0.5:
            src, dst = pkt[IP].src, pkt[IP].dst
            proto = pkt[IP].proto
            now = time.time()
            if should_alert(src, dst, atype, now):
                alert = {
                    "src": src,
                    "dst": dst,
                    "protocol": proto,
                    "attack_type": atype,
                    "confidence": final,
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
                    "attack": True,
                    "action": "Blocked" if atype != "Port Scan" else "Monitored"
                }

                if atype != 'Port Scan':
                    if src not in cooldown or now - cooldown[src] > COOLDOWN_SEC:
                        cooldown[src] = now
                        alert['action'] = 'Blocked'
                        try:
                            subprocess.run(['iptables', '-I', 'INPUT', '-s', src, '-j', 'DROP'], check=True)
                        except Exception as e:
                            print(f"[ERROR] Failed to block IP {src}: {e}")
                    else:
                        alert['action'] = 'Cooldown'
                else:
                    alert['action'] = 'Monitored'

                try:
                    requests.post('http://localhost:5000/report', json=alert, timeout=1)
                except:
                    print("[WARNING] Failed to send alert to server")

                print('[DETECTED]', alert)

    except Exception as e:
        print(f"[ERROR] Failed to handle packet: {e}")


if __name__ == '__main__':
    print('[INFO] Starting sniff on eth0')
    sniff(iface='eth0', prn=handle, store=False, filter='ip')
