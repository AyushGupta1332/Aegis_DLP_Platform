from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, IFACES
import pandas as pd
from collections import defaultdict
import time
import os


def _find_active_iface():
    """Auto-detect the network interface that is actually receiving packets.
    
    On Windows, Scapy often defaults to an Ethernet adapter even when the
    system is on WiFi. This tests each interface with a short capture and
    returns the one with real traffic.
    """
    # Quick test of default first
    try:
        pkts = sniff(count=0, timeout=2, store=True)
        if len(pkts) > 0:
            print(f"[*] Default interface works: {conf.iface} ({len(pkts)} pkts in 2s)")
            return None  # None = use default
    except Exception:
        pass
    
    print("[!] Default interface captured 0 packets — scanning all interfaces...")
    best_iface = None
    best_count = 0
    
    for name, iface in IFACES.items():
        try:
            pkts = sniff(iface=name, count=0, timeout=2, store=True)
            desc = getattr(iface, 'description', name)
            if len(pkts) > best_count:
                best_count = len(pkts)
                best_iface = name
                print(f"    {desc}: {len(pkts)} packets  <-- best so far")
            elif len(pkts) > 0:
                print(f"    {desc}: {len(pkts)} packets")
        except Exception:
            continue
    
    if best_iface:
        desc = getattr(IFACES[best_iface], 'description', best_iface)
        print(f"[*] Selected interface: {desc} ({best_count} pkts in 2s)")
    else:
        print("[!] WARNING: No interface captured any packets — capture may fail")
    
    return best_iface

class NormalCapture:
    def __init__(self, samples=10000, output_file=None):
        self.connections = defaultdict(dict)
        self.host_history = defaultdict(list)
        self.dataset = []
        self.target = samples
        self.stop_requested = False  # Flag for stopping capture
        
        # Save to data folder - use fixed filename (overwrite mode)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, 'data')
        os.makedirs(data_dir, exist_ok=True)
        
        # Use provided output file or default fixed filename
        if output_file:
            self.output = output_file
        else:
            self.output = os.path.join(data_dir, "ids_capture.csv")

    def extract_key(self, pkt):
        if IP in pkt:
            return (pkt[IP].src, pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
                    pkt[IP].dst, pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
                    pkt[IP].proto)
        return None

    def get_proto(self, pkt):
        if TCP in pkt: return 'tcp'
        elif UDP in pkt: return 'udp'
        elif ICMP in pkt: return 'icmp'
        return 'other'

    def get_service(self, pkt):
        ports = {21:'ftp', 22:'ssh', 23:'telnet', 25:'smtp', 53:'domain', 80:'http', 
                 110:'pop3', 139:'netbios_ssn', 143:'imap', 443:'https', 445:'microsoft_ds'}
        if TCP in pkt or UDP in pkt:
            return ports.get(pkt[TCP].dport if TCP in pkt else pkt[UDP].dport, 'other')
        return 'other'

    def get_flag(self, pkt):
        if TCP in pkt:
            f = pkt[TCP].flags
            if f & 0x02 and not (f & 0x10): return 'S0'
            elif f & 0x01: return 'SF'
            elif f & 0x04: return 'REJ'
            elif f & 0x10: return 'S1'
            return 'S2'
        return 'OTH'

    def process(self, pkt):
        if IP not in pkt or len(self.dataset) >= self.target:
            return
        
        key = self.extract_key(pkt)
        if not key: return
        
        ts = time.time()
        if key not in self.connections:
            self.connections[key] = {
                'start': ts, 'proto': self.get_proto(pkt), 'svc': self.get_service(pkt),
                'flag': self.get_flag(pkt), 'sbytes': 0, 'dbytes': 0, 'pkts': 0,
                'src': key[0], 'dst': key[2]
            }
        
        c = self.connections[key]
        c['pkts'] += 1
        if pkt[IP].src == key[0]: c['sbytes'] += len(pkt)
        else: c['dbytes'] += len(pkt)
        c['dur'] = ts - c['start']
        self.host_history[c['dst']].append({'ts': ts, 'svc': c['svc'], 'flag': c['flag']})
        
        if c['pkts'] == 1:
            self.dataset.append(self.features(key))
            if len(self.dataset) % 100 == 0:
                print(f"  >> {len(self.dataset)}/{self.target} samples")
                self.save()

    def features(self, key):
        c = self.connections[key]
        now = time.time()
        recent = [x for x in self.connections.values() if now - x['start'] <= 2]
        cnt = len(recent) or 1
        same = [x for x in recent if x['svc'] == c['svc']]
        serr = [x for x in recent if x['flag'] in ['S0','S1','S2']]
        rerr = [x for x in recent if x['flag'] == 'REJ']
        
        dhist = [x for x in self.host_history[c['dst']] if now - x['ts'] <= 100]
        dcnt = len(dhist) or 1
        dsame = [x for x in dhist if x['svc'] == c['svc']]
        dserr = [x for x in dhist if x['flag'] in ['S0','S1','S2']]
        drerr = [x for x in dhist if x['flag'] == 'REJ']
        
        return [
            round(c['dur'], 2), c['proto'], c['svc'], c['flag'], c['sbytes'], c['dbytes'],
            cnt, len(same), len(same)/cnt, 1-len(same)/cnt, len(serr)/cnt, len(rerr)/cnt,
            dcnt, len(dsame), len(dsame)/dcnt, 1-len(dsame)/dcnt, len(dserr)/dcnt, len(drerr)/dcnt,
            'normal', 0
        ]

    def save(self):
        if self.dataset:
            df = pd.DataFrame(self.dataset, columns=[
                'duration','protocol_type','service','flag','src_bytes','dst_bytes',
                'count','srv_count','same_srv_rate','diff_srv_rate','serror_rate','rerror_rate',
                'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
                'dst_host_serror_rate','dst_host_rerror_rate','label','anomaly'])
            df.to_csv(self.output, index=False)
    
    def reset(self):
        """Reset capture state and delete existing CSV file for fresh start."""
        self.connections = defaultdict(dict)
        self.host_history = defaultdict(list)
        self.dataset = []
        self.stop_requested = False
        
        # Delete existing CSV file if it exists
        if os.path.exists(self.output):
            try:
                os.remove(self.output)
                print(f"[*] Cleared previous capture data: {self.output}")
            except Exception as e:
                print(f"[!] Warning: Could not delete old file: {e}")
    
    def stop(self):
        """Request capture to stop."""
        self.stop_requested = True
        print("[*] Stop requested for packet capture")
    
    def run(self):
        # Reset state for fresh capture
        self.reset()
        
        print("="*60)
        print(f" NORMAL TRAFFIC CAPTURE - Target: {self.target} samples")
        print(f" Output: {self.output}")
        print("="*60)
        
        # Auto-detect the active network interface
        active_iface = _find_active_iface()
        if active_iface:
            print(f"[*] Using interface: {active_iface}")
        else:
            print(f"[*] Using default interface: {conf.iface}")
        
        print("\n[*] Capturing packets... (Ctrl+C to stop)\n")
        try:
            sniff_kwargs = dict(
                prn=self.process,
                stop_filter=lambda x: len(self.dataset) >= self.target or self.stop_requested,
                store=False,
            )
            if active_iface:
                sniff_kwargs['iface'] = active_iface
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        except Exception as e:
            print(f"\n[!] Capture error: {e}")
        finally:
            self.save()
            print(f"\n[✓] Complete! {len(self.dataset)} samples → {self.output}")

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Scapy packet capture for Aegis DLP")
    parser.add_argument('--samples', type=int, default=1000000,
                        help='Number of samples to capture (default: 1000000)')
    parser.add_argument('--output', type=str, default=None,
                        help='Output CSV file path')
    args = parser.parse_args()

    NormalCapture(samples=args.samples, output_file=args.output).run()
