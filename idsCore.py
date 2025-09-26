import json, time, logging
from collections import defaultdict, deque
from datetime import datetime
import numpy as np
import pandas as pd

from .extractor import NetworkFeatureExtractor
from .anomalyDetector import AnomalyDetector

try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class RealTimeIDS:
    """Real-time Intrusion Detection System"""
    
    def __init__(self):
        self.feature_extractor = NetworkFeatureExtractor()
        self.anomaly_detector = AnomalyDetector()
        self.alert_queue = deque(maxlen=1000)
        self.stats = defaultdict(int)
        self.is_monitoring = False
        self.packet_buffer = deque(maxlen=100)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ids.log'),
                logging.StreamHandler()
            ]
        )
        
    def generate_sample_data(self):
        """Generate sample network traffic data for testing"""
        print("🔄 Generating sample network traffic data...")
        
        # Create synthetic normal traffic
        normal_data = []
        for i in range(800):
            sample = {
                'src_ip': f"192.168.1.{np.random.randint(1, 100)}",
                'dst_ip': f"10.0.0.{np.random.randint(1, 100)}",
                'protocol': np.random.choice([6, 17]),  # TCP, UDP
                'src_port': np.random.randint(1024, 65535),
                'dst_port': np.random.choice([80, 443, 22, 21, 25, 53]),
                'packet_count': np.random.randint(10, 100),
                'total_bytes': np.random.randint(1000, 50000),
                'avg_packet_size': np.random.randint(64, 1500),
                'flow_duration': np.random.uniform(0.1, 10.0),
                'bytes_per_second': np.random.randint(1000, 10000),
                'packets_per_second': np.random.randint(1, 50),
                'label': 'normal'
            }
            normal_data.append(sample)
        
        # Create synthetic attack traffic
        attack_data = []
        
        # Port scan attack
        for i in range(50):
            sample = {
                'src_ip': f"203.0.113.{np.random.randint(1, 10)}",
                'dst_ip': f"192.168.1.{np.random.randint(1, 100)}",
                'protocol': 6,
                'src_port': np.random.randint(1024, 65535),
                'dst_port': np.random.randint(1, 1024),  # Scanning common ports
                'packet_count': np.random.randint(1, 5),  # Few packets per port
                'total_bytes': np.random.randint(64, 200),  # Small packets
                'avg_packet_size': 64,
                'flow_duration': np.random.uniform(0.001, 0.1),  # Very short
                'bytes_per_second': np.random.randint(50000, 100000),  # High rate
                'packets_per_second': np.random.randint(100, 1000),  # High packet rate
                'label': 'attack'
            }
            attack_data.append(sample)
        
        # DDoS attack
        for i in range(100):
            sample = {
                'src_ip': f"203.0.113.{np.random.randint(1, 50)}",
                'dst_ip': "192.168.1.10",  # Target server
                'protocol': np.random.choice([6, 17]),
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 80,
                'packet_count': np.random.randint(100, 1000),
                'total_bytes': np.random.randint(100000, 1000000),
                'avg_packet_size': np.random.randint(64, 1500),
                'flow_duration': np.random.uniform(0.1, 1.0),
                'bytes_per_second': np.random.randint(100000, 1000000),  # Very high
                'packets_per_second': np.random.randint(1000, 10000),  # Very high
                'label': 'attack'
            }
            attack_data.append(sample)
        
        # Brute force attack
        for i in range(50):
            sample = {
                'src_ip': f"198.51.100.{np.random.randint(1, 10)}",
                'dst_ip': f"192.168.1.{np.random.randint(1, 10)}",
                'protocol': 6,
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 22,  # SSH
                'packet_count': np.random.randint(20, 100),
                'total_bytes': np.random.randint(2000, 10000),
                'avg_packet_size': np.random.randint(100, 500),
                'flow_duration': np.random.uniform(1.0, 30.0),
                'bytes_per_second': np.random.randint(500, 2000),
                'packets_per_second': np.random.randint(2, 10),
                'label': 'attack'
            }
            attack_data.append(sample)
        
        all_data = normal_data + attack_data
        np.random.shuffle(all_data)
        
        df = pd.DataFrame(all_data)
        print(f"✅ Generated {len(df)} samples ({df['label'].value_counts().to_dict()})")
        
        return df
    
    def train_system(self, data_source=None):
        """Train the IDS system"""
        if data_source is None:
            # Use generated sample data
            df = self.generate_sample_data()
        else:
            # Load from file or other source
            df = pd.read_csv(data_source)
        
        # Train anomaly detector
        self.anomaly_detector.train_models(df, target_col='label' if 'label' in df.columns else None)
        
        # Save trained models
        self.anomaly_detector.save_models()
        
    def create_alert(self, features, anomaly_score):
        """Create and log security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': features.get('src_ip', 'unknown'),
            'dst_ip': features.get('dst_ip', 'unknown'),
            'protocol': features.get('protocol', 'unknown'),
            'src_port': features.get('src_port', 0),
            'dst_port': features.get('dst_port', 0),
            'anomaly_score': anomaly_score,
            'alert_type': self.classify_attack_type(features),
            'severity': 'HIGH' if anomaly_score > 0.8 else 'MEDIUM' if anomaly_score > 0.5 else 'LOW'
        }
        
        self.alert_queue.append(alert)
        self.stats['total_alerts'] += 1
        
        # Log alert
        logging.warning(f"🚨 SECURITY ALERT: {alert['alert_type']} from {alert['src_ip']} to {alert['dst_ip']}:{alert['dst_port']}")
        
        return alert
    
    def classify_attack_type(self, features):
        """Classify the type of potential attack"""
        dst_port = features.get('dst_port', 0)
        packets_per_second = features.get('packets_per_second', 0)
        bytes_per_second = features.get('bytes_per_second', 0)
        
        # High packet rate to many ports = Port Scan
        if packets_per_second > 100 and dst_port < 1024:
            return "Port Scan Detected"
        
        # Very high traffic rate = DDoS
        elif bytes_per_second > 50000:
            return "Potential DDoS Attack"
        
        # SSH/RDP repeated attempts = Brute Force
        elif dst_port in [22, 3389] and packets_per_second > 5:
            return "Brute Force Attack"
        
        # Default
        else:
            return "Suspicious Network Activity"
    
    def simulate_packet_capture(self, duration=60):
        """Simulate packet capture for demonstration"""
        print(f"🔄 Simulating packet capture for {duration} seconds...")
        
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration and self.is_monitoring:
            # Simulate packet arrival
            time.sleep(np.random.uniform(0.001, 0.1))
            
            # Generate synthetic packet features
            if np.random.random() < 0.95:  # 95% normal traffic
                features = self.generate_normal_packet()
            else:  # 5% attack traffic
                features = self.generate_attack_packet()
            
            # Process packet
            self.process_packet_features(features)
            packet_count += 1
            
            if packet_count % 100 == 0:
                print(f"📊 Processed {packet_count} packets, {len(self.alert_queue)} alerts generated")
        
        print(f"✅ Simulation completed. Processed {packet_count} packets")
    
    def generate_normal_packet(self):
        """Generate normal packet features"""
        return {
            'src_ip': f"192.168.1.{np.random.randint(1, 100)}",
            'dst_ip': f"10.0.0.{np.random.randint(1, 100)}",
            'protocol': np.random.choice([6, 17]),
            'src_port': np.random.randint(1024, 65535),
            'dst_port': np.random.choice([80, 443, 22, 21, 25, 53]),
            'packet_count': np.random.randint(10, 100),
            'total_bytes': np.random.randint(1000, 50000),
            'avg_packet_size': np.random.randint(64, 1500),
            'flow_duration': np.random.uniform(0.1, 10.0),
            'bytes_per_second': np.random.randint(1000, 10000),
            'packets_per_second': np.random.randint(1, 50)
        }
    
    def generate_attack_packet(self):
        """Generate attack packet features"""
        attack_types = ['port_scan', 'ddos', 'brute_force']
        attack_type = np.random.choice(attack_types)
        
        if attack_type == 'port_scan':
            return {
                'src_ip': f"203.0.113.{np.random.randint(1, 10)}",
                'dst_ip': f"192.168.1.{np.random.randint(1, 100)}",
                'protocol': 6,
                'src_port': np.random.randint(1024, 65535),
                'dst_port': np.random.randint(1, 1024),
                'packet_count': np.random.randint(1, 5),
                'total_bytes': np.random.randint(64, 200),
                'avg_packet_size': 64,
                'flow_duration': np.random.uniform(0.001, 0.1),
                'bytes_per_second': np.random.randint(50000, 100000),
                'packets_per_second': np.random.randint(100, 1000)
            }
        elif attack_type == 'ddos':
            return {
                'src_ip': f"203.0.113.{np.random.randint(1, 50)}",
                'dst_ip': "192.168.1.10",
                'protocol': np.random.choice([6, 17]),
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 80,
                'packet_count': np.random.randint(100, 1000),
                'total_bytes': np.random.randint(100000, 1000000),
                'avg_packet_size': np.random.randint(64, 1500),
                'flow_duration': np.random.uniform(0.1, 1.0),
                'bytes_per_second': np.random.randint(100000, 1000000),
                'packets_per_second': np.random.randint(1000, 10000)
            }
        else:  # brute_force
            return {
                'src_ip': f"198.51.100.{np.random.randint(1, 10)}",
                'dst_ip': f"192.168.1.{np.random.randint(1, 10)}",
                'protocol': 6,
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 22,
                'packet_count': np.random.randint(20, 100),
                'total_bytes': np.random.randint(2000, 10000),
                'avg_packet_size': np.random.randint(100, 500),
                'flow_duration': np.random.uniform(1.0, 30.0),
                'bytes_per_second': np.random.randint(500, 2000),
                'packets_per_second': np.random.randint(2, 10)
            }
    
    def process_packet_features(self, features):
        """Process packet features and check for anomalies"""
        self.stats['total_packets'] += 1
        
        # Check for anomaly
        is_anomaly, confidence = self.anomaly_detector.predict_anomaly(features)
        
        if is_anomaly and confidence > 0.3:  # Threshold for alerting
            alert = self.create_alert(features, confidence)
            return alert
        
        return None
    
    def start_monitoring(self, interface=None, duration=60):
        """Start real-time monitoring"""
        if not self.anomaly_detector.is_trained:
            print("❌ System not trained! Please train the system first.")
            return
        
        self.is_monitoring = True
        print(f"🔄 Starting IDS monitoring...")
        
        if SCAPY_AVAILABLE and interface:
            # Real packet capture using Scapy
            print(f"📡 Capturing packets on interface: {interface}")
            try:
                sniff(iface=interface, prn=self.process_real_packet, timeout=duration, store=False)
            except Exception as e:
                print(f"❌ Error capturing packets: {e}")
                print("🔄 Switching to simulation mode...")
                self.simulate_packet_capture(duration)
        else:
            # Simulation mode
            print("🎭 Running in simulation mode (install Scapy for real packet capture)")
            self.simulate_packet_capture(duration)
        
        self.is_monitoring = False
        print("🛑 Monitoring stopped")
    
    def process_real_packet(self, packet):
        """Process real captured packets"""
        if not self.is_monitoring:
            return
        
        features = self.feature_extractor.extract_packet_features(packet)
        if features:
            self.packet_buffer.append(features)
            
            # Process in batches for flow analysis
            if len(self.packet_buffer) >= 10:
                flow_features = self.feature_extractor.extract_flow_features(list(self.packet_buffer))
                
                for flow_feature in flow_features:
                    alert = self.process_packet_features(flow_feature)
                    if alert:
                        print(f"🚨 {alert['alert_type']}: {alert['src_ip']} -> {alert['dst_ip']}")
    
    def get_statistics(self):
        """Get current IDS statistics"""
        return {
            'total_packets': self.stats['total_packets'],
            'total_alerts': self.stats['total_alerts'],
            'alert_rate': self.stats['total_alerts'] / max(self.stats['total_packets'], 1),
            'recent_alerts': list(self.alert_queue)[-10:]  # Last 10 alerts
        }
    
    def export_alerts(self, filepath="alerts.json"):
        """Export alerts to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(list(self.alert_queue), f, indent=2, default=str)
        print(f"✅ Alerts exported to {filepath}")