import logging
import numpy as np
from collections import defaultdict
try:
    from scapy.all import IP, TCP, UDP, ICMP
except ImportError:
    IP = TCP = UDP = ICMP = None


class NetworkFeatureExtractor:
    """Extract features from network packets for ML analysis"""
    
    def __init__(self):
        self.features = []
        self.connection_tracker = defaultdict(list)
        
    def extract_packet_features(self, packet):
        """Extract features from a single packet"""
        try:
            feature_dict = {
                'timestamp': float(packet.time),
                'packet_size': len(packet),
                'protocol': getattr(packet, 'proto', 0),
                'src_port': 0,
                'dst_port': 0,
                'tcp_flags': 0,
                'icmp_type': 0,
                'payload_size': 0
            }
            
            if IP and packet.haslayer(IP):
                ip = packet[IP]
                feature_dict.update({
                    'src_ip': ip.src,
                    'dst_ip': ip.dst,
                    'ttl': ip.ttl,
                    'ip_flags': ip.flags,
                    'fragment_offset': ip.frag
                })
            
            if TCP and packet.haslayer(TCP):
                tcp = packet[TCP]
                feature_dict.update({
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'tcp_flags': tcp.flags,
                    'window_size': tcp.window,
                    'tcp_seq': tcp.seq,
                    'tcp_ack': tcp.ack
                })
            elif UDP and packet.haslayer(UDP):
                udp = packet[UDP]
                feature_dict.update({'src_port': udp.sport, 'dst_port': udp.dport})
            elif ICMP and packet.haslayer(ICMP):
                icmp = packet[ICMP]
                feature_dict['icmp_type'] = icmp.type
            
            if hasattr(packet, 'payload') and packet.payload:
                feature_dict['payload_size'] = len(bytes(packet.payload))
                
            return feature_dict
        except Exception as e:
            logging.error(f"Error extracting packet features: {e}")
            return None
    
    def extract_flow_features(self, packets, window_size=10):
        """Extract flow-based features from packet sequences"""
        flows = defaultdict(list)
        
        for packet_data in packets:
            if 'src_ip' in packet_data and 'dst_ip' in packet_data:
                key = (packet_data['src_ip'], packet_data['dst_ip'], packet_data['protocol'])
                flows[key].append(packet_data)
        
        flow_features = []
        for (src, dst, proto), flow_packets in flows.items():
            if len(flow_packets) < 2:
                continue
            
            sizes = [pkt['packet_size'] for pkt in flow_packets]
            intervals = [
                flow_packets[i]['timestamp'] - flow_packets[i-1]['timestamp']
                for i in range(1, len(flow_packets))
            ]
            
            feature = {
                'src_ip': src,
                'dst_ip': dst,
                'protocol': proto,
                'packet_count': len(flow_packets),
                'total_bytes': sum(sizes),
                'avg_packet_size': np.mean(sizes),
                'std_packet_size': np.std(sizes) if len(sizes) > 1 else 0,
                'flow_duration': flow_packets[-1]['timestamp'] - flow_packets[0]['timestamp'],
                'avg_interval': np.mean(intervals) if intervals else 0,
                'bytes_per_second': sum(sizes) / max(flow_packets[-1]['timestamp'] - flow_packets[0]['timestamp'], 0.001),
                'packets_per_second': len(flow_packets) / max(flow_packets[-1]['timestamp'] - flow_packets[0]['timestamp'], 0.001)
            }
            flow_features.append(feature)
        
        return flow_features
