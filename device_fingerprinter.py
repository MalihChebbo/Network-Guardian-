import socket
import scapy.all as scapy
from datetime import datetime
from detect_os import detect_os
from get_mac_api import get_mac_vendor

class DeviceFingerprinter:
    def __init__(self):
        # Load device fingerprint database
        self.fingerprints = {
            "patterns": {
                "android": [
                    {"ports": [5555], "name": "Android Device"},
                    {"ua": "Dalvik", "name": "Android Device"},
                ],
                "ios": [
                    {"ports": [62078], "name": "iOS Device"},
                    {"mdns": "_apple-mobdev2", "name": "iOS Device"}
                ],
                "smart_tv": [
                    {"ports": [9080, 9090], "name": "Smart TV"},
                    {"ua": "SmartTV", "name": "Smart TV"},
                    {"mdns": "_googlecast", "name": "Chromecast"}
                ]
            }
        }

    def get_mdns_info(self,ip):
        """Query mDNS services for device information"""
        try:
            mdns_query = scapy.IP(dst="224.0.0.251")/scapy.UDP(dport=5353)/scapy.DNS(qd=scapy.DNSQR(qname="_services._dns-sd._udp.local"))
            reply = scapy.sr1(mdns_query, timeout=1, verbose=0)
            if reply:
                return reply[scapy.DNS].summary()
            return None
        except:
            return None

    def get_ssdp_info(self, ip):
        """Query SSDP for device information"""
        try:
            ssdp_request = (
                'M-SEARCH * HTTP/1.1\r\n' +
                'HOST: 239.255.255.250:1900\r\n' +
                'MAN: "ssdp:discover"\r\n' +
                'MX: 1\r\n' +
                'ST: ssdp:all\r\n' +
                '\r\n'
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(ssdp_request.encode(), (ip, 1900))
            data, _ = sock.recvfrom(1024)
            return data.decode()
        except:
            return None

    def analyze_device(self, ip, mac):
        """Comprehensive device analysis"""
        device_info = {
            "ip": ip,
            "mac": mac,
            "vendor": get_mac_vendor(mac),
            "type": "Unknown",
            "os": "Unknown",
            "name": "Unknown Device",
            "services": [],
            "last_seen": datetime.now().isoformat()
        
        }

        # Get OS info using existing detect_os function
        device_info["os"] = detect_os(ip)

        # Scan for common services
        open_ports = self.scan_ports_with_service_detection(ip)
        device_info["open_ports"] = open_ports

        # Get mDNS info
        mdns_info = self.get_mdns_info(ip)
        if mdns_info:
            device_info["mdns"] = mdns_info

        # Get SSDP info
        ssdp_info = self.get_ssdp_info(ip)
        if ssdp_info:
            device_info["ssdp"] = ssdp_info

        # Match device patterns
        device_type = self.match_device_patterns(device_info)
        if device_type:
            device_info["type"] = device_type
            
        return device_info

    def scan_ports_with_service_detection(self, ip):
        """Scan ports and detect services"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB",
            548: "AFP", 631: "IPP", 3389: "RDP", 5000: "UPnP",
            5353: "mDNS", 5357: "WSDAPI", 62078: "iOS",
            8008: "HTTP Alt", 8009: "HTTP Alt", 
            8080: "HTTP Proxy", 9100: "Printer"
        }
        
        open_ports = {}
        for port, service in common_ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        banner = self.get_service_banner(ip, port)
                        open_ports[port] = {
                            "service": service,
                            "banner": banner
                        }
            except:
                continue
        return open_ports

    def match_device_patterns(self, device_info):
        """Match device patterns against fingerprint database"""
        for device_type, patterns in self.fingerprints["patterns"].items():
            for pattern in patterns:
                if "ports" in pattern and any(port in device_info["open_ports"] for port in pattern["ports"]):
                    return pattern["name"]
                if "mdns" in pattern and pattern["mdns"] in str(device_info.get("mdns", "")):
                    return pattern["name"]
                if "ua" in pattern and pattern["ua"] in str(device_info.get("ua", "")):
                    return pattern["name"]
        return "Unknown"