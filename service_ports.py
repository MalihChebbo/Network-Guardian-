import socket

def get_service_banner(ip, port):
    """Attempt to get service banner for better OS detection"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            return s.recv(1024).decode('utf-8', errors='ignore')
    except:
        return ""

def probe_ports(ip, ports):
    """Probe specific ports for OS fingerprinting"""
    open_ports = set()
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.add(port)
        except:
            continue
    return open_ports