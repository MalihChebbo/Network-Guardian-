import socket
import scapy.all as scapy
from device_fingerprinter import DeviceFingerprinter


def get_local_network():
    """Gets the local network subnet."""
    try:
        # Create a socket and connect to an external server (doesn't actually establish connection)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Create subnet from IP (e.g., 192.168.1.0/24)
        subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
        return subnet
    except:
        # Fallback method if the above fails
        for interface in socket.if_nameindex():
            try:
                ip = socket.gethostbyname(socket.gethostname())
                if not ip.startswith("127.") and not ip.startswith("169."):
                    return ".".join(ip.split(".")[:3]) + ".0/24"
            except:
                continue
        
        # If all else fails, return common local networks to try
        return "192.168.1.0/24"
    
def is_valid_host(ip):
    """Filters out multicast, broadcast, and link-local addresses."""
    if ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255":
        return False
    if ip.startswith("169.254."):
        return False
    if ip.split(".")[-1] == "255":
        return False
    return True

def scan_local_network():
    """Scans the local network for active devices and their types."""
    fingerprinter = DeviceFingerprinter()
    local_network = get_local_network()
    print(f"Scanning local network: {local_network}\n")
    active_hosts = []
    device_count = 0  # Initialize counter

    try:
        # First attempt: Using Scapy
        arp = scapy.ARP(pdst=local_network)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        result = scapy.srp(packet, timeout=3, verbose=0)[0]
        
        if not result:
            raise Exception("No devices found using Scapy")
            
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            
            if is_valid_host(ip):
                try:
                    device_count += 1  # Increment counter
                    device_info = fingerprinter.analyze_device(ip, mac)
                    active_hosts.append(device_info)
                    
                    print(f"\n[+] Device {device_count} Found:")
                    print(f"    IP: {ip}")
                    print(f"    MAC: {mac}")
                    print(f"    Vendor: {device_info['vendor']}")
                    print(f"    Type: {device_info['type']}")
                    print(f"    OS: {device_info['os']}")
                    if device_info['open_ports']:
                        print(f"    Open ports: {', '.join(f'{port} ({info['service']})' for port, info in device_info['open_ports'].items())}")
                except Exception as e:
                    print(f"Error analyzing device {ip}: {str(e)}")
                    device_count -= 1  # Decrement if analysis failed
                    
    except Exception as e:
        print(f"Falling back to basic network scan method...")
        # Fallback method: Basic socket scanning
        for i in range(1, 255):
            ip = local_network.split('/')[0].rsplit('.', 1)[0] + f".{i}"
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, 80)) == 0:
                        try:
                            device_count += 1  # Increment counter
                            mac = "Unknown"
                            device_info = fingerprinter.analyze_device(ip, mac)
                            active_hosts.append(device_info)
                            
                            print(f"\n[+] Device {device_count} Found:")
                            print(f"    IP: {ip}")
                            print(f"    OS: {device_info['os']}")
                            if device_info['open_ports']:
                                print(f"    Open ports: {', '.join(f'{port} ({info['service']})' for port, info in device_info['open_ports'].items())}")
                        except Exception as inner_e:
                            print(f"Error analyzing device {ip}: {str(inner_e)}")
                            device_count -= 1  # Decrement if analysis failed
            except:
                continue

    if device_count > 0:
        print(f"\nTotal devices found: {device_count}")
    else:
        print("No devices found on the network.")
    
    return active_hosts

