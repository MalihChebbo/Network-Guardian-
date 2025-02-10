import platform 
import subprocess
import requests
from service_ports import get_service_banner,probe_ports
def detect_os(ip):
    """Enhanced OS detection using multiple methods"""
    # Port signatures
    windows_ports = {135, 139, 445, 3389}  # Windows services
    linux_ports = {22, 111, 2049}          # Common Linux services
    android_ports = {5555}                 # Android ADB
    ios_ports = {62078}                   # iOS services
    
    os_type = "Unknown"
    os_details = []
    
    try:
        # 1. TTL Analysis
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", "1", ip]
        else:
            ping_cmd = ["ping", "-c", "1", ip]
            
        result = subprocess.run(ping_cmd, capture_output=True, text=True)
        
        if "TTL=" in result.stdout or "ttl=" in result.stdout:
            ttl_line = [line for line in result.stdout.split('\n') if 'TTL=' in line.upper()][0]
            ttl = int(''.join(filter(str.isdigit, ttl_line.split('TTL=')[1].split()[0])))
            
            # More precise TTL analysis
            if ttl <= 64:
                os_details.append("Linux/Unix/Android")
            elif ttl <= 128:
                os_details.append("Windows")
            elif ttl <= 255:
                os_details.append("Network Device")
        
        # 2. Port Analysis
        open_ports = probe_ports(ip, windows_ports | linux_ports | android_ports | ios_ports)
        
        # Check for Android Debug Bridge
        if 5555 in open_ports:
            os_details.append("Android")
        
        # Check for Windows-specific services
        if any(port in open_ports for port in windows_ports):
            os_details.append("Windows")
        
        # Check for Linux-specific services
        if any(port in open_ports for port in linux_ports):
            os_details.append("Linux")
            
        # 3. Service Banner Analysis
        common_ports = [80, 443, 8080]
        for port in common_ports:
            banner = get_service_banner(ip, port)
            if banner:
                if "windows" in banner.lower():
                    os_details.append("Windows")
                elif "ubuntu" in banner.lower():
                    os_details.append("Ubuntu Linux")
                elif "android" in banner.lower():
                    os_details.append("Android")
                elif "debian" in banner.lower():
                    os_details.append("Debian Linux")
                    
        # 4. HTTP User Agent Detection
        try:
            response = requests.get(f"http://{ip}", timeout=1)
            server = response.headers.get('Server', '')
            if server:
                if "windows" in server.lower():
                    os_details.append("Windows")
                elif "ubuntu" in server.lower():
                    os_details.append("Ubuntu Linux")
                elif "debian" in server.lower():
                    os_details.append("Debian Linux")
        except:
            pass

        # Determine final OS type based on collected evidence
        if os_details:
            if "Android" in os_details:
                os_type = "Android"
            elif "Windows" in os_details:
                os_type = "Windows"
            elif any("Linux" in detail for detail in os_details):
                os_type = next((detail for detail in os_details if "Linux" in detail), "Linux/Unix")
            elif "Network Device" in os_details:
                os_type = "Network Device"
            
            # Add version information if available
            if os_type == "Windows" and open_ports:
                if 3389 in open_ports:
                    os_type += " (RDP Enabled)"
                    
    except Exception as e:
        pass
        
    return os_type