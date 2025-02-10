import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(target, port):
    """Attempts to connect to a given port and checks if it's open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Shorter timeout
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open on {target}")
    except:
        pass  # Silently handle errors for smoother scanning

def threaded_port_scan(target, start_port, end_port):
    """Runs a multi-threaded port scan."""
    try:
        # Create thread pool with reasonable number of workers
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Convert port range to list for mapping
            ports = list(range(start_port, end_port + 1))
            # Use map to distribute port scanning across threads
            executor.map(lambda p: scan_port(target, p), ports)
    except Exception as e:
        print(f"Error during port scan: {e}")