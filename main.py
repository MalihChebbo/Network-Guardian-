from network_scanner import scan_local_network
from port_scanner import threaded_port_scan

def main():
    while True:
        print("\nNetwork Scanner Menu:")
        print("1. Scan Local Network")
        print("2. Scan Ports on Target")
        print("3. Exit")
        choice = input("Enter your choice: ")
        
        if choice == "1":
            scan_local_network()
        elif choice == "2":
            target_ip = input("Enter target IP: ")
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))
            threaded_port_scan(target_ip, start_port, end_port)
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
