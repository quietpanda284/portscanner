import socket
from concurrent.futures import ThreadPoolExecutor
import csv
import sys

def port_scan(target_ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            # Port is open, attempt banner grabbing
            try:
                banner = sock.recv(1024).decode().strip()
            except socket.timeout:
                banner = "No banner detected"
            except Exception:
                banner = "Error fetching banner"
            return (port, "Open", banner)
        else:
            return (port, "Closed", "N/A")
    except Exception as e:
        return (port, "Error", str(e))
    finally:
        sock.close()

def scan_ports(target_ip, start_port, end_port, max_threads=10):
    open_ports = []

    def log_to_csv(results):
        with open("port_scan_results.csv", "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Port", "Status", "Banner"])
            csv_writer.writerows(results)

    print(f"Starting scan on {target_ip} from port {start_port} to {end_port}...\n")
    with ThreadPoolExecutor(max_threads) as executor:
        futures = [executor.submit(port_scan, target_ip, port) for port in range(start_port, end_port + 1)]
        results = [future.result() for future in futures]

    for port, status, banner in results:
        if status == "Open":
            open_ports.append((port, status, banner))
            print(f"Port {port}: {status} (Banner: {banner})")
        else:
            print(f"Port {port}: {status}")
    
    log_to_csv(results)
    print("\nScan complete! Results saved to 'port_scan_results.csv'.")

if __name__ == "__main__":
    try:
        target_ip = input("Enter target IP address: ")
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))
        max_threads = int(input("Enter the number of threads (default 10): ") or 10)
        
        if start_port < 0 or end_port > 65535 or start_port > end_port:
            print("Invalid port range. Ports must be between 0 and 65535.")
            sys.exit(1)

        scan_ports(target_ip, start_port, end_port, max_threads)
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
    except ValueError:
        print("Invalid input. Please enter numeric values for ports and threads.")
    except Exception as e:
        print(f"An error occurred: {e}")
