from flask import Flask, render_template, request
import socket
import concurrent.futures
from scapy.all import IP, TCP, ICMP, sr1

app = Flask(__name__, static_folder='static')

def scan_port(target, port, scan_type="SYN"):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            if scan_type == "SYN":
                packet = IP(dst=target) / TCP(dport=port, flags="S")
            elif scan_type == "FIN":
                packet = IP(dst=target) / TCP(dport=port, flags="F")
            elif scan_type == "XMAS":
                packet = IP(dst=target) / TCP(dport=port, flags="FPU")
            else:
                return None

            response = sr1(packet, timeout=1, verbose=False)

            if response is not None and response.haslayer(TCP) and response.haslayer(IP):
                if response.getlayer(TCP).flags == 0x12:  # SYN/ACK
                    return port, "Open", detect_os(target)
    except Exception as e:
        pass
    return None


def detect_os(target):
    # ICMP fingerprinting
    icmp_packet = IP(dst=target)/ICMP()
    icmp_response = sr1(icmp_packet, timeout=1, verbose=False)

    if icmp_response is not None:
        if icmp_response.haslayer(ICMP) and icmp_response.haslayer(IP):
            return "Linux/Unix" if icmp_response.getlayer(ICMP).type == 0 else "Windows"

    return "Unknown"

def detect_os_advanced(target):
    try:
        # TCP SYN packet to port 80 (HTTP)
        syn_packet = IP(dst=target) / TCP(dport=80, flags="S")
        syn_response = sr1(syn_packet, timeout=1, verbose=False)

        if syn_response is not None and syn_response.haslayer(TCP) and syn_response.haslayer(IP):
            if syn_response.getlayer(TCP).flags == 0x12:  # SYN/ACK
                # Send an HTTP GET request to port 80
                http_get_packet = IP(dst=target) / TCP(dport=80, flags="A") / "GET / HTTP/1.1\r\n\r\n"
                http_response = sr1(http_get_packet, timeout=1, verbose=False)

                if http_response is not None and http_response.haslayer(TCP) and http_response.haslayer(IP):
                    # Analyze HTTP response to identify the server type
                    if "Server:" in str(http_response):
                        server_info = str(http_response).split("Server:")[1].split("\r\n")[0].strip()
                        return f"Web server identified: {server_info}"

    except Exception as e:
        pass

    return "Unknown"

os_info = detect_os_advanced("target_ip")
print(os_info)


def scan_ports(target, start_port, end_port, scan_type="SYN"):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_port, target, port, scan_type) for port in range(start_port, end_port + 1)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                port, status, os_type = result
                open_ports.append((port, status, os_type))
                print(f"Port {port} is {status} on {os_type} system")
    return open_ports


@app.route('/')
def index():
    return render_template('index.html')

def scan_ports(target, start_port, end_port, scan_type="SYN"):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(scan_port, target, port, scan_type) for port in range(start_port, end_port + 1)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                port, status, os_type = result
                open_ports.append((port, status, os_type))
                print(f"Port {port} is {status} on {os_type} system")
    return open_ports

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    num_threads = int(request.form['num_threads'])
    scan_type = request.form['scan_type']  # 获取用户选择的扫描方式

    start_port = 1
    end_port = 1000

    ports_per_thread = (end_port - start_port + 1) // num_threads
    start_ports = [start_port + i * ports_per_thread for i in range(num_threads)]
    end_ports = [start_port + (i + 1) * ports_per_thread - 1 for i in range(num_threads)]

    open_ports = []

    os_type = detect_os(target)
    server_info = detect_os_advanced(target)

    for start, end in zip(start_ports, end_ports):
        open_ports.extend(scan_ports(target, start, end, scan_type))

    print("Scan completed. Open ports:", open_ports)
    return render_template('result.html', target=target, num_threads=num_threads, open_ports=open_ports, os_type=os_type, server_info=server_info)


if __name__ == '__main__':
    app.run(debug=True)

    
