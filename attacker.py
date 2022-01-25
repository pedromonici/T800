import socket
from scapy.all import *
import sys
import random
import time
import subprocess
from tqdm import tqdm

import threading

# Attacking computer UDP server configs
class Attacker():
    def __init__(self, fname, ip_str):
        # Service used for synchronizing Attacker and ESP32
        self.service = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.service.bind((ip_str, 6767))

        # Port used to collect experiment data - runs in another thread
        self.data_port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.data_port.bind((ip_str, 6768))
        self.experiment = threading.Thread(target=self._collect, args=(fname, ))
        self.experiment_running = False
        self.fname = fname
        self.header_written = False
        self.tasks = dict()

    def _collect(self, fname):
        data_file = open(fname, "a+")
        period = 0
        while self.experiment_running:
            try:
                data, _ = self.data_port.recvfrom(4096, socket.MSG_DONTWAIT)
            except IOError as e :
                print(f"[!] no data in collect - {e}")
            else:
                print("[+] collect received data")
                data = str(data.decode())
                for line in data.split("\r\n"):
                    name, metric = tuple(map(lambda x: x.strip(), line.split('\t')[:2]))
                    self.tasks[name] = metric

                exp_data = ",".join(self.tasks.values())
                experiment = f"{period},{exp_data}\n"
                if not self.header_written:
                    header = "period," + ",".join(self.tasks.keys()) + "\n"
                    data_file.write(header)
                    self.header_written = True

                data_file.write(experiment)
                period += 1

            time.sleep(1)

        data_file.close()

    def collect_experiment_data(self):
        print(f"[+] Start collect_experiment_data for file '{self.fname}'")
        self.experiment_running = True
        self.experiment = threading.Thread(target=self._collect, args=(self.fname, ))
        self.experiment.start()

    def stop_experiment(self):
        self.experiment_running = False
        self.experiment.join()
        print(f"[-] Stopped collecting - closed file '{self.fname}'")


def get_packets(num_packets, ip):
    pkts = []
    rand_string = "".join([chr(random.randint(65, 123)) for _ in range(4096)])
    print(f'here: {rand_string}')
    for _ in tqdm(range(num_packets)):
        pkt = fuzz(IP(dst=ip))/fuzz(TCP())
        pkt[TCP].payload = rand_string
        pkts.append(pkt)

    return pkts


def print_packets(pkts):
    for pkt in pkts:
        pkt.show()


def send_packets(pkts):
    for pkt in pkts:
        send(pkt, count=1000, inter=1/1000)

    # sendpfast(pkts[0], mbps=1.0)


if __name__ == "__main__":
    # ESP32 TCP server configs
    esp32_server_addr = sys.argv[1]
    esp32_server_port = 3333
    random.seed(13)

    num_packets = sys.argv[2] if len(sys.argv) > 2 else 100
    print(f"Running with #{num_packets} packets")

    # packets = get_packets(int(num_packets), sys.argv[1])
    attacker = Attacker("data.csv", sys.argv[3])

    # trees = [b"r", b"6", b"7", b"8", b"9", b"0", b"1", b"2"]
    trees = [b"2"]
    for i, tree in enumerate(trees):
        print("Going to tree", tree)

        esp32_signal = b""
        while esp32_signal.strip() != b"start":
            esp32_signal, esp32_addr = attacker.service.recvfrom(4096)
            print(esp32_signal)

        print(f"[+] Starting experiment: received signal {esp32_signal}")

        esp32_signal = b""

        while esp32_signal.strip() != b"assigned":
            attacker.service.sendto(tree, esp32_addr)
            esp32_signal, esp32_addr = attacker.service.recvfrom(4096)

        print(f"[!] ESP32 assigned tree {tree}")
        attacker.collect_experiment_data()

        print(f"[>] Sending packets ...", end="")
        timeout = time.time() + 11
        t = time.time()
        # time.sleep(5)
        print("\niperf:")
        subprocess.run(["iperf", "-c", "192.168.15.20", "-i", "3", "-t", "10", "-p", "5001"])
        while t <= timeout:
            # send_packets(packets)
            t = time.time()

        print(" done")

        # Receiving experiment results
        attacker_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        not_connected = True
        while not_connected:
            try:
                attacker_client.connect((esp32_server_addr, 3333))
                not_connected = False
                attacker_client.send(b"D") # done experimenting, receive results
                print("[~] D sent sucessfully")
            except:
                pass

        time.sleep(5)
        attacker.stop_experiment()

        esp32_signal = b""
        while esp32_signal != b"complete":
            esp32_signal = attacker.service.recv(4096).strip()

        print("[-] ESP32 experiment complete, moving to next index")
        print("[~] Experiment data saved in file")
