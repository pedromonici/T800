import socket
import sys
import random
import time
import subprocess
import threading

# Attacking computer UDP server configs
class Attacker():
    def __init__(self, fname):
        # Service used for synchronizing Attacker and ESP32
        self.service = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.service.bind(('0.0.0.0', 6767))

        # Port used to collect experiment data - runs in another thread
        self.data_port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.data_port.bind(('0.0.0.0', 6768))
        self.fname = fname
        self.header_written = False
        self.tasks = dict()

        self.experiment = threading.Thread(target=self._collect, args=(fname, ))
        self.experiment_running = False

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

def msg_esp(expected, esp32_addr = None, msg = None):
    esp32_signal = b""
    while esp32_signal.strip() != expected:
        if msg:
            attacker.service.sendto(msg, esp32_addr)

        esp32_signal, esp32_addr = attacker.service.recvfrom(4096)
        print(esp32_signal)

    # warn ESP that we received the expected message
    attacker.service.sendto("x", esp32_addr)

    return esp32_addr

def main():
    attacker = Attacker("data.csv")

    # trees = [b"r", b"6", b"7", b"8", b"9", b"0", b"1", b"2"]
    trees = [b"2"]
    for tree in trees:
        print("Going to tree", tree)
        
        esp32_addr = msg_esp(b"start")

        print(f"[+] Starting experiment: received signal {esp32_signal}")

        esp32_addr = msg_esp(b"assigned", esp32_addr, tree)

        print(f"[+] ESP32 assigned tree {tree}")
        
        print(f"[>] Sending packets ...")
        time.sleep(1)   # Wait for esp32 open iperf server
        attacker.collect_experiment_data()
        subprocess.run(["iperf", "-c", esp32_server_addr, "-i", "3", "-t", "10", "-p", "5001"])
        print(f"[>] Finished sending packets")

        attacker.stop_experiment()

        # Receiving experiment results
        msg_esp(b"complete", esp32_addr, b"D")

        print("[+] ESP32 experiment complete, moving to next index")
        print("[+] Experiment data saved in file")

if __name__ == "__main__":
    main()