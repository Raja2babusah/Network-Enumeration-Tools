import argparse
import nmap
import json
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox

class NetworkEnumerationTool:
    def __init__(self, target):
        self.target = target
        self.scanner = nmap.PortScanner()

    def scan_ports(self):
        """Perform a port scan and return formatted results."""
        print("\n[+] Scanning ports on:", self.target)
        try:
            self.scanner.scan(hosts=self.target, arguments='-p 1-65535 -T4')
        except Exception as e:
            print("[-] Error scanning ports:", e)
            return None

        results = {}
        for host in self.scanner.all_hosts():
            ports = self.scanner[host].get("tcp", {})
            formatted_ports = {
                port: details["name"]
                for port, details in ports.items() if details["state"] == "open"
            }
            results[host] = {
                "IP": self.scanner[host].get("addresses", {}).get("ipv4", ""),
                "Status": self.scanner[host].get("status", {}).get("state", "unknown"),
                "Open Ports": formatted_ports,
            }

        self.save_results(results, "port_scan_results")
        return results

    def os_detection(self):
        """Detect the OS of the target."""
        print("\n[+] Detecting OS for:", self.target)
        try:
            self.scanner.scan(self.target, arguments='-O')
        except Exception as e:
            print("[-] OS detection failed:", e)
            return None

        os_info = self.scanner[self.target].get("osmatch", [])
        detected_os = os_info[0]["name"] if os_info else "OS detection failed"

        results = {"Target": self.target, "Detected OS": detected_os}
        self.save_results(results, "os_detection_results")
        return results

    def vulnerability_scan(self):
        """Scan for known vulnerabilities using Nmap scripts."""
        print("\n[+] Scanning for vulnerabilities on:", self.target)
        try:
            self.scanner.scan(hosts=self.target, arguments="--script=vuln")
        except Exception as e:
            print("[-] Vulnerability Scan failed:", e)
            return None

        results = self.scanner[self.target] if self.target in self.scanner.all_hosts() else {}
        self.save_results(results, "vulnerability_scan_results")
        return results

    def save_results(self, data, filename):
        """Save results in JSON format."""
        with open(f"{filename}.json", "w") as json_file:
            json.dump(data, json_file, indent=4)
        print(f"\n[+] Results saved to {filename}.json")

# GUI Implementation
class NetworkEnumerationToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Enumeration Tool")
        self.root.geometry("700x500")
        self.scanner = nmap.PortScanner()

        tk.Label(root, text="Target IP/Domain:").pack()
        self.target_entry = tk.Entry(root, width=50)
        self.target_entry.pack()

        tk.Button(root, text="Scan Ports", command=self.scan_ports).pack(pady=5)
        tk.Button(root, text="OS Detection", command=self.os_detection).pack(pady=5)
        tk.Button(root, text="Vulnerability Scan", command=self.vulnerability_scan).pack(pady=5)
        tk.Button(root, text="Save Results", command=self.save_results).pack(pady=10)

        tk.Label(root, text="Results:").pack()
        self.output_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.output_area.pack()

    def scan_ports(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain.")
            return

        threading.Thread(target=self._scan_ports_thread, args=(target,)).start()

    def _scan_ports_thread(self, target):
        self.output_area.insert(tk.END, f"\n[+] Scanning ports on {target}...\n")
        try:
            self.scanner.scan(hosts=target, arguments='-p 1-65535 -T4')
            results = {host: self.scanner[host]["tcp"] for host in self.scanner.all_hosts()}
            formatted_results = json.dumps(results, indent=4)
            self.output_area.insert(tk.END, formatted_results + "\n")
        except Exception as e:
            self.output_area.insert(tk.END, f"[-] Error scanning ports: {e}\n")

    def os_detection(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain.")
            return

        threading.Thread(target=self._os_detection_thread, args=(target,)).start()

    def _os_detection_thread(self, target):
        self.output_area.insert(tk.END, f"\n[+] Detecting OS for {target}...\n")
        try:
            self.scanner.scan(target, arguments='-O')
            os_info = self.scanner[target].get("osmatch", [])
            detected_os = os_info[0]["name"] if os_info else "OS detection failed"
            self.output_area.insert(tk.END, f"Detected OS: {detected_os}\n")
        except Exception as e:
            self.output_area.insert(tk.END, f"[-] OS detection failed: {e}\n")

    def vulnerability_scan(self):
        target = self.target_entry.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or domain.")
            return

        threading.Thread(target=self._vulnerability_scan_thread, args=(target,)).start()

    def _vulnerability_scan_thread(self, target):
        self.output_area.insert(tk.END, f"\n[+] Scanning for vulnerabilities on {target}...\n")
        try:
            self.scanner.scan(hosts=target, arguments="--script=vuln")
            results = json.dumps(self.scanner[target], indent=4) if target in self.scanner.all_hosts() else "{}"
            self.output_area.insert(tk.END, results + "\n")
        except Exception as e:
            self.output_area.insert(tk.END, f"[-] Vulnerability scan failed: {e}\n")

    def save_results(self):
        data = self.output_area.get("1.0", tk.END).strip()
        if not data:
            messagebox.showerror("Error", "No scan results to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"),
                                                            ("JSON files", "*.json"),
                                                            ("All files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(data)
            messagebox.showinfo("Success", f"Results saved to {file_path}")

def main():
    parser = argparse.ArgumentParser(description="Network Enumeration Tool")
    parser.add_argument("-t", "--target", help="Specify the target IP or Domain")
    parser.add_argument("--scan", action="store_true", help="Perform a full port scan")
    parser.add_argument("--os", action="store_true", help="Detect the OS of the target")
    parser.add_argument("--vuln", action="store_true", help="Perform a vulnerability scan")

    args = parser.parse_args()

    if any([args.scan, args.os, args.vuln]):
        tool = NetworkEnumerationTool(args.target)
        if args.scan:
            tool.scan_ports()
        if args.os:
            tool.os_detection()
        if args.vuln:
            tool.vulnerability_scan()
    else:
        root = tk.Tk()
        app = NetworkEnumerationToolGUI(root)
        root.mainloop()

if __name__ == "__main__":
    main()
