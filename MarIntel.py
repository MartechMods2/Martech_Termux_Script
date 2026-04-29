#!/usr/bin/env python3
"""
MARINTEL - Termux Edition (CLI only)
Cyber Intelligence IP Lookup Tool – Optimised for Android Termux.
No PyQt5, no GUI fallbacks.
"""
import sys, os, re, json, csv, argparse, socket, subprocess, time, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional

# --------------- Beautiful output (optional) ---------------
try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# --------------- Constants ---------------
PRIMARY_API   = "http://ip-api.com/json/{}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,timezone,proxy,hosting,mobile,query"
FALLBACK_API  = "http://ipapi.co/{}/json/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
HISTORY_FILE  = "marintel_history.json"
TARGETS_FILE  = "marintel_targets.json"
SETTINGS_FILE = "marintel_settings.json"
LOG_FILE      = "marintel_errors.log"
REQUEST_TIMEOUT = 8
MAX_WORKERS   = 15

logging.basicConfig(filename=LOG_FILE, level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --------------- Network / Backend ---------------
def create_session(retries=2):
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except (socket.error, OSError):
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except (socket.error, OSError):
            return False

def reverse_dns(ip: str) -> Optional[str]:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror):
        return None

def query_abuseipdb(ip: str, key: str) -> Dict:
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=5
        )
        data = resp.json()["data"]
        return {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", "N/A"),
            "report_url": f"https://www.abuseipdb.com/check/{ip}"
        }
    except Exception:
        return {}

def fetch_ip(ip: str, abuse_key: str = None) -> Dict:
    if not is_valid_ip(ip):
        return {"ip": ip, "error": "Invalid IP address"}

    session = create_session()
    result = {"ip": ip}

    # Primary API
    try:
        resp = session.get(PRIMARY_API.format(ip), timeout=REQUEST_TIMEOUT)
        data = resp.json()
        if data.get("status") == "success":
            result.update({
                "location": f"{data.get('city','')}, {data.get('regionName','')}, {data.get('country','')}",
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "asn": data.get("as", ""),
                "timezone": data.get("timezone", ""),
                "proxy": data.get("proxy", False),
                "hosting": data.get("hosting", False),
                "mobile": data.get("mobile", False),
                "status": "Clean",
                "map": f"https://www.google.com/maps/search/?api=1&query={data.get('lat')},{data.get('lon')}",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "rdns": reverse_dns(ip)
            })
            flags = []
            if data.get("proxy"): flags.append("Proxy")
            if data.get("hosting"): flags.append("Hosting/VPN")
            if data.get("mobile"): flags.append("Mobile")
            result["status"] = ", ".join(flags) if flags else "Clean"
        else:
            raise Exception(data.get("message", "Unknown API error"))
    except Exception as e:
        # Fallback API
        try:
            resp = session.get(FALLBACK_API.format(ip), timeout=REQUEST_TIMEOUT)
            data = resp.json()
            if "error" in data:
                raise Exception(data["reason"])
            result.update({
                "location": f"{data.get('city','')}, {data.get('region','')}, {data.get('country_name','')}",
                "lat": data.get("latitude"),
                "lon": data.get("longitude"),
                "isp": data.get("org", ""),
                "org": data.get("org", ""),
                "asn": data.get("asn", ""),
                "timezone": data.get("timezone", ""),
                "proxy": False,
                "hosting": False,
                "mobile": False,
                "status": "Clean",
                "map": f"https://www.google.com/maps/search/?api=1&query={data.get('latitude')},{data.get('longitude')}",
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "rdns": reverse_dns(ip)
            })
        except Exception as fallback_exc:
            logging.error(f"IP {ip}: {fallback_exc}")
            return {"ip": ip, "error": f"Lookup failed: {str(fallback_exc)}"}

    if abuse_key:
        abuse = query_abuseipdb(ip, abuse_key)
        result.update(abuse)
    return result

def scan_ips(ips: List[str], abuse_key: str = None, progress_callback=None) -> List[Dict]:
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(fetch_ip, ip, abuse_key): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                res = future.result()
            except Exception as e:
                res = {"ip": ip, "error": str(e)}
            results.append(res)
            if progress_callback:
                progress_callback(len(results), len(ips))
    return results

# --------------- Termux helpers ---------------
def termux_open_url(url):
    try:
        subprocess.run(["termux-open-url", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("❌ termux-open-url not found. Install termux-api: pkg install termux-api")

def termux_copy_to_clipboard(text):
    try:
        subprocess.run(["termux-clipboard-set"], input=text.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ Copied to clipboard.")
    except FileNotFoundError:
        print("❌ termux-clipboard-set not found. Install termux-api: pkg install termux-api")

# --------------- CLI interactive menu ---------------
class MarintelCLI:
    def __init__(self):
        self.settings = self.load_json(SETTINGS_FILE, {"abuse_key": "", "default_export": "csv"})
        self.abuse_key = self.settings.get("abuse_key", "") or os.environ.get("ABUSEIPDB_KEY", "")
        self.current_results = []
        self.targets = self.load_json(TARGETS_FILE, {"lists": {}})

    def cprint(self, text, color=""):
        if HAS_COLOR:
            print(color + text + Style.RESET_ALL)
        else:
            print(text)

    def clear_screen(self):
        os.system('clear')

    def print_banner(self):
        self.clear_screen()
        print(Fore.CYAN + Style.BRIGHT + r"""
  __  __          _       _____       _      _
 |  \/  |        | |     |_   _|     | |    | |
 | \  / |_ _ _ __| |_ ___  | |  _ __ | | ___| |
 | |\/| | '_| '__| __/ _ \ | | | '_ \| |/ _ \ |
 | |  | | | | |  | || (_) || |_| | | | |  __/ |
 |_|  |_|_| |_|   \__\___/_____|_| |_|_|\___|_|
        """)
        print(Fore.GREEN + "⚡ Cyber Intelligence IP Lookup Tool")
        print(Fore.MAGENTA + "by Martech | Termux Edition v3.0\n")

    def input_ips(self, prompt="Enter IP(s) (comma/space separated): "):
        raw = input(prompt).strip()
        ips = [ip.strip() for ip in raw.replace(",", " ").split() if ip.strip()]
        return ips

    def load_ip_file(self):
        path = input("File path: ").strip().strip('"')
        if not os.path.isfile(path):
            self.cprint("File not found.", Fore.RED)
            return []
        with open(path) as f:
            ips = [line.strip() for line in f if line.strip()]
        self.cprint(f"Loaded {len(ips)} IPs from {path}", Fore.GREEN)
        return ips

    def perform_scan(self, ips):
        if not ips:
            self.cprint("No IPs to scan.", Fore.RED)
            return
        invalid = [ip for ip in ips if not is_valid_ip(ip)]
        if invalid:
            self.cprint(f"⚠  Skipping invalid IPs: {', '.join(invalid)}", Fore.YELLOW)
            ips = [ip for ip in ips if is_valid_ip(ip)]
        if not ips:
            return

        self.cprint(f"\n⚡ Scanning {len(ips)} IP(s)... Press Ctrl+C to cancel.\n", Fore.CYAN)
        start = time.time()

        def progress(done, total):
            pct = int(100 * done / total)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r[{bar}] {done}/{total}  ", end="", flush=True)

        try:
            results = scan_ips(ips, self.abuse_key, progress_callback=progress)
        except KeyboardInterrupt:
            self.cprint("\nScan aborted.", Fore.YELLOW)
            return

        elapsed = time.time() - start
        print(f"\n\n✅ Scan completed in {elapsed:.1f}s\n")
        self.current_results = results
        self.display_results(results)
        self.save_history(results)

    def display_results(self, results):
        if not results:
            return
        valid = [r for r in results if "error" not in r]
        errors = [r for r in results if "error" in r]
        if valid:
            headers = ["#", "IP", "Location", "ISP", "ASN", "Status", "RDNS", "Map"]
            rows = []
            for i, r in enumerate(valid):
                rdns = r.get("rdns") or "N/A"
                rows.append([i+1, r["ip"], r["location"], r["isp"], r["asn"], r["status"], rdns, r["map"]])

            if HAS_TABULATE:
                print(tabulate(rows, headers=headers, tablefmt="grid"))
            else:
                col_widths = [max(len(str(item)) for item in col) for col in zip(headers, *rows)]
                header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_widths))
                print(header_line)
                print("-" * len(header_line))
                for row in rows:
                    print("  ".join(str(item).ljust(w) for item, w in zip(row, col_widths)))

            # Quick actions
            print("\n📌 Actions: [M] open map of row  |  [C] copy IP of row  |  [Enter] return")
            action = input("👉 Choice: ").strip().lower()
            if action.startswith("m"):
                idx = self._parse_row(action[1:], len(valid))
                if idx is not None:
                    termux_open_url(valid[idx]["map"])
            elif action.startswith("c"):
                idx = self._parse_row(action[1:], len(valid))
                if idx is not None:
                    termux_copy_to_clipboard(valid[idx]["ip"])
        if errors:
            print("\n❌ Errors:")
            for err in errors:
                print(f"  {err['ip']}: {err['error']}")

    def _parse_row(self, part, max_row):
        row = part.strip()
        if not row:
            row = input("Row number: ").strip()
        if row.isdigit():
            num = int(row) - 1
            if 0 <= num < max_row:
                return num
        print("Invalid row number.")
        return None

    def export_results(self, fmt=None):
        if not self.current_results:
            self.cprint("No results to export.", Fore.YELLOW)
            return
        if not fmt:
            fmt = input("Export format (csv/json): ").strip().lower()
        if fmt not in ["csv", "json"]:
            self.cprint("Invalid format.", Fore.RED)
            return
        default_name = f"marintel_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        path = input(f"Filename (Enter: {default_name}): ").strip()
        if not path:
            path = default_name

        valid = [r for r in self.current_results if "error" not in r]
        if fmt == "csv":
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["ip", "location", "isp", "asn", "status", "rdns", "map", "time"])
                    for r in valid:
                        writer.writerow([r["ip"], r["location"], r["isp"], r["asn"], r["status"],
                                         r.get("rdns",""), r["map"], r.get("time","")])
                self.cprint(f"✅ CSV saved: {path}", Fore.GREEN)
            except Exception as e:
                self.cprint(f"❌ Export failed: {e}", Fore.RED)
        else:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.current_results, f, indent=2)
                self.cprint(f"✅ JSON saved: {path}", Fore.GREEN)
            except Exception as e:
                self.cprint(f"❌ Export failed: {e}", Fore.RED)

    def save_history(self, results):
        try:
            history = self.load_json(HISTORY_FILE, [])
            entry = {"timestamp": datetime.now().isoformat(), "results": results}
            history.append(entry)
            self.save_json(HISTORY_FILE, history[-50:])
        except:
            pass

    def view_history(self):
        history = self.load_json(HISTORY_FILE, [])
        if not history:
            self.cprint("No scan history.", Fore.YELLOW)
            return
        print(Fore.CYAN + "\n📜 Scan History (last 50)")
        for i, entry in enumerate(reversed(history), 1):
            ts = entry.get("timestamp", "unknown time")
            valid = [r for r in entry.get("results", []) if "error" not in r]
            print(f"{i:>3}. {ts} - {len(valid)} IPs scanned")
        choice = input("\nEnter number to view details (0=return): ").strip()
        if choice.isdigit() and choice != "0":
            idx = int(choice) - 1
            if 0 <= idx < len(history):
                entry = history[::-1][idx]
                self.current_results = entry["results"]
                self.display_results(entry["results"])

    def clear_history(self):
        self.save_json(HISTORY_FILE, [])
        self.cprint("History cleared.", Fore.GREEN)

    def manage_targets(self):
        while True:
            self.clear_screen()
            self.print_banner()
            print(Fore.CYAN + "🎯 Target List Manager")
            print("  1. View saved lists")
            print("  2. Save current scan IPs as new list")
            print("  3. Load a list for scanning")
            print("  4. Delete a list")
            print("  5. Return to main menu")
            choice = input("\n👉 Choice: ").strip()

            if choice == "1":
                lists = self.targets.get("lists", {})
                if not lists:
                    self.cprint("No saved lists.", Fore.YELLOW)
                else:
                    for name, ips in lists.items():
                        print(f"  📄 {name}: {len(ips)} IPs")
                input("\nPress Enter...")

            elif choice == "2":
                if not self.current_results:
                    self.cprint("No scan results. Run a scan first.", Fore.YELLOW)
                    input()
                    continue
                name = input("List name: ").strip()
                if name:
                    ips = [r["ip"] for r in self.current_results if "error" not in r]
                    self.targets["lists"][name] = ips
                    self.save_json(TARGETS_FILE, self.targets)
                    self.cprint(f"✅ List '{name}' saved ({len(ips)} IPs).", Fore.GREEN)
                input()

            elif choice == "3":
                lists = self.targets.get("lists", {})
                if not lists:
                    self.cprint("No lists.", Fore.YELLOW)
                    input()
                    continue
                print("\nAvailable lists:")
                for i, (name, ips) in enumerate(lists.items(), 1):
                    print(f"  {i}. {name} ({len(ips)} IPs)")
                sel = input("\nEnter number or name: ").strip()
                selected = None
                if sel.isdigit():
                    idx = int(sel) - 1
                    if 0 <= idx < len(lists):
                        selected = list(lists.values())[idx]
                else:
                    selected = lists.get(sel)
                if selected:
                    self.perform_scan(selected)
                else:
                    self.cprint("Invalid.", Fore.RED)
                input()

            elif choice == "4":
                lists = self.targets.get("lists", {})
                if not lists:
                    self.cprint("No lists.", Fore.YELLOW)
                    input()
                    continue
                print("\nLists:")
                for name in lists:
                    print(f"  - {name}")
                name = input("\nName to delete: ").strip()
                if name in lists:
                    del self.targets["lists"][name]
                    self.save_json(TARGETS_FILE, self.targets)
                    self.cprint("Deleted.", Fore.GREEN)
                else:
                    self.cprint("Not found.", Fore.RED)
                input()

            elif choice == "5":
                break

    def settings_menu(self):
        self.clear_screen()
        self.print_banner()
        print(Fore.CYAN + "⚙️  Settings")
        print(f"  1. AbuseIPDB Key [{'****' if self.abuse_key else 'Not set'}]")
        print(f"  2. Default export format [{self.settings.get('default_export','csv')}]")
        print("  3. Clear scan history")
        print("  4. Back to main menu")
        choice = input("\n👉 Choice: ").strip()
        if choice == "1":
            key = input("Enter API key (or Enter to clear): ").strip()
            self.abuse_key = key
            self.settings["abuse_key"] = key
            self.save_json(SETTINGS_FILE, self.settings)
            self.cprint("Key updated.", Fore.GREEN)
        elif choice == "2":
            fmt = input("Default export format (csv/json): ").strip().lower()
            if fmt in ["csv", "json"]:
                self.settings["default_export"] = fmt
                self.save_json(SETTINGS_FILE, self.settings)
                self.cprint(f"Default set to {fmt}.", Fore.GREEN)
            else:
                self.cprint("Invalid.", Fore.RED)
        elif choice == "3":
            self.clear_history()
        input("\nPress Enter...")

    def load_json(self, path, default=None):
        if default is None:
            default = {}
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r") as f:
                return json.load(f)
        except:
            return default

    def save_json(self, path, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def main_menu(self):
        while True:
            self.clear_screen()
            self.print_banner()
            print(Fore.CYAN + "📋 Main Menu")
            print("  1. Scan IPs (manual input)")
            print("  2. Scan IPs from file")
            print("  3. Target list manager")
            print("  4. Export last scan results")
            print("  5. View scan history")
            print("  6. Settings")
            print("  7. Exit")
            choice = input("\n👉 Choice: ").strip()

            if choice == "1":
                ips = self.input_ips()
                self.perform_scan(ips)
                input("\nPress Enter to continue...")

            elif choice == "2":
                ips = self.load_ip_file()
                if ips:
                    self.perform_scan(ips)
                input("\nPress Enter...")

            elif choice == "3":
                self.manage_targets()

            elif choice == "4":
                self.export_results()
                input("\nPress Enter...")

            elif choice == "5":
                self.view_history()
                input("\nPress Enter...")

            elif choice == "6":
                self.settings_menu()

            elif choice == "7":
                self.cprint("\n👋 Exiting MARINTEL. Stay secure!", Fore.GREEN)
                sys.exit(0)
            else:
                self.cprint("Invalid option.", Fore.RED)
                input("\nPress Enter...")

    def run_batch(self, ips):
        """Non‑interactive scan when IPs are passed as arguments."""
        self.perform_scan(ips)

# --------------- Entry point ---------------
def main():
    # Batch mode if arguments given
    if len(sys.argv) > 1:
        args = sys.argv[1:]
        ips = []
        file_path = None
        abuse_flag = False
        for arg in args:
            if arg == "--abuse":
                abuse_flag = True
            elif os.path.isfile(arg):
                file_path = arg
            else:
                ips.append(arg)
        if file_path:
            with open(file_path) as f:
                ips.extend([line.strip() for line in f if line.strip()])
        if not ips:
            print("No valid IPs provided.")
            return
        cli = MarintelCLI()
        if abuse_flag:
            cli.abuse_key = os.environ.get("ABUSEIPDB_KEY", "")
        cli.run_batch(ips)
    else:
        cli = MarintelCLI()
        cli.main_menu()

if __name__ == "__main__":
    main()
