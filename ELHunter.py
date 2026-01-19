import os
import socket
import getpass
import time
import re
from datetime import datetime
from Evtx.Evtx import Evtx

BANNER = r"""
███████╗██╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██║     ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
█████╗  ██║     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══╝  ██║     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████╗███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ 

╔══════════════════════════════════════════╗
║        ELHunter :: EVTX Forensic CLI     ║
╠══════════════════════════════════════════╣
║  Evidence-driven Windows Event Analysis  ║
║  File-based Keyword Hunting & Reporting  ║
║  Author : exyKim                         ║
╚══════════════════════════════════════════╝
"""

# -------------------------------------------------------------------

def get_system_info():
    user = getpass.getuser()
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "UNKNOWN"
    return user, hostname, ip

def iter_evtx_files(folder):
    for root, _, files in os.walk(folder):
        for name in files:
            if name.lower().endswith(".evtx"):
                yield os.path.join(root, name)

# XML 요약 (가독성 핵심)
def summarize_event(xml):
    time_m = re.search(r'SystemTime="([^"]+)"', xml)
    id_m = re.search(r'<EventID.*?>(\d+)</EventID>', xml)
    data_m = re.search(r'<Data Name="([^"]+)">([^<]+)</Data>', xml)

    time_str = time_m.group(1).replace("T", " ").replace("Z", "") if time_m else "-"
    event_id = id_m.group(1) if id_m else "-"
    summary = f"{data_m.group(1)} = {data_m.group(2)}" if data_m else "Event detected"

    return time_str, event_id, summary

def search_evtx(evtx_path, keywords, results, counter):
    filename = os.path.basename(evtx_path)
    matches = []

    print(f"\n[+] Searching: {filename}")

    try:
        with Evtx(evtx_path) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                except Exception:
                    continue

                for kw in keywords:
                    if kw.lower() in xml.lower():
                        t, eid, summary = summarize_event(xml)
                        matches.append((t, eid, summary))
                        counter["total"] += 1
                        print(f"| {filename:<25} | {eid:<5} | {summary[:80]}")
                        break
    except Exception as e:
        print(f"[!] Failed to parse {filename}: {e}")

    if matches:
        results[filename] = matches
        print(f"[+] {len(matches)} matches found")
    else:
        print("[-] No matches")

# -------------------------------------------------------------------

def save_report(
    path,
    user,
    hostname,
    ip,
    start_time,
    end_time,
    elapsed,
    folder,
    keywords,
    results,
    total_matches
):
    with open(path, "w", encoding="utf-8") as f:
        f.write("ELHunter Forensic Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"User          : {user}\n")
        f.write(f"Hostname      : {hostname}\n")
        f.write(f"IP Address    : {ip}\n")
        f.write(f"Start Time    : {start_time}\n")
        f.write(f"End Time      : {end_time}\n")
        f.write(f"Elapsed Time  : {elapsed:.2f} seconds\n")
        f.write(f"Target Folder : {folder}\n")
        f.write(f"Keywords      : {', '.join(keywords)}\n")
        f.write(f"Total Matches : {total_matches}\n")
        f.write("=" * 60 + "\n\n")

        for fname, entries in results.items():
            f.write(f"[FILE] {fname}\n")
            f.write("-" * 60 + "\n")
            f.write("| No | Time (UTC)              | EventID | Summary\n")
            f.write("|----|-------------------------|---------|------------------------------\n")

            for i, (t, eid, s) in enumerate(entries, 1):
                f.write(f"| {i:>2} | {t:<23} | {eid:<7} | {s}\n")

            f.write("\n")

        f.write("=" * 60 + "\n")
        f.write("END OF REPORT\n")

# -------------------------------------------------------------------

def main():
    print(BANNER)
    input("[+] Press Enter to continue...")

    print("\n[?] Select input type")
    print(" [1] Single EVTX file")
    print(" [2] EVTX folder")
    choice = input(" >> ").strip()

    evtx_targets = []
    target_desc = ""

    if choice == "1":
        file_path = input("[?] Enter EVTX file path: ").strip().strip('"')
        if not os.path.isfile(file_path) or not file_path.lower().endswith(".evtx"):
            print("[!] Invalid EVTX file.")
            return
        evtx_targets = [file_path]
        target_desc = file_path

    elif choice == "2":
        folder = input("[?] Enter EVTX log folder path: ").strip().strip('"')
        if not os.path.isdir(folder):
            print("[!] Invalid folder path.")
            return
        evtx_targets = list(iter_evtx_files(folder))
        target_desc = folder

        if not evtx_targets:
            print("[!] No EVTX files found in folder.")
            return
    else:
        print("[!] Invalid selection.")
        return

    keywords = input("[?] Enter keywords (space-separated): ").split()
    if not keywords:
        print("[!] No keywords provided.")
        return

    user, hostname, ip = get_system_info()
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n========== SEARCH START ==========")
    print(f"User     : {user}")
    print(f"Hostname : {hostname}")
    print(f"IP       : {ip}")
    print(f"Time     : {start_time}")
    print(f"Target   : {target_desc}")
    print(f"Keywords : {', '.join(keywords)}")
    print("=================================")

    start_perf = time.perf_counter()

    results = {}
    counter = {"total": 0}

    for evtx in evtx_targets:
        search_evtx(evtx, keywords, results, counter)

    end_perf = time.perf_counter()
    elapsed = end_perf - start_perf
    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n========== SEARCH END ==========")
    print(f"Start Time   : {start_time}")
    print(f"End Time     : {end_time}")
    print(f"Elapsed Time : {elapsed:.2f} sec")
    print(f"Total Hits   : {counter['total']}")
    print("================================")

    if counter["total"] == 0:
        print("[*] No results to save.")
        return

    if input("[?] Save forensic report? (Y/N): ").lower() == "y":
        base_dir = os.path.dirname(evtx_targets[0])
        out = os.path.join(base_dir, "ELHunter_report.txt")
        save_report(
            out,
            user,
            hostname,
            ip,
            start_time,
            end_time,
            elapsed,
            target_desc,
            keywords,
            results,
            counter["total"]
        )
        print(f"[+] Report saved: {out}")

# -------------------------------------------------------------------

if __name__ == "__main__":
    main()
