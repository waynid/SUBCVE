import csv, requests
from pathlib import Path
from colorama import init, Fore, Style

init(autoreset=True)

subdomains = "subdomains.csv"
exitfile = "vulnerable.csv"
api = "https://internetdb.shodan.io"

def scan(ip):
    try:
        resp = requests.get(f"{api}/{ip}", timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return {}

def main():
    if not Path(subdomains).exists():
        return

    vulnerable = []

    with open(subdomains, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row["IP"].strip()
            host = row["Subdomain"].strip()
            cloud = row["Cloudflare"].strip().upper()

            info = scan(ip)

            if "detail" in info and info["detail"] == "No information available":
                print(f"{host} | {Fore.YELLOW}No Record found{Style.RESET_ALL}")
                continue

            cves = info.get("vulns", [])
            cve_status = f"{Fore.RED}YES{Style.RESET_ALL}" if cves else f"{Fore.GREEN}NO{Style.RESET_ALL}"
            cloud_status = f"{Fore.CYAN}{cloud}{Style.RESET_ALL}"

            print(f"{host} | CVE : {cve_status} | CLOUDFLARE : {cloud_status}")

            if cves:
                vulnerable.append({
                    "Hostname": host,
                    "IP": ip,
                    "CVEs": ",".join(cves)
                })

    if vulnerable:
        with open(exitfile, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Hostname", "IP", "CVEs"])
            writer.writeheader()
            writer.writerows(vulnerable)

if __name__ == "__main__":
    main()
