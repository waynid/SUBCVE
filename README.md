# SUBCVE

![Shodan](https://img.shields.io/badge/Shodan-InternetDB-red?logo=shodan) ![Python](https://img.shields.io/badge/Python-3.8%2B-green)

**SUBCVE** | Simple CVE scanner on **subdomains**.

Export your subdomains from [subdomainfinder.c99.nl](https://subdomainfinder.c99.nl/), paste the CSV into `subdomains.csv`, and run the script.

hosts with CVE will be listed in `vulnerable.csv`.

---

## Installation

```bash
git clone https://github.com/waynid/SUBCVE.git
cd SUBCVE
pip install -r requirements.txt
