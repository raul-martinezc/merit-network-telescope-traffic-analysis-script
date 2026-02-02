# Network Telescope Darknet Analysis (Fall 2025 Baseline)

This repository contains a Python script (`analyze_darknet.py`) for analyzing **unsolicited internet traffic** from **network telescope (darknet) CSV records**, with a focus on identifying patterns consistent with **scanning**, **reconnaissance**, and **backscatter/DoS-like behavior**. This script is the **Fall 2025 baseline** pipeline from CPT_S 455 at *Washington State University - Tri Cities* and will be extended as project requirements evolve.

---

## What the script does

Given a telescope CSV file, the script:
- Loads and normalizes column names
- Attempts to **auto-detect** common field names (source IP, destination port, flags, timestamps, etc.)
- Converts key fields (ports, packets, bytes) to numeric when available
- Optionally enriches records with **origin country** using a GeoLite2 database (if a country column is not already present)
- Produces summary statistics (printed to console) and exports **plots and CSVs** to support analysis and reporting

The console output includes numbered “Step” sections that align with the project’s analysis goals (e.g., top ports, scanning candidates, backscatter candidates).

---

## Requirements

### Python
- Python 3.x

### Python packages
- `pandas`
- `matplotlib`
- *(optional)* `geoip2` for GeoLite2 country enrichment

Install dependencies:
```bash
pip install pandas matplotlib
pip install geoip2   # optional
```

---

## Input data

- A darknet / network telescope dataset exported as a **CSV**
  - Example: `traffic-2025-01-20.00-1M.csv`

### Optional: GeoLite2 Country database
If the CSV does **not** already contain a country field, the script can enrich country codes using a GeoLite2 database.

- Download `GeoLite2-Country.mmdb` from MaxMind (account required)
- By default, the script looks for:
  ```
  GeoLite2-Country_20251104/GeoLite2-Country.mmdb
  ```
- You may also provide the path manually when running the script

---

## How to run

### Basic run (no GeoLite2 enrichment)
```bash
python3 analyze_darknet.py <your_csv_file>
```

Example:
```bash
python3 analyze_darknet.py traffic-2025-01-20.00-1M.csv
```

### Run with GeoLite2 enrichment (recommended if country is missing)
```bash
python3 analyze_darknet.py <your_csv_file> <path_to_GeoLite2-Country.mmdb>
```

Example:
```bash
python3 analyze_darknet.py traffic-2025-01-20.00-1M.csv GeoLite2-Country.mmdb
```

---

## Outputs

After execution, the script writes analysis outputs to the **current directory**.

### Plots (PNG)
- `top_countries.png` – Top origin countries by record count
- `top_ports.png` – Most frequently targeted destination ports
- `syn_vs_ack.png` – SYN vs ACK comparison
- `traffic_by_time.png` *(optional)* – Hourly traffic volume

### CSV files
- `scanning_ips.csv` – Source IPs ranked by unique destination ports
- `backscatter_examples.csv` – Candidate backscatter rows
- `tls_examples.csv` – Example rows targeting port 443

---

## Example Workflow

1. Run the script on your assigned CSV(s)
2. Review generated plots and CSVs
3. Use outputs directly in analysis notes and figures
4. Commit only scripts and documentation (not raw data)

---

## Project status

This repository represents the **Fall 2025 baseline** analysis script from CPT_S 455 at *Washington State University - Tri Cities*. Future milestones will extend this pipeline with additional feature engineering, aggregation, and visualization capabilities.
