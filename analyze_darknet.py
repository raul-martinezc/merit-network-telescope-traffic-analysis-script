#!/usr/bin/env python3

#Robust darknet analysis for telescope CSVs.
#
#Usage:
#  python3 analyze_darknet.py traffic-2025-01-20.00-1M.csv [GeoLite2-Country.mmdb]
#
#Outputs:
#  - top_countries.png, top_ports.png, syn_vs_ack.png, (optional) traffic_by_time.png
#  - scanning_ips.csv, backscatter_examples.csv, tls_examples.csv
#  - Console prints that answer Steps 1–8


import sys
import os
import pandas as pd
import matplotlib.pyplot as plt

# Optional GeoIP lookup
GEO_OK = True
try:
    import geoip2.database
except Exception:
    GEO_OK = False

def pick_first_present(df, candidates):
    for c in candidates:
        if c in df.columns:
            return c
    return None

def load_df(csv_path):
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    return df

def ensure_numeric(df, col, new_name=None):
    name = new_name or col
    if col in df.columns:
        df[name] = pd.to_numeric(df[col], errors='coerce')
    return name

def guess_columns(df):
    ip_candidates       = ["SourceIP","src_ip","saddr","SrcIP","ip_src","Src"]
    port_candidates     = ["Port","dport","dst_port","DestPort","DestinationPort","port"]
    sport_candidates    = ["sport","src_port","SourcePort"]
    proto_candidates    = ["Protocol","proto","Proto"]
    flags_candidates    = ["TCPFlags","tcp_flags","Flags","flags","tcpflag","tcp-flag"]
    packets_candidates  = ["Packets","pkts","packets","packet_count"]
    bytes_candidates    = ["Bytes","bytes","octets","byte_count"]
    country_candidates  = ["Country","country","geo_country"]
    first_ts_candidates = ["First","FirstSeen","first_ts","first","start_time","time_start"]
    last_ts_candidates  = ["Last","LastSeen","last_ts","last","end_time","time_end"]

    return {
        "src_ip":   pick_first_present(df, ip_candidates),
        "dst_port": pick_first_present(df, port_candidates),
        "src_port": pick_first_present(df, sport_candidates),
        "proto":    pick_first_present(df, proto_candidates),
        "flags":    pick_first_present(df, flags_candidates),
        "packets":  pick_first_present(df, packets_candidates),
        "bytes":    pick_first_present(df, bytes_candidates),
        "country":  pick_first_present(df, country_candidates),
        "first":    pick_first_present(df, first_ts_candidates),
        "last":     pick_first_present(df, last_ts_candidates)
    }

def enrich_country(df, cols, geo_path):
    if cols["country"]:
        return df, cols["country"]
    if not GEO_OK or not os.path.exists(geo_path):
        print("GeoIP: country column missing and GeoLite2 DB not available — skipping enrichment.")
        return df, None

    reader = geoip2.database.Reader(geo_path)
    col_name = "__Country"
    out = []
    ip_col = cols["src_ip"]
    if not ip_col:
        print("GeoIP: No source IP column to enrich from — skipping.")
        return df, None
    for ip in df[ip_col].astype(str):
        try:
            resp = reader.country(ip)
            cc = resp.country.iso_code or resp.registered_country.iso_code
            out.append(cc if cc else "ZZ")
        except Exception:
            out.append("ZZ")
    df[col_name] = out
    reader.close()
    return df, col_name

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_darknet.py <csv> [GeoLite2-Country.mmdb]")
        sys.exit(1)

    csv_path = sys.argv[1]
    geo_default = os.path.join("GeoLite2-Country_20251104", "GeoLite2-Country.mmdb")
    geo_path = sys.argv[2] if len(sys.argv) >= 3 else geo_default

    df = load_df(csv_path)
    print("\nLoaded:", csv_path, "shape:", df.shape)
    print("Columns:", df.columns.tolist())

    cols = guess_columns(df)
    print("\nGuessed columns:", cols)

    if cols["dst_port"]:
        ensure_numeric(df, cols["dst_port"], "Port_num")
    if cols["packets"]:
        ensure_numeric(df, cols["packets"], "Packets_num")
    if cols["bytes"]:
        ensure_numeric(df, cols["bytes"], "Bytes_num")

    df, country_col = enrich_country(df, cols, geo_path)

    # ---- Step 1 ----
    print("\n--- Step 1: Field explanations ---")
    print("SourceIP  - origin IP that sent unsolicited traffic (likely scanner/compromised host).")
    print("Port      - destination port on darknet address; maps to a service (22 SSH, 80 HTTP...).")
    print("Packets   - number of packets in the record; intensity indicator.")
    print("Bytes     - total bytes in the record; payload/DoS indicator.")
    print("EventType - dataset classification (scan/backscatter/DoS/etc.) if present.")

    # ---- Step 2 ----
    print("\n--- Step 2: Top Origin Countries ---")
    if country_col:
        top_c = df[country_col].fillna("ZZ").value_counts().head(10)
        print("Top 5 countries by record count:\n", top_c.head(5))
        if cols["packets"]:
            pkts_by_country = df.groupby(country_col, dropna=False)["Packets_num"].sum().sort_values(ascending=False)
            print("Highest total packets country:", pkts_by_country.index[0], "packets=", int(pkts_by_country.iloc[0]))
        top_c.head(10).plot(kind="bar", title="Top origin countries (record count)").set_ylabel("Record count")
        plt.tight_layout(); plt.savefig("top_countries.png"); plt.clf()
        print("Saved: top_countries.png")

    # ---- Step 3 ----
    print("\n--- Step 3: Top Ports & Protocols ---")
    if "Port_num" in df.columns:
        top_ports = df["Port_num"].value_counts().head(10)
        print("Top 5 ports:\n", top_ports.head(5))
        service_map = {
            22:"SSH", 23:"Telnet", 80:"HTTP", 443:"HTTPS/TLS", 3389:"RDP", 445:"SMB",
            8080:"HTTP-alt/Proxy", 2323:"Telnet-alt", 81:"HTTP-alt", 8443:"HTTPS-alt",
            1433:"MSSQL", 1900:"SSDP/UPnP", 53:"DNS", 123:"NTP", 25:"SMTP"
        }
        print("\nService mapping:")
        for p in top_ports.head(5).index:
            try: label = service_map.get(int(p), "unknown")
            except: label = "unknown"
            print(f"Port {p} -> {label}")
        top_ports.plot(kind="bar", title="Top destination ports").set_ylabel("Record count")
        plt.tight_layout(); plt.savefig("top_ports.png"); plt.clf()
        print("Saved: top_ports.png")

    # ---- Protocol prevalence (fixed) ----
    if cols["proto"] and cols["proto"] in df.columns:
        print("\nProtocol counts:\n", df[cols["proto"]].value_counts().head(10))
    else:
        tcp_ct = icmp_ct = 0
        if "TCP" in df.columns:
            tcp_series = df["TCP"].astype(str).str.lower()
            tcp_bool = (pd.to_numeric(df["TCP"], errors="coerce").fillna(0) != 0) | tcp_series.isin(["true","t","yes","y"])
            tcp_ct = int(tcp_bool.sum())
        if "ICMP" in df.columns:
            icmp_series = df["ICMP"].astype(str).str.lower()
            icmp_bool = (pd.to_numeric(df["ICMP"], errors="coerce").fillna(0) != 0) | icmp_series.isin(["true","t","yes","y"])
            icmp_ct = int(icmp_bool.sum())
        if tcp_ct or icmp_ct:
            print(f"\nProtocol heuristic -> TCP:{tcp_ct}  ICMP:{icmp_ct}  (TCP usually dominates scanning)")
        else:
            print("\nNo explicit protocol columns found (look for TCP, ICMP, or Protocol).")

    # ---- Step 4 ----
    print("\n--- Step 4: Scanning IPs ---")
    if cols["src_ip"] and "Port_num" in df.columns:
        ports_per_ip = df.groupby(cols["src_ip"])["Port_num"].nunique().sort_values(ascending=False)
        scanners = ports_per_ip[ports_per_ip >= 5]
        print("Top scanning candidates (IP -> unique ports):\n", scanners.head(10))
        scanners.reset_index().rename(columns={"Port_num":"UniquePorts","index":"SourceIP"}).to_csv("scanning_ips.csv", index=False)
        print("Saved: scanning_ips.csv")
        if "UniqueDests" in df.columns:
            print("\nTop by UniqueDests:\n", df.groupby(cols["src_ip"])["UniqueDests"].max().sort_values(ascending=False).head(10))
        if "UniqueDest24s" in df.columns:
            print("\nTop by UniqueDest24s:\n", df.groupby(cols["src_ip"])["UniqueDest24s"].max().sort_values(ascending=False).head(10))

    # ---- Step 5 ----
    print("\n--- Step 5: Backscatter candidates ---")
    backscatter_written = False
    if cols["flags"] and cols["flags"] in df.columns:
        flags_col = cols["flags"]
        has_ack = df[flags_col].astype(str).str.upper().str.contains("A", na=False)
        has_syn = df[flags_col].astype(str).str.upper().str.contains("S", na=False)
        backscatter_examples = df[has_ack & ~has_syn]
        print("Backscatter candidate count:", len(backscatter_examples))
        if not backscatter_examples.empty:
            backscatter_examples.head(200).to_csv("backscatter_examples.csv", index=False)
            backscatter_written = True
            print("Saved: backscatter_examples.csv (ACK w/out SYN)")
    if not backscatter_written:
        backscatter_candidate = pd.Series(False, index=df.index)
        if "ICMP" in df.columns:
            try: backscatter_candidate |= df["ICMP"].astype(bool)
            except: pass
        if "Port_num" in df.columns and "Packets_num" in df.columns:
            backscatter_candidate |= df["Port_num"].between(1024,65535) & (df["Packets_num"] > 10)
        cands = df[backscatter_candidate]
        print("Heuristic backscatter candidate count:", len(cands))
        if not cands.empty:
            cands.head(200).to_csv("backscatter_examples.csv", index=False)
            print("Saved: backscatter_examples.csv (heuristic)")

    # ---- Step 6 ----
    print("\n--- Step 6: TLS rows (port 443) ---")
    if "Port_num" in df.columns:
        tls_rows = df[df["Port_num"] == 443]
        print("TLS-targeted rows:", len(tls_rows))
        if not tls_rows.empty:
            tls_rows.head(200).to_csv("tls_examples.csv", index=False)
            print("Saved: tls_examples.csv")

    # ---- Step 7 ----
    print("\n--- Step 7: IDS/Firewall suggestions ---")
    print("Firewall: block unnecessary high-risk ports (23/Telnet, 3389/RDP, 445/SMB).")
    print("IDS fields: SourceIP, Destination Port, TCPFlags (if avail), Packets/Bytes thresholds, Country/ASN.")

    # ---- Step 8 ----
    print("\n--- Step 8: Crypto/Integrity ---")
    print("Use TLS/IPsec so captured data is unreadable; digital signatures detect tampering/spoofing.")

    # ---- Step 9 ----
    print("\n--- Step 9: Optional time & SYN/ACK plots ---")
    ts_col = cols["first"] or cols["last"]
    if ts_col and ts_col in df.columns:
        try:
            ts = pd.to_datetime(df[ts_col], errors="coerce")
            tmp = df.copy(); tmp["__ts"] = ts
            if cols["packets"] and "Packets_num" in tmp.columns:
                series = tmp.dropna(subset=["__ts"]).set_index("__ts").resample("1h")["Packets_num"].sum()
            else:
                series = tmp.dropna(subset=["__ts"]).set_index("__ts").resample("1h").size()
            if not series.empty:
                series.plot(title="Traffic volume over time (hourly)").set_ylabel("Packets")
                plt.tight_layout(); plt.savefig("traffic_by_time.png"); plt.clf()
                print("Saved: traffic_by_time.png")
        except Exception as e:
            print("Time parsing failed:", e)

    if cols["flags"] and cols["flags"] in df.columns:
        fcol = cols["flags"]
        syn_count = df[fcol].astype(str).str.upper().str.contains("S", na=False).sum()
        ack_count = df[fcol].astype(str).str.upper().str.contains("A", na=False).sum()
        plt.bar(["SYN","ACK"], [syn_count, ack_count])
        plt.title("SYN vs ACK counts"); plt.ylabel("Count")
        plt.tight_layout(); plt.savefig("syn_vs_ack.png"); plt.clf()
        print("Saved: syn_vs_ack.png")

    print("\nDone. Files in current directory:\n"
          "  - top_countries.png, top_ports.png, syn_vs_ack.png, (maybe) traffic_by_time.png\n"
          "  - scanning_ips.csv, backscatter_examples.csv, tls_examples.csv")

if __name__ == "__main__":
    main()

