
from __future__ import annotations
import argparse
import json
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Try import requests for HTTP title/status; if not available we skip HTTP details
try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    REQUESTS_AVAILABLE = False

# Default sensible ports (compact list focusing on likely services)
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5900, 8080, 8443]

# Utility ---------------------------------------------------------
def normalize_host(host: str) -> str:
    host = host.strip()
    host = re.sub(r"^https?://", "", host, flags=re.I)
    host = host.split('/')[0]
    return host.split(':')[0]

def resolve_ips(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except Exception:
        return []

def reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

# Port check + banner ------------------------------------------------
def check_port(ip: str, port: int, timeout: float=1.5) -> Dict:
    """Try to connect to ip:port. Return dict with 'open' boolean and optional banner/http/ssl."""
    result = {'port': port, 'open': False}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        result['open'] = True
        # Try small banner read
        try:
            s.settimeout(1.0)
            data = s.recv(1024)
            if data:
                banner = data.decode(errors='ignore').strip()
                # short banner line
                result['banner'] = banner.replace('\n', ' ').replace('\r', ' ').strip()[:200]
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

        # If it's an HTTP-ish port, try HTTP title/status (if requests available)
        if port in (80, 8080, 8000, 443, 8443) and REQUESTS_AVAILABLE:
            scheme = 'https' if port in (443, 8443) else 'http'
            url = f"{scheme}://{ip}:{port}/"
            try:
                # Use Host header equal to original domain when possible (caller will set)
                resp = requests.get(url, timeout=3, verify=False, headers={'User-Agent': 'web_recon_minimal/1.0'})
                result['http_status'] = resp.status_code
                # extract <title>
                m = re.search(r'<title[^>]*>(.*?)</title>', resp.text, flags=re.I|re.S)
                if m:
                    title = m.group(1).strip()
                    result['http_title'] = re.sub(r'\s+', ' ', title)[:200]
            except Exception:
                pass

        # If SSL port, try to get cert summary
        if port == 443:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                        cert = ssock.getpeercert()
                        # get subject CN and issuer CN (best-effort)
                        subject = cert.get('subject', ())
                        issuer = cert.get('issuer', ())
                        def find_cn(tuples):
                            for part in tuples:
                                for k, v in part:
                                    if k.lower() == 'commonname' or k.lower() == 'cn':
                                        return v
                            return None
                        subj_cn = find_cn(subject) or None
                        iss_cn = find_cn(issuer) or None
                        result['ssl_subject'] = subj_cn
                        result['ssl_issuer'] = iss_cn
                        result['ssl_notBefore'] = cert.get('notBefore')
                        result['ssl_notAfter'] = cert.get('notAfter')
            except Exception:
                pass

    except Exception:
        # closed / filtered
        result['open'] = False
        try:
            s.close()
        except Exception:
            pass
    return result

# Orchestrator -----------------------------------------------------
def scan_ip_ports(ip: str, ports: List[int], workers: int=50, timeout: float=1.5) -> List[Dict]:
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports) or 1)) as ex:
        futures = {ex.submit(check_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res.get('open'):
                results.append(res)
    # sort by port
    return sorted(results, key=lambda x: x['port'])

def gather_minimal(target: str, ports: List[int], threads: int, timeout: float, save_json: Optional[str]=None) -> Dict:
    t0 = datetime.utcnow().isoformat() + 'Z'
    host = normalize_host(target)
    ips = resolve_ips(host)
    out = {'target': host, 'scanned_at': t0, 'ips': []}
    for ip in ips:
        ip_entry = {'ip': ip, 'reverse_dns': reverse_dns(ip)}
        open_ports = scan_ip_ports(ip, ports, workers=threads, timeout=timeout)
        ip_entry['open_ports'] = open_ports
        out['ips'].append(ip_entry)
    if save_json:
        try:
            with open(save_json, 'w', encoding='utf-8') as fh:
                json.dump(out, fh, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[!] Failed to save JSON: {e}", file=sys.stderr)
    return out

# Output (minimal formatting) ------------------------------------
def print_minimal(out: Dict):
    host = out.get('target')
    print(f"Target: {host}")
    for ip_entry in out.get('ips', []):
        ip = ip_entry['ip']
        rdns = ip_entry.get('reverse_dns') or 'N/A'
        print(f"\nIP: {ip}  (reverse: {rdns})")
        open_ports = ip_entry.get('open_ports', [])
        if not open_ports:
            print("  Open ports: None found (scanned defaults)")
            continue
        print(f"  Open ports: {len(open_ports)}")
        for p in open_ports:
            line = f"   - {p['port']}"
            # banner if present
            if 'banner' in p and p['banner']:
                line += f"  banner: {p['banner']}"
            # HTTP info
            if 'http_status' in p:
                line += f"  | HTTP {p.get('http_status')}"
                if p.get('http_title'):
                    line += f" - \"{p.get('http_title')}\""
            # SSL info
            if p.get('ssl_subject') or p.get('ssl_issuer'):
                subj = p.get('ssl_subject') or 'N/A'
                iss = p.get('ssl_issuer') or 'N/A'
                nb = p.get('ssl_notBefore') or 'N/A'
                na = p.get('ssl_notAfter') or 'N/A'
                line += f"  | SSL subj:{subj} issuer:{iss} valid:{nb}..{na}"
            print(line)

# CLI -------------------------------------------------------------
def parse_ports_arg(s: Optional[str]) -> List[int]:
    if not s:
        return DEFAULT_PORTS
    parts = s.split(',')
    out = []
    for part in parts:
        part = part.strip()
        if '-' in part:
            a,b = part.split('-',1)
            try:
                out.extend(list(range(int(a), int(b)+1)))
            except Exception:
                pass
        else:
            try:
                out.append(int(part))
            except Exception:
                pass
    return sorted(list(set(out)))

def main():
    parser = argparse.ArgumentParser(description="Minimal website recon - compact output")
    parser.add_argument('target', help='Domain or URL (e.g. example.com or https://example.com)')
    parser.add_argument('-p','--ports', help='Comma list or ranges (e.g. 80,443,8000-8010). Default common ports', default=None)
    parser.add_argument('-t','--threads', type=int, default=50, help='Threads per IP (default 50)')
    parser.add_argument('--timeout', type=float, default=1.5, help='Connect timeout seconds (default 1.5)')
    parser.add_argument('-o','--output', help='Save result JSON to file (optional)')
    args = parser.parse_args()

    ports = parse_ports_arg(args.ports)
    target = args.target
    if not REQUESTS_AVAILABLE:
        # inform once — but script will still run without HTTP title/status
        print("[!] 'requests' not installed — HTTP title/status will be skipped. To enable, run: pip install requests")

    result = gather_minimal(target, ports, threads=args.threads, timeout=args.timeout, save_json=args.output)
    print_minimal(result)

if __name__ == "__main__":
    main()
