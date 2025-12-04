 Minimal Website Recon & Port Scanner (CLI Tool)

Install required packages:

```bash
pip install requests
```

*(If you don’t install `requests`, the tool still works — just without HTTP title/status.)*

---

##  Installation

```bash
git clone https://github.com/yourusername/minimal-web-recon.git
cd minimal-web-recon
```

Save the script as:

```
web_recon_minimal.py
```

Make it executable (optional):

```bash
chmod +x web_recon_minimal.py
```

---

## Usage

###  Basic scan
```bash
python web_recon_minimal.py example.com
```

###  Scan specific ports
```bash
python web_recon_minimal.py example.com -p 80,443,8080
```

###  Scan a port range
```bash
python web_recon_minimal.py example.com -p 1-1024
```

###  Increase threads (faster)
```bash
python web_recon_minimal.py example.com -t 200
```

###  Save results to JSON
```bash
python web_recon_minimal.py example.com -o output.json
```

###  Combined example
```bash
python web_recon_minimal.py example.com -p 1-1024 -t 200 -o scan.json
```

---

##  Example Output

```
Target: example.com

IP: 93.184.216.34  (reverse: N/A)
  Open ports: 2
   - 80  | HTTP 200 - "Example Domain"
   - 443 | SSL subj:example.com issuer:Let's Encrypt Authority X3 valid:Jan 1..Mar 31
```

**Simple. Clean. No unnecessary lines.**

---

## ⚙️ Settings

| Flag | Description |
|------|-------------|
| `-p` | Set ports / ranges (e.g. `80,443,1-1024`) |
| `-t` | Number of threads (default: 50) |
| `--timeout` | Set connection timeout (default: 1.5s) |
| `-o` | Save JSON to file |
| `target` | Domain or URL |

---

##  Legal Warning

This tool is for:
- Educational use  
- OSINT  
- Testing your **own systems**  
- Authorized cybersecurity work  


---

## ⭐ Support

If this tool helped you, please give the project a **star** on GitHub ⭐

