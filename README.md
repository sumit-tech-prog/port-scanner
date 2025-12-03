# 🌐 Minimal Website Recon & Port Scanner (CLI Tool)

A clean and fast **terminal-based website reconnaissance tool**.  
It takes a domain or URL, resolves the IP(s), scans ports, grabs banners, checks HTTP title/status, and reads SSL certificate info (port 443).  
All in **minimal, noise-free output** — perfect for cybersecurity beginners, OSINT learners, and Kali Linux users.

---

## 🚀 Features

### 🔍 Essential Information Only (No Junk)
- Resolve domain → IP(s)
- Reverse DNS lookup  
- Fast multi-threaded port scanning  
- For each open port:
  - Banner grabbing (if any)
  - HTTP status code & `<title>` (80/443/8080/8443)
  - SSL certificate summary (subject, issuer, validity)
- JSON export option (`-o file.json`)
- Clean, readable terminal output  
- Supports port ranges (e.g., `1-1024`)

---

## 🛠 Dependencies

Install required packages:

```bash
pip install requests
```

*(If you don’t install `requests`, the tool still works — just without HTTP title/status.)*

---

## 📥 Installation

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

## 📚 Usage

### 🔹 Basic scan
```bash
python web_recon_minimal.py example.com
```

### 🔹 Scan specific ports
```bash
python web_recon_minimal.py example.com -p 80,443,8080
```

### 🔹 Scan a port range
```bash
python web_recon_minimal.py example.com -p 1-1024
```

### 🔹 Increase threads (faster)
```bash
python web_recon_minimal.py example.com -t 200
```

### 🔹 Save results to JSON
```bash
python web_recon_minimal.py example.com -o output.json
```

### 🔹 Combined example
```bash
python web_recon_minimal.py example.com -p 1-1024 -t 200 -o scan.json
```

---

## 🧪 Example Output

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

## ⚠️ Legal Warning

This tool is for:
- Educational use  
- OSINT  
- Testing your **own systems**  
- Authorized cybersecurity work  

**Unauthorized port scanning may be illegal.  
Always get permission before scanning any website or server.**

---

## 📂 Project Structure

```
minimal-web-recon/
│
├── web_recon_minimal.py   # Main tool
└── README.md              # Documentation
```

---

## ❤️ Contribute

Pull requests & feature ideas are welcome!

Want advanced features like:
- IP geolocation  
- Colorized output  
- Subdomain enumeration  
- Screenshot capture  

Just open an issue or ask!

---

## ⭐ Support

If this tool helped you, please give the project a **star** on GitHub ⭐

