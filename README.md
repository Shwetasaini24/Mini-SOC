# 🛡 Mini SOC — Security Operations Center

A fully working real-time log monitoring and threat detection dashboard
built with Python (Flask), SQLite, Chart.js, and a dark cybersecurity UI.

---

## 📁 Project Structure

```
mini-soc/
├── app.py                  ← Flask backend (all routes + logic)
├── requirements.txt        ← Python dependencies
├── sample_logs.txt         ← Sample Apache log file for testing
├── instance/
│   └── soc.db              ← SQLite database (auto-created)
├── uploads/                ← Uploaded log files (auto-created)
├── templates/
│   ├── login.html          ← Login page
│   └── dashboard.html      ← Main SOC dashboard
└── static/
    ├── css/
    │   └── dashboard.css   ← Dark cybersecurity theme
    └── js/
        └── dashboard.js    ← Charts, real-time updates, file upload
```

---

## ⚡ Quick Start

### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the application
```bash
python app.py
```

### 3. Open in browser
```
http://localhost:5000
```

### 4. Login
- **Username:** `admin`
- **Password:** `admin123`

---

## 🔑 Features

| Feature | Description |
|---|---|
| **Log Upload** | Upload `.txt` / `.log` files (Apache, auth.log, custom) |
| **Log Parsing** | Extracts IP, timestamp, method, path, status, severity |
| **Threat Detection** | Brute force, HTTP flood, path scan detection |
| **Severity Levels** | LOW / MEDIUM / HIGH classification |
| **Live Dashboard** | Auto-refreshes every 4 seconds |
| **Simulation** | Generates realistic fake log traffic |
| **Charts** | Hourly volume (line) + status code distribution (doughnut) |
| **Login System** | Session-based authentication |

---

## 🧪 Testing with Sample Logs

1. Login to the dashboard
2. Click **Upload Logs** in the sidebar
3. Upload `sample_logs.txt` (included)
4. View detected threats in the **Threat Alerts** section

The sample file contains:
- Brute force attempts (192.168.1.100, 45.33.32.156, 10.10.10.10)
- Path scanning (185.220.101.34 — 20+ unique paths)
- HTTP error floods (198.51.100.77)

---

## 🚀 How It Works

### Backend (app.py)
1. **Log Parsing** — Regex matches Apache Combined Log Format and auth.log
2. **Severity Classification** — Based on HTTP status codes
3. **Threat Detection** — Runs after each upload or every ~10 simulation ticks:
   - Brute Force: ≥5 HTTP 401 responses from same IP
   - HTTP Flood: ≥10 total 4xx/5xx from same IP
   - Path Scan: ≥20 distinct paths from same IP
4. **REST API** — JSON endpoints for all data (`/api/stats`, `/api/logs`, `/api/upload`)
5. **Live Simulation** — Background thread inserts entries every 2 seconds

### Frontend (dashboard.js)
1. Auto-polls `/api/stats` every 4 seconds
2. Renders Chart.js charts (line + doughnut) with live updates
3. Animated KPI counters, severity badges, risk bars
4. File upload with drag-and-drop support

---
## 🛡 Security Notes

- Change `SECRET_KEY` in production (use environment variable)
- Change default admin password after first login
- Run behind a reverse proxy (nginx) in production
- Enable HTTPS with SSL certificate
