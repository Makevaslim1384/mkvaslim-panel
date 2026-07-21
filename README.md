# MaKeVaslim Panel

> **Complete VPN Management Panel** with multi-protocol support, Cloudflare integration, Telegram bot management, and beautiful UI.

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/MakeVaslim/Panel)
[![Python](https://img.shields.io/badge/python-3.11+-green.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-teal.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 🌟 Features

### 🔐 Protocols Supported
| Protocol | Transports | Status |
|----------|------------|--------|
| **VLESS** | WebSocket, HTTP/2, gRPC, XHTTP, TCP | ✅ Core |
| **VMess** | WebSocket, HTTP/2, gRPC, TCP | ✅ Full |
| **Trojan** | WebSocket, HTTP/2, gRPC, TCP | ✅ Full |
| **Shadowsocks** | TCP, WebSocket | ✅ Full |
| **Hysteria2** | QUIC | ✅ Full |
| **TUIC** | QUIC | ✅ Full |
| **WireGuard** | UDP | 🔄 Planned |

### 🌐 Transport Layer
- **WebSocket (WS)** - Classic VLESS/WS with TLS
- **HTTP/2 (h2)** - Multiplexed streams
- **gRPC** - High-performance RPC
- **XHTTP** - Siz10a Ultra (packet-up, stream-up modes)
- **QUIC** - Hysteria2, TUIC
- **TCP** - Raw TCP with header obfuscation

### 🎛️ Management Features
- **Multi-user management** with quotas, speed limits, IP limits
- **Subscription groups** with public pages (password protected)
- **Real-time monitoring** - live connections, traffic stats, hourly charts
- **Telegram Bot** - Full management via Telegram (wizard-based config creation)
- **Cloudflare Integration** - Dynamic proxy IPs, DNS management, Worker auto-update
- **Backup/Restore** - SQLite + Cloudflare D1 sync
- **Auto-update** - GitHub → Cloudflare Worker deployment

### 🎨 UI/UX
- **3 Themes**: Light, Dark (AMOLED), Sunset (warm orange)
- **RTL Persian/English** support with Vazirmatn font
- **Responsive** - Works on mobile, tablet, desktop
- **QR Codes** - Auto-generated for all configs
- **Real-time updates** - Live stats, connection tracking

---

## 🚀 Quick Deploy

### 📋 Prerequisites
- Docker & Docker Compose
- Cloudflare account (for Workers, D1, DNS)
- Telegram Bot Token (optional)
- Domain (for Cloudflare)

### ⚡ One-Line Deploy (Railway)
```bash
# 1. Fork this repo
# 2. Connect to Railway
# 3. Add Volume: /data → /data
# 4. Set Environment Variables (see below)
# 5. Deploy!
```

### 🐳 Docker Compose (Local/VPS)
```bash
git clone https://github.com/MakeVaslim/Panel.git
cd Panel

# Configure environment
cp .env.example .env
nano .env  # Edit with your values

# Deploy
docker-compose up -d --build
```

### ☁️ Cloudflare Worker (Edge)
```bash
# 1. Install Wrangler
npm install -g wrangler

# 2. Configure
cp wrangler.toml.example wrangler.toml
# Edit with your CF_ACCOUNT_ID, CF_API_TOKEN, D1 database ID

# 3. Deploy
wrangler deploy
```

---

## ⚙️ Configuration

### 🔧 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ADMIN_PASSWORD` | ✅ | `MakeVaslim2024!` | Panel admin password |
| `SECRET_KEY` | ❌ | Auto-generated | JWT/session signing key |
| `DATA_DIR` | ❌ | `/data` | Data directory (mount volume here) |
| `TELEGRAM_BOT_TOKEN` | ❌ | - | Bot token from @BotFather |
| `TELEGRAM_ADMIN_IDS` | ❌ | - | Comma-separated admin Telegram IDs |
| `CF_API_TOKEN` | ❌ | - | Cloudflare API token (Workers/D1/DNS) |
| `CF_ACCOUNT_ID` | ❌ | - | Cloudflare account identifier |
| `RAILWAY_PUBLIC_DOMAIN` | ❌ | - | Auto-set by Railway |
| `PUBLIC_DOMAIN` | ❌ | - | Your domain (e.g., panel.example.com) |
| `DEBUG` | ❌ | `false` | Enable debug mode |
| `LOG_LEVEL` | ❌ | `INFO` | Logging level |

### 📁 Volume Mount
**Critical**: Mount a persistent volume to `/data` for:
- SQLite database (`makevaslim.db`)
- State file (`state.json`)
- Secret key (`secret.key`)
- Backups (`backups/`)

---

## 🎯 Usage Guide

### 1. First Login
```
https://your-domain.com/panel
Username: admin
Password: [ADMIN_PASSWORD]
```

### 2. Create Configs
- Go to **Configs** → **New Config**
- Set: Label, Protocol, Transport, Fingerprint, Port
- Limits: Volume (GB/MB), Speed (Mbps), IP Limit, Expiry (days)
- Assign to **Subscription Group** (optional)

### 3. Subscription Groups
- Create **Group** → Add configs → Get public page URL
- Public page: `https://domain.com/p/{uuid_key}`
- Optional password protection
- QR codes, copy-all, proto breakdown

### 4. Client Links
| Type | URL Format |
|------|------------|
| Single Config | `https://domain.com/sub/{uuid}` |
| All Configs | `https://domain.com/sub-all` |
| Group | `https://domain.com/sub-group/{uuid_key}` |
| Status Page | `https://domain.com/status/{username}` |

### 5. Telegram Bot
1. Create bot via @BotFather
2. Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_ADMIN_IDS`
3. Restart panel
4. Message bot `/start` for full management

---

## 🔌 API Reference

### Authentication
```bash
# Login
curl -X POST https://domain.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"password": "your-password"}'

# Use cookie for subsequent requests
curl -b "mk_session=xxx" https://domain.com/api/users
```

### Key Endpoints
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/login` | POST | ❌ | Login |
| `/api/logout` | POST | ✅ | Logout |
| `/api/me` | GET | ✅ | Current user |
| `/api/users` | GET | ✅ | List users |
| `/api/users` | POST | ✅ | Create user |
| `/api/users/{username}` | PATCH | ✅ | Update user |
| `/api/users/{username}` | DELETE | ✅ | Delete user |
| `/api/configs` | GET | ✅ | List configs |
| `/api/configs` | POST | ✅ | Create config |
| `/api/configs/{uuid}` | GET | ✅ | Get config |
| `/api/configs/{uuid}` | PATCH | ✅ | Update config |
| `/api/configs/{uuid}` | DELETE | ✅ | Delete config |
| `/api/groups` | GET | ✅ | List groups |
| `/api/groups` | POST | ✅ | Create group |
| `/api/stats` | GET | ✅ | System stats |
| `/api/cf/proxy-ip` | GET/POST | ✅ | Proxy IP management |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Client                                │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS/WSS
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Cloudflare CDN                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Worker    │  │    KV/D1    │  │      DNS/Proxy      │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │ Failover/Load Balance
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Railway/VPS Backend                        │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ FastAPI App (Python 3.11)                                │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐  │ │
│  │  │   WS     │ │  XHTTP   │ │   H2     │ │   gRPC     │  │ │
│  │  │ Transport│ │ Transport│ │ Transport│ │ Transport  │  │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────────┘  │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐  │ │
│  │  │ Protocols│ │ Limits   │ │  Auth    │ │  Storage   │  │ │
│  │  │ VLESS,   │ │ Speed,   │ │ JWT,     │ │ SQLite +   │  │ │
│  │  │ VMess,   │ │ IP, Vol  │ │ Sessions │ │ D1 Sync    │  │ │
│  │  │ Trojan.. │ │          │ │          │ │              │  │ │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Development

### Local Setup
```bash
# Clone
git clone https://github.com/MakeVaslim/Panel.git
cd Panel

# Create venv
python -m venv venv
source venv/bin/activate

# Install deps
pip install -r requirements.txt

# Run
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Project Structure
```
makevaslim/
├── backend/
│   ├── main.py              # FastAPI app entry
│   ├── config.py            # Configuration
│   ├── database.py          # SQLite + D1 sync
│   ├── auth.py              # JWT + sessions
│   ├── protocols/           # Link generators
│   ├── transports/          # WS, XHTTP, H2, gRPC, QUIC
│   ├── limits/              # Token bucket, AIMD, quota
│   ├── api/                 # REST endpoints
│   └── telegram/            # Bot handlers
├── frontend/
│   ├── panel.html           # Main dashboard
│   ├── login.html           # Login page
│   ├── sub-view.html        # Public sub page
│   └── status.html          # User status page
├── worker/
│   └── worker.js            # Cloudflare Worker
├── deployment/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── railway.json
│   ├── start.sh
│   └── nginx.conf.template
└── tests/
```

### Running Tests
```bash
pytest tests/ -v --asyncio-mode=auto
```

---

## 📊 Monitoring

### Health Checks
- `GET /health` - Basic health
- `GET /api/stats` - Detailed stats (requires auth)

### Metrics (Prometheus)
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'makevaslim'
    static_configs:
      - targets: ['your-domain.com:8000']
```

### Logs
```bash
# Docker
docker-compose logs -f app

# Railway
railway logs

# Local
tail -f logs/app.log
```

---

## 🔒 Security

- **JWT + HttpOnly Cookies** for sessions
- **SHA-256 + Salt** for password hashing
- **Rate Limiting** - API, WebSocket, subscription endpoints
- **CSP Headers** - Strict content security policy
- **Input Validation** - Pydantic models everywhere
- **SQL Injection Prevention** - Parameterized queries
- **XSS Prevention** - Auto-escaping in templates

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open Pull Request

### Code Style
- **Black** formatting
- **Type hints** everywhere
- **Async/await** for all I/O
- **Docstrings** for public functions

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Cloudflare Workers](https://workers.cloudflare.com/) - Edge computing
- [Xray-core](https://github.com/XTLS/Xray-core) - Protocol implementations
- [3x-ui](https://github.com/MHSanaei/3x-ui) - Inspiration
- [Vazirmatn Font](https://github.com/rastikerdar/vazirmatn) - Persian font

---

## 📞 Support

- **Telegram**: [@MakeVaslim](https://t.me/MakeVaslim)
- **Issues**: [GitHub Issues](https://github.com/MakeVaslim/Panel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/MakeVaslim/Panel/discussions)

---

<div align="center">
  <strong>Made with ❤️ by the MaKeVaslim Team</strong>
  <br>
  <sub>Version 1.0.0 | Built with FastAPI + Cloudflare Workers</sub>
</div>