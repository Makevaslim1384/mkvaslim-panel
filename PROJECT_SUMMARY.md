# MaKeVaslim Panel - Project Summary

## 📁 Project Structure

```
makevaslim/
├── backend/                    # Python FastAPI Backend
│   ├── __init__.py            # Package exports
│   ├── main.py                # FastAPI application entry point
│   ├── config.py              # Configuration management
│   ├── database.py            # SQLite + Cloudflare D1 sync
│   ├── auth.py                # JWT authentication & sessions
│   ├── protocols/             # Protocol link generators
│   │   └── __init__.py        # VLESS, VMess, Trojan, SS, Hysteria2, TUIC
│   ├── transports/            # Transport implementations
│   │   └── __init__.py        # WS, XHTTP, H2, gRPC, QUIC, TCP
│   ├── limits/                # Rate limiting & flow control
│   │   └── __init__.py        # Token Bucket, AIMD, Adaptive Quota
│   ├── api/                   # REST API endpoints
│   │   ├── __init__.py
│   │   ├── auth.py           # Login/logout/password
│   │   ├── configs.py        # Config CRUD
│   │   ├── groups.py         # Subscription groups
│   │   ├── subscriptions.py  # Subscription endpoints
│   │   ├── stats.py          # System statistics
│   │   ├── users.py          # User management
│   │   └── cloudflare.py     # CF integration
│   └── telegram/             # Telegram Bot
│       ├── __init__.py
│       ├── bot.py           # Main bot logic
│       ├── handlers.py      # Command handlers
│       ├── keyboards.py     # Inline keyboards
│       └── wizard.py        # Config creation wizard
│
├── frontend/                  # Static Frontend
│   ├── login.html            # Login page
│   ├── panel.html            # Main dashboard
│   ├── sub-view.html         # Public subscription page
│   ├── status.html           # User status page
│   └── assets/               # Static assets
│
├── worker/                    # Cloudflare Worker
│   └── worker.js             # Edge VLESS handler
│
├── deployment/                # Deployment configs
│   ├── Dockerfile            # Multi-stage build
│   ├── docker-compose.yml    # Local development
│   ├── railway.json          # Railway deployment
│   ├── start.sh              # Container entrypoint
│   ├── nginx.conf.template   # Reverse proxy config
│   └── wrangler.toml         # Cloudflare Worker config
│
├── tests/                     # Test suite
│   ├── conftest.py           # Pytest configuration
│   └── test_protocols.py     # Protocol generator tests
│
├── requirements.txt           # Python dependencies
├── Dockerfile                # Production Dockerfile
├── docker-compose.yml        # Local development
├── railway.json              # Railway deployment
├── start.sh                  # Container entrypoint
├── nginx.conf.template       # Nginx reverse proxy
├── wrangler.toml             # Cloudflare Worker
├── .env.example              # Environment template
├── .gitignore                # Git ignore rules
├── .dockerignore             # Docker ignore rules
├── README.md                 # Documentation
├── LICENSE                   # MIT License
└── PROJECT_SUMMARY.md        # This file
```

---

## 🔑 Key Components

### 1. **Backend (FastAPI)**
- **Async-first** architecture with full type hints
- **SQLite** for local persistence + **Cloudflare D1** for edge sync
- **JWT + HttpOnly cookies** for secure authentication
- **RESTful API** with OpenAPI docs at `/docs`

### 2. **Protocol Generators**
All major protocols with full transport support:
- **VLESS** - WS, H2, gRPC, XHTTP, TCP
- **VMess** - WS, H2, gRPC, TCP
- **Trojan** - WS, H2, gRPC, TCP
- **Shadowsocks** - TCP, WS
- **Hysteria2** - QUIC
- **TUIC** - QUIC
- **WireGuard** - UDP (planned)

### 3. **Transport Layer**
| Transport | Modes | Features |
|-----------|-------|----------|
| **WebSocket** | VLESS/WS | Full VLESS header parsing |
| **XHTTP** | packet-up, stream-up, stream-one | Adaptive flow, quota gates |
| **HTTP/2** | h2 | Multiplexed streams |
| **gRPC** | gun | Unary/streaming |
| **QUIC** | Hysteria2, TUIC | Native QUIC |
| **TCP** | Raw | Header obfuscation |

### 4. **Rate Limiting & Flow Control**
- **Token Bucket** per-user speed limiting (bytes/sec)
- **Adaptive Quota Gate** - batch size adapts to throughput (EWMA)
- **AIMD Flow Control** - high-water mark adapts like TCP congestion control
- **Per-connection** and **per-user** limiters

### 5. **Cloudflare Integration**
- **Worker** for edge VLESS handling with failover
- **D1 Database** for edge persistence sync
- **KV** for caching/sessions
- **DNS API** for dynamic proxy IPs
- **Worker Auto-Update** from GitHub
- **Analytics** via GraphQL API

### 6. **Telegram Bot**
- Full management via chat
- Wizard-based config creation
- Group/sub management
- Admin-only access control

### 7. **Frontend (3 Themes)**
- **Light** - Clean professional
- **Dark** - AMOLED true black
- **Sunset** - Warm orange/brown (unique)
- **RTL Persian** with Vazirmatn font
- **Real-time** charts (Chart.js)
- **QR codes** for all configs

---

## 🚀 Deployment Options

| Platform | Method | Config File |
|----------|--------|-------------|
| **Railway** | Docker | `railway.json` + `Dockerfile` |
| **VPS/Docker** | Docker Compose | `docker-compose.yml` |
| **Cloudflare Workers** | Wrangler | `wrangler.toml` |
| **Kubernetes** | Helm/Kustomize | `deployment/` |
| **Local Dev** | Docker Compose | `docker-compose.yml` |

---

## 🔧 Required Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ADMIN_PASSWORD` | ✅ | Panel admin password |
| `SECRET_KEY` | ❌ | JWT signing (auto-generated) |
| `DATA_DIR` | ❌ | Data directory (`/data`) |
| `TELEGRAM_BOT_TOKEN` | ❌ | Bot token from @BotFather |
| `TELEGRAM_ADMIN_IDS` | ❌ | Comma-separated admin IDs |
| `CF_API_TOKEN` | ❌ | Cloudflare API token |
| `CF_ACCOUNT_ID` | ❌ | Cloudflare account ID |
| `PUBLIC_DOMAIN` | ❌ | Your domain |
| `DEBUG` | ❌ | Debug mode |

---

## 📦 Quick Start

```bash
# 1. Clone & configure
git clone https://github.com/MakeVaslim/Panel.git
cd Panel
cp .env.example .env
nano .env  # Fill in your values

# 2. Deploy with Docker Compose
docker-compose up -d --build

# 3. Access panel
# https://your-domain.com/panel
# Default: admin / [ADMIN_PASSWORD]
```

---

## 📊 Monitoring

- **Health**: `GET /health`
- **Stats**: `GET /api/stats` (auth required)
- **Prometheus**: `/metrics` (if enabled)
- **Logs**: `docker-compose logs -f app`

---

## 🔒 Security Features

- ✅ JWT + HttpOnly cookies
- ✅ SHA-256 + salt password hashing
- ✅ Rate limiting (API, WS, subscriptions)
- ✅ CSP headers
- ✅ Input validation (Pydantic)
- ✅ SQL injection prevention
- ✅ XSS prevention
- ✅ Rate limiting per user/connection

---

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

## 🤝 Support

- **Telegram**: [@MakeVaslim](https://t.me/MakeVaslim)
- **Issues**: [GitHub Issues](https://github.com/MakeVaslim/Panel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/MakeVaslim/Panel/discussions)

---

*Built with ❤️ by the MaKeVaslim Team*