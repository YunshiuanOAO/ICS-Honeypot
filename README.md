<p align="right">
  <strong>繁體中文</strong> | <a href="./README.en.md">English</a>
</p>

# 分散式 ICS Honeypot 系統

<p align="center">
  <img src="./assets/distributed-honeypot-logo-white.png" alt="Distributed ICS Honeypot Logo" width="260">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-Server-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-Honeypot-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/PostgreSQL-Database-4169E1?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/SQLite-Agent_Buffer-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/MQTT-Protocol-660066?style=for-the-badge&logo=eclipsemosquitto&logoColor=white" alt="MQTT">
  <img src="https://img.shields.io/badge/Elasticsearch-Logs-005571?style=for-the-badge&logo=elasticsearch&logoColor=white" alt="Elasticsearch">
  <img src="https://img.shields.io/badge/Kibana-Dashboard-E8478B?style=for-the-badge&logo=kibana&logoColor=white" alt="Kibana">
  <img src="https://img.shields.io/badge/Filebeat-Collector-005571?style=for-the-badge&logo=elastic&logoColor=white" alt="Filebeat">
  <img src="https://img.shields.io/badge/ElastAlert-Alerting-FF6F00?style=for-the-badge" alt="ElastAlert">
</p>

## Demo 影片

<p align="center">
  <a href="https://youtu.be/dVBAW2rm6SY">
    <img src="https://img.youtube.com/vi/dVBAW2rm6SY/maxresdefault.jpg" alt="ICS Honeypot Demo Video" width="720">
  </a>
</p>

<p align="center">
  <a href="https://youtu.be/dVBAW2rm6SY">觀看 Demo 影片</a>
</p>

## 簡介

本專案是一套以 Python 建置的分散式 ICS Honeypot 系統，用於模擬工控設備、誘捕攻擊流量並進行集中分析。系統採用 Server 與 Honeypot Agent 分離式架構，Server 負責管理蜜罐節點、部署設定、攻擊日誌接收與儀表板展示；Agent 可部署在不同主機或網路環境中，透過 Docker 執行 MQTT、HTTP、TCP Socket、模擬 PLC 或自製 HMI 等服務。

蜜罐服務前方會透過 Proxy 攔截、轉送並記錄攻擊流量，Agent 會先將資料暫存於本地 SQLite，再定時回傳至 Server。Server 端使用 PostgreSQL 儲存攻擊日誌，並可搭配 Filebeat、Elasticsearch、Kibana 與 ElastAlert 建立日誌分析、視覺化與告警機制。多個蜜罐節點之間也可互相連動，形成更接近真實工控場域的蜜網環境。

## 系統架構

![architecture](./assets/arch.png)

```text
Attacker
   |
   v
Honeypot Agent Node
   |-- Proxy Layer: MQTT / HTTP / TCP / Modbus
   |-- Docker Honeypot Services: HMI / PLC / Streetlight Simulator
   |-- Local Buffer: SQLite
   |
   |  heartbeat + logs + status
   v
Central Server
   |-- FastAPI Dashboard
   |-- Agent Management
   |-- Deployment Config
   |-- PostgreSQL
   |
   v
Filebeat -> Elasticsearch -> Kibana -> ElastAlert
```

### 主要元件

| 元件 | 說明 |
| --- | --- |
| Server | FastAPI 中央控制端，提供 Dashboard、Agent 管理、部署設定、日誌接收與查詢功能。 |
| Honeypot Agent | 部署於各蜜罐節點，接收 Server 設定，啟動 Docker 服務並回傳狀態與攻擊日誌。 |
| Proxy Layer | 攔截並轉送 MQTT、HTTP、TCP、Modbus 等協定流量，產生結構化攻擊事件。 |
| Docker Services | 實際執行蜜罐服務，可部署模擬 PLC、HMI、路燈控制服務或自訂服務。 |
| PostgreSQL / SQLite | Server 使用 PostgreSQL 儲存日誌；Agent 使用 SQLite 作為本地暫存緩衝。 |
| ELK / ElastAlert | 使用 Filebeat、Elasticsearch、Kibana 與 ElastAlert 進行日誌分析、視覺化與告警。 |

## 功能特色

- 分散式架構，Server 與 Honeypot Agent 可部署於不同主機。
- 支援多蜜罐節點互動，形成蜜網環境。
- 可透過 Docker 快速部署自製 HMI、模擬 PLC、MQTT、HTTP、TCP Socket 等服務。
- 使用 Proxy 攔截、轉送並記錄攻擊流量。
- 支援 PostgreSQL、SQLite 與 JSON 日誌輸出。
- 可整合 Filebeat、Elasticsearch、Kibana 與 ElastAlert 進行分析與告警。
- 提供 Web Dashboard 管理 Agent、部署蜜罐套件與查看攻擊資料。

## API 存取能力

系統主要資料與管理功能皆由 FastAPI 提供。Web 管理 API 需先登入取得 session cookie；Agent 與 ElastAlert 上傳類 API 則需在 HTTP header 帶入 `X-Api-Key: <API_KEY>`。

### 認證與頁面端點

| Method | Endpoint | 驗證 | 功能 |
| --- | --- | --- | --- |
| `GET` | `/login` | Public | 顯示 Web Dashboard 登入頁。 |
| `POST` | `/login` | Public | 使用 `ADMIN_USERNAME` / `ADMIN_PASSWORD` 登入並建立 session。 |
| `POST` | `/logout` | Session | 清除 session 並登出。 |
| `GET` | `/` | Session | 顯示主 Dashboard 頁面。 |
| `GET` | `/config/{node_id}` | Session | 顯示指定 Agent 的部署設定頁。 |

### Agent 同步與資料上傳

| Method | Endpoint | 驗證 | 功能 |
| --- | --- | --- | --- |
| `POST` | `/api/heartbeat` | API Key | Agent 回報 `node_id`、IP、名稱、目前設定與部署狀態；Server 會自動註冊新 Agent，並回傳 `start` / `stop` 指令。 |
| `GET` | `/api/config/{node_id}` | API Key 或 Session | 取得指定 Agent 的部署設定、節點名稱與 whitelist，Agent 會用此端點同步最新設定。 |
| `POST` | `/api/logs` | API Key | Agent 批次上傳攻擊日誌，body 格式為 `{ "node_id": "...", "logs": [...] }`。 |
| `POST` | `/api/whitelist_logs` | API Key | Agent 批次上傳白名單流量紀錄；此類資料不會進入攻擊流量分析。 |
| `POST` | `/api/alerts/ingest` | API Key | 接收 ElastAlert 或外部偵測系統送入的告警，必要欄位為 `signature` 與 `attacker_ip`。 |

### Agent 管理與設定

| Method | Endpoint | 驗證 | 功能 |
| --- | --- | --- | --- |
| `GET` | `/api/agents` | Session | 查詢所有 Agent 的狀態、IP、名稱、最後心跳與設定摘要。 |
| `POST` | `/api/agents` | Session | 手動新增 Agent，表單欄位包含 `node_id`、`name`、`ip`、`config_json`。 |
| `POST` | `/api/agents/{node_id}/toggle` | Session | 啟用或停用指定 Agent，停用後 Agent 會收到停止指令。 |
| `DELETE` | `/api/agents/{node_id}` | Session | 刪除指定 Agent 與其設定。 |
| `POST` | `/api/agents/{node_id}/reset` | Session | 重設指定 Agent，讓 Server 忘記此節點並允許它重新註冊。 |
| `POST` | `/api/update_agent_config` | Session | 更新 Agent 的部署設定、名稱或 `node_id`；會檢查 proxy listen/backend port 是否衝突。 |
| `GET` | `/api/whitelist?node_id={node_id}` | Session | 查詢指定 Agent 的 whitelist 設定。 |
| `PUT` | `/api/whitelist` | Session | 更新指定 Agent 的 whitelist，下一次 Agent 拉取 config 時生效。 |
| `GET` | `/api/whitelist_logs?limit=100&node_id={node_id}` | Session | 查詢白名單命中紀錄，可依 Agent 過濾。 |

### 攻擊資料、分析與告警

| Method | Endpoint | 驗證 | 功能 |
| --- | --- | --- | --- |
| `GET` | `/api/recent_logs?limit=50` | Session | 查詢最近攻擊日誌；`limit=all` 時最多回傳 500 筆。 |
| `GET` | `/api/dashboard_stats` | Session | 查詢 Dashboard 統計資料，例如 Agent 數量、攻擊數、協定分布等。 |
| `GET` | `/api/ip_analysis` | Session | 依攻擊者 IP 分組統計攻擊量、協定、觸及節點、告警數與最高嚴重度。支援 `hours`、`from_ts`、`to_ts`、`page`、`page_size`、`search`、`hide_agent_ips`、`hide_private_ips`。 |
| `GET` | `/api/ip_details/{ip}?limit=200` | Session | 查詢單一攻擊者 IP 的封包紀錄與相關告警。 |
| `GET` | `/api/alerts?limit=200&ip={ip}` | Session | 查詢告警清單，可依攻擊者 IP 過濾。 |
| `POST` | `/api/admin/sync_elk` | Session | 手動將 Server 日誌匯出給 Filebeat / ELK 使用。 |

### Profile、Package 與 Service Template

| Method | Endpoint | 驗證 | 功能 |
| --- | --- | --- | --- |
| `GET` | `/api/profiles` | Session | 查詢可用的模擬設備 profile，例如 Modbus profile。 |
| `GET` | `/api/profiles/{name}` | Session | 取得指定 profile 的完整 JSON 內容。 |
| `POST` | `/api/import_package_zip` | Session | 上傳自訂 Docker package zip，解壓後存入 package library，並回傳可部署檔案列表。 |
| `POST` | `/api/import_package_json` | Session | 上傳 JSON 設定並指定 `protocol`，Server 會自動產生可部署的 honeypot package。 |
| `GET` | `/api/package_library` | Session | 查詢已匯入的 package library 清單。 |
| `GET` | `/api/package_library/{package_id}` | Session | 取得指定 package 的 metadata 與檔案內容。 |
| `DELETE` | `/api/package_library/{package_id}` | Session | 刪除指定 package。 |
| `GET` | `/api/service_templates` | Session | 查詢可用的服務模板清單。 |
| `POST` | `/api/service_templates/{template_id}/instantiate` | Session | 將指定服務模板展開成多個 deployments，匯入 Agent config 頁面。 |

### 輔助 API

| Method | Endpoint | 驗證 | 功能 |
| --- | --- | --- | --- |
| `GET` | `/api/server_info` | Public | 回傳 Server public URL 與 Kibana URL，供前端顯示與連結使用。 |
| `GET` | `/api/geoip/{ip}` | Public | 查詢 IP 地理位置，Server 端會快取結果並處理 private IP。 |

靜態頁面、Logo、CSS、JavaScript 與 README 圖片屬於前端或文件資源，不是資料 API。

## 如何安裝

### 環境需求

- Python 3.8 以上
- Docker
- Docker Compose plugin
- Linux / Ubuntu 環境建議

### 1. 下載專案

```bash
git clone <repo-url>
cd ICS-Honeypot
```

### 2. 建立 Python 虛擬環境

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. 設定 Server 環境變數

複製範例檔並建立 `server/.env`：

```bash
cp server/.env.example server/.env
```

接著編輯 `server/.env`：

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me
API_KEY=shared-agent-key
SESSION_SECRET=change-this-session-secret

POSTGRES_DB=honeypot
POSTGRES_USER=honeypot
POSTGRES_PASSWORD=honeypot_change_me
POSTGRES_PORT=5432
DATABASE_URL=postgresql://honeypot:honeypot_change_me@127.0.0.1:5432/honeypot
```

`API_KEY` 必須與 Client Agent 的設定一致，Agent 才能向 Server 取得部署設定並回傳日誌。

### 4. 設定 Client Agent 環境變數

複製範例檔並建立 `client/.env`：

```bash
cp client/.env.example client/.env
```

接著確認 `client/.env` 內的 `API_KEY` 與 Server 相同：

```env
API_KEY=shared-agent-key
```

確認 `client/client_config.json` 內的 `node_id` 與 `server_url`：

```json
{
  "node_id": "node_01",
  "server_url": "http://127.0.0.1:8000",
  "deployments": []
}
```

若 Agent 與 Server 位於不同主機，請將 `server_url` 改成 Server 的實際 IP 或網域。

### 5. 啟動 Server 與分析服務

```bash
./server/start_services.sh
```

啟動後可開啟：

- Dashboard: <http://127.0.0.1:8000>
- Kibana: <http://127.0.0.1:5601>

若只想啟動 FastAPI Server，不啟動 ELK：

```bash
cd server
python3 main.py
```

### 6. 啟動 Honeypot Agent

開啟另一個 terminal：

```bash
cd client
chmod +x start_agent.sh
./start_agent.sh -d
```

`start_agent.sh` 會檢查 Docker、Python、uv 與相依套件，並使用專案根目錄的 `.venv` 啟動 Agent。若需要使用 443 等低於 1024 的連接埠，或目前使用者沒有 Docker 權限，可改用：

```bash
sudo ./start_agent.sh -d
```

常用管理指令：

```bash
./start_agent.sh status
./start_agent.sh logs
./start_agent.sh stop
```

Agent 啟動後會向 Server 註冊並等待部署設定。可在 Dashboard 中新增或修改該 Agent 的蜜罐服務。

### 7. 部署蜜罐服務

進入 Dashboard 後，可針對 Agent 新增部署項目：

- 使用內建模板產生 Modbus 或 MQTT 模擬服務。
- 上傳自訂 Docker package。
- 編輯 `Dockerfile`、`docker-compose.yml`、程式碼與設定檔。
- 設定 Proxy 監聽埠與後端服務埠。

部署完成後，Agent 會建立 Docker container，並開始攔截與記錄攻擊流量。

## 專案結構

```text
ICS-Honeypot/
├── assets/                  # Logo 與架構圖
├── client/                  # Honeypot Agent
│   ├── main.py              # Agent 入口
│   ├── agent.py             # 與 Server 同步、部署與日誌回傳
│   ├── docker_manager.py    # Docker / Docker Compose 部署管理
│   ├── log_collector.py     # 日誌收集
│   └── proxy/               # MQTT / HTTP / TCP / Modbus Proxy
├── server/                  # 中央 Server
│   ├── main.py              # FastAPI app 與 Dashboard
│   ├── database.py          # SQLite fallback
│   ├── postgres_database.py # PostgreSQL 資料庫操作
│   ├── package_generators.py
│   ├── static/
│   ├── templates/
│   └── elk/                 # PostgreSQL / ELK / ElastAlert docker-compose
├── tools/                   # 測試工具
├── requirements.txt
└── README.md
```

## License

[MIT](LICENSE)
