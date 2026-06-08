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

建立 `server/.env`：

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

建立 `client/.env`：

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
source .venv/bin/activate
python3 client/main.py
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
