# PLC Simulation Scenarios

此資料夾包含預定義的工業場景配置檔案。

## 場景列表

### 1. water_treatment.json - 水處理廠
模擬完整的淨水處理流程，包含：
- 進水/出水流量控制
- pH 值、濁度、餘氯監測
- 儲水槽液位管理
- 泵浦和加藥系統控制

### 2. manufacturing.json - 製造生產線
模擬自動化組裝產線，包含：
- 馬達轉速和電流監測
- 軸承溫度和振動監測
- 生產計數和品質統計
- 輸送帶和機械手臂控制

### 3. hvac.json - 空調系統
模擬大型建築的中央空調系統，包含：
- 室內外溫濕度監測
- 送風/回風溫度控制
- CO2 濃度監測
- 風機和壓縮機控制

### 4. power_substation.json - 電力變電站
模擬配電變電站運行，包含：
- 電壓、電流、功率監測
- 功率因數和頻率監測
- 變壓器油溫和繞組溫度
- 斷路器和保護設備狀態

## 場景檔案格式

```json
{
    "name": "場景名稱",
    "description": "場景說明",
    "author": "作者",
    "version": "版本號",
    "modbus": {
        "registers": [
            {
                "addr": 0,
                "name": "register_name",
                "wave": "sine|random_walk|sawtooth|fixed|counter",
                "description": "說明",
                ...波形參數...
            }
        ],
        "coils": [...],
        "input_registers": [...],
        "discrete_inputs": [...]
    },
    "s7": {
        "db": {
            "1": {
                "0": {
                    "type": "INT|REAL|BYTE|DINT",
                    "wave": "波形類型",
                    "name": "變數名稱",
                    ...波形參數...
                }
            }
        },
        "m": {...},
        "i": {...},
        "q": {...}
    }
}
```

## 波形類型及參數

### fixed (固定值)
- `value`: 固定數值或布林值

### sine (正弦波)
- `min`: 最小值
- `max`: 最大值
- `period`: 週期（秒）

### random_walk (隨機漫步)
- `min`: 最小值
- `max`: 最大值
- `step`: 每次變化的步長
- `initial`: 初始值（可選）

### sawtooth (鋸齒波)
- `min`: 最小值
- `max`: 最大值
- `period`: 週期（秒）

### counter (計數器)
- `max`: 最大值（到達後歸零）

### square (方波 - 用於 Coils)
- `on`: ON 狀態持續時間（秒）
- `off`: OFF 狀態持續時間（秒）

### random (隨機觸發 - 用於 Coils)
- `probability`: 觸發機率（0-1）

### noise (帶雜訊 - S7 REAL)
- `base`: 基礎值
- `amplitude`: 雜訊幅度

### status_flags (狀態標誌 - S7 BYTE)
- 自動生成運行狀態位元組

## 如何新增場景

1. 複製現有場景檔案
2. 修改 `name`, `description`, `author`
3. 根據需求調整 registers/coils 配置
4. 儲存為 `場景名稱.json`
5. 場景會自動被系統識別和載入

## 範例：新增一個簡單的水泵站場景

```json
{
    "name": "Pump Station",
    "description": "簡單的水泵站控制",
    "author": "Your Name",
    "version": "1.0",
    "modbus": {
        "registers": [
            {"addr": 0, "name": "flow_rate", "wave": "random_walk", "min": 50, "max": 200, "step": 10},
            {"addr": 1, "name": "pressure", "wave": "sine", "min": 100, "max": 300, "period": 600}
        ],
        "coils": [
            {"addr": 0, "name": "pump_1", "wave": "fixed", "value": true},
            {"addr": 1, "name": "pump_2", "wave": "square", "on": 600, "off": 300}
        ]
    },
    "s7": {
        "db": {
            "1": {
                "0": {"type": "INT", "wave": "random_walk", "min": 50, "max": 200, "step": 10, "name": "flow_rate"}
            }
        }
    }
}
```

儲存後，在配置中使用：
```json
{
    "simulation": {
        "scenario": "pump_station"
    }
}
```

系統會自動載入 `scenarios/pump_station.json`！

