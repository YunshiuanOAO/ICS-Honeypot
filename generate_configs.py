"""
Generate 3 client config files for local multi-node testing.
Reads streetlight project files and produces deployment configs
with env modifications for Docker Desktop local networking.
"""
import json
import os

STREETLIGHT_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "streetlight"
)
CLIENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client")


def read_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def read_project_files(component_dir, file_list):
    files = []
    for rel_path in file_list:
        abs_path = os.path.join(component_dir, rel_path)
        files.append({"path": rel_path, "content": read_file(abs_path)})
    return files


def generate_mosquitto_config():
    files = read_project_files(os.path.join(STREETLIGHT_ROOT, "mosquitto"), [
        "docker-compose.yml",
        "mosquitto.conf",
    ])
    return {
        "node_id": "node_mosquitto",
        "name": "Mosquitto MQTT Broker",
        "server_url": "http://localhost:8000",
        "deployments": [{
            "id": "streetlight-mosquitto",
            "name": "Mosquitto Broker",
            "template": "mqtt",
            "enabled": True,
            "source_dir": "mosquitto",
            "files": files,
            "proxy": {
                "enabled": True,
                "protocol": "mqtt",
                "listen_port": 1883,
            },
        }],
    }


def generate_subscriber_config():
    base = os.path.join(STREETLIGHT_ROOT, "subscriber")
    files = read_project_files(base, [
        "docker-compose.yml",
        "subscriber.Dockerfile",
        "app.py",
        "streetlight_data.json",
        "templates/index.html",
        "templates/login.html",
    ])
    # Modified subscriber.env for local Docker networking
    files.append({
        "path": "subscriber.env",
        "content": (
            "BROKER_HOST=host.docker.internal\n"
            "BROKER_SUB_PORT=1883\n"
            "BROKER_PUB_PORT=1883\n"
            "ADMIN_USER=admin\n"
            "ADMIN_PASS=admin\n"
            "SECRET_KEY=c51d5bcbf589ae74eb0ad42b101d69b8caadd22d8f231eb86fc2a3be0c11f54c\n"
        ),
    })
    return {
        "node_id": "node_subscriber",
        "name": "Streetlight Subscriber Web UI",
        "server_url": "http://localhost:8000",
        "deployments": [{
            "id": "streetlight-subscriber",
            "name": "Subscriber Web UI",
            "template": "http",
            "enabled": True,
            "source_dir": "subscriber",
            "files": files,
            "proxy": {
                "enabled": True,
                "protocol": "http",
                "listen_port": 5000,
            },
        }],
    }


def generate_gateway_config():
    base = os.path.join(STREETLIGHT_ROOT, "gateway")
    files = read_project_files(base, [
        "docker-compose.yml",
        "Dockerfile",
        "gateway.py",
        "streetlight_data.json",
    ])
    # Modified gateway.env for local Docker networking
    files.append({
        "path": "gateway.env",
        "content": (
            "BROKER_HOST=host.docker.internal\n"
            "BROKER_PORT=1883\n"
        ),
    })
    return {
        "node_id": "node_gateway",
        "name": "Streetlight Gateway",
        "server_url": "http://localhost:8000",
        "deployments": [{
            "id": "streetlight-gateway",
            "name": "Gateway Simulator",
            "template": "custom",
            "enabled": True,
            "source_dir": "gateway",
            "files": files,
        }],
    }


def main():
    configs = [
        ("client_config_mosquitto.json", generate_mosquitto_config),
        ("client_config_subscriber.json", generate_subscriber_config),
        ("client_config_gateway.json", generate_gateway_config),
    ]
    for filename, gen_fn in configs:
        config = gen_fn()
        out_path = os.path.join(CLIENT_DIR, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print(f"Generated {out_path}")
        print(f"  node_id: {config['node_id']}, deployments: {len(config['deployments'])}")


if __name__ == "__main__":
    main()
