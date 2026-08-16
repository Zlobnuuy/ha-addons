FROM ghcr.nju.edu.cn/xiaomi/miloco-backend:v0.1.2

# SSL patch for HA ingress (supervisor proxies plain HTTP)
COPY main.py /app/miloco_server/main.py

# Multi-segment LAN scan patch (extra_subnets via MILOCO_LAN_SUBNETS)
COPY miot_kit_patch/miot/lan.py /app/miot_kit/miot/lan.py
COPY miot_kit_patch/miot/client.py /app/miot_kit/miot/client.py

# Frontend: официальный образ НЕ содержит собранный web_ui (static пуст → CSS/JS 404).
# Собран локально из XiaoMi/xiaomi-miloco@v0.1.2 web_ui (npm run build) и вшит в static.
COPY web_ui_dist/ /app/miloco_server/static/
