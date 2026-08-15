FROM ghcr.nju.edu.cn/xiaomi/miloco-backend:v0.1.2

# SSL patch for HA ingress (supervisor proxies plain HTTP)
COPY main.py /app/miloco_server/main.py

# Frontend: официальный образ НЕ содержит собранный web_ui (static пуст → CSS/JS 404).
# Собран локально из XiaoMi/xiaomi-miloco@v0.1.2 web_ui (npm run build) и вшит в static.
COPY web_ui_dist/ /app/miloco_server/static/
