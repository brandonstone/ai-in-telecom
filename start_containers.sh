#!/bin/bash
set -e

echo "Starting IDS lab environment..."
docker compose up -d

echo "Waiting for containers to initialize..."
sleep 5

echo "Verifying containers are running..."
docker compose ps

echo "Installing Scapy in traffic generator..."
docker exec -it ai-in-telecom-traffic_gen-1 pip install scapy -q

echo "Copying traffic generator script..."
docker cp ./traffic_generator.py ai-in-telecom-traffic_gen-1:/traffic_generator.py

echo "Starting traffic generation..."
echo "Monitor Suricata alerts in a new terminal:"
echo "  docker exec -it ai-in-telecom-snort-1 tail -f /var/log/suricata/fast.log"
echo ""
echo "Monitor Zeek notices in a new terminal:"
echo "  docker exec -it ai-in-telecom-zeek-1 tail -f /var/log/zeek/notice.log"
echo ""

read -p "Open two monitoring terminals, then press Enter to start traffic..."
docker exec -it ai-in-telecom-traffic_gen-1 python /traffic_generator.py

