# AI in Telecom

This repo is for my capstone project at the Norfolk State University.

'''docker exec -it ai-in-telecom-traffic_gen-1 pip install scapy -q'''

docker cp ./traffic_generator.py ai-in-telecom-traffic_gen-1:/traffic_generator.py

docker exec -it ai-in-telecom-traffic_gen-1 python /traffic_generator.py

docker exec -it ai-in-telecom-snort-1 tail -f /var/log/suricata/fast.log

docker exec -it ai-in-telecom-zeek-1 tail -f /var/log/zeek/conn.log