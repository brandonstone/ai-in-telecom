# AI in Telecom

This repo is for my capstone project at the Norfolk State University.

## Usage

Once repo is cloned and docker has been installed, please use the following steps to start up and run the python programs. Some instructions may only work for UNIX-based systems.

### Start Up

```
docker compose up -d

# begin traffic for ids systems to alert
docker exec -it ai-in-telecom-traffic_gen-1 pip install scapy -q
docker cp ./traffic_generator.py ai-in-telecom-traffic_gen-1:/traffic_generator.py
docker exec -it ai-in-telecom-traffic_gen-1 python /traffic_generator.py

# watch logs (optional)
docker exec -it ai-in-telecom-snort-1 tail -f /var/log/suricata/fast.log
docker exec -it ai-in-telecom-zeek-1 tail -f /var/log/zeek/notice.log

```

### Tool Comparison

These steps will allow you to compare the log files of zeek and snort into 4 distint graphs.

```
python tool_comparison.py
open id_comparison_results.png
```

### Economic Analysis

These steps will allow you to based on information from IBM.

```
cd econ-analysis
python economic-model.py
open economic simulation_results.png
```