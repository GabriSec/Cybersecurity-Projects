🕵️‍♂️Network Traffic Analyzer – SOC Dashboard

A real-time network traffic analysis tool built with Python and Streamlit.
It captures live packets, logs them into a CSV file, and provides a SOC-style dashboard to monitor traffic patterns, top talkers, protocols, anomalies, and even geolocate external IPs on a world map.



FEATURES:

-Live Packet Capture

-Logs network packets (source IP, destination IP, protocol, size, timestamp) into a CSV file.

-SOC Dashboard (built with Streamlit)

-Latest packet table (live updates)

-Top source/destination IPs

-Protocol distribution (TCP/UDP/ICMP)

-Packets-per-second (PPS) trend line

-Alert system for large packets and high PPS spikes

-Real-Time Alerts

-Detects packets larger than a configurable threshold.

-Warns when PPS exceeds normal levels (possible DoS activity).

-Geolocation of External IPs

-Uses MaxMind’s GeoLite2 database.

-Displays external IPs on a world map.

-Provides country and coordinates for each IP.



INSTALLATION AND SETUP:

1. Clone the repo

git clone https://github.com/GabriSec/Cybersecurity-Projects/network-traffic-analyzer.git
cd network-traffic-analyzer


2. Create a virtual environment

python -m venv .venv
source .venv/bin/activate   # macOS/Linux
.venv\Scripts\activate      # Windows


3. Install dependencies

pip install -r requirements.txt


4. Download GeoLite2 Database (for geolocation)

Register a free account at https://dev.maxmind.com
Download GeoLite2-City.mmdb.
Place it inside the data/ folder:


USAGE:

1. Start packet capture (requires sudo/admin privileges)

sudo python traffic_analyzer.py

This will generate/update data/packets.csv.


2. Start the SOC dashboard

streamlit run dashboard.py

Open your browser at:
http://localhost:8501


PUT IT ON GOOD USE.


