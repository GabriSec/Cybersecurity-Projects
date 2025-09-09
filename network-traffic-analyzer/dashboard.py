import streamlit as st
import pandas as pd
import numpy as np
import time
import os
import geoip2.database

CSV_PATH = "data/packets.csv"
GEO_DB_PATH = "data/your_GeoLite2-City.mmdb"

st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
st.title("🔍 Network Traffic Analyzer - Live SOC Dashboard")


def protocol_name(proto_num):
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, str(proto_num))


geo_reader = geoip2.database.Reader(GEO_DB_PATH)


def ip_to_location(ip):
    try:
        response = geo_reader.city(ip)
        return response.location.latitude, response.location.longitude, response.country.name
    except:
        return None, None, None


st.sidebar.header("Options")
refresh_rate = st.sidebar.slider("Refresh rate (seconds)", 1, 5, 1)
top_count = st.sidebar.slider("Top talkers/destinations", 1, 10, 5)
packet_alert_size = st.sidebar.number_input("Alert packet size threshold", min_value=100, max_value=5000, value=1000)

alert_placeholder = st.empty()

tab1, tab2, tab3, tab4 = st.tabs(["📦 Packets", "📊 Analytics", "🚨 Alerts", "🌍 Geo Map"])

pps_history = []

while True:
    if os.path.exists(CSV_PATH):
        df = pd.read_csv(CSV_PATH)
        if not df.empty:

            df["protocol_name"] = df["protocol"].apply(protocol_name)

            df["alert"] = df["length"].apply(lambda x: "🔴" if x > packet_alert_size else "")

            timestamps = df["timestamp"].tolist()[-200:]
            if len(timestamps) > 1:
                times = np.diff(timestamps)
                pps = np.mean(1 / times) if np.any(times) else 0
            else:
                pps = 0
            pps_history.append(pps)

            if any(df["length"] > packet_alert_size):
                alert_placeholder.error(f"🚨 Large packet detected (> {packet_alert_size} bytes)!")
            if pps > 200:  # Example PPS threshold
                alert_placeholder.warning(f"⚠️ High PPS detected: {pps:.2f}")


            with tab1:
                st.subheader("Latest Packets")
                st.dataframe(df.tail(50))

            with tab2:
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("Top Source IPs")
                    st.bar_chart(df["src_ip"].value_counts().head(top_count))
                with col2:
                    st.subheader("Top Destination IPs")
                    st.bar_chart(df["dst_ip"].value_counts().head(top_count))

                st.subheader("Protocol Distribution")
                st.bar_chart(df["protocol_name"].value_counts())

                st.subheader("Packets Per Second Trend")
                st.line_chart(pps_history[-50:])

            with tab3:
                st.subheader("Alert Events")
                alerts = df[df["alert"] != ""]
                if not alerts.empty:
                    st.dataframe(alerts.tail(20))
                else:
                    st.success("✅ No alerts triggered")

            with tab4:
                st.subheader("🌍 Geolocation of External IPs")


                unique_ips = pd.concat([df["src_ip"], df["dst_ip"]]).unique()
                geo_data = []
                for ip in unique_ips:
                    lat, lon, country = ip_to_location(ip)
                    if lat and lon:
                        geo_data.append({"lat": lat, "lon": lon, "ip": ip, "country": country})

                if geo_data:
                    geo_df = pd.DataFrame(geo_data)
                    st.map(geo_df[["lat", "lon"]])
                    st.dataframe(geo_df)
                else:
                    st.info("No external IPs resolved yet.")

    time.sleep(refresh_rate)
