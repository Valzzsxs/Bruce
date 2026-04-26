import re

content = open("bw16_firmware/BW16-Tools.ino").read()

content = content.replace("struct WiFiScanResult {", "typedef struct {\n  String ssid;\n  String bssid_str;\n  uint8_t bssid[6];\n  short rssi;\n  uint8_t channel;\n  int security;\n} WiFiScanResult;")
if "typedef struct {\n  String ssid;\n  String bssid_str;\n  uint8_t bssid[6];\n  short rssi;\n  uint8_t channel;\n  int security;\n} WiFiScanResult;" not in content:
    content = "#include <vector>\n" + content
    # add definition
    content = content.replace("std::vector<WiFiScanResult> scan_results;", "typedef struct {\n  String ssid;\n  String bssid_str;\n  uint8_t bssid[6];\n  short rssi;\n  uint8_t channel;\n  int security;\n} WiFiScanResult;\n\nstd::vector<WiFiScanResult> scan_results;")

with open("bw16_firmware/BW16-Tools.ino", "w") as f:
    f.write(content)
