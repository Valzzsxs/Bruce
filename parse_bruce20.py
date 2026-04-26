import re

content = open("bw16_firmware/BW16-Tools.ino").read()

content = content.replace("struct WiFiScanResult;", "") # Remove any forward declarations
content = content.replace("struct rtw_result_t;", "typedef int rtw_result_t;")

with open("bw16_firmware/BW16-Tools.ino", "w") as f:
    f.write(content)
