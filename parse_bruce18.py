import re

content = open("bw16_firmware/BW16-Tools.ino").read()

content = content.replace("rtw_result_t scanResultHandler", "int scanResultHandler")
content = content.replace("std::vector", "std::vector") # Make sure it's valid std::vector

with open("bw16_firmware/BW16-Tools.ino", "w") as f:
    f.write(content)
