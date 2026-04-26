import re

content = open("bw16_firmware/BW16-Tools.ino").read()

content = content.replace("U8G2_FOR_ADAFRUIT_GFX u8g2_for_adafruit_gfx;", "")
content = content.replace("Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);", "")
content = content.replace("u8g2_for_adafruit_gfx", "//")
content = content.replace("display.", "//")
content = content.replace("display(", "//")

with open("bw16_firmware/BW16-Tools.ino", "w") as f:
    f.write(content)
