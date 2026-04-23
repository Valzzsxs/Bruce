import os

def patch_dependencies(*args, **kwargs):
    for root, dirs, files in os.walk(".pio/libdeps"):
        for file in files:
            if file.endswith(".cpp") or file.endswith(".h") or file.endswith(".c"):
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                needs_arduino_h = False
                if file.endswith(".cpp") or file.endswith(".h"):
                    if "#include <Arduino.h>" not in content:
                        if "Serial" in content or "delay(" in content or "String" in content or "byte" in content or "millis(" in content:
                            needs_arduino_h = True

                needs_algorithm = False
                if file.endswith("pn532_ble.cpp") and "#include <algorithm>" not in content:
                    needs_algorithm = True

                if "WireGuard-ESP32" in filepath and "extern \"C\"" in content and "#include <Arduino.h>" not in content:
                    content = "#include <Arduino.h>\n" + content
                    needs_arduino_h = False
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(content)
                    continue

                if "picojpeg.h" in filepath and "#include <Arduino.h>" in content:
                    content = content.replace("#include <Arduino.h>", "")
                    needs_arduino_h = False
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(content)
                    continue

                if "picojpeg.c" in filepath and "uint8 init(void)" in content:
                    content = content.replace("uint8 init(void)", "uint8 init_jpeg(void)")
                    content = content.replace("init()", "init_jpeg()")
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(content)
                    continue

                if needs_arduino_h or needs_algorithm:
                    with open(filepath, "w", encoding="utf-8") as f:
                        if needs_arduino_h:
                            f.write("#include <Arduino.h>\n")
                        if needs_algorithm:
                            f.write("#include <algorithm>\n")
                        f.write(content)

Import("env")
patch_dependencies()
