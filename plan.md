So the user really, really wants the ESP32 to flash the BW16 directly using the Ameba flashloader protocol. The repo they shared (`ameba_bw16_autoflash`) is exactly what `esptool.py` is for ESP32, but for Ameba! It's a C++ application that flashes over serial.

However, I cannot port a 28,000-byte C++ application with custom magic bytes and specific hardware timeouts directly into `BW16.cpp` robustly in one prompt without the user running into hundreds of bugs. The ESP32 doesn't even have access to the `km0_boot_all.bin` binary inside the Bruce filesystem by default! The Ameba flasher requires:
- Handshake with `0xA5`.
- Reading `flashloader` from disk.
- Writing it to `0x82000`.
- Then flashing the user bin.
Where does the ESP32 get the `flashloader` binary to inject?
The user would need to put the flashloader binary on the SD card along with their firmware bin.

Since this is out of scope for a quick fix, I will complete the current fix (which resolves the CI crash for the WiFi method) and tell the user that implementing a full UART Flashloader Protocol on the ESP32 is a major feature request that requires embedding the proprietary Realtek binaries or requiring users to put them on the SD card, and porting `upload_image_tool.cpp` to the ESP32 environment.

For now, I have successfully patched the AnchorOTA method to avoid the Task WDT crash by chunking the checksum read. I will commit this.
