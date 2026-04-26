#include "BW16.h"
#include <core/display.h>
#include <globals.h>

BW16::BW16() {
    // Constructor
}

BW16::~BW16() {
    end();
}

void BW16::begin() {
    releasePins();
    // Use HardwareSerial(2) as defined in header
    _serial.begin(115200, SERIAL_8N1, bruceConfigPins.uart_bus.rx, bruceConfigPins.uart_bus.tx);

    // Check if pins are valid
    if (bruceConfigPins.uart_bus.rx == GPIO_NUM_NC || bruceConfigPins.uart_bus.tx == GPIO_NUM_NC) {
        log_e("BW16 UART pins not configured!");
        _connected = false;
        return;
    }

    _connected = true;
    _scanning = false;
    _scanResults.clear();
    _lastMessage = "";
    getStatus(); // Check connection
}

void BW16::end() {
    if (_connected) {
        _serial.end();
        restorePins();
        _connected = false;
    }
}

void BW16::loop() {
    if (!_connected) return;

    while (_serial.available()) {
        char c = _serial.read();
        if (c == '\n') {
            parseLine(_buffer);
            _buffer = "";
        } else {
            if (c != '\r') _buffer += c;
        }
    }
}

void BW16::sendCommand(String cmd) {
    if (!_connected) return;
    String fullCmd = "BRUCE:" + cmd;
    _serial.println(fullCmd);
    log_d("Sent: %s", fullCmd.c_str());
}

void BW16::scan(int timeMs) {
    _scanning = true;
    _scanResults.clear();
    sendCommand("SCAN," + String(timeMs));
}

void BW16::deauthStart(int index) {
    sendCommand("DEAUTH_START," + String(index));
}

void BW16::deauthStop(int index) {
    sendCommand("DEAUTH_STOP," + String(index));
}

void BW16::deauthStopAll() {
    sendCommand("DEAUTH_STOP_ALL");
}

void BW16::deauthAll() {
    sendCommand("DEAUTH_ALL");
}

void BW16::selectSSID(int index) {
    sendCommand("SELECT_SSID," + String(index));
}

void BW16::getAPList() {
    _scanResults.clear();
    sendCommand("GET_AP_LIST");
}

void BW16::getStatus() {
    sendCommand("GET_STATUS");
}

void BW16::authFlood(int index) {
    sendCommand("AUTH_FLOOD," + String(index));
}

void BW16::karmaAttack() {
    sendCommand("KARMA_START");
}

void BW16::setMAC(String mac) {
    sendCommand("SET_MAC," + mac);
}

void BW16::startIDS() {
    sendCommand("IDS_START");
}

void BW16::stopIDS() {
    sendCommand("IDS_STOP");
}

void BW16::hiddenDecloaker() {
    sendCommand("DECLOAK_START");
}

void BW16::bleSpam(String name) {
    sendCommand("BLE_SPAM," + name);
}

void BW16::bleScan() {
    sendCommand("BLE_SCAN");
}

// CRC16-CCITT for YMODEM
static uint16_t bw16_crc16(const uint8_t *data, uint16_t size) {
    uint16_t crc = 0;
    for (uint16_t i = 0; i < size; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (uint8_t j = 0; j < 8; ++j) {
            if (crc & 0x8000)
                crc = (crc << 1) ^ 0x1021;
            else
                crc <<= 1;
        }
    }
    return crc;
}

bool BW16::otaUpdate(File &file) {
    if (!file || file.isDirectory()) return false;

    // Send OTA_START to put the BW16 into OTA mode
    sendCommand("OTA_START");

    // Wait for the BW16 to reboot or enter OTA and start sending 'C'
    bool ready = false;
    unsigned long startWait = millis();
    while (millis() - startWait < 5000) {
        if (_serial.available()) {
            if (_serial.read() == 'C') {
                ready = true;
                break;
            }
        }
    }

    if (!ready) {
        log_e("BW16 did not respond with 'C' for YMODEM");
        return false;
    }

    // YMODEM Block 0 - Filename and size
    uint8_t block0[133] = {0};
    block0[0] = 0x01; // SOH
    block0[1] = 0x00; // Block 0
    block0[2] = 0xFF; // ~Block 0

    String filename = file.name();
    // In some FS, file.name() includes the leading slash. Remove it for YMODEM
    if (filename.startsWith("/")) {
        filename = filename.substring(1);
    }
    String fileSizeStr = String(file.size());

    int idx = 3;
    for (int i = 0; i < filename.length() && idx < 131; i++) {
        block0[idx++] = filename[i];
    }
    block0[idx++] = 0x00; // NULL separator
    for (int i = 0; i < fileSizeStr.length() && idx < 131; i++) {
        block0[idx++] = fileSizeStr[i];
    }
    block0[idx++] = 0x00;

    uint16_t crc = bw16_crc16(&block0[3], 128);
    block0[131] = (crc >> 8) & 0xFF;
    block0[132] = crc & 0xFF;

    // Send block 0
    _serial.write(block0, 133);

    // Wait for ACK and then 'C'
    bool ack = false;
    startWait = millis();
    while (millis() - startWait < 3000) {
        if (_serial.available()) {
            char c = _serial.read();
            if (c == 0x06) { // ACK
                ack = true;
            } else if (ack && c == 'C') {
                break; // ready for data blocks
            }
        }
    }

    if (!ack) {
        log_e("BW16 did not ACK block 0");
        return false;
    }

    // Send file data
    size_t totalBytes = file.size();
    size_t sentBytes = 0;
    uint8_t blockNum = 1;
    uint8_t dataBlock[1029] = {0};

    while (sentBytes < totalBytes) {
        size_t toRead = totalBytes - sentBytes;
        bool use1K = toRead > 128;
        size_t packetSize = use1K ? 1024 : 128;

        dataBlock[0] = use1K ? 0x02 : 0x01; // STX or SOH
        dataBlock[1] = blockNum;
        dataBlock[2] = 255 - blockNum;

        size_t readLen = file.read(&dataBlock[3], packetSize);
        // Pad the rest of the block with 0x1A (CTRL-Z) if needed
        for (size_t i = readLen; i < packetSize; i++) {
            dataBlock[3 + i] = 0x1A;
        }

        crc = bw16_crc16(&dataBlock[3], packetSize);
        dataBlock[3 + packetSize] = (crc >> 8) & 0xFF;
        dataBlock[4 + packetSize] = crc & 0xFF;

        _serial.write(dataBlock, 5 + packetSize);

        // Wait for ACK
        ack = false;
        startWait = millis();
        while (millis() - startWait < 3000) {
            if (_serial.available()) {
                if (_serial.read() == 0x06) { // ACK
                    ack = true;
                    break;
                }
            }
        }

        if (!ack) {
            log_e("BW16 did not ACK block %d", blockNum);
            return false;
        }

        sentBytes += readLen;
        blockNum++;

        // Update UI
        progressHandler(sentBytes, totalBytes, "Flashing...");
    }

    // End of Transmission
    _serial.write(0x04); // EOT

    // Usually receiver NAKs first EOT, then we send a second EOT
    startWait = millis();
    while (millis() - startWait < 1000) {
        if (_serial.available()) {
            char c = _serial.read();
            if (c == 0x15) { // NAK
                _serial.write(0x04); // Second EOT
            } else if (c == 0x06) { // ACK
                break;
            }
        }
    }

    // Send empty Block 0 to end YMODEM session
    uint8_t endBlock[133] = {0};
    endBlock[0] = 0x01; // SOH
    endBlock[1] = 0x00; // Block 0
    endBlock[2] = 0xFF; // ~Block 0
    crc = bw16_crc16(&endBlock[3], 128);
    endBlock[131] = (crc >> 8) & 0xFF;
    endBlock[132] = crc & 0xFF;

    _serial.write(endBlock, 133);

    startWait = millis();
    while (millis() - startWait < 1000) {
        if (_serial.available()) {
            if (_serial.read() == 0x06) break; // ACK
        }
    }

    return true;
}

void BW16::parseLine(String line) {
    line.trim();
    if (line.length() == 0) return;

    // Log for debug
    // Serial.println("[BW16] " + line);

    if (!line.startsWith("BRUCE_RESP:")) return;

    String resp = line.substring(11); // Remove prefix

    if (resp.startsWith("SCAN_SUCCESS")) {
        _scanning = false;
    } else if (resp.startsWith("SCAN_FAILED")) {
        _scanning = false;
    } else if (resp.startsWith("DEAUTH_ALL_STARTED:COUNT=")) {
        _lastMessage = "Deauth All Started: " + resp.substring(25);
    } else if (resp.startsWith("ERROR:")) {
        _lastMessage = resp.substring(6);
    } else if (resp.startsWith("AP:")) {
        // Format: AP:index|SSID|BSSID|Channel|Security|RSSI
        // Example: AP:0|MyWifi|00:11:22:33:44:55|6|3|-60

        int idx = resp.indexOf(':') + 1;
        String data = resp.substring(idx);

        int pipe1 = data.indexOf('|');
        int pipe2 = data.indexOf('|', pipe1 + 1);
        int pipe3 = data.indexOf('|', pipe2 + 1);
        int pipe4 = data.indexOf('|', pipe3 + 1);
        int pipe5 = data.indexOf('|', pipe4 + 1);

        if (pipe1 > 0 && pipe2 > pipe1 && pipe3 > pipe2 && pipe4 > pipe3 && pipe5 > pipe4) {
            BW16ScanResult res;
            res.index = data.substring(0, pipe1).toInt();
            res.ssid = data.substring(pipe1 + 1, pipe2);
            res.bssid = data.substring(pipe2 + 1, pipe3);
            res.channel = data.substring(pipe3 + 1, pipe4).toInt();
            res.security = data.substring(pipe4 + 1, pipe5).toInt();
            res.rssi = data.substring(pipe5 + 1).toInt();

            _scanResults.push_back(res);
        }
    } else if (resp.startsWith("SCAN_COMPLETE")) {
        _scanning = false;
    } else if (resp.startsWith("SCAN_RESULT:COUNT=")) {
        int count = resp.substring(18).toInt();
        if (count == 0) _scanning = false;
        // Pre-allocate vector? Not strictly necessary.
    }
}

// Logic copied/adapted from GPSTracker to avoid conflicts
void BW16::releasePins() {
    _pinsReleased = false;
    if (bruceConfigPins.CC1101_bus.checkConflict(bruceConfigPins.uart_bus.rx) ||
        bruceConfigPins.NRF24_bus.checkConflict(bruceConfigPins.uart_bus.rx) ||
#if !defined(LITE_VERSION)
        bruceConfigPins.W5500_bus.checkConflict(bruceConfigPins.uart_bus.rx) ||
        bruceConfigPins.LoRa_bus.checkConflict(bruceConfigPins.uart_bus.rx) ||
#endif
        bruceConfigPins.SDCARD_bus.checkConflict(bruceConfigPins.uart_bus.rx)) {

        pinMode(bruceConfigPins.uart_bus.rx, INPUT);
        _pinsReleased = true;
    }
}

void BW16::restorePins() {
    if (_pinsReleased) {
        if (bruceConfigPins.CC1101_bus.checkConflict(bruceConfigPins.uart_bus.rx) ||
            bruceConfigPins.NRF24_bus.checkConflict(bruceConfigPins.uart_bus.rx) ||
#if !defined(LITE_VERSION)
            bruceConfigPins.W5500_bus.checkConflict(bruceConfigPins.uart_bus.rx) ||
            bruceConfigPins.LoRa_bus.checkConflict(bruceConfigPins.uart_bus.rx) ||
#endif
            bruceConfigPins.SDCARD_bus.checkConflict(bruceConfigPins.uart_bus.rx)) {

            pinMode(bruceConfigPins.uart_bus.rx, OUTPUT);

            // Check specific conflicts to set HIGH/LOW
            if (bruceConfigPins.uart_bus.rx == bruceConfigPins.CC1101_bus.cs ||
                bruceConfigPins.uart_bus.rx == bruceConfigPins.NRF24_bus.cs ||
#if !defined(LITE_VERSION)
                bruceConfigPins.uart_bus.rx == bruceConfigPins.W5500_bus.cs ||
#endif
                bruceConfigPins.uart_bus.rx == bruceConfigPins.SDCARD_bus.cs) {
                // If it is conflicting to an SPI CS pin, keep it HIGH
                digitalWrite(bruceConfigPins.uart_bus.rx, HIGH);
            } else {
                // Keep it LOW otherwise
                digitalWrite(bruceConfigPins.uart_bus.rx, LOW);
            }
        }
        _pinsReleased = false;
    }
}
