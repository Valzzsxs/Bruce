#include "BW16Menu.h"
#include <FS.h>
#include <core/display.h>
#include <core/mykeyboard.h>
#include <core/sd_functions.h>
#include <core/utils.h>

void BW16Menu::drawIcon(float scale) {
    clearIconArea();
    int x = iconCenterX;
    int y = iconCenterY;
    
    tft.setTextSize(scale * 7.0);
    tft.setTextColor(bruceConfig.priColor);
    
    // Draw "5G" larger and slightly higher
    tft.drawCentreString("5G", x, y - (15 * scale), 1);
    
    // Draw "Hz" larger below it
    tft.setTextSize(max(2.5f, scale)); 
    tft.drawCentreString("Hz", x, y + (10 * scale), 1);
}

// Global static tick helper
static bool bw16_tick(void* ptr, bool) {
    if (ptr) {
        BW16Menu* menu = (BW16Menu*)ptr;
        menu->runLoop();
    }
    return false;
}

void BW16Menu::optionsMenu() {
    bw16.begin();

    // Initial status check
    bw16.getStatus();

    while(1) {
        options = {
            {"Scan Networks", [this]() { scanNetworks(); }, false, bw16_tick, this},
            {"Show AP List", [this]() { showAPList(); }, false, bw16_tick, this},
            {"Wifi Analyzer", [this]() {
                displaySuccess("Feature WIP");
                delay(500);
            }, false, bw16_tick, this},
            {"Hidden SSID Decloaker", [this]() {
                bw16.hiddenDecloaker();
                displaySuccess("Decloaking...");
                delay(500);
            }, false, bw16_tick, this},
            {"Deauth Detection (IDS)", [this]() {
                bw16.startIDS();
                displaySuccess("IDS Started");
                delay(500);
            }, false, bw16_tick, this},
            {"BLE Tools", [this]() {
                while(1) {
                    std::vector<Option> bleOptions = {
                        {"BLE Spam", [this]() {
                            String name = keyboard("Rickroll", 20, "Spam Name:");
                            if(name.length() > 0) {
                                bw16.bleSpam(name);
                                displaySuccess("BLE Spamming");
                                delay(500);
                            }
                        }, false, bw16_tick, this},
                        {"BLE Scan", [this]() {
                            bw16.bleScan();
                            displaySuccess("Scanning BLE");
                            delay(500);
                        }, false, bw16_tick, this}
                    };
                    int ret = loopOptions(bleOptions, MENU_TYPE_REGULAR, "BLE Tools");
                    if (ret == -1) break;
                }
            }, false, bw16_tick, this},
            {"Deauth All", [this]() {
                bw16.deauthAll();
                long start = millis();
                while(millis() - start < 1000) {
                     bw16.loop();
                     delay(10);
                }
                displaySuccess("Deauth All Sent");
            }, false, bw16_tick, this},
            {"Stop All Attacks", [this]() {
                bw16.deauthStopAll();
                bw16.stopIDS();
                displaySuccess("Stopped All!");
                delay(1000);
            }, false, bw16_tick, this},
            {"BW16 OTA Update", [this]() {
                FS *fs = &LittleFS;
                setupSdCard();
                if (sdcardMounted) {
                    std::vector<Option> fsOptions = {
                        {"SD Card", [&]() { fs = &SD; }},
                        {"LittleFS", [&]() { fs = &LittleFS; }},
                    };
                    int ret = loopOptions(fsOptions);
                    if (ret == -1) return;
                }
                String filename = loopSD(*fs, true, "BIN");
                if (filename == "") return;

                File file = fs->open(filename, FILE_READ);
                if (!file) {
                    displayError("Failed to open file");
                    delay(1000);
                    return;
                }

                displayInfo("Starting OTA...");
                if (bw16.otaUpdate(file)) {
                    displaySuccess("OTA Success");
                } else {
                    displayError("OTA Failed");
                }
                delay(1000);
            }, false, bw16_tick, this},
            {"Settings", [this]() {
                while(1) {
                    std::vector<Option> settingOptions = {
                        {"Change UART RX Pin", [this]() {
                            String pin = num_keyboard(String(bruceConfigPins.uart_bus.rx), 2, "RX Pin");
                            if(pin.length() > 0) {
                                bw16.end();
                                bruceConfigPins.uart_bus.rx = (gpio_num_t)pin.toInt();
                                displaySuccess("RX Updated");
                                delay(500);
                                bw16.begin();
                            }
                        }, false, bw16_tick, this},
                        {"Change UART TX Pin", [this]() {
                            String pin = num_keyboard(String(bruceConfigPins.uart_bus.tx), 2, "TX Pin");
                            if(pin.length() > 0) {
                                bw16.end();
                                bruceConfigPins.uart_bus.tx = (gpio_num_t)pin.toInt();
                                displaySuccess("TX Updated");
                                delay(500);
                                bw16.begin();
                            }
                        }, false, bw16_tick, this},
                        {"MAC Spoofing", [this]() {
                            String mac = keyboard("", 17, "New MAC (XX:XX...)");
                            if(mac.length() > 0) {
                                bw16.setMAC(mac);
                                displaySuccess("MAC Spoofed");
                                delay(500);
                            }
                        }, false, bw16_tick, this}
                    };
                    int ret = loopOptions(settingOptions, MENU_TYPE_REGULAR, "Settings");
                    if (ret == -1) break;
                }
            }, false, bw16_tick, this},
        };

        String status = "Status: ";
        if (bw16.isConnected()) status += "Ready";
        else status += "Checking...";

        status += " | APs: " + String(bw16.getResults().size());

        if (bw16.getLastMessage().length() > 0) {
            status += "\n" + bw16.getLastMessage();
        }

        int ret = loopOptions(options, MENU_TYPE_REGULAR, status.c_str());

        if (returnToMenu) break;
        if (ret == -1) break;
    }

    bw16.end();
}

void BW16Menu::scanNetworks() {
    drawMainBorderWithTitle("Scanning..."); // Clear screen and show title
    tft.drawCentreString("Scanning...", tftWidth/2, tftHeight/2 - 20, 1);

    bw16.scan(5000);

    long start = millis();
    bool completed = false;

    while(millis() - start < 6000) { // 6s timeout for 5s scan
        bw16.loop();

        // Progress bar
        float progress = (millis() - start) / 5000.0;
        if (progress > 1.0) progress = 1.0;

        int barWidth = tftWidth - 40;
        int barX = 20;
        int barY = tftHeight/2 + 20;

        tft.drawRect(barX, barY, barWidth, 10, bruceConfig.priColor);
        tft.fillRect(barX + 2, barY + 2, (barWidth-4) * progress, 6, bruceConfig.secColor);

        if (!bw16.isScanning() && (millis() - start > 500)) {
            completed = true;
            break;
        }

        if (check(EscPress)) {
            completed = false;
            break;
        }

        delay(10);
    }

    if (completed) {
        long extraWait = millis();
        while(millis() - extraWait < 500) {
            bw16.loop();
            delay(10);
        }
        showAPList();
    } else {
        displayError("Scan Timeout");
        delay(1000);
    }
}

void BW16Menu::showAPList() {
    auto results = bw16.getResults();
    if (results.empty()) {
        displayError("No APs Found");
        delay(1000);
        return;
    }

    while(1) {
        options.clear();
        for(const auto& res : results) {
            String label = res.ssid;
            if (label.length() == 0) label = "<hidden>";
            label += " (" + String(res.rssi) + ")";

            options.push_back({label, [this, res]() { showActionMenu(res.index); }, false, bw16_tick, this});
        }

        int ret = loopOptions(options, MENU_TYPE_REGULAR, "Select AP");
        if (ret == -1) break;
    }
}

void BW16Menu::showActionMenu(int index) {
    auto results = bw16.getResults();
    BW16ScanResult target;
    bool found = false;
    for(const auto& res : results) {
        if (res.index == index) {
            target = res;
            found = true;
            break;
        }
    }

    if (!found) return;

    while(1) {
        options = {
            {"Deauth Start", [this, index]() {
                bw16.deauthStart(index);
                displaySuccess("Deauth Started");
                delay(500);
            }, false, bw16_tick, this},

            {"Deauth Stop", [this, index]() {
                bw16.deauthStop(index);
                displaySuccess("Deauth Stopped");
                delay(500);
            }, false, bw16_tick, this},

            {"Select SSID", [this, index]() {
                bw16.selectSSID(index);
                displaySuccess("SSID Selected");
                delay(500);
            }, false, bw16_tick, this}
        };

        String info = "Ch:" + String(target.channel) + " " + target.bssid + "\nSec:" + String(target.security) + " RSSI:" + String(target.rssi);

        // drawMainBorderWithTitle(target.ssid); // loopOptions handles title if passed via subText? No, title is separate.
        // loopOptions clears screen.

        // We can pass target.ssid as title to loopOptions if we modify utils...
        // But loopOptions uses generic title logic.
        // Let's rely on info string.

        int ret = loopOptions(options, MENU_TYPE_REGULAR, info.c_str());
        if (ret == -1) break;
    }
}
