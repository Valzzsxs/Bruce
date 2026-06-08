#ifndef WEB_CONFIG_H
#define WEB_CONFIG_H

// Web UIConfig
#define WEB_UI_SSID "BW16-WebUI"        // APSSID
#define WEB_UI_PASSWORD "1234567890"     // APPassword（8）
#define WEB_UI_CHANNEL 1                 // APChannel
#define WEB_UI_MAX_CONNECTIONS 4         // LargeConnect
#define WEB_SERVER_PORT 80               // WebService

// Web Test Config（OpenSSID，Password）
#define WEB_TEST_SSID "BW16-WebTest"    // TestAPSSID（Password）
#define WEB_TEST_CHANNEL 1               // TestAPChannel

// ConfigDesc：
// 1. SSID：WiFiListMediumNetwork
// 2. Password：ConnectAPPassword
// 3. Channel：APWiFiChannel（1-132.4GHz，36+5GHz）
// 4. LargeConnect：ConnectAPLargeDevice
// 5. WebService：HTTPService

// ModifyWeb UISettings
// Note：Password8，NoAPStart

#endif
