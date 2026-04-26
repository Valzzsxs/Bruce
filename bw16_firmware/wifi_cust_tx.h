#ifndef WIFI_CUST_TX
#define WIFI_CUST_TX

#include <Arduino.h>

// Type
typedef uint8_t __u8;

// Const
#define WLAN0_NAME "wlan0"

// Packet4Align，/Align

// DeauthFrame
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xC0;      // Frame，SettingsDeauthType
  uint16_t duration = 0xFFFF;         // Time
  uint8_t destination[6];             // TargetMAC
  uint8_t source[6];                  // MAC
  uint8_t access_point[6];            // MAC
  const uint16_t sequence_number = 0;  //
  uint16_t reason = 0x06;             // Deauth
} DeauthFrame;

// 802.11wCryptoManageFrame
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xC0;      // Frame，SettingsDeauthType
  uint16_t duration = 0xFFFF;         // Time
  uint8_t destination[6];             // TargetMAC
  uint8_t source[6];                  // MAC
  uint8_t access_point[6];            // MAC
  const uint16_t sequence_number = 0;  //
  uint16_t reason = 0x06;             // Deauth
  uint8_t mic[16];                    // Message
  uint8_t key_replay_counter[8];      // Key
} ProtectedDeauthFrame;

// BeaconFrame
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x80;      // Frame，SettingsBeaconType
  uint16_t duration = 0;              // Time
  uint8_t destination[6];             // TargetMAC
  uint8_t source[6];                  // MAC
  uint8_t access_point[6];            // MAC
  const uint16_t sequence_number = 0;  //
  const uint64_t timestamp = 0;       // Time
  uint16_t beacon_interval = 0x64;    // Beacon
  uint16_t ap_capabilities = 0x21;    // Info
  const uint8_t ssid_tag = 0;         // SSIDTag
  uint8_t ssid_length = 0;            // SSIDLength
  uint8_t ssid[255];                  // SSID
} BeaconFrame;

// DetectResponseFrame（SmallFree，BeaconClassIE）
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x50;      // Type/Subtype: Probe Response
  uint16_t duration = 0;              // Time
  uint8_t destination[6];             // TargetMAC（Broadcast/）
  uint8_t source[6];                  // MAC（SpoofAP）
  uint8_t access_point[6];            // BSSID（MAC）
  const uint16_t sequence_number = 0; //
  const uint64_t timestamp = 0;       // Time
  uint16_t beacon_interval = 0x64;    //
  uint16_t ap_capabilities = 0x21;    //
  const uint8_t ssid_tag = 0;         // SSIDTag
  uint8_t ssid_length = 0;            // SSIDLength
  uint8_t ssid[255];                  // SSID
} ProbeRespFrame;

// 802.11 CertifyRequestFrame（Open System）Small
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xB0;      // Type/Subtype: Authentication
  uint16_t duration = 0;
  uint8_t destination[6];             // BSSID/
  uint8_t source[6];                  // STA MAC（Spoof）
  uint8_t bssid[6];                   // BSSID
  const uint16_t sequence_number = 0;
  uint16_t auth_algorithm = 0x0000;   // Open System
  uint16_t auth_sequence = 0x0001;    // Seq 1: authentication request
  uint16_t status_code = 0x0000;      // 0
} AuthReqFrame;

// 802.11 RequestFrame（SmallFree，+SSID IE + RateIE ）
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x0000 | (0x0 << 2) | (0x0 << 4); // ，SDK0
  uint16_t duration = 0;
  uint8_t destination[6];             // BSSID
  uint8_t source[6];                  // STA MAC
  uint8_t bssid[6];                   // BSSID
  const uint16_t sequence_number = 0;
  uint16_t capability = 0x0431;       // Basic
  uint16_t listen_interval = 0x000A;  // 10 TU
  // IE: SSID
  const uint8_t ssid_tag = 0x00;
  uint8_t ssid_length = 0;
  uint8_t ssid[32];
} AssocReqFrame;

// ImportCFunc
// Note：FuncYes100%，CompileMediumTypeInfo
extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

// Func - ，UsageSDKMediumVersion

// Func
void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x06);
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid);
// BuildBeaconFrameSend，BackFrameLength，Send
size_t wifi_build_beacon_frame(void* src_mac, void* dst_mac, const char *ssid, BeaconFrame &out);

// Build/SendDetectResponse，
size_t wifi_build_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid, ProbeRespFrame &out);
void wifi_tx_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid);

// ：802.11wCryptoManageFrameFunc
void wifi_tx_protected_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason, const uint8_t* mic, const uint8_t* replay_counter);
bool wifi_generate_pmf_mic(const uint8_t* frame, size_t frame_len, const uint8_t* key, uint8_t* mic);
bool wifi_attempt_pmf_attack(const uint8_t* bssid, const uint8_t* client_mac, uint8_t channel);

// ：BuildSendCertify/Request
size_t wifi_build_auth_req(void* sta_mac, void* bssid, AuthReqFrame &out);
void wifi_tx_auth_req(void* sta_mac, void* bssid);
size_t wifi_build_assoc_req(void* sta_mac, void* bssid, const char* ssid, AssocReqFrame &out);
void wifi_tx_assoc_req(void* sta_mac, void* bssid, const char* ssid);

// ：BroadcastCertify/Deauth（WakeSTA/）
void wifi_tx_broadcast_deauth(void* bssid, uint16_t reason, int burstCount, int interDelayUs);
void wifi_tx_broadcast_disassoc(void* bssid, uint16_t reason, int burstCount, int interDelayUs);



#endif
