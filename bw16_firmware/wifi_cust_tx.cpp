#include "wifi_cust_tx.h"

/*
 * SendLength802.11Frame
 * FrameYesValid，0（Settings）
 * Frame，PacketLengthMedium
 * @param frame Frame
 * @param size FrameSize
*/
void wifi_tx_raw_frame(void* frame, size_t length) {
  void *ptr = (void *)**(uint32_t **)((uint8_t*)rltk_wlan_info + 0x10);
  void *frame_control = alloc_mgtxmitframe((uint8_t*)ptr + 0xae0);

  if (frame_control != 0) {
    // UpdateFrame
    update_mgntframe_attrib(ptr, (uint8_t*)frame_control + 8);
    // EmptyFrameData
    memset((void *)*(uint32_t *)((uint8_t*)frame_control + 0x80), 0, 0x68);
    // FrameDataData
    uint8_t *frame_data = (uint8_t *)*(uint32_t *)((uint8_t*)frame_control + 0x80) + 0x28;
    memcpy(frame_data, frame, length);
    // SettingsFrameLength
    *(uint32_t *)((uint8_t*)frame_control + 0x14) = length;
    *(uint32_t *)((uint8_t*)frame_control + 0x18) = length;
    // SendFrame
    dump_mgntframe(ptr, frame_control);
  }
}

/*
 * ChannelSend802.11DeauthFrame
 * @param src_mac PacketSendMACArray，6
 * @param dst_mac PacketTargetMACArray，UsageFF:FF:FF:FF:FF:FFBroadcast
 * @param reason 802.11（）
*/
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  // SettingsMAC
  memcpy(&frame.source, src_mac, 6);
  // SettingsMAC
  memcpy(&frame.access_point, src_mac, 6);
  // SettingsTargetMAC
  memcpy(&frame.destination, dst_mac, 6);
  // SettingsDeauth
  frame.reason = reason;
  // SendFrame
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

/*
 * ChannelSendBasic802.11BeaconFrame
 * @param src_mac PacketSendMACArray，6
 * @param dst_mac PacketTargetMACArray，UsageFF:FF:FF:FF:FF:FFBroadcast
 * @param ssid '\0'Array，SSID
*/
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  // SettingsMAC
  memcpy(&frame.source, src_mac, 6);
  // SettingsMAC
  memcpy(&frame.access_point, src_mac, 6);
  // SettingsTargetMAC
  memcpy(&frame.destination, dst_mac, 6);
  // SSIDLength
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  // SendFrame（FrameSizeSize38SSIDLength）
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

size_t wifi_build_beacon_frame(void* src_mac, void* dst_mac, const char *ssid, BeaconFrame &out) {
  // BuildBeaconFrame
  memcpy(&out.source, src_mac, 6);
  memcpy(&out.access_point, src_mac, 6);
  memcpy(&out.destination, dst_mac, 6);
  out.ssid_length = 0;
  for (int i = 0; ssid[i] != '\0'; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  return 38 + out.ssid_length;
}

void wifi_tx_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid) {
  ProbeRespFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.ssid_length = 0;
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

size_t wifi_build_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid, ProbeRespFrame &out) {
  memcpy(&out.source, src_mac, 6);
  memcpy(&out.access_point, src_mac, 6);
  memcpy(&out.destination, dst_mac, 6);
  out.ssid_length = 0;
  for (int i = 0; ssid[i] != '\0'; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  return 38 + out.ssid_length;
}

size_t wifi_build_auth_req(void* sta_mac, void* bssid, AuthReqFrame &out) {
  memcpy(&out.source, sta_mac, 6);
  memcpy(&out.destination, bssid, 6);
  memcpy(&out.bssid, bssid, 6);
  out.auth_algorithm = 0x0000; // Open System
  out.auth_sequence = 0x0001;
  out.status_code = 0x0000;
  return sizeof(AuthReqFrame);
}

void wifi_tx_auth_req(void* sta_mac, void* bssid) {
  AuthReqFrame frame;
  size_t len = wifi_build_auth_req(sta_mac, bssid, frame);
  wifi_tx_raw_frame(&frame, len);
}

size_t wifi_build_assoc_req(void* sta_mac, void* bssid, const char* ssid, AssocReqFrame &out) {
  memcpy(&out.source, sta_mac, 6);
  memcpy(&out.destination, bssid, 6);
  memcpy(&out.bssid, bssid, 6);
  out.ssid_length = 0;
  for (int i = 0; ssid && ssid[i] != '\0' && i < 32; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  // ListenMedium
  // RequestFrameLength = 24MAC() + (4) + IE(2+len)
  // ，BackValidUsedLength
  return sizeof(AssocReqFrame) - (32 - out.ssid_length);
}

void wifi_tx_assoc_req(void* sta_mac, void* bssid, const char* ssid) {
  AssocReqFrame frame;
  size_t len = wifi_build_assoc_req(sta_mac, bssid, ssid, frame);
  wifi_tx_raw_frame(&frame, len);
}


void wifi_tx_broadcast_deauth(void* bssid, uint16_t reason, int burstCount, int interDelayUs) {
  uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  DeauthFrame frame;
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, broadcast, 6);
  frame.reason = reason;
  for (int i = 0; i < burstCount; i++) {
    wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
    if (interDelayUs > 0) delayMicroseconds(interDelayUs);
  }
}

typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xA0;      // Disassociation
  uint16_t duration = 0x0000;
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t bssid[6];
  const uint16_t sequence_number = 0;
  uint16_t reason = 0x0008;           // Disassoc due to inactivity by default
} DisassocFrame;

void wifi_tx_broadcast_disassoc(void* bssid, uint16_t reason, int burstCount, int interDelayUs) {
  uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  DisassocFrame frame = {};
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.bssid, bssid, 6);
  memcpy(&frame.destination, broadcast, 6);
  frame.reason = reason;
  for (int i = 0; i < burstCount; i++) {
    wifi_tx_raw_frame(&frame, sizeof(DisassocFrame));
    if (interDelayUs > 0) delayMicroseconds(interDelayUs);
  }
}
