#ifndef DEBUG_H
#define DEBUG_H

#include <Arduino.h>

//#define DEBUG  // DebugModeSwitch

// SettingsDebug
#define DEBUG_BAUD 115200

#ifdef DEBUG
  // DEBUG，Init
  #define DEBUG_SER_INIT() Serial.begin(DEBUG_BAUD);
  // DEBUG，OutputDebugInfo
  #define DEBUG_SER_PRINT(...) Serial.print(__VA_ARGS__);
#else
  // DEBUG，Exec
  #define DEBUG_SER_PRINT(...)
  #define DEBUG_SER_INIT()
#endif

#endif
