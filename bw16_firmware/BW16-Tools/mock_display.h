
#ifndef MOCK_DISPLAY_H
#define MOCK_DISPLAY_H

#include <Arduino.h>

#define SSD1306_SWITCHCAPVCC 0
#define SSD1306_WHITE 1
#define SSD1306_BLACK 0
#define WHITE 1
#define BLACK 0

struct u8g2_font_ncenB14_tr {};
struct u8g2_font_ncenB10_tr {};
struct u8g2_font_wqy12_t_gb2312 {};

extern u8g2_font_ncenB14_tr u8g2_font_ncenB14_tr;
extern u8g2_font_ncenB10_tr u8g2_font_ncenB10_tr;
extern u8g2_font_wqy12_t_gb2312 u8g2_font_wqy12_t_gb2312;

class DummyDisplay {
public:
    void begin(int, int) {}
    void clearDisplay() {}
    void display() {}
    void setTextColor(int) {}
    void setTextSize(int) {}
    void setCursor(int, int) {}
    void print(String) {}
    void print(const char*) {}
    void print(int) {}
    void print(unsigned long) {}
    void print(char) {}
    void drawRoundRect(int,int,int,int,int,int) {}
    void fillRoundRect(int,int,int,int,int,int) {}
    void drawRect(int,int,int,int,int) {}
    void fillRect(int,int,int,int,int) {}
    void drawLine(int,int,int,int,int) {}
    void drawBitmap(int,int,const unsigned char*,int,int,int) {}
    void fillTriangle(int,int,int,int,int,int,int) {}
    int width() { return 128; }
    int height() { return 64; }
};

class DummyU8g2 {
public:
    template<typename T>
    void begin(T&) {}
    template<typename T>
    void setFont(T) {}
    void setFontMode(int) {}
    void setForegroundColor(int) {}
    void setCursor(int, int) {}
    void print(String) {}
    void print(const char*) {}
    void print(int) {}
    void print(unsigned int) {}
    void print(unsigned long) {}
    int getUTF8Width(const char*) { return 10; }
};

extern DummyDisplay display;
extern DummyU8g2 u8g2_for_adafruit_gfx;

#endif
