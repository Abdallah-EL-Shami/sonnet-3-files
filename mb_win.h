// mb_win.h - طبقة ويندوز: التتبّع، الإعدادات، الحالة، والجسر (UDP + خيوط).
#pragma once
#include "mb_core.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <memory>
#include <string>

namespace mb {

extern const GUID kEtwProvider;       // {7C1E2B9A-5D3F-4A86-9B27-1E4D6C8F0A35}
extern std::atomic<long> g_liveThreads;

// ---- التتبّع: ETW + OutputDebugString + ملف (مع بدائل عند رفض الوصول). لا يُستدعى أبدًا من APOProcess.
void TraceInit();
void TraceShutdown();
void TraceLite(const char* stage, const char* fmt, ...);  // ETW + OutputDebugString فقط (آمن داخل DllMain)
void Trace(const char* stage, const char* fmt, ...);      // + ملف السجل
std::wstring DataDir();                                   // MICBRIDGE_DATADIR أو ProgramData\MicBridgeAPO
std::wstring DataPath(const wchar_t* file);

// ---- الإعدادات: ملف واحد MicBridge.ini
//   [Bridge]  إعدادات ثابتة تُقرأ عند بدء المجرى
//   [Control] Enabled=1/0  تحكم فوري تغيّره الواجهة وتقرؤه المحرك كل 250ms
enum class RatePolicy { Resample, Ignore };
struct BridgeConfig {
    char sendId[33];
    char recvId[33];
    char bcast[64];
    char bind[64];
    int sendPort, recvPort;
    bool fallback;
    int jitterMs, staleMs;
    int recvChannel;  // -1 = متوسط القنوات
    RatePolicy ratePolicy;
    bool diagnostics;
};
void LoadBridgeConfig(BridgeConfig& c);
bool ReadControlEnabled(const wchar_t* ini);

// ---- ملف الحالة status.txt (يُكتب من خيط مساعد فقط، ذريًا)
struct StatusFields {
    const char* apo = "IDLE";   // INITIALIZED / LOCKED / UNLOCKED
    const char* mode = "IDLE";  // PROCESSING / FALLBACK / BYPASS / ERROR / IDLE
    int cantabile = 0;
    uint32_t rate = 0, ch = 0;
    double bufMs = 0, blockMs = 0, latencyMs = 0, cpu = 0, txps = 0, rxps = 0;
    uint32_t rxBad = 0, underruns = 0, overruns = 0, drops = 0;
    int rateMismatch = 0, bind = 0;
    const char* lastError = "";
};
void WriteStatusFile(const StatusFields& f);
void WriteSimpleStatus(const char* apo, const char* mode, const char* err);

// ---- الجسر
class Bridge {
public:
    Bridge();
    ~Bridge();
    // يفتح السوكتات ويشغّل الخيوط. عند الفشل يتراجع عن كل شيء ويعيد false مع err.
    bool Start(uint32_t rate, uint32_t ch, uint32_t maxFrames, const BridgeConfig& cfg, std::string& err);
    void Stop();  // آمن للاستدعاء المتكرر
    // الوقت الحقيقي: لا تخصيص ولا قفل ولا I/O. io يحمل المايك الأصلي ويُعدَّل في مكانه.
    void Process(float* io, uint32_t frames, bool silent, bool* hasSignal) noexcept;
    bool active() const;

private:
    struct Shared;
    std::shared_ptr<Shared> s_;
};

}  // namespace mb
