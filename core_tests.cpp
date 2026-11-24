// core_tests.cpp - اختبارات المنطق الخالص (تعمل على ويندوز وعلى لينكس).
#include "../src/mb_core.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static int g_fail = 0, g_pass = 0;
#define CHECK(c)                                                                   \
    do {                                                                           \
        if (c) { ++g_pass; }                                                       \
        else { ++g_fail; std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } \
    } while (0)
#define SECTION(n) std::printf("[%s]\n", n)

static std::vector<uint8_t> Hex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back((uint8_t)std::strtoul(s.substr(i, 2).c_str(), nullptr, 16));
    return v;
}

// الترويسة الحقيقية الملتقطة من Audition (47 بايت): MRSR, size=1247, id=mic_out, ch=2, sr=48000, bytes=1200
static const char* kGoldenHdr =
    "4d525352" "df040000" "6d69635f6f757400000000000000000000000000000000000000000000000000" "02" "80bb0000" "b004";
// أول 4 عينات حقيقية من القناة الأولى في تلك الحزمة
static const char* kGoldenSamples = "00d820ba" "0040e9b9" "00e036b9" "00005838";

static void TestGoldenHeader() {
    SECTION("golden header from real capture");
    auto h = Hex(kGoldenHdr);
    CHECK(h.size() == mb::kHeaderSize);
    mb::ReaHdr hdr;
    std::memcpy(&hdr, h.data(), mb::kHeaderSize);
    CHECK(std::memcmp(hdr.magic, "MRSR", 4) == 0);
    CHECK(hdr.size == 1247);
    CHECK(hdr.ch == 2);
    CHECK(hdr.sr == 48000);
    CHECK(hdr.bytes == 1200);
    CHECK(std::strncmp((const char*)hdr.id, "mic_out", 32) == 0);

    // الحزمة الرابعة الحقيقية: 703 - 4 (Npcap) - 28 (IP+UDP) = 671 = 47 + 624
    CHECK(703 - 4 - 28 == 671);
    CHECK(671 - (int)mb::kHeaderSize == 624);
    CHECK(300 * 3 + 156 == 1056);  // 3 حزم كاملة + حزمة 156 عينة
}

static void TestPackParseRoundtrip() {
    SECTION("pack/parse roundtrip + id handling (strncpy_s bug regression)");
    uint8_t id[32];
    mb::MakeId("APO_MIC_RAW", id);
    float s[300];
    for (int i = 0; i < 300; ++i) s[i] = std::sin(i * 0.1f) * 0.5f;
    uint8_t pkt[2048];
    size_t n = mb::PackAudio(pkt, sizeof pkt, id, 1, 48000, s, 300);
    CHECK(n == mb::kHeaderSize + 1200);
    // الحقل بعد المعرّف (القنوات) لا يُمسّ: بايت 40 = 1
    CHECK(pkt[40] == 1);
    mb::Parsed p;
    CHECK(mb::ParseAudio(pkt, n, id, p) == mb::Parse::Ok);
    CHECK(p.ch == 1 && p.sr == 48000 && p.frames == 300 && p.bytes == 1200);
    CHECK(!p.sizeFieldMismatch);
    float out[300];
    mb::ExtractMono(p.data, p.frames, p.ch, 0, out);
    bool same = true;
    for (int i = 0; i < 300; ++i) same &= (out[i] == s[i]);
    CHECK(same);

    // معرّف طوله 32 بالضبط: لا تجاوز ولا مساس بالقنوات
    uint8_t id32[32];
    mb::MakeId("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345EXTRA", id32);
    CHECK(id32[31] == '5');
    uint8_t pk2[256];
    size_t n2 = mb::PackAudio(pk2, sizeof pk2, id32, 1, 48000, s, 10);
    CHECK(n2 == mb::kHeaderSize + 40 && pk2[40] == 1);

    // قيود البناء
    CHECK(mb::PackAudio(pkt, sizeof pkt, id, 1, 48000, s, 301) == 0);  // أكبر من 1200 بايت
    CHECK(mb::PackAudio(pkt, 50, id, 1, 48000, s, 10) == 0);           // مخزن صغير
    CHECK(mb::PackAudio(pkt, sizeof pkt, id, 2, 48000, s, 5) == 0);    // عدد عينات لا يقبل القسمة على القنوات
    CHECK(mb::PackAudio(pkt, sizeof pkt, id, 0, 48000, s, 4) == 0);
}

static void TestParseMalformed() {
    SECTION("malformed / truncated / foreign packets");
    uint8_t id[32], other[32];
    mb::MakeId("APO_MIC_FX", id);
    mb::MakeId("Cantabile_TO_APO", other);
    float s[64] = {};
    uint8_t good[512];
    size_t n = mb::PackAudio(good, sizeof good, id, 1, 48000, s, 64);
    mb::Parsed p;
    CHECK(mb::ParseAudio(good, n, id, p) == mb::Parse::Ok);
    CHECK(mb::ParseAudio(good, 10, id, p) == mb::Parse::TooShort);
    CHECK(mb::ParseAudio(good, mb::kHeaderSize - 1, id, p) == mb::Parse::TooShort);
    CHECK(mb::ParseAudio(nullptr, 100, id, p) == mb::Parse::TooShort);
    CHECK(mb::ParseAudio(good, n, other, p) == mb::Parse::BadId);  // معرّف مختلف: غريبة
    {
        uint8_t m[512];
        std::memcpy(m, good, n);
        m[0] = 'm';  // ميدي
        CHECK(mb::ParseAudio(m, n, id, p) == mb::Parse::NotAudio);
    }
    // مبتورة: الحقل يقول 256 بايت لكن وصل أقل
    CHECK(mb::ParseAudio(good, n - 1, id, p) == mb::Parse::BadLength);
    mb::ReaHdr h;
    auto mutate = [&](auto fn) {
        uint8_t m[512];
        std::memcpy(m, good, n);
        std::memcpy(&h, m, mb::kHeaderSize);
        fn(h);
        std::memcpy(m, &h, mb::kHeaderSize);
        return mb::ParseAudio(m, n, id, p);
    };
    CHECK(mutate([](mb::ReaHdr& x) { x.ch = 0; }) == mb::Parse::BadChannels);
    CHECK(mutate([](mb::ReaHdr& x) { x.ch = 9; }) == mb::Parse::BadChannels);
    CHECK(mutate([](mb::ReaHdr& x) { x.sr = 100; }) == mb::Parse::BadRate);
    CHECK(mutate([](mb::ReaHdr& x) { x.sr = 1000000; }) == mb::Parse::BadRate);
    CHECK(mutate([](mb::ReaHdr& x) { x.bytes = 0; }) == mb::Parse::BadLength);
    CHECK(mutate([](mb::ReaHdr& x) { x.bytes = 60000; }) == mb::Parse::BadLength);
    CHECK(mutate([](mb::ReaHdr& x) { x.bytes = 260; }) == mb::Parse::BadLength);  // أكبر من الموجود فعلًا (الحمولة 256)
    CHECK(mutate([](mb::ReaHdr& x) { x.bytes = 250; }) == mb::Parse::Misaligned);  // لا يقبل القسمة على 4
    CHECK(mutate([](mb::ReaHdr& x) { x.ch = 3; x.bytes = 256; }) == mb::Parse::Misaligned);  // 64 عينة / 3 قنوات
    CHECK(mutate([](mb::ReaHdr& x) { x.size = 9999; }) == mb::Parse::Ok);  // حقل الحجم تحذير فقط
    CHECK(p.sizeFieldMismatch);
}

static void TestChannelMapping() {
    SECTION("planar channel mapping (verified on real capture: 150 samples + 150 zeros)");
    // بيانات حقيقية: القناة الأولى ثم القناة الثانية (الصامتة)
    auto real = Hex(kGoldenSamples);  // 4 عينات حقيقية
    std::vector<uint8_t> data;
    const uint32_t frames = 4;
    data.insert(data.end(), real.begin(), real.end());           // ch0
    for (uint32_t i = 0; i < frames * 4; ++i) data.push_back(0);  // ch1 صامتة
    float ch0[4], ch1[4], avg[4];
    mb::ExtractMono(data.data(), frames, 2, 0, ch0);
    mb::ExtractMono(data.data(), frames, 2, 1, ch1);
    mb::ExtractMono(data.data(), frames, 2, -1, avg);
    for (int i = 0; i < 4; ++i) {
        CHECK(ch0[i] != 0.f);          // القناة الأولى تحمل الصوت
        CHECK(ch1[i] == 0.f);          // الثانية صامتة: لا تسرب بين القنوات
        CHECK(std::fabs(avg[i] - ch0[i] * 0.5f) < 1e-9f);
    }
    CHECK(ch0[0] < 0.f && std::fabs(ch0[0] + 0.0006f) < 0.0001f);  // ≈ -0.0006 كما حُسب سابقًا
    // قناة غير موجودة => متوسط، لا قراءة خارج المدى
    float bad[4];
    mb::ExtractMono(data.data(), frames, 2, 7, bad);
    CHECK(std::fabs(bad[0] - avg[0]) < 1e-12f);

    // NaN / Inf / قيم ضخمة
    float evil[4] = {NAN, INFINITY, -INFINITY, 1e30f};
    uint8_t eb[16];
    std::memcpy(eb, evil, 16);
    float o[4];
    mb::ExtractMono(eb, 4, 1, 0, o);
    CHECK(o[0] == 0.f && o[1] == 0.f && o[2] == 0.f && o[3] == 1.f);
}

static void TestRing() {
    SECTION("ring buffer");
    mb::SpscRing r(16);
    float in[40], out[40];
    for (int i = 0; i < 40; ++i) in[i] = (float)i;
    CHECK(r.push(in, 10) == 0);
    CHECK(r.available() == 10);
    CHECK(r.push(in + 10, 10) == 4);  // السعة 16: رُفضت 4
    CHECK(r.available() == 16);
    CHECK(r.pop(out, 6) == 6 && out[0] == 0.f && out[5] == 5.f);
    CHECK(r.push(in + 20, 6) == 0);   // التفاف المؤشرات
    CHECK(r.pop(out, 100) == 16);
    CHECK(out[0] == 6.f && out[9] == 15.f && out[10] == 20.f && out[15] == 25.f);
    r.push(in, 8);
    r.skip(5);
    CHECK(r.available() == 3);
    r.skip(100);
    CHECK(r.available() == 0);
    r.reset();
    CHECK(r.pop(out, 4) == 0);
}

static void TestSendChunking() {
    SECTION("send chunking: 480 frames -> <=300-sample packets, lossless reassembly");
    uint8_t id[32];
    mb::MakeId("APO_MIC_RAW", id);
    std::vector<float> src(480);
    for (size_t i = 0; i < src.size(); ++i) src[i] = std::sin(i * 0.05f) * 0.3f;
    std::vector<float> back;
    size_t pos = 0;
    int packets = 0;
    while (pos < src.size()) {
        size_t chunk = std::min<size_t>(300, src.size() - pos);
        uint8_t pkt[2048];
        size_t n = mb::PackAudio(pkt, sizeof pkt, id, 1, 48000, src.data() + pos, chunk);
        CHECK(n > 0 && n <= mb::kHeaderSize + mb::kMaxChunkBytes);
        mb::Parsed p;
        CHECK(mb::ParseAudio(pkt, n, id, p) == mb::Parse::Ok);
        std::vector<float> tmp(p.frames);
        mb::ExtractMono(p.data, p.frames, p.ch, 0, tmp.data());
        back.insert(back.end(), tmp.begin(), tmp.end());
        pos += chunk;
        ++packets;
    }
    CHECK(packets == 2);
    CHECK(back == src);
}

static void TestResampler() {
    SECTION("resampler: 44100 -> 48000, continuity across packet boundaries");
    const double inRate = 44100, outRate = 48000, f = 1000;
    const size_t total = 4410;
    std::vector<float> in(total);
    for (size_t i = 0; i < total; ++i) in[i] = (float)(0.5 * std::sin(2 * M_PI * f * i / inRate));
    const double step = inRate / outRate;
    // دفعة واحدة
    mb::LinearResampler a;
    std::vector<float> oa(total * 2);
    size_t na = a.Process(in.data(), total, step, oa.data(), oa.size());
    // على دفعات 300 عينة
    mb::LinearResampler b;
    std::vector<float> ob;
    for (size_t pos = 0; pos < total; pos += 300) {
        size_t n = std::min<size_t>(300, total - pos);
        std::vector<float> tmp(2000);
        size_t m = b.Process(in.data() + pos, n, step, tmp.data(), tmp.size());
        ob.insert(ob.end(), tmp.begin(), tmp.begin() + m);
    }
    CHECK(std::abs((long)na - (long)(total * outRate / inRate)) <= 2);
    CHECK(ob.size() == na);
    double maxd = 0;
    for (size_t i = 0; i < na && i < ob.size(); ++i) maxd = std::max(maxd, (double)std::fabs(oa[i] - ob[i]));
    CHECK(maxd < 1e-6);
    // أقصى فرق بين عينتين متتاليتين يطابق نغمة 1kHz (لا قفزات عند حدود الحزم)
    double maxStep = 0;
    for (size_t i = 1; i < ob.size(); ++i) maxStep = std::max(maxStep, (double)std::fabs(ob[i] - ob[i - 1]));
    CHECK(maxStep < 0.5 * 2 * M_PI * f / outRate * 1.1);
}

// ---- Blender
struct Sim {
    mb::SpscRing ring{1 << 16};
    mb::Blender bl;
    std::vector<float> scratch = std::vector<float>(4096);
    uint32_t rate = 48000, frames = 480;
    uint64_t jitter = 1920;
    double phaseDry = 0, phaseWet = 0;
    std::vector<float> out;
    Sim() { bl.Configure(rate, jitter, jitter + 4800, true, 240); }
    void FeedWet(size_t n, float amp = 0.25f) {
        std::vector<float> w(n);
        for (size_t i = 0; i < n; ++i) { w[i] = amp; }
        ring.push(w.data(), n);
    }
    // كتلة: المايك الأصلي ثابت 0.5، الصوت المعالج ثابت 0.25 => نرى بوضوح مَن يخرج
    void Block(bool wetAllowed, uint32_t ch = 1) {
        std::vector<float> io((size_t)frames * ch, 0.5f);
        bl.Process(io.data(), frames, ch, ring, wetAllowed, scratch.data());
        for (uint32_t i = 0; i < frames; ++i) out.push_back(io[(size_t)i * ch]);
    }
};

static void TestBlender() {
    SECTION("blender: priming, steady state, underrun fade, recovery, stale, overrun");
    {
        Sim s;
        // قبل امتلاء المخزن: المايك الأصلي فقط
        s.FeedWet(480);
        s.Block(true);
        CHECK(!s.bl.wetOk());
        CHECK(s.out.back() == 0.5f);
        // بعد بلوغ حد الجيتر: يبدأ الصوت المعالج مع مزج ناعم
        s.FeedWet(3000);
        size_t before = s.out.size();
        s.Block(true);
        CHECK(s.bl.wetOk());
        CHECK(s.out[before] > 0.4f);                    // البداية قرب المايك
        CHECK(std::fabs(s.out.back() - 0.25f) < 1e-6f);  // النهاية = معالج بالكامل بعد 240 عينة
        // لا قفزة أكبر من خطوة الميل الواحدة
        double maxd = 0;
        for (size_t i = before + 1; i < s.out.size(); ++i) maxd = std::max(maxd, (double)std::fabs(s.out[i] - s.out[i - 1]));
        CHECK(maxd <= (0.5 - 0.25) / 240.0 + 1e-6);
    }
    {
        Sim s;
        s.FeedWet(2400);
        s.Block(true);  // يعمل
        CHECK(s.bl.wetOk());
        // نفاد البيانات: خروج تدريجي إلى المايك الأصلي بلا قفزة
        size_t before = s.out.size();
        for (int i = 0; i < 6; ++i) s.Block(true);
        CHECK(s.bl.underruns() >= 1);
        CHECK(!s.bl.wetOk());
        double maxd = 0;
        for (size_t i = before; i < s.out.size(); ++i) maxd = std::max(maxd, (double)std::fabs(s.out[i] - s.out[i - 1]));
        CHECK(maxd <= (0.5 - 0.25) / 240.0 + 1e-6);
        CHECK(std::fabs(s.out.back() - 0.5f) < 1e-6f);
        // التعافي: يحتاج امتلاء الجيتر من جديد ثم يعود تدريجيًا
        s.FeedWet(4000);
        size_t b2 = s.out.size();
        for (int i = 0; i < 3; ++i) s.Block(true);
        CHECK(s.bl.wetOk());
        CHECK(s.bl.primings() >= 2);
        double md2 = 0;
        for (size_t i = b2; i < s.out.size(); ++i) md2 = std::max(md2, (double)std::fabs(s.out[i] - s.out[i - 1]));
        CHECK(md2 <= (0.5 - 0.25) / 240.0 + 1e-6);
    }
    {
        Sim s;  // حزم قديمة (stale): المايك الأصلي ويُفرغ المخزن
        s.FeedWet(5000);
        s.Block(true);
        s.Block(true);
        CHECK(s.bl.wetOk());
        for (int i = 0; i < 4; ++i) s.Block(false);
        CHECK(s.ring.available() == 0);
        CHECK(std::fabs(s.out.back() - 0.5f) < 1e-6f);
    }
    {
        Sim s;  // تراكم زائد: يُقتطع إلى حد الجيتر ويُحسب
        s.FeedWet(30000);
        s.Block(true);
        CHECK(s.bl.overruns() >= 1);
        CHECK(s.ring.available() <= s.jitter + 4800);
    }
    {
        // وضع الصمت بدل المايك عند فقدان الصوت المعالج (Fallback=0)
        Sim s;
        s.bl.Configure(48000, 1920, 6720, false, 240);
        s.Block(true);
        CHECK(std::fabs(s.out.back()) < 1e-6f);
    }
    {
        // قنوات متعددة: الصوت المعالج الأحادي يُنسخ لكل القنوات
        Sim s;
        s.FeedWet(5000);
        std::vector<float> io((size_t)480 * 2, 0.5f);
        s.bl.Process(io.data(), 480, 2, s.ring, true, s.scratch.data());
        s.bl.Process(io.data(), 480, 2, s.ring, true, s.scratch.data());
        // الكتلة الثانية تحتوي معالجًا خالصًا في كلتا القناتين
        std::vector<float> io2((size_t)480 * 2, 0.5f);
        s.bl.Process(io2.data(), 480, 2, s.ring, true, s.scratch.data());
        CHECK(std::fabs(io2[958] - 0.25f) < 1e-6f && std::fabs(io2[959] - 0.25f) < 1e-6f);
    }
}

int main() {
    TestGoldenHeader();
    TestPackParseRoundtrip();
    TestParseMalformed();
    TestChannelMapping();
    TestRing();
    TestSendChunking();
    TestResampler();
    TestBlender();
    std::printf("\ncore_tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
