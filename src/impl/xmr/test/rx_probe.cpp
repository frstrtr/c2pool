// X0 feasibility: measured light-mode (cache-only) RandomX verify cost + a
// real-network end-to-end PoW reproduction, on THIS host.
//
// Links tevador/RandomX (BSD-3-Clause). It (1) proves the RandomX build is
// Monero's algorithm by reproducing the official v1 KAT, then (2) allocates
// ONLY the 256 MiB light cache (NO 2 GiB dataset), and (3) times ONE
// randomx_calculate_hash over the REAL 76-byte hashing_blob of mainnet block
// 3,000,000 keyed by its seed-height block hash -- the exact input Monero's
// own `rx_slow_hash` consumes -- and prints the resulting PoW hash so the
// caller can check it against the block's difficulty.
//
// Build (light single lib, no dataset):
//   cmake -DCMAKE_BUILD_TYPE=Release .. && make -j3 randomx
//   g++ -std=c++20 -O2 rx_probe.cpp -I<rx>/src -L<build> -lrandomx -pthread -o rx_probe

#include "randomx.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <algorithm>
#include <sys/resource.h>
#include <unistd.h>

using clk = std::chrono::steady_clock;
static double ms_since(clk::time_point a){
    return std::chrono::duration<double,std::milli>(clk::now()-a).count();
}
static long rss_kb(){ struct rusage r; getrusage(RUSAGE_SELF,&r); return r.ru_maxrss; } // peak
static double cur_rss_mib(){ // CURRENT resident set, /proc/self/statm (pages)
    long pages=0; FILE*f=fopen("/proc/self/statm","r");
    if(f){ long total; if(fscanf(f,"%ld %ld",&total,&pages)!=2) pages=0; fclose(f);}
    return pages * (double)sysconf(_SC_PAGESIZE) / (1024.0*1024.0);
}
static std::vector<uint8_t> unhex(const std::string&h){
    std::vector<uint8_t> o; for(size_t i=0;i+1<h.size();i+=2)
        o.push_back((uint8_t)strtol(h.substr(i,2).c_str(),nullptr,16)); return o;
}
static void phex(const char*l,const uint8_t*b,int n){
    printf("%s",l); for(int i=0;i<n;i++) printf("%02x",b[i]); printf("\n");
}

int main(){
    randomx_flags flags = randomx_get_flags();     // auto: JIT + HARD_AES + ARGON2 if available
    printf("randomx_flags (auto) = 0x%x  [", (unsigned)flags);
    if(flags & RANDOMX_FLAG_JIT)        printf(" JIT");
    if(flags & RANDOMX_FLAG_HARD_AES)   printf(" HARD_AES");
    if(flags & RANDOMX_FLAG_ARGON2_SSSE3) printf(" ARGON2_SSSE3");
    if(flags & RANDOMX_FLAG_ARGON2_AVX2)  printf(" ARGON2_AVX2");
    if(flags & RANDOMX_FLAG_FULL_MEM)   printf(" FULL_MEM(!)");
#ifdef RANDOMX_FLAG_V2
    if(flags & RANDOMX_FLAG_V2)         printf(" V2(!)");
#endif
    printf(" ]  (LIGHT mode: FULL_MEM deliberately NOT set)\n");
    printf("RANDOMX_HASH_SIZE=%d  (light cache = RANDOMX_ARGON_MEMORY 262144 KiB = 256 MiB)\n",
           RANDOMX_HASH_SIZE);

    // ---------- (2)+(3) real-network light verify + cost, block 3,000,000 ----------
    // Done FIRST so RSS deltas are clean (before any other cache is allocated).
    // seed key = block hash at seed_height 2,998,272 ; input = the 76-B hashing_blob
    auto seed = unhex("3c512c1a6e8210e985b47e855eaf93af952abb61b9bd032872a376910ba7d448");
    auto blob = unhex("1010dea6caa906cc64d29f62794dbb5309732f74447d88389198cfbf86a499bd"
                      "5b4b5347bc43ae2b8000313cc88694451e92299e5283b2c51985e5c0d31b8d91"
                      "0f53d9a8b167a24e7bdf0626");
    printf("\n--- LIGHT-MODE verify of REAL mainnet block 3000000 ---\n");
    printf("seed_height=2998272  seed=%zuB  hashing_blob=%zuB\n", seed.size(), blob.size());
    double rss0 = cur_rss_mib();

    auto t_alloc = clk::now();
    randomx_cache* cache = randomx_alloc_cache(flags);   // 256 MiB, NO dataset
    if(!cache){ printf("alloc_cache FAILED\n"); return 2; }
    double alloc_ms = ms_since(t_alloc);
    double rss_after_alloc = cur_rss_mib();

    auto t_init = clk::now();
    randomx_init_cache(cache, seed.data(), seed.size()); // Argon2d fill (serial)
    double init_ms = ms_since(t_init);
    double rss_after_init = cur_rss_mib();

    randomx_vm* vm = randomx_create_vm(flags, cache, nullptr);  // light VM (cache, no dataset)
    if(!vm){ printf("create_vm FAILED (JIT page perms?) - retrying without JIT\n");
        flags = (randomx_flags)(flags & ~RANDOMX_FLAG_JIT);
        vm = randomx_create_vm(flags, cache, nullptr);
        if(!vm){ printf("create_vm FAILED again\n"); return 3; } }
    double rss_after_vm = cur_rss_mib();

    uint8_t pow[RANDOMX_HASH_SIZE];
    // one cold hash (the number the task asks for), then N to get a stable stat
    auto t1 = clk::now();
    randomx_calculate_hash(vm, blob.data(), blob.size(), pow);
    double first_ms = ms_since(t1);

    const int N = 16;
    std::vector<double> times;
    for(int i=0;i<N;i++){
        auto t = clk::now();
        randomx_calculate_hash(vm, blob.data(), blob.size(), pow);
        times.push_back(ms_since(t));
    }
    std::sort(times.begin(), times.end());
    double med = times[N/2], mn = times.front(), mx = times.back();

    phex("PoW(randomx) = ", pow, RANDOMX_HASH_SIZE);
    printf("  (interpret little-endian; caller checks pow_LE * difficulty(308739704685) < 2^256)\n");
    printf("\n=== MEASURED on THIS host ===\n");
    printf("cache alloc          : %8.2f ms\n", alloc_ms);
    printf("cache init (Argon2d) : %8.2f ms   <- per-epoch (every 2048 blocks), amortized\n", init_ms);
    printf("ONE cold verify hash : %8.2f ms\n", first_ms);
    printf("per-hash min/med/max : %.2f / %.2f / %.2f ms  (N=%d, warm cache)\n", mn, med, mx, N);
    printf("RSS baseline         : %8.1f MiB\n", rss0);
    printf("RSS after cache alloc: %8.1f MiB  (+%.1f)\n", rss_after_alloc, rss_after_alloc-rss0);
    printf("RSS after cache init : %8.1f MiB  (+%.1f = the 256 MiB light cache, touched)\n",
           rss_after_init, rss_after_init-rss_after_alloc);
    printf("RSS after VM create  : %8.1f MiB  (+%.1f = ~2 MiB scratchpad)\n",
           rss_after_vm, rss_after_vm-rss_after_init);
    printf("RSS peak (maxrss)    : %8.1f MiB\n", rss_kb()/1024.0);

    randomx_destroy_vm(vm);
    randomx_release_cache(cache);

    // ---------- (1) official v1 KAT: proves this is Monero's RandomX ----------
    // The reference initCache()/calcStringHash() pass N-1 / H-1 => EXCLUDE the
    // trailing NUL of the string literal. Reproduce that exactly.
    {
        printf("\n--- official RandomX v1 KAT ---\n");
        const char key[]   = "test key 000";      // use sizeof-1 = 12 bytes
        const char input[] = "This is a test";    // use sizeof-1 = 14 bytes
        randomx_cache* c = randomx_alloc_cache(flags);
        randomx_init_cache(c, key, sizeof(key)-1);
        randomx_vm* vmk = randomx_create_vm(flags, c, nullptr);
        uint8_t h[RANDOMX_HASH_SIZE];
        randomx_calculate_hash(vmk, input, sizeof(input)-1, h);
        randomx_destroy_vm(vmk); randomx_release_cache(c);
        phex("KAT  computed = ", h, RANDOMX_HASH_SIZE);
        printf("KAT  expected = 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f  (RandomX v1)\n");
        static const uint8_t want[32] = {
            0x63,0x91,0x83,0xaa,0xe1,0xbf,0x4c,0x9a,0x35,0x88,0x4c,0xb4,0x6b,0x09,0xca,0xd9,
            0x17,0x5f,0x04,0xef,0xd7,0x68,0x4e,0x72,0x62,0xa0,0xac,0x1c,0x2f,0x0b,0x4e,0x3f};
        printf("KAT  %s\n", memcmp(h,want,32)==0 ? "MATCH  -> build is Monero's RandomX v1"
                                                 : "MISMATCH  !!!");
    }
    return 0;
}
