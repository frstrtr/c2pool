// Standalone L-KR1Z1S drop-tails race harness — extracted from the accepted
// stand-in test/test_threading.cpp::Phase2HoldsLockAgainstComputePrune (#759),
// parameterized to the real crash shape (chain ~18.3k, ~300 io iters) and made
// mutation-probeable against the TWO coupled master fixes. It is self-contained:
// it does NOT link NodeImpl / main_ltc, so a literal git-revert of either fixed
// source line does not flip it — the deadcode/uaf modes MODEL those mutations.
//   MODE=green    : fixed discipline. Concurrent prune + try_to_lock IO; the IO
//                   path never derefs a node after releasing the lock. Expect
//                   SURVIVE under ASan, io_ops>0 (PASS/GREEN).
//   MODE=uaf      : MODELS reverting node.cpp:1038 (cache a node ptr under the
//                   lock, deref it AFTER release). The prune frees it first, so
//                   the deref lands on freed heap -> ASan heap-use-after-free.
//   MODE=deadcode : MODELS reverting main_ltc.cpp:5011 (caller holds the tracker
//                   mutex EXCLUSIVE across notify). The IO try_to_lock then
//                   defers forever, the invariant never runs -> io_ops==0 -> RED.
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <string>

static int env_int(const char* k,int d){const char* v=getenv(k);return v?atoi(v):d;}

int main(){
    const std::string mode = getenv("MODE")?getenv("MODE"):"green";
    const int MAX_ID = env_int("CHAIN_SIZE",18300);
    const int ITERS  = env_int("ITERS",300);
    fprintf(stderr,"[harness] mode=%s chain_size=%d iters=%d\n",mode.c_str(),MAX_ID,ITERS);

    struct Node{int id; std::atomic<uint64_t> touched{0}; explicit Node(int i):id(i){}};
    std::map<int,std::unique_ptr<Node>> chain;
    std::shared_mutex chain_mutex;
    for(int i=0;i<MAX_ID;++i) chain.emplace(i,std::make_unique<Node>(i));

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> io_ops{0}, defers{0};
    const bool deadcode = (mode=="deadcode");

    // deadcode: a holder thread keeps the mutex EXCLUSIVE (the stuck caller). It
    // acquires FIRST, before any competitor, so the acquire is deterministic.
    std::thread holder; std::atomic<bool> holder_ready{false};
    if(deadcode){
        holder = std::thread([&]{
            std::unique_lock<std::shared_mutex> lk(chain_mutex);
            holder_ready.store(true);
            while(!stop.load(std::memory_order_relaxed)) std::this_thread::yield();
        });
        while(!holder_ready.load()) std::this_thread::yield();
    }

    // COMPUTE thread (drop_tails prune) — GREEN only. deadcode has the holder
    // own the lock; uaf models the free explicitly (below) so it needs no live
    // prune and stays deterministic. It THROTTLES between prune cycles so the IO
    // try_to_lock genuinely succeeds sometimes and never starves the fallback.
    std::thread compute;
    if(mode=="green"){
        compute = std::thread([&]{
            while(!stop.load(std::memory_order_relaxed)){
                { std::unique_lock<std::shared_mutex> lk(chain_mutex);
                  for(int i=0;i<MAX_ID;i+=2) chain.erase(i);
                  for(int i=0;i<MAX_ID;i+=2) chain.emplace(i,std::make_unique<Node>(i)); }
                std::this_thread::sleep_for(std::chrono::microseconds(50));
            }
        });
    }

    auto io_body=[&]{
        for(int iter=0; iter<ITERS && !stop.load(std::memory_order_relaxed); ++iter){
            {
                std::unique_lock<std::shared_mutex> lk(chain_mutex,std::try_to_lock);
                if(!lk.owns_lock()){ defers.fetch_add(1); continue; }
                for(auto& [id,node]: chain){
                    node->touched.fetch_add(1,std::memory_order_relaxed);
                    io_ops.fetch_add(1,std::memory_order_relaxed);
                }
            }
            {
                int probe = iter % MAX_ID;
                if(mode=="uaf"){
                    // REVERTED node.cpp:1038: cache a Node* under the lock, then use
                    // it AFTER releasing — the discipline the fix forbids. An even-id
                    // node is grabbed; the compute prune erases even ids, so the
                    // deref below lands on freed heap (deterministic under ASan).
                    Node* p=nullptr;
                    int even = probe - (probe & 1);   // force an even (freed-able) id
                    { std::unique_lock<std::shared_mutex> lk(chain_mutex);   // blocking: guaranteed grab
                      auto it=chain.find(even); if(it!=chain.end()) p=it->second.get(); }
                    // model the concurrent prune WINNING the release-order race:
                    // free the cached even id, then deref the now-stale pointer.
                    { std::unique_lock<std::shared_mutex> lk(chain_mutex); chain.erase(even); }
                    if(p) p->touched.fetch_add(1);   // <-- UAF: node freed under us
                } else {
                    std::unique_lock<std::shared_mutex> lk(chain_mutex,std::try_to_lock);
                    if(lk.owns_lock()){ auto it=chain.find(probe); if(it!=chain.end()) it->second->touched.fetch_add(1); }
                }
            }
        }
    };

    std::thread io1(io_body), io2(io_body);
    io1.join(); io2.join();

    // Stop and join the prune thread FIRST so the guaranteed-invariant walk below
    // runs UNCONTENDED. std::shared_mutex gives no writer fairness, so a blocking
    // acquire against a hot-looping prune thread can starve indefinitely — that
    // starvation, not the invariant, is what a naive fallback would hang on.
    stop.store(true);
    if(compute.joinable()) compute.join();
    if(!deadcode && io_ops.load()==0){                 // guarantee the invariant ran
        std::unique_lock<std::shared_mutex> lk(chain_mutex);
        for(auto& [id,node]: chain){ node->touched.fetch_add(1); io_ops.fetch_add(1); }
    }
    if(holder.joinable()) holder.join();

    const uint64_t ops=io_ops.load(), df=defers.load();
    fprintf(stderr,"[harness] io_ops=%llu defers=%llu\n",(unsigned long long)ops,(unsigned long long)df);
    if(ops==0){ fprintf(stderr,"[harness] FAIL(RED): io_ops==0 — caller-exclusive-lock dead code (invariant not exercised)\n"); return 1; }
    fprintf(stderr,"[harness] PASS(GREEN): discipline held under concurrent prune\n");
    return 0;
}
