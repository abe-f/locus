#include "pin.H"
#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

namespace {

KNOB<UINT32> KnobPageShift(KNOB_MODE_WRITEONCE, "pintool",
    "pageshift", "12", "Page shift (12 for 4KiB pages)");
KNOB<BOOL>   KnobRecordWrites(KNOB_MODE_WRITEONCE, "pintool",
    "record_writes", "0", "Also count stores (default 0 = loads only)");
KNOB<UINT64> KnobReservePerThread(KNOB_MODE_WRITEONCE, "pintool",
    "reserve_per_thread", "1000000", "Initial per-thread hashmap bucket hint");

// Base: 'outputs/results'; tool creates results<N>/ and puts all PIDs under it.
KNOB<std::string> KnobResultsBase(KNOB_MODE_WRITEONCE, "pintool",
    "results_base", "outputs/results", "Base path; tool creates results<N>/results<PID>/");

KNOB<std::string> KnobControlFile(KNOB_MODE_WRITEONCE, "pintool",
    "control_file", "outputs/ctl.txt", "Text file with commands: start|stop|quit");
KNOB<UINT32> KnobPollMs(KNOB_MODE_WRITEONCE, "pintool",
    "poll_ms", "200", "Polling interval in ms for control file");
KNOB<BOOL>   KnobStartEnabled(KNOB_MODE_WRITEONCE, "pintool",
    "start_enabled", "1", "Start with counting enabled (set 0 to start paused)");
KNOB<BOOL>   KnobLogCommands(KNOB_MODE_WRITEONCE, "pintool",
    "log_commands", "0", "If 1, log control commands to stderr");

using VpnT   = uint64_t;
using CntT   = uint64_t;
using VpnMap = std::unordered_map<VpnT, CntT>;

TLS_KEY g_tls_key;
struct ThreadData {
    THREADID tid;
    VpnMap   counts;
    ThreadData(THREADID t, size_t reserve_hint) : tid(t) {
        if (reserve_hint) counts.reserve(reserve_hint);
    }
};
static inline ThreadData* TD(THREADID tid) {
    return static_cast<ThreadData*>(PIN_GetThreadData(g_tls_key, tid));
}

std::mutex g_threads_mu;
std::vector<ThreadData*> g_threads;
std::atomic<bool> g_collecting{true};

static inline VpnT AddrToVpn(ADDRINT addr, UINT32 page_shift) {
    return static_cast<VpnT>(static_cast<uint64_t>(addr) >> page_shift);
}
static bool MkdirIfNeeded(const std::string& path, mode_t mode = 0755) {
    if (path.empty()) return false;
    struct stat st;
    if (::stat(path.c_str(), &st) == 0) return S_ISDIR(st.st_mode);
    return ::mkdir(path.c_str(), mode) == 0;
}
// Create outputs/results<N> using mkdir loop
static std::string NextResultsRoot(const std::string& base) {
    auto slash = base.find_last_of('/');
    if (slash != std::string::npos) MkdirIfNeeded(base.substr(0, slash));
    else MkdirIfNeeded(".");
    for (uint64_t n = 0;; ++n) {
        std::string root = base + std::to_string(static_cast<unsigned long long>(n));
        if (::mkdir(root.c_str(), 0755) == 0) return root;
        if (errno == EEXIST) { continue; }
        std::perror(("mkdir " + root).c_str());
        MkdirIfNeeded(base);
        return base;
    }
}
// Shared results root for all processes in a run.
// Parent picks it once and exports via LOCUS_RESULTS_ROOT so fork/exec children reuse it.
static std::string GetResultsRoot() {
    static std::string g_root;
    if (!g_root.empty()) return g_root;
    const char* env = std::getenv("LOCUS_RESULTS_ROOT");
    if (env && *env) {
        g_root = env;
        MkdirIfNeeded(g_root);
        return g_root;
    }
    const std::string base = KnobResultsBase.Value();
    g_root = NextResultsRoot(base);
    ::setenv("LOCUS_RESULTS_ROOT", g_root.c_str(), 1);
    return g_root;
}
// Read command name (short) from /proc/self/comm, minimal and robust.
static std::string ReadComm() {
    std::ifstream in("/proc/self/comm", std::ios::in | std::ios::binary);
    if (!in) return "";
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    while (!s.empty() && (s.back()=='\n' || s.back()=='\r')) s.pop_back();
    return s;
}

static inline VOID CountVpn(VpnMap& m, VpnT vpn) {
    auto it = m.find(vpn);
    if (it != m.end()) it->second += 1;
    else m.emplace(vpn, 1);
}
static VOID RecordRead(THREADID tid, VOID* addr, UINT32 /*size*/) {
    if (!g_collecting.load(std::memory_order_relaxed)) return;
    ThreadData* td = TD(tid);
    if (td) CountVpn(td->counts, AddrToVpn(reinterpret_cast<ADDRINT>(addr), KnobPageShift.Value()));
}
static VOID RecordRead2(THREADID tid, VOID* addr, UINT32 /*size*/) { RecordRead(tid, addr, 0); }
static VOID RecordWrite(THREADID tid, VOID* addr, UINT32 /*size*/) {
    if (!KnobRecordWrites.Value()) return;
    if (!g_collecting.load(std::memory_order_relaxed)) return;
    ThreadData* td = TD(tid);
    if (td) CountVpn(td->counts, AddrToVpn(reinterpret_cast<ADDRINT>(addr), KnobPageShift.Value()));
}
static VOID InsInstrument(INS ins, VOID*) {
    if (INS_IsMemoryRead(ins)) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordRead,
            IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }
    if (INS_HasMemoryRead2(ins)) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordRead2,
            IARG_THREAD_ID, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }
    if (INS_IsMemoryWrite(ins)) {
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWrite,
            IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
    }
}

struct Header {
    uint32_t magic;       // "LOCS" = 0x4C4F4353
    uint32_t version;     // = 1
    uint32_t page_shift;  // knob
    uint32_t reserved;    // 0
    uint64_t thread_count;
    uint64_t total_entries; // distinct vpns across all threads
};
struct ThreadBlockHeader {
    uint32_t tid;
    uint32_t reserved;    // 0
    uint64_t n_entries;   // distinct pages for this thread
};

static VOID DumpResultsOnce() {
    const pid_t pid = getpid();

    const std::string root = GetResultsRoot();
    const std::string procdir = root + "/results" + std::to_string(static_cast<unsigned long long>(pid));
    MkdirIfNeeded(procdir);
    const std::string outfile = procdir + "/results.out";

    std::vector<ThreadData*> threads;
    { std::lock_guard<std::mutex> lock(g_threads_mu); threads = g_threads; }
    std::sort(threads.begin(), threads.end(),
              [](const ThreadData* a, const ThreadData* b){ return a->tid < b->tid; });

    uint64_t total_entries = 0;
    uint64_t total_accesses = 0;
    for (auto* td : threads) {
        total_entries += td->counts.size();
        for (const auto& kv : td->counts) total_accesses += kv.second;
    }

    std::FILE* f = std::fopen(outfile.c_str(), "wb");
    if (!f) { std::perror(("fopen " + outfile).c_str()); return; }

    Header hdr{0x4C4F4353u, 1u, KnobPageShift.Value(), 0u,
               static_cast<uint64_t>(threads.size()), total_entries};
    if (std::fwrite(&hdr, sizeof(hdr), 1, f) != 1) { std::perror("fwrite hdr"); std::fclose(f); return; }

    for (auto* td : threads) {
        ThreadBlockHeader th{static_cast<uint32_t>(td->tid), 0u, static_cast<uint64_t>(td->counts.size())};
        if (std::fwrite(&th, sizeof(th), 1, f) != 1) { std::perror("fwrite th"); std::fclose(f); return; }
        for (const auto& kv : td->counts) {
            if (std::fwrite(&kv.first,  sizeof(kv.first),  1, f) != 1) { std::perror("fwrite vpn");   std::fclose(f); return; }
            if (std::fwrite(&kv.second, sizeof(kv.second), 1, f) != 1) { std::perror("fwrite count"); std::fclose(f); return; }
        }
    }
    std::fclose(f);

    // Compact info file
    std::ofstream info(procdir + "/results.info.txt");
    if (info) {
        info << "results.out is binary.\n";
        info << "Header { magic='LOCS', version=1, page_shift=" << KnobPageShift.Value()
             << ", thread_count=" << threads.size()
             << ", total_entries=" << total_entries
             << " }\n";
        info << "Total_accesses: " << total_accesses << "\n";
        info << "PID: " << static_cast<unsigned long long>(pid) << "\n";
        info << "Command: " << ReadComm() << "\n";
    }
}

static VOID ThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    auto* td = new ThreadData(tid, static_cast<size_t>(KnobReservePerThread.Value()));
    PIN_SetThreadData(g_tls_key, td, tid);
    { std::lock_guard<std::mutex> lock(g_threads_mu); g_threads.push_back(td); }
}
static VOID ThreadFini(THREADID, const CONTEXT*, INT32, VOID*) { }

static VOID ControlThread(VOID* arg) {
    const char* path = static_cast<const char*>(arg);

    std::string p(path);
    auto s = p.find_last_of('/');
    if (s != std::string::npos) MkdirIfNeeded(p.substr(0, s));
    { std::ofstream init(path, std::ios::out | std::ios::trunc); }

    const useconds_t sleep_us = KnobPollMs.Value() * 1000u;
    const bool log = KnobLogCommands.Value();

    while (true) {
        std::ifstream in(path);
        if (in) {
            std::string content((std::istreambuf_iterator<char>(in)),
                                 std::istreambuf_iterator<char>());
            in.close();

            if (!content.empty()) {
                const char* c = content.c_str();
                while (*c) {
                    while (*c && std::isspace(static_cast<unsigned char>(*c))) ++c;
                    const char* start = c;
                    while (*c && !std::isspace(static_cast<unsigned char>(*c))) ++c;
                    std::string cmd(start, c - start);
                    if (cmd.empty()) break;

                    if (cmd == "start") {
                        g_collecting.store(true, std::memory_order_relaxed);
                        if (log) std::cerr << "[locus] command: start\n";
                    } else if (cmd == "stop") {
                        g_collecting.store(false, std::memory_order_relaxed);
                        if (log) std::cerr << "[locus] command: stop + dump\n";
                        DumpResultsOnce();
                    } else if (cmd == "quit") {
                        if (log) std::cerr << "[locus] command: quit (dump+exit)\n";
                        DumpResultsOnce();
                        PIN_ExitProcess(0);
                    } else {
                        if (log) std::cerr << "[locus] unknown command: " << cmd << "\n";
                    }
                }
                std::ofstream truncf(path, std::ios::out | std::ios::trunc);
            }
        }
        usleep(sleep_us);
    }
}

static BOOL FollowChild(CHILD_PROCESS child, VOID* /*userData*/) {
    // For execv()-spawned children; enabled when pin is run with -follow_execv 1
    (void)child;
    return TRUE;
}

// Fork handling
static VOID BeforeFork(THREADID, const CONTEXT*, VOID*) { }
static VOID AfterForkInParent(THREADID, const CONTEXT*, VOID*) { }
static VOID AfterForkInChild(THREADID tid, const CONTEXT*, VOID*) {
    // Reset per-process state in the child after fork
    {
        std::lock_guard<std::mutex> lock(g_threads_mu);
        for (auto* td : g_threads) delete td;
        g_threads.clear();
    }
    auto* td = new ThreadData(tid, static_cast<size_t>(KnobReservePerThread.Value()));
    PIN_SetThreadData(g_tls_key, td, tid);
    { std::lock_guard<std::mutex> lock(g_threads_mu); g_threads.push_back(td); }

    // Re-spawn control thread in child
    static std::string ctl_storage_child;
    ctl_storage_child = KnobControlFile.Value();
    if (!ctl_storage_child.empty()) {
        PIN_SpawnInternalThread(ControlThread, (VOID*)ctl_storage_child.c_str(), 0, NULL);
    }
    // results root is inherited via LOCUS_RESULTS_ROOT env var
}

static INT32 Usage() {
    std::cerr << "Locus pintool (shared results<N> per run; per-PID subdirs; control file; follows execv; handles fork).\n"
              << "Knobs:\n"
              << "  -pageshift N          (default 12)\n"
              << "  -record_writes 0|1    (default 0)\n"
              << "  -reserve_per_thread N (default 1000000)\n"
              << "  -results_base PATH    (default outputs/results; tool writes results<N>/results<PID>/)\n"
              << "  -control_file PATH    (default outputs/ctl.txt)\n"
              << "  -poll_ms N            (default 200)\n"
              << "  -start_enabled 0|1    (default 1)\n"
              << "  -log_commands 0|1     (default 0)\n";
    return -1;
}

} // namespace

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) return Usage();

    MkdirIfNeeded("outputs");
    g_collecting.store(KnobStartEnabled.Value() != 0, std::memory_order_relaxed);

    // Pick shared results root early; export to env so execv children reuse it.
    (void)GetResultsRoot();

    // Follow execv children when pin is run with -follow_execv 1
    PIN_AddFollowChildProcessFunction(FollowChild, 0);

    // Handle forked children that do not exec
    PIN_AddForkFunction(FPOINT_BEFORE,          BeforeFork,         0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, AfterForkInParent,  0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD,  AfterForkInChild,   0);

    // Launch control thread for this process
    static std::string ctl_storage;
    ctl_storage = KnobControlFile.Value();
    if (!ctl_storage.empty()) {
        PIN_SpawnInternalThread(ControlThread, (VOID*)ctl_storage.c_str(), 0, NULL);
    }

    g_tls_key = PIN_CreateThreadDataKey(nullptr);
    INS_AddInstrumentFunction(InsInstrument, nullptr);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);
    PIN_AddFiniFunction([](INT32, VOID*) { DumpResultsOnce(); }, nullptr);

    PIN_StartProgram();
    return 0;
}