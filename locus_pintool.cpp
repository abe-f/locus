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
KNOB<std::string> KnobResultsBase(KNOB_MODE_WRITEONCE, "pintool",
    "results_base", "outputs/results", "Base path; tool creates results<NN>/ then per-PID subdirs");
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
std::atomic<bool> g_instr_on{true};
static UINT32 g_page_shift = 12;
static BOOL   g_count_writes = FALSE;

static std::string g_results_base_abs;
static std::string g_control_file_abs;
static std::string g_launcher_cwd;

static inline VpnT AddrToVpn(ADDRINT addr, UINT32 page_shift) {
    return static_cast<VpnT>(static_cast<uint64_t>(addr) >> page_shift);
}

static bool MkdirIfNeededMode(const std::string& path, mode_t mode) {
    if (path.empty()) return false;
    struct stat st;
    if (::stat(path.c_str(), &st) == 0) return S_ISDIR(st.st_mode);
    return ::mkdir(path.c_str(), mode) == 0;
}

static std::string MakeAbsolute(const std::string& p) {
    if (!p.empty() && p[0] == '/') return p;
    if (g_launcher_cwd.empty()) return p;
    return g_launcher_cwd + "/" + p;
}

static std::string NextResultsRoot(const std::string& base_abs) {
    auto slash = base_abs.find_last_of('/');
    if (slash != std::string::npos) MkdirIfNeededMode(base_abs.substr(0, slash), 01777);
    else MkdirIfNeededMode(".", 01777);
    for (uint64_t n = 0;; ++n) {
        std::string root = base_abs + std::to_string(static_cast<unsigned long long>(n));
        if (::mkdir(root.c_str(), 01777) == 0) return root;
        if (errno == EEXIST) { continue; }
        std::perror(("mkdir " + root).c_str());
        MkdirIfNeededMode(base_abs, 01777);
        return base_abs;
    }
}

static std::string GetResultsRoot() {
    static std::string g_root;
    if (!g_root.empty()) return g_root;
    const char* env = std::getenv("LOCUS_RESULTS_ROOT");
    if (env && *env) {
        g_root = env;
        MkdirIfNeededMode(g_root, 01777);
        return g_root;
    }
    const std::string base_abs = g_results_base_abs;
    g_root = NextResultsRoot(base_abs);
    ::setenv("LOCUS_RESULTS_ROOT", g_root.c_str(), 1);
    return g_root;
}

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

static VOID PIN_FAST_ANALYSIS_CALL RecordRead(THREADID tid, ADDRINT addr) {
    if (!g_collecting.load(std::memory_order_relaxed)) return;
    ThreadData* td = TD(tid);
    if (td) CountVpn(td->counts, (VpnT)((uint64_t)addr >> g_page_shift));
}

static VOID PIN_FAST_ANALYSIS_CALL RecordWrite(THREADID tid, ADDRINT addr) {
    if (!g_count_writes) return;
    if (!g_collecting.load(std::memory_order_relaxed)) return;
    ThreadData* td = TD(tid);
    if (td) CountVpn(td->counts, (VpnT)((uint64_t)addr >> g_page_shift));
}

static VOID Trace(TRACE trace, VOID*) {
    if (!g_instr_on.load(std::memory_order_relaxed)) return;
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsMemoryRead(ins)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordRead,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_END);
            }
            if (INS_HasMemoryRead2(ins)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordRead,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID, IARG_MEMORYREAD2_EA, IARG_END);
            }
            if (g_count_writes && INS_IsMemoryWrite(ins)) {
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWrite,
                    IARG_FAST_ANALYSIS_CALL,
                    IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_END);
            }
        }
    }
}

struct Header {
    uint32_t magic;
    uint32_t version;
    uint32_t page_shift;
    uint32_t reserved;
    uint64_t thread_count;
    uint64_t total_entries;
};
struct ThreadBlockHeader {
    uint32_t tid;
    uint32_t reserved;
    uint64_t n_entries;
};

static VOID DumpResultsOnce() {
    const pid_t pid = getpid();
    const std::string procdir = GetResultsRoot() + "/results" + std::to_string(static_cast<unsigned long long>(pid));
    MkdirIfNeededMode(procdir, 01777);
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

    Header hdr{0x4C4F4353u, 1u, g_page_shift, 0u,
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

    std::ofstream info(procdir + "/results.info.txt");
    if (info) {
        info << "results.out is binary.\n";
        info << "Header { magic='LOCS', version=1, page_shift=" << g_page_shift
             << ", thread_count=" << threads.size()
             << ", total_entries=" << total_entries
             << " }\n";
        info << "Total_accesses: " << total_accesses << "\n";
        info << "PID: " << static_cast<unsigned long long>(pid) << "\n";
        info << "Command: " << ReadComm() << "\n";
    }
}

static BOOL SignalHandler(THREADID, INT32, CONTEXT*, BOOL, const EXCEPTION_INFO*, VOID*) {
    g_collecting.store(false, std::memory_order_relaxed);
    g_instr_on.store(false, std::memory_order_relaxed);
    PIN_RemoveInstrumentation();
    DumpResultsOnce();
    return TRUE;
}

static VOID ThreadStart(THREADID tid, CONTEXT*, INT32, VOID*) {
    auto* td = new ThreadData(tid, static_cast<size_t>(KnobReservePerThread.Value()));
    PIN_SetThreadData(g_tls_key, td, tid);
    { std::lock_guard<std::mutex> lock(g_threads_mu); g_threads.push_back(td); }
}
static VOID ThreadFini(THREADID, const CONTEXT*, INT32, VOID*) { }

static VOID ControlThread(VOID*) {
    const char* path = g_control_file_abs.c_str();

    std::string p(path);
    auto s = p.find_last_of('/');
    if (s != std::string::npos) MkdirIfNeededMode(p.substr(0, s), 01777);
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
                        g_instr_on.store(true, std::memory_order_relaxed);
                        PIN_RemoveInstrumentation();
                        if (log) std::cerr << "[locus] command: start (reinstrument)\n";
                    } else if (cmd == "stop") {
                        g_collecting.store(false, std::memory_order_relaxed);
                        g_instr_on.store(false, std::memory_order_relaxed);
                        PIN_RemoveInstrumentation();
                        if (log) std::cerr << "[locus] command: stop + dump (deinstrument)\n";
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

static BOOL FollowChild(CHILD_PROCESS child, VOID*) {
    (void)child;
    return TRUE;
}

static VOID BeforeFork(THREADID, const CONTEXT*, VOID*) { }
static VOID AfterForkInParent(THREADID, const CONTEXT*, VOID*) { }
static VOID AfterForkInChild(THREADID tid, const CONTEXT*, VOID*) {
    {
        std::lock_guard<std::mutex> lock(g_threads_mu);
        for (auto* td : g_threads) delete td;
        g_threads.clear();
    }
    auto* td = new ThreadData(tid, static_cast<size_t>(KnobReservePerThread.Value()));
    PIN_SetThreadData(g_tls_key, td, tid);
    { std::lock_guard<std::mutex> lock(g_threads_mu); g_threads.push_back(td); }

    PIN_SpawnInternalThread(ControlThread, nullptr, 0, NULL);
}

static INT32 Usage() {
    std::cerr << "Locus pintool (shared results<NN> per run; per-PID subdirs; control file; follows execv; handles fork).\n"
              << "Knobs:\n"
              << "  -pageshift N          (default 12)\n"
              << "  -record_writes 0|1    (default 0)\n"
              << "  -reserve_per_thread N (default 1000000)\n"
              << "  -results_base PATH    (default outputs/results; tool writes results<NN>/resultsPID/)\n"
              << "  -control_file PATH    (default outputs/ctl.txt)\n"
              << "  -poll_ms N            (default 200)\n"
              << "  -start_enabled 0|1    (default 1)\n"
              << "  -log_commands 0|1     (default 0)\n";
    return -1;
}

} // namespace

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) return Usage();

    PIN_InterceptSignal(SIGINT,  SignalHandler, 0);
    PIN_InterceptSignal(SIGTERM, SignalHandler, 0);
    PIN_InterceptSignal(SIGQUIT, SignalHandler, 0);

    char cwd_buf[4096]; if (::getcwd(cwd_buf, sizeof(cwd_buf))) g_launcher_cwd = cwd_buf;
    g_results_base_abs = MakeAbsolute(KnobResultsBase.Value());
    g_control_file_abs = MakeAbsolute(KnobControlFile.Value());

    g_page_shift   = KnobPageShift.Value();
    g_count_writes = KnobRecordWrites.Value();

    g_collecting.store(KnobStartEnabled.Value() != 0, std::memory_order_relaxed);
    g_instr_on.store(KnobStartEnabled.Value() != 0, std::memory_order_relaxed);

    (void)GetResultsRoot();

    PIN_AddFollowChildProcessFunction(FollowChild, 0);
    PIN_AddForkFunction(FPOINT_BEFORE,          BeforeFork,         0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, AfterForkInParent,  0);
    PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD,  AfterForkInChild,   0);

    PIN_SpawnInternalThread(ControlThread, nullptr, 0, NULL);

    g_tls_key = PIN_CreateThreadDataKey(nullptr);
    TRACE_AddInstrumentFunction(Trace, nullptr);
    PIN_AddThreadStartFunction(ThreadStart, nullptr);
    PIN_AddThreadFiniFunction(ThreadFini, nullptr);
    PIN_AddFiniFunction([](INT32, VOID*) { DumpResultsOnce(); }, nullptr);

    PIN_StartProgram();
    return 0;
}