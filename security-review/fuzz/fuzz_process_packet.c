/*
 * Fuzz harness for the Argus sensor's top-level packet-processing entry point.
 *
 * Target: ArgusProcessPacket(struct ArgusSourceStruct *, char *, int, struct timeval *, int)
 *         (argus/ArgusModeler.c:1629)
 *
 * This is the function called directly from every pcap/live-capture dispatch path in
 * ArgusSource.c immediately after a packet is captured (see e.g. ArgusSource.c:2734,
 * "ArgusProcessPacket (src, (char *)ep, length, tvp, ARGUS_ETHER_HDR)"). Feeding it a raw
 * Ethernet-framed buffer exercises the entire protocol-dispatch tree reachable from
 * ArgusProcessPacketHdrs() in ArgusModeler.c -- IP/IPv6, TCP, UDP, ICMP, IGMP, ARP, GRE, ESP,
 * fragmentation reassembly, VLAN/MPLS, and (via UDP payload dispatch) NetFlow/sFlow parsing --
 * without needing a live interface, root privileges, or a real pcap handle.
 *
 * This harness replicates the minimal startup sequence performed by argus.c's main() at
 * argus/argus.c:422-431 (ArgusNewModeler -> ArgusNewSource -> ArgusNewDump -> ArgusNewOutput
 * -> ArgusInitModeler), skipping everything CLI/config/privilege/socket-related that isn't
 * needed to reach the parser code.
 *
 * Build: see security-review/fuzz/build.sh
 * Run (AFL persistent mode):
 *   afl-fuzz -i security-review/fuzz/corpus -o security-review/fuzz/out -- \
 *     security-review/fuzz/fuzz_process_packet
 */

#define Argus

#include <argus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ArgusProcessPacket is declared 'extern int' in ArgusModeler.c but is NOT exposed in
 * ArgusModeler.h's public prototype list (it's an internal dispatch function called only
 * from ArgusSource.c). Declare it here to link against the real definition in the compiled
 * ArgusModeler.o. */
extern int ArgusProcessPacket(struct ArgusSourceStruct *, char *, int, struct timeval *, int);

/* The following globals/functions are normally defined in argus/argus.c, which this harness
 * deliberately does not compile/link (it has main() and CLI/config/privilege-drop code we
 * don't want). They are referenced by ArgusModeler.c/ArgusSource.c/ArgusOutput.c's compiled
 * code paths that are reachable from ArgusProcessPacket even though packet processing itself
 * doesn't functionally need them (mostly shutdown-flag checks, PID-file/thread-attr plumbing,
 * and control-plane-monitoring mode). Minimal, faithful stand-ins, matching the real
 * definitions' types exactly (confirmed via grep against argus/argus.c). */
int ArgusShutDownFlag = 0;
char *ArgusPidFile = NULL;
char *ArgusPidPath = NULL;
#if defined(ARGUS_THREADS)
pthread_attr_t argus_harness_attrbuf;
pthread_attr_t *ArgusAttr = &argus_harness_attrbuf;
#endif

void
ArgusBacktrace(void)
{
   /* real implementation (argus.c) prints a backtrace via backtrace()/backtrace_symbols();
    * not needed for fuzzing -- ASan/UBSan provide much better crash diagnostics already. */
}

char *
ArgusCopyArgv(char **argv)
{
   (void) argv;
   return NULL;
}

char *
ArgusCreatePIDFile(struct ArgusSourceStruct *src, char *pidpath, char *appname)
{
   (void) src; (void) pidpath; (void) appname;
   return NULL;
}

int
getArguspidflag(void)
{
   return 0;
}

int
getArgusControlMonitor(struct ArgusModelerStruct *model)
{
   /* real implementation (argus.c:2153-2156) just returns model->ArgusControlMonitor */
   return model->ArgusControlMonitor;
}


/* ARGUS_ETHER_HDR is defined in ArgusModeler.h (#define ARGUS_ETHER_HDR 1) -- confirmed by
 * grep against the real header, matching the value used for standard live Ethernet capture
 * throughout ArgusSource.c. */

static struct ArgusSourceStruct *g_src;

/* Bound packet size to something realistic -- real interfaces cap at the configured snaplen
 * (ARGUS_MINSNAPLEN default, or whatever -s specifies; jumbo frames can be up to ~9000 bytes).
 * AFL will explore lengths up to this bound; libpcap's own max caplen is used as a ceiling. */
#define MAX_PACKET_LEN 65535

static void
argus_harness_init(void)
{
   struct ArgusModelerStruct *model;

   /* Mirrors argus/argus.c:422-436 */
   if ((model = ArgusNewModeler()) == NULL) {
      fprintf(stderr, "harness: ArgusNewModeler failed\n");
      exit(1);
   }
   ArgusModel = model;

   if ((g_src = ArgusNewSource(model)) == NULL) {
      fprintf(stderr, "harness: ArgusNewSource failed\n");
      exit(1);
   }

   if ((ArgusDumpTask = ArgusNewDump(g_src, NULL)) == NULL) {
      fprintf(stderr, "harness: ArgusNewDump failed\n");
      exit(1);
   }

   model->ArgusSrc = g_src;

   if ((ArgusOutputTask = ArgusNewOutput(g_src, model)) == NULL) {
      fprintf(stderr, "harness: ArgusNewOutput failed\n");
      exit(1);
   }

   /* ArgusInitModeler requires model->ArgusSrc (set above) and ArgusOutputTask (set above)
    * to already exist -- see ArgusModeler.c:189-288, specifically the
    * "model->ArgusOutputList = ArgusOutputTask->ArgusInputList;" dependency. */
   ArgusInitModeler(model);

   /* The real capture path (ArgusOpenInterface / ArgusOpenDevice, ArgusSource.c) populates
    * src->ArgusInterface[i].ArgusDevice with a live device's srcid/transport info before any
    * packet ever reaches ArgusProcessPacket -- see e.g. ArgusModeler.c:2276
    * ("model->ArgusSrc->ArgusInterface[model->ArgusSrc->ArgusThisIndex].ArgusDevice"), which
    * is dereferenced unconditionally when building the ARGUS_TRANSPORT_INDEX DSR for every
    * flow. Since this harness bypasses interface-opening entirely, provide a minimal
    * zero-initialized stand-in (a device with no configured srcid is a valid, if minimal,
    * real-world state -- matches an interface that hasn't had ARGUS_MONITOR_ID/-e set). */
   {
      struct ArgusDeviceStruct *dev = (struct ArgusDeviceStruct *) calloc(1, sizeof(*dev));
      if (dev == NULL) {
         fprintf(stderr, "harness: calloc ArgusDeviceStruct failed\n");
         exit(1);
      }
      g_src->ArgusThisIndex = 0;
      g_src->ArgusInterface[0].ArgusDevice = dev;
   }

   /* Silence debug/log output during fuzzing -- keep stderr clean, avoid slowing down runs.
    * setArgusLogDisplayPriority() gates what ArgusLog() actually prints (see argus_util.c,
    * ArgusLogDisplayPriority is 'static' there -- must go through the setter, not a direct
    * extern reference). */
   setArgusLogDisplayPriority(0);
}

/* One fuzzed iteration: feed `data` (of length `len`) to ArgusProcessPacket as a raw
 * Ethernet-framed packet buffer, exactly as ArgusSource.c's live-capture dispatch does. */

/* Diagnostic aid for reproducing stateful/cross-packet crashes found by AFL's
 * persistent-mode loop (which reuses model/flow-table state across many packets within
 * one forked child, unlike a single-input replay): keep a small ring buffer of the most
 * recently processed packets, and on an ASan-detected error, dump them in order so the
 * exact preceding sequence can be replayed later via the plain multi-file harness mode.
 * Enabled by setting AFL_SEQ_LOG_DIR; ring size via AFL_SEQ_LOG_RING (default 64). */
#define SEQ_RING_MAX 4096
static unsigned char *seq_ring[SEQ_RING_MAX];
static size_t seq_ring_len[SEQ_RING_MAX];
static int seq_ring_size = 64;
static int seq_ring_head = 0;
static long seq_ring_total = 0;
static const char *seq_log_dir = NULL;

/* ASan/UBSan runtime hook: invoked just before the process aborts on a detected error
 * (see sanitizer/common_interface_defs.h). Declared here rather than including the full
 * sanitizer header, to keep this diagnostic addition minimal. */
extern void __sanitizer_set_death_callback(void (*callback)(void));

static void
seq_ring_dump_and_die(void)
{
   char path[512];
   int i, n;

   if (seq_log_dir == NULL)
      return;

   n = (seq_ring_total < seq_ring_size) ? (int) seq_ring_total : seq_ring_size;
   for (i = 0; i < n; i++) {
      /* oldest-first order */
      int idx = (seq_ring_head - n + i + seq_ring_size) % seq_ring_size;
      FILE *sf;
      if (seq_ring[idx] == NULL)
         continue;
      snprintf(path, sizeof(path), "%s/pid%d_seq_%04d.bin", seq_log_dir, (int) getpid(), i);
      sf = fopen(path, "wb");
      if (sf != NULL) {
         fwrite(seq_ring[idx], 1, seq_ring_len[idx], sf);
         fclose(sf);
      }
   }
   fprintf(stderr, "[seq_ring] dumped %d packet(s) (of %ld total processed by this pid) to %s\n",
           n, seq_ring_total, seq_log_dir);
}

static void
seq_ring_record(const unsigned char *data, size_t len)
{
   if (seq_log_dir == NULL)
      return;
   free(seq_ring[seq_ring_head]);
   seq_ring[seq_ring_head] = (unsigned char *) malloc(len);
   if (seq_ring[seq_ring_head] != NULL)
      memcpy(seq_ring[seq_ring_head], data, len);
   seq_ring_len[seq_ring_head] = len;
   seq_ring_head = (seq_ring_head + 1) % seq_ring_size;
   seq_ring_total++;
}

static void
seq_ring_init_once(void)
{
   static int done = 0;
   if (done) return;
   done = 1;
   seq_log_dir = getenv("AFL_SEQ_LOG_DIR");
   if (seq_log_dir != NULL) {
      const char *r = getenv("AFL_SEQ_LOG_RING");
      if (r != NULL) {
         int v = atoi(r);
         if (v > 0 && v <= SEQ_RING_MAX)
            seq_ring_size = v;
      }
      __sanitizer_set_death_callback(seq_ring_dump_and_die);
   }
}

static void
argus_harness_run_one(const unsigned char *data, size_t len)
{
   struct ArgusModelerStruct *model = g_src->ArgusModel;
   struct timeval tvp;
   /* AFL/libFuzzer buffers are read-only/const; ArgusProcessPacket's signature takes a
    * non-const char *, and the parser code does write into DSR/canonicalization structures
    * but --- per the real capture path in ArgusSource.c --- does not require writing back
    * into the *packet* buffer itself for standard Ethernet dispatch, aside from a few
    * decapsulation-in-place patterns; to be safe (and to mirror the real caller, which passes
    * a mutable capture buffer) we copy into a local heap buffer for each iteration. */
   unsigned char *buf;

   if (len == 0 || len > MAX_PACKET_LEN)
      return;

   seq_ring_init_once();
   seq_ring_record(data, len);

   buf = (unsigned char *) malloc(len);
   if (buf == NULL)
      return;
   memcpy(buf, data, len);

   gettimeofday(&tvp, NULL);

   /* Mirrors ArgusSource.c:2725-2731 (ArgusReadDLTRawSocket... family) exactly:
    *   src->ArgusModel->ArgusThisLength  = length;
    *   src->ArgusModel->ArgusSnapLength  = caplen;
    *   src->ArgusModel->ArgusThisSnapEnd = ((u_char *)ep) + caplen;
    *   src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_ETHER;
    * Using len for both "on-the-wire length" and "captured length" (caplen), the common case
    * when the whole packet was captured (no truncation). */
   model->ArgusThisLength  = (int) len;
   model->ArgusSnapLength  = (int) len;
   model->ArgusThisSnapEnd = buf + len;
   model->ArgusThisEncaps  = ARGUS_ENCAPS_ETHER;

   (void) ArgusProcessPacket(g_src, (char *) buf, (int) len, &tvp, ARGUS_ETHER_HDR);

   free(buf);
}

#ifdef __AFL_FUZZ_TESTCASE_LEN
/* AFL++ persistent-mode ("deferred fork server") harness -- avoids re-forking/re-init'ing
 * the modeler for every single test case, which would otherwise dominate runtime given how
 * much state ArgusInitModeler() allocates. See afl++ docs: "Persistent mode". */
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv)
{
   (void) argc; (void) argv;

   argus_harness_init();

#ifdef __AFL_HAVE_MANUAL_CONTROL
   __AFL_INIT();
#endif

   unsigned char *afl_buf = __AFL_FUZZ_TESTCASE_BUF;

   while (__AFL_LOOP(10000)) {
      int len = __AFL_FUZZ_TESTCASE_LEN;
      if (len < 0)
         continue;
      argus_harness_run_one(afl_buf, (size_t) len);
   }

   return 0;
}

#else
/* Plain, non-persistent-mode fallback -- also usable directly as a standalone reproducer:
 *   ./fuzz_process_packet <crash-input-file>
 * or reads a single packet buffer from stdin if no argument given.
 *
 * If multiple file arguments are given, each is fed to argus_harness_run_one() in argv
 * order within a *single* argus_harness_init() call, i.e. against shared, accumulating
 * model/flow-table state -- replicating what AFL's persistent-mode __AFL_LOOP does across
 * a sequence of mutated inputs within one forked child. This is needed to reproduce
 * cross-packet stateful bugs that a single-input (or same-input-repeated) replay cannot
 * trigger. REPLAY_REPS (if set) replays the whole given sequence that many times. */
int main(int argc, char **argv)
{
   unsigned char buf[MAX_PACKET_LEN];
   size_t n;
   int reps = 1;
   const char *r = getenv("REPLAY_REPS");
   if (r != NULL) reps = atoi(r);
   if (reps < 1) reps = 1;

   argus_harness_init();

   if (argc > 1) {
      for (int rep = 0; rep < reps; rep++) {
         for (int a = 1; a < argc; a++) {
            FILE *fp = fopen(argv[a], "rb");
            if (fp == NULL) {
               perror("fopen");
               return 1;
            }
            n = fread(buf, 1, sizeof(buf), fp);
            fclose(fp);
            argus_harness_run_one(buf, n);
         }
      }
   } else {
      n = fread(buf, 1, sizeof(buf), stdin);
      for (int i = 0; i < reps; i++)
         argus_harness_run_one(buf, n);
   }
   return 0;
}
#endif
