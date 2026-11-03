/*
 * container-guard: fail-closed security entrypoint for containers.
 *
 * Usage:  container-guard [--] <program> [args...]
 *
 * Built in one of two variants, chosen at compile time with -DGUARD_LSM_SELINUX
 * or -DGUARD_LSM_APPARMOR. Before exec'ing <program> it:
 *
 *  A. Checks LSM confinement (fails with exit 126 on any problem).
 *     SELinux variant:
 *     1. The process has an SELinux context (/proc/self/attr/selinux/current,
 *        falling back to /proc/self/attr/current on kernels without LSM stacking).
 *     2. The context is user:role:type:level and the type is allowlisted: the
 *        Kubernetes "restricted" container types plus udica "*.process" types.
 *     3. If selinuxfs is visible (/sys/fs/selinux/enforce), it reports enforcing.
 *     AppArmor variant:
 *     1. The process has an AppArmor label (/proc/self/attr/apparmor/current,
 *        falling back to /proc/self/attr/current).
 *     2. The label is "<profile> (enforce)" or "<profile> (kill)". "unconfined" and
 *        the complain, mixed and other modes are rejected.
 *     3. If /sys/module/apparmor/parameters/enabled is visible, it reports Y.
 *     Neither variant can check what the profile itself allows; that's the
 *     cluster's job (admission policy + RuntimeDefault or vetted Localhost profiles).
 *
 *  B. Locks down syscalls:
 *     1. Sets PR_SET_NO_NEW_PRIVS (no setuid/file-capability escalation, ever).
 *     2. Installs a seccomp-BPF filter. It's inherited across exec and can't be
 *        removed, and it stacks with the runtime's profile (strictest wins).
 *        - Wrong architecture or x32 ABI: kill the process.
 *        - Dangerous syscalls (see DENY below): EPERM.
 *        - clone/unshare with namespace flags: EPERM.
 *        - clone3: ENOSYS, because its flags can't be inspected. libc falls back to clone.
 *        - personality(): only the values Docker/containerd allow by default.
 *
 * There is deliberately no runtime override (env var or flag); policy is fixed at
 * compile time. Supported architectures: x86_64, aarch64.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(GUARD_LSM_SELINUX) == defined(GUARD_LSM_APPARMOR)
#error "define exactly one of GUARD_LSM_SELINUX or GUARD_LSM_APPARMOR"
#endif

#ifdef GUARD_LSM_SELINUX
#define LSM_NAME "SELinux"
#ifndef ATTR_PATH_STACKED
#define ATTR_PATH_STACKED "/proc/self/attr/selinux/current"
#endif
#ifndef ENFORCE_PATH
#define ENFORCE_PATH "/sys/fs/selinux/enforce"           /* "1" = enforcing */
#endif
#else
#define LSM_NAME "AppArmor"
#ifndef ATTR_PATH_STACKED
#define ATTR_PATH_STACKED "/proc/self/attr/apparmor/current"
#endif
#ifndef ENFORCE_PATH
#define ENFORCE_PATH "/sys/module/apparmor/parameters/enabled"  /* "Y" = enabled */
#endif
#endif

#ifndef ATTR_PATH_LEGACY
#define ATTR_PATH_LEGACY "/proc/self/attr/current"
#endif

#define EXIT_DENY 126

#if defined(__x86_64__)
#define GUARD_AUDIT_ARCH AUDIT_ARCH_X86_64
#define GUARD_X32_BIT 0x40000000U
#elif defined(__aarch64__)
#define GUARD_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "container-guard supports x86_64 and aarch64 only"
#endif

/* ------------------------------------------------------------------------- */
/* Policy                                                                     */
/* ------------------------------------------------------------------------- */

#ifdef GUARD_LSM_SELINUX
static const char *const ALLOWED_TYPES[] = {
    "container_t", "container_init_t", "container_kvm_t", NULL,
};
static const char UDICA_SUFFIX[] = ".process";
#endif

/* Syscalls that return EPERM. #ifdef'd because the set varies by architecture. */
static const long DENY[] = {
    /* kernel modules, kexec, reboot */
#ifdef __NR_init_module
    __NR_init_module,
#endif
#ifdef __NR_finit_module
    __NR_finit_module,
#endif
#ifdef __NR_delete_module
    __NR_delete_module,
#endif
#ifdef __NR_create_module
    __NR_create_module,
#endif
#ifdef __NR_get_kernel_syms
    __NR_get_kernel_syms,
#endif
#ifdef __NR_query_module
    __NR_query_module,
#endif
#ifdef __NR_kexec_load
    __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
    __NR_kexec_file_load,
#endif
#ifdef __NR_reboot
    __NR_reboot,
#endif
    /* namespaces / filesystem topology */
#ifdef __NR_setns
    __NR_setns,
#endif
#ifdef __NR_mount
    __NR_mount,
#endif
#ifdef __NR_umount
    __NR_umount,
#endif
#ifdef __NR_umount2
    __NR_umount2,
#endif
#ifdef __NR_pivot_root
    __NR_pivot_root,
#endif
#ifdef __NR_chroot
    __NR_chroot,
#endif
#ifdef __NR_fsopen
    __NR_fsopen,
#endif
#ifdef __NR_fsconfig
    __NR_fsconfig,
#endif
#ifdef __NR_fsmount
    __NR_fsmount,
#endif
#ifdef __NR_fspick
    __NR_fspick,
#endif
#ifdef __NR_move_mount
    __NR_move_mount,
#endif
#ifdef __NR_open_tree
    __NR_open_tree,
#endif
#ifdef __NR_mount_setattr
    __NR_mount_setattr,
#endif
#ifdef __NR_open_tree_attr
    __NR_open_tree_attr,
#endif
#ifdef __NR_swapon
    __NR_swapon,
#endif
#ifdef __NR_swapoff
    __NR_swapoff,
#endif
#ifdef __NR_quotactl
    __NR_quotactl,
#endif
#ifdef __NR_quotactl_fd
    __NR_quotactl_fd,
#endif
#ifdef __NR_name_to_handle_at
    __NR_name_to_handle_at,
#endif
#ifdef __NR_open_by_handle_at
    __NR_open_by_handle_at,
#endif
#ifdef __NR_fanotify_init
    __NR_fanotify_init,
#endif
    /* cross-process introspection / injection */
#ifdef __NR_ptrace
    __NR_ptrace,
#endif
#ifdef __NR_process_vm_readv
    __NR_process_vm_readv,
#endif
#ifdef __NR_process_vm_writev
    __NR_process_vm_writev,
#endif
#ifdef __NR_process_madvise
    __NR_process_madvise,
#endif
#ifdef __NR_pidfd_getfd
    __NR_pidfd_getfd,
#endif
#ifdef __NR_kcmp
    __NR_kcmp,
#endif
    /* large kernel attack surface */
#ifdef __NR_bpf
    __NR_bpf,
#endif
#ifdef __NR_perf_event_open
    __NR_perf_event_open,
#endif
#ifdef __NR_userfaultfd
    __NR_userfaultfd,
#endif
#ifdef __NR_io_uring_setup
    __NR_io_uring_setup,
#endif
#ifdef __NR_io_uring_enter
    __NR_io_uring_enter,
#endif
#ifdef __NR_io_uring_register
    __NR_io_uring_register,
#endif
#ifdef __NR_keyctl
    __NR_keyctl,
#endif
#ifdef __NR_add_key
    __NR_add_key,
#endif
#ifdef __NR_request_key
    __NR_request_key,
#endif
    /* LSM self-relabel (e.g. SELinux setcon) */
#ifdef __NR_lsm_set_self_attr
    __NR_lsm_set_self_attr,
#endif
    /* host time / logs / accounting / legacy */
#ifdef __NR_settimeofday
    __NR_settimeofday,
#endif
#ifdef __NR_clock_settime
    __NR_clock_settime,
#endif
#ifdef __NR_clock_adjtime
    __NR_clock_adjtime,
#endif
#ifdef __NR_adjtimex
    __NR_adjtimex,
#endif
#ifdef __NR_syslog
    __NR_syslog,
#endif
#ifdef __NR_acct
    __NR_acct,
#endif
#ifdef __NR_lookup_dcookie
    __NR_lookup_dcookie,
#endif
#ifdef __NR_nfsservctl
    __NR_nfsservctl,
#endif
#ifdef __NR_iopl
    __NR_iopl,
#endif
#ifdef __NR_ioperm
    __NR_ioperm,
#endif
#ifdef __NR_vhangup
    __NR_vhangup,
#endif
#ifdef __NR_uselib
    __NR_uselib,
#endif
#ifdef __NR_ustat
    __NR_ustat,
#endif
#ifdef __NR_sysfs
    __NR_sysfs,
#endif
#ifdef __NR__sysctl
    __NR__sysctl,
#endif
};

/* Namespace-creating flags. CLONE_NEWTIME (0x80) overlaps clone()'s exit-signal byte,
 * so it's only checked for unshare(). */
#define NS_FLAGS (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | \
                  CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

static const unsigned int PERSONALITY_OK[] = { 0x0, 0x8, 0x20000, 0x20008, 0xffffffffU };

/* ------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* ------------------------------------------------------------------------- */

static void deny(const char *why, const char *detail) {
    fprintf(stderr, "container-guard: DENY: %s%s%s\n", why,
            detail ? ": " : "", detail ? detail : "");
    exit(EXIT_DENY);
}

static ssize_t read_small(const char *path, char *buf, size_t cap) {
    FILE *f = fopen(path, "re");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    int err = ferror(f);
    fclose(f);
    if (err) return -1;
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\0')) buf[--n] = '\0';
    return (ssize_t)n;
}

/* Read this process's label: LSM-specific attr first (kernels with LSM stacking),
 * then the legacy shared attr. */
static ssize_t read_label(char *buf, size_t cap) {
    ssize_t n = read_small(ATTR_PATH_STACKED, buf, cap);
    if (n <= 0) n = read_small(ATTR_PATH_LEGACY, buf, cap);
    if (n <= 0) deny("no " LSM_NAME " label readable for this process", NULL);
    return n;
}

#ifdef GUARD_LSM_SELINUX

static int type_allowed(const char *type) {
    for (const char *const *t = ALLOWED_TYPES; *t; t++)
        if (strcmp(type, *t) == 0) return 1;
    size_t len = strlen(type), sl = sizeof(UDICA_SUFFIX) - 1;
    return len > sl && strcmp(type + len - sl, UDICA_SUFFIX) == 0;
}

static void check_lsm(void) {
    char ctx[512];
    ssize_t n = read_label(ctx, sizeof ctx);

    char copy[sizeof ctx];
    memcpy(copy, ctx, (size_t)n + 1);
    char *save = NULL;
    char *user = strtok_r(copy, ":", &save);
    char *role = strtok_r(NULL, ":", &save);
    char *type = strtok_r(NULL, ":", &save);
    char *level = strtok_r(NULL, "", &save);
    if (!user || !role || !type || !level || !*level)
        deny("process is not SELinux-confined (context is not user:role:type:level)", ctx);
    if (!type_allowed(type))
        deny("SELinux type is not an allowed container type", ctx);

    char enforce[8];
    if (read_small(ENFORCE_PATH, enforce, sizeof enforce) >= 0) {
        if (strcmp(enforce, "1") != 0)
            deny("SELinux is not enforcing on this node", enforce);
    } else {
        fprintf(stderr, "container-guard: notice: selinuxfs hidden; confined as %s\n", ctx);
    }
}

#else /* GUARD_LSM_APPARMOR */

static void check_lsm(void) {
    char label[512];
    ssize_t n = read_label(label, sizeof label);

    /* Expected: "<profile> (<mode>)". The profile may contain spaces, '//' (hats,
     * children), '//&' (stacks) or ':ns:' prefixes, so split on the LAST " (". */
    if (strcmp(label, "unconfined") == 0)
        deny("process is not AppArmor-confined", label);
    char *open = NULL;
    for (char *p = strstr(label, " ("); p; p = strstr(p + 1, " (")) open = p;
    if (!open || label[n - 1] != ')' || open == label)
        deny("process is not AppArmor-confined (label is not \"<profile> (<mode>)\")", label);

    size_t mlen = (size_t)(&label[n - 1] - (open + 2));
    const char *mode = open + 2;
    int mode_ok = (mlen == 7 && strncmp(mode, "enforce", 7) == 0) ||
                  (mlen == 4 && strncmp(mode, "kill", 4) == 0);
    if (!mode_ok)
        deny("AppArmor profile is not in enforce mode", label);

    size_t plen = (size_t)(open - label);
    if (plen == 10 && strncmp(label, "unconfined", 10) == 0)
        deny("AppArmor profile is 'unconfined'", label);

    char enabled[8];
    if (read_small(ENFORCE_PATH, enabled, sizeof enabled) >= 0) {
        if (strcmp(enabled, "Y") != 0)
            deny("AppArmor is not enabled on this node", enabled);
    }
}

#endif

/* ------------------------------------------------------------------------- */
/* seccomp filter                                                             */
/* ------------------------------------------------------------------------- */

#define MAX_INSNS 512
static struct sock_filter prog[MAX_INSNS];
static unsigned short ninsn;

static void emit(struct sock_filter f) {
    if (ninsn >= MAX_INSNS) deny("internal: seccomp program too large", NULL);
    prog[ninsn++] = f;
}
#define STMT(code, k)        emit((struct sock_filter)BPF_STMT((code), (k)))
#define JUMP(code, k, t, f)  emit((struct sock_filter)BPF_JUMP((code), (k), (t), (f)))

#define LD_NR    STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))
#define LD_ARG0  STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])) /* low 32 bits, LE */
#define RET(v)   STMT(BPF_RET | BPF_K, (v))

/* if (nr == sys) { if (arg0 & mask) EPERM; else ALLOW; }   -- 5 insns, A = nr on fallthrough */
static void emit_flag_check(long sys, unsigned int mask) {
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)sys, 0, 4);
    LD_ARG0;
    JUMP(BPF_JMP | BPF_JSET | BPF_K, mask, 0, 1);
    RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    RET(SECCOMP_RET_ALLOW);
}

static void install_seccomp(void) {
    const size_t npers = sizeof PERSONALITY_OK / sizeof *PERSONALITY_OK;

    /* Architecture pin: anything else (e.g. i386 int 0x80 on x86_64) is killed. */
    STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, GUARD_AUDIT_ARCH, 1, 0);
    RET(SECCOMP_RET_KILL_PROCESS);
    LD_NR;
#ifdef GUARD_X32_BIT
    JUMP(BPF_JMP | BPF_JGE | BPF_K, GUARD_X32_BIT, 0, 1);
    RET(SECCOMP_RET_KILL_PROCESS);
#endif

    for (size_t i = 0; i < sizeof DENY / sizeof *DENY; i++) {
        JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)DENY[i], 0, 1);
        RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }

#ifdef __NR_clone3
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1);
    RET(SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA));
#endif
    emit_flag_check(__NR_clone, NS_FLAGS);
    emit_flag_check(__NR_unshare, NS_FLAGS | CLONE_NEWTIME);

    /* personality: allow only known-safe personas. */
    /* not personality: skip LD_ARG0 + npers JEQs + 2 RETs */
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_personality, 0, (unsigned char)(npers + 3));
    LD_ARG0;
    for (size_t i = 0; i < npers; i++)
        JUMP(BPF_JMP | BPF_JEQ | BPF_K, PERSONALITY_OK[i], (unsigned char)(npers - i), 0);
    RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    RET(SECCOMP_RET_ALLOW); /* jump target of the personality matches */

    RET(SECCOMP_RET_ALLOW); /* everything else */

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        deny("prctl(PR_SET_NO_NEW_PRIVS) failed", strerror(errno));

    struct sock_fprog fprog = { .len = ninsn, .filter = prog };
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog) != 0)
        deny("installing seccomp filter failed", strerror(errno));
}

/* ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    int first = 1;
    if (argc > 1 && strcmp(argv[1], "--") == 0) first = 2;
    if (first >= argc) {
        fprintf(stderr, "usage: container-guard [--] <program> [args...]\n");
        return 2;
    }

    check_lsm();
    install_seccomp();

    execvp(argv[first], &argv[first]);
    fprintf(stderr, "container-guard: exec %s: %s\n", argv[first], strerror(errno));
    return 127;
}
