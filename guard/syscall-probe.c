/*
 * Test helper: attempts a set of syscalls and prints "<name> <errno>" per line
 * (0 = success), plus "nnp" and "seccomp_filters" lines from /proc/self/status.
 * Used by test-guard.sh to compare runs with and without container-guard.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void report(const char *name, long rc) { printf("%s %d\n", name, rc < 0 ? errno : 0); }

static void *thread_fn(void *arg) { return arg; }

static void status_field(const char *key, const char *label) {
    FILE *f = fopen("/proc/self/status", "re");
    char line[256];
    size_t kl = strlen(key);
    while (f && fgets(line, sizeof line, f))
        if (strncmp(line, key, kl) == 0) { printf("%s %ld\n", label, strtol(line + kl, NULL, 10)); break; }
    if (f) fclose(f);
}

int main(void) {
    errno = 0;
    report("getpid", syscall(__NR_getpid));

    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    report("open", fd);
    if (fd >= 0) close(fd);

    /* ptrace: target a pid that can't exist. Unfiltered gives ESRCH; filtered gives EPERM. */
    report("ptrace", ptrace(PTRACE_ATTACH, (pid_t)0x3fffffff, 0, 0));

    char src[8] = "abc", dst[8];
    struct iovec l = { dst, sizeof dst }, r = { src, sizeof src };
    report("process_vm_readv", process_vm_readv(getpid(), &l, 1, &r, 1, 0));

    report("bpf", syscall(__NR_bpf, 0, NULL, 0));
#ifdef __NR_io_uring_setup
    report("io_uring_setup", syscall(__NR_io_uring_setup, 1, NULL));
#endif
    report("keyctl", syscall(__NR_keyctl, 0, 0, 0, 0, 0));
    report("perf_event_open", syscall(__NR_perf_event_open, NULL, 0, -1, -1, 0));
    report("mount", syscall(__NR_mount, "none", "/tmp", "tmpfs", 0, NULL));
    report("setns", syscall(__NR_setns, -1, 0));

    report("unshare_newuser", syscall(__NR_unshare, CLONE_NEWUSER));
    report("unshare_newnet", syscall(__NR_unshare, CLONE_NEWNET));
    report("unshare_fs", syscall(__NR_unshare, CLONE_FS));   /* no namespace flag: allowed */

#ifdef __NR_clone3
    report("clone3", syscall(__NR_clone3, NULL, 0));
#endif

    report("personality_query", personality(0xffffffff));
    report("personality_no_aslr", personality(ADDR_NO_RANDOMIZE));

    /* posix_spawn uses clone3 first; this proves the ENOSYS fallback to clone works. */
    pid_t pid;
    int prc = posix_spawn(&pid, "/bin/true", NULL, NULL, (char *[]){ "true", NULL }, environ);
    int st = 0;
    if (prc == 0) waitpid(pid, &st, 0);
    printf("spawn %d\n", prc == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : (prc ? prc : -1));

    pid_t c = fork();
    if (c == 0) _exit(0);
    if (c > 0) waitpid(c, &st, 0);
    report("fork", c);

    pthread_t th;
    int trc = pthread_create(&th, NULL, thread_fn, NULL);
    if (trc == 0) pthread_join(th, NULL);
    printf("pthread %d\n", trc);

    status_field("NoNewPrivs:", "nnp");
    status_field("Seccomp_filters:", "seccomp_filters");
    return 0;
}
