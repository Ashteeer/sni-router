#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

// Loaded only into the test child. Keep real socket readiness, but make its
// raw writes temporarily fail, just as in the production EAGAIN/POLLOUT loop.
static _Atomic uint64_t *attempts;
static int copy_mode;
static __thread uint64_t until;
static __thread int recovered;

__attribute__((constructor)) static void setup(void) {
    int fd = open(getenv("SNI_TEST_COUNTER"), O_RDWR);
    attempts = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (attempts == MAP_FAILED) _exit(90);
    copy_mode = getenv("SNI_TEST_COPY") != NULL;
}

static int stall(void) {
    if (recovered) return 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t ns = (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
    if (!until) until = ns + 500000000;
    if (ns >= until) {
        recovered = 1;
        return 0;
    }
    atomic_fetch_add_explicit(attempts, 1, memory_order_relaxed);
    errno = EAGAIN;
    return 1;
}

ssize_t splice(int in, off64_t *off_in, int out, off64_t *off_out,
               size_t len, unsigned int flags) {
    struct stat st;
    if (copy_mode) {
        errno = EINVAL;
        return -1;
    }
    if (fstat(out, &st) == 0 && S_ISSOCK(st.st_mode) && stall()) return -1;
    ssize_t (*real_splice)(int, off64_t *, int, off64_t *, size_t, unsigned int)
        = dlsym(RTLD_NEXT, "splice");
    return real_splice(in, off_in, out, off_out, len, flags);
}

ssize_t write(int fd, const void *buf, size_t len) {
    struct stat st;
    if (copy_mode && fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode) && stall()) return -1;
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    return real_write(fd, buf, len);
}
