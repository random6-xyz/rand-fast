// Minimal mount(2) wrapper for initramfs-only QEMU guests.
//
// The initcpio busybox does not ship the mount applet, and pulling in
// util-linux drags in a library chain, so the guest init uses this static
// helper instead:
//
//   gcc -static -O2 -o /bin/mount2 tools/qemu-guest-mount.c
//
// usage: mount2 <source> <fstype> <target>
#include <sys/mount.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s source fstype target\n", argv[0]);
        return 2;
    }
    if (mount(argv[1], argv[3], argv[2], 0, NULL) != 0) {
        perror("mount");
        return 1;
    }
    return 0;
}
