/* upxfd_create.c -- workaround for 32-bit Android

   This file is part of the UPX executable compressor.

   Copyright (C) 2023 John F. Reiser
   All Rights Reserved.
 */

#include "include/linux.h"  // syscall decls; i386 inlines via "int 0x80"
#define MFD_EXEC 0x10
//#define O_RDWR 2
#define O_DIRECTORY 0200000  /* 0x010000 asm-generic/fcntl.h */
#define O_TMPFILE 020000000  /* 0x400000 asm-generic/fcntl.h */
#define EINVAL 22 /* asm-generic/errno-base.h */
// Implementation for Linux-native, where memfd_create
// (or /dev/shm) works.  Saves space in contrast to
// upxfd_android (or Android emulator), which must
// fall back to  /data/data/$APP_NAME/cache/upxAAA ,
// and also must work around inconsistent __NR_ftruncate.
// 1. Try memfd_create
// 2. Try /dev/shm
unsigned long upx_mmap_and_fd_linux( // returns (mapped_addr | (1+ fd))
    void *ptr  // desired address
    , unsigned datlen  // mapped length
    , char *pathname  // 0 ==> get_upxfn_path()
)
{
    (void)pathname;  // FIXME NYI
    char str_upx[] = {'u','p','x',0};
    int fd = memfd_create(str_upx, MFD_EXEC);
    if (-EINVAL == fd) { // 2024-10-15 MFD_EXEC unknown to ubuntu-20.04
        fd = memfd_create(str_upx, 0);  // try again
    }
    if (fd < 0) { // last chance for Linux
        char str_dev_shm[] = {'/','d','e','v','/','s','h','m', 0};
        fd = open(str_dev_shm, O_RDWR | O_DIRECTORY | O_TMPFILE, 0700);
        if (fd < 0) {
            return (unsigned long)(long)fd;
        }
        // Beware: /dev/shm might limit write() to 8KiB at a time.
    }
    int rv = ftruncate(fd, datlen);
    if (rv < 0) {
        return (unsigned long)(long)rv;
    }
    ptr = mmap(ptr, datlen, PROT_READ|PROT_WRITE,
        (ptr ? MAP_FIXED : 0)|MAP_SHARED, fd, 0);
    if (PAGE_MASK <= (unsigned long)ptr) {
        return (unsigned long)ptr;  // errno
    }
    return (unsigned long)ptr + (1+ (unsigned)fd);
}
