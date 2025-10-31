#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <xfs/xfs.h>


// Missing definitions
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef FS_FILEID_TYPE_MASK
#define FS_FILEID_TYPE_MASK 0xff
#endif

#ifndef FS_FILEID_INO32_GEN
#define FS_FILEID_INO32_GEN 1
#endif

#ifndef FS_FILEID_INO64_GEN
#define FS_FILEID_INO64_GEN 0x81
#endif

#ifndef O_PATH
#define O_PATH 010000000
#endif

// File handle structure
struct file_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[0];
};

// File handle structures (simplified versions from fuse_passthrough.cpp)
struct fid64 {
    uint64_t ino;
    uint32_t gen;
} __attribute__((packed));

struct fid32 {
    uint32_t ino;
    uint32_t gen;
} __attribute__((packed));

struct xfs_fh {
    struct file_handle fh;
    union {
        struct fid64 fid64;
        struct fid32 fid32;
    } fid;
};

// Function declarations
extern int name_to_handle_at(int dfd, const char *name, struct file_handle *handle, int *mnt_id, int flags);
extern int open_by_handle_at(int mount_fd, const struct file_handle *handle, int flags);

// major/minor functions are provided by xfs.h

static void usage(void)
{
    fprintf(stderr, "Usage: open_by_ino <mount_path> <ino> [-d]\n");
    fprintf(stderr, "  mount_path: path to the mounted filesystem\n");
    fprintf(stderr, "  ino: inode number to open\n");
    exit(1);
}

static int debug;

#define dprintf(fmt, ...) \
	if (debug) fprintf(stderr, "DEBUG: " fmt, ## __VA_ARGS__)

static int get_xfs_generation(int mount_fd, __u64 ino)
{
    __s32 count = 0;
    struct xfs_bstat bstat = { };
    struct xfs_fsop_bulkreq breq = {
        .lastip = &ino,
        .icount = 1,
        .ubuffer = (void *)&bstat,
        .ocount = &count,
    };

    if (ioctl(mount_fd, XFS_IOC_FSBULKSTAT_SINGLE, &breq) != 0) {
        fprintf(stderr, "WARNING: failed to bulkstat inode %llu, errno=%d\n",
                (unsigned long long)ino, errno);
        return 0; // Return 0 generation if bulkstat fails
    }

    dprintf("xfs_bulkstat_gen(): ino=%llu, count=%d, bs_ino=%llu, bs_gen=%u\n",
            (unsigned long long)ino, count, (unsigned long long)bstat.bs_ino, bstat.bs_gen);

    return bstat.bs_gen;
}

static int create_file_handle(int mount_fd, __u64 ino, struct xfs_fh *xfh)
{
    int mount_id;
    int ret;

    // Initialize file handle buffer
    xfh->fh.handle_bytes = sizeof(xfh->fid);
    xfh->fh.handle_type = 0;
    memset(&xfh->fid, 0, sizeof(xfh->fid));

    // Try to get file handle for the root first to understand the format
    ret = name_to_handle_at(mount_fd, "", &xfh->fh, &mount_id, AT_EMPTY_PATH);
    if (ret < 0) {
        fprintf(stderr, "ERROR: name_to_handle_at failed: %s\n", strerror(errno));
        return -1;
    }

    dprintf("Root file handle type: 0x%x, handle_bytes: %u\n",
            xfh->fh.handle_type, xfh->fh.handle_bytes);

    // For XFS, we can try to construct a basic file handle
    // We need to get the proper generation number using bulkstat
    if (xfh->fh.handle_type == FS_FILEID_INO64_GEN) { // XFS 64-bit handle (0x81)
        // Get the generation for the target inode
        __u32 gen = get_xfs_generation(mount_fd, ino);
        dprintf("Got generation %u for inode %llu\n",
		gen, (unsigned long long)ino);

        // Try to construct a file handle for the target inode
        // We'll use the same format but with our target inode
        struct fid64 *fid = (struct fid64 *)xfh->fh.f_handle;
        fid->ino = ino;
        fid->gen = gen;

        dprintf("Constructed file handle for inode %llu with gen %u\n",
                (unsigned long long)ino, gen);
    } else if (xfh->fh.handle_type == FS_FILEID_INO32_GEN) { // ext4 32-bit handle (0x01)
        // Try to construct a file handle for the target inode
        // We'll use the same format but with our target inode
        struct fid32 *fid = (struct fid32 *)xfh->fh.f_handle;
        fid->ino = ino;
        fid->gen = 0;

        dprintf("Constructed 32-bit file handle for inode %llu\n",
                (unsigned long long)ino);
    } else {
        fprintf(stderr, "ERROR: Unsupported file handle type for construction: 0x%x\n", 
                xfh->fh.handle_type);
        return -1;
    }

    return 0;
}

static int open_by_handle(int mount_fd, struct xfs_fh *xfh)
{
    int fd = open_by_handle_at(mount_fd, &xfh->fh, O_PATH);
    if (fd < 0) {
        fprintf(stderr, "ERROR: open_by_handle_at failed: %s\n", strerror(errno));
        return -1;
    }

    dprintf("Successfully opened fd=%d by handle\n", fd);
    return fd;
}

static int get_path_from_fd(int fd, char *path, size_t path_size)
{
    char proc_path[64];
    ssize_t n;

    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    n = readlink(proc_path, path, path_size - 1);
    if (n < 0) {
        fprintf(stderr, "ERROR: readlink(%s) failed: %s\n", proc_path, strerror(errno));
        return -1;
    }

    path[n] = '\0';
    dprintf("Path from fd %d: %s\n", fd, path);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc > 3 && !strcmp(argv[3], "-d")) {
	    debug = 1;
	    argc--;
    }
    if (argc != 3) {
        usage();
    }

    const char *mount_path = argv[1];
    __u64 ino = strtoull(argv[2], NULL, 10);
    if (ino == 0) {
        fprintf(stderr, "ERROR: Invalid inode number: %s\n", argv[2]);
        return 1;
    }

    dprintf("Opening mount_path='%s', ino=%llu\n",
            mount_path, (unsigned long long)ino);

    // Open the mount path
    int mount_fd = open(mount_path, O_DIRECTORY | O_RDONLY);
    if (mount_fd < 0) {
        fprintf(stderr, "ERROR: open(%s) failed: %s\n", mount_path, strerror(errno));
        return 1;
    }

    dprintf("Opened mount_fd=%d\n", mount_fd);

    // Get file system info
    struct stat st;
    if (fstat(mount_fd, &st) < 0) {
        fprintf(stderr, "ERROR: fstat failed: %s\n", strerror(errno));
        close(mount_fd);
        return 1;
    }

    dprintf("Mount device: major=%d, minor=%d, ino=%llu\n",
            major(st.st_dev), minor(st.st_dev), (__u64)st.st_ino);

    // Create file handle for the inode
    struct xfs_fh xfh;
    if (create_file_handle(mount_fd, ino, &xfh) < 0) {
        close(mount_fd);
        return 1;
    }

    // Open by file handle
    int fd = open_by_handle(mount_fd, &xfh);
    if (fd < 0) {
        close(mount_fd);
        return 1;
    }

    // Get the path from the proc fd
    char path[PATH_MAX];
    if (get_path_from_fd(fd, path, sizeof(path)) < 0) {
        close(fd);
        close(mount_fd);
        return 1;
    }

    printf("%s\n", path);

    // Clean up
    close(fd);
    close(mount_fd);

    return 0;
}
