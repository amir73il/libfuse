/*
 * Prints each directory entry, its inode and d_type as returned by 'readdir'.
 * Skips '.' and '..' because readdir is not required to return them and
 * some of our examples don't. However if they are returned, their d_type
 * should be valid.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include "wyhash.h"

static int khash;
static int mbits = 32;
static int mdigits;
static uint32_t mask;
static uint64_t *bitmap = NULL;
static uint64_t nwords;
static int debug;
static int quiet;

#define dprintf(fmt, ...) \
	if (debug) fprintf(stderr, fmt, ## __VA_ARGS__)

static uint64_t ci_hash(char *s)
{
    static char lowername[NAME_MAX+1];
    char *p = lowername;
    int l;

    for (l = 0; *s; ++l, ++s, ++p)
        *p = tolower((unsigned char)*s);

    return wyhash(lowername, l, 0, _wyp);
}

static void print_bitmap(void)
{
    dprintf("\nbloom filter bitmap:\n");
    for (size_t w = 0; w < nwords; ++w) {
        dprintf("%016lx ", bitmap[w]);
        if (w >= 256) {
		printf("...");
		break;
	}
    }
    dprintf("\n");
}

static void print_ci_hash(char *s)
{
    uint64_t wh = ci_hash(s);
    uint32_t h = (uint32_t)wh;
    uint32_t h2 = (uint32_t)(wh >> 32);
    uint32_t b, w;
    uint64_t v;
    int k;
    int match = !!bitmap;

    for (k = 0; k < khash; k++, h+=h2) {
        b = h & mask;
	w = b >> 6;
	v = 1ULL << (b & 63);
        if (!quiet)
            printf("%0*x ", mdigits, b);
        if (bitmap) {
            match = match && bitmap[w] & v;
            dprintf("bitmap[%d] = %016lx | %016lx; ", w, bitmap[w], v);
            bitmap[w] |= v;
        }
    }
    if (match)
        printf("%s collision\n", s);
    else if (!quiet)
        printf("\n");
    if (debug)
        print_bitmap();
}

static void usage(void)
{
    fprintf(stderr, "Usage: readdir_inode dir [khash] [mbits] [-d|-q]\n");
    exit(1);
}

int main(int argc, char* argv[])
{
    DIR* dirp;
    struct dirent* dent;
    struct stat st;
    off_t dbits, dbytes;

    if (argc < 2) {
        usage();
    }

    if (argc > 4 && argv[4][0] == '-') {
            switch (argv[4][1]) {
            case 'd':
	        debug = 1;
	        break;
            case 'q':
	        quiet = 1;
	        break;
            }
	    argc--;
    }

    if (stat(argv[1], &st) != 0) {
        perror("failed to stat directory");
        exit(1);
    }
    dbytes = st.st_blocks * 512;
    if (debug)
        dprintf("size of %s %ld bytes, estimated %ld entries\n",
                argv[1], dbytes, dbytes / 32);
    for (dbits = 1; dbytes; dbits++, dbytes >>= 1);

    if (argc > 3) {
        if (argv[3][0] == '-')
            mbits = dbits ? dbits - 1 : 8;
        else
            mbits = atoi(argv[3]);
        if (mbits < 8 || mbits > 32) {
            fprintf(stderr, "Invalid mbits value %d [8..32]\n", mbits);
            usage();
        }
        printf("allocating bloom filter of size 2^%u bits\n", mbits);
        nwords = 1UL << (mbits - 6);
        bitmap = calloc(nwords, sizeof(uint64_t));
        if (!bitmap) {
            perror("allocation failed");
            exit(1);
        }
        argc--;
    }
    mask = (1UL << mbits) - 1;
    mdigits = (mbits + 3) / 4;

    if (argc > 2) {
        if (argv[2][0] == '-')
            khash = (dbits > 15) ? dbits - 14 : 1;
        else
            khash = atoi(argv[2]);
        if (khash <= 0 || khash > 20) {
            fprintf(stderr, "Invalid khash value %d [1..20]\n", khash);
            usage();
        }
        printf("using %d bloom filter hashes\n", khash);
        argc--;
    }

    if (argc != 2) {
        usage();
    }

    dirp = opendir(argv[1]);
    if (dirp == NULL) {
        perror("failed to open directory");
        exit(1);
    }

    errno = 0;
    dent = readdir(dirp);
    while (dent != NULL) {
        if (strcmp(dent->d_name, ".") != 0 && strcmp(dent->d_name, "..") != 0) {
            if (!quiet)
                printf("%llu %d %s ", (unsigned long long)dent->d_ino,
                       (int)dent->d_type, dent->d_name);
            if (khash)
                print_ci_hash(dent->d_name);
	    else if (!quiet)
	        printf("\n");
            if ((long long)dent->d_ino < 0)
               fprintf(stderr,"%s : bad d_ino %llu\n",
                        dent->d_name, (unsigned long long)dent->d_ino);
            if ((dent->d_type < 1) || (dent->d_type > 15))
               fprintf(stderr,"%s : bad d_type %d\n",
                        dent->d_name, (int)dent->d_type);
        } else {
            if (dent->d_type != DT_DIR)
               fprintf(stderr,"%s : bad d_type %d\n",
                        dent->d_name, (int)dent->d_type);
        }
        dent = readdir(dirp);
    }
    if (errno != 0) {
        perror("failed to read directory entry");
        return 3;
    }

    closedir(dirp);

    return 0;
}
