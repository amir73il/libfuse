#!/usr/bin/env bash
# GROUP: examples passthrough
# 500-entry readdir plus test_syscalls over FUSE; the default 60s is
# not enough on a loaded runner, and -d makes it slower again.
# TIMEOUT: 300

. "$TEST_LIB/common.sh"
_require_root

FS_NAME=passthrough_fs
FS_ARGS="--foreground --nocache"
PT_POSITIONAL="$TEST_SRC"
INODE_CHECK=exact
PT_MIRROR=0
PT_SRC_VISIBLE=1
# The unlinked-testfiles check needs "fuse: fix illegal access to
# inode with reused nodeid"; the suite assumes a current kernel.
SYSCALL_ARGS=-u

. "$TEST_LIB/passthrough.sh"
