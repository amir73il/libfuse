/*
  notifyfs: FUSE passthrough module

  Copyright (C) 2021       CTERA Networks

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING
*/

#ifndef NOTIFYFS_H_
#define NOTIFYFS_H_

void nfyfs_init(fuse_passthrough_opts &opts, std::string index_path,
		bool index_new = false);
fuse_passthrough_module *nfyfs_module(void);

#endif /* NOTIFYFS_H_ */
