/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

/*-
 * Copyright (c) 2005-2007, Kohsuke Ohtani
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * vfs_conf.c - File system configuration.
 */

#include <osv/drivers_config.h>
#include <osv/kernel_config_fs_procfs.h>
#include <osv/kernel_config_fs_sysfs.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "vfs.h"

extern struct vfsops ramfs_vfsops;
extern struct vfsops rofs_vfsops;
extern struct vfsops devfs_vfsops;
extern struct vfsops nfs_vfsops;
#if CONF_fs_procfs
extern struct vfsops procfs_vfsops;
#endif
#if CONF_fs_sysfs
extern struct vfsops sysfs_vfsops;
#endif
extern struct vfsops zfs_vfsops;
#if CONF_drivers_virtio_fs
extern struct vfsops virtiofs_vfsops;
#endif
extern struct vfsops ext_vfsops;

extern int ramfs_init(void);
extern int rofs_init(void);
#if CONF_drivers_virtio_fs
extern int virtiofs_init(void);
#endif
extern int devfs_init(void);
extern int nfs_init(void);
extern int procfs_init(void);
extern int sysfs_init(void);
extern "C" int zfs_init(void);
extern "C" int ext_init(void);

/*
 * VFS switch table
 */
const struct vfssw vfssw[] = {
	{"ramfs",	ramfs_init,	&ramfs_vfsops},
	{"devfs",	devfs_init,	&devfs_vfsops},
	{"nfs",		nfs_init,	&nfs_vfsops},
#if CONF_fs_procfs
	{"procfs",	procfs_init,	&procfs_vfsops},
#endif
#if CONF_fs_sysfs
	{"sysfs",	sysfs_init,	&sysfs_vfsops},
#endif
	{"zfs",		zfs_init,	&zfs_vfsops},
	{"rofs", 	rofs_init, 	&rofs_vfsops},
#if CONF_drivers_virtio_fs
	{"virtiofs", 	virtiofs_init, 	&virtiofs_vfsops},
#endif
	{"ext",		ext_init,	&ext_vfsops},
	{nullptr,	fs_noop,	nullptr},
};
