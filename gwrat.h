// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWRAT_H
#define GWRAT_H

#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;

enum {
	GWRAT_MSG_RESV		= 0x00,
	GWRAT_MSG_HANDSHAKE	= 0x01,
	GWRAT_MSG_DEVICE_INFO	= 0x02,
	GWRAT_MSG_ERROR		= 0x03,
	GWRAT_MSG_CLOSE		= 0x04,
	GWRAT_MSG_PING		= 0x05,
	GWRAT_MSG_PONG		= 0x06,
	GWRAT_MSG_SHELL_EXEC	= 0x07,
};

enum {
	GWRAT_OS_WIN32		= 0x01,
	GWRAT_OS_LINUX		= 0x02,
	GWRAT_OS_DARWIN		= 0x03,
};

enum {
	GWRAT_ARCH_X86		= 0x01,
	GWRAT_ARCH_X86_64	= 0x02,
	GWRAT_ARCH_ARM		= 0x03,
	GWRAT_ARCH_ARM64	= 0x04,
};

enum {
	GWRAT_ERR_UNKNOWN	= 0x01,
	GWRAT_ERR_VERSION	= 0x02,
	GWRAT_ERR_INVAL		= 0x03,
	GWRAT_ERR_NOMEM		= 0x04,
	GWRAT_ERR_AGAIN		= 0x05,
	GWRAT_ERR_TIMEOUT	= 0x06,
};

struct gwrat_os_info_win32 {
	u8	name[32];
	u8	version[32];
	u8	build[32];
	u8	reserved[32];
} __attribute__((__packed__));

struct gwrat_os_info_linux {
	u8	distro[32];
	u8	version[32];
	u8	codename[32];
	u8	reserved[32];
} __attribute__((__packed__));

struct gwrat_os_info_darwin {
	u8	name[32];
	u8	version[32];
	u8	build[32];
	u8	reserved[32];
} __attribute__((__packed__));

struct gwrat_os_info {
	u8 os_type;
	union {
		struct gwrat_os_info_win32	win32;
		struct gwrat_os_info_linux	linux;
		struct gwrat_os_info_darwin	darwin;
	};
} __attribute__((__packed__));

struct gwrat_hw_info {
	__be16	arch_type;
	__be32	nr_cpu;
	__be64	mem;
	__be64	swap;
} __attribute__((__packed__));


struct gwrat_msg_hdr {
	u8	type;
	u8	__resv;
	__be16 	length;
} __attribute__((__packed__));

struct gwrat_msg_handshake {
	u8	major;
	u8	minor;
	u8	patch;
	u8	extra[29];
} __attribute__((__packed__));

struct gwrat_msg_device_info {
	struct gwrat_os_info	os_info;
	struct gwrat_hw_info	hw_info;
} __attribute__((__packed__));

struct gwrat_msg_close {
	u8 	__resv;
} __attribute__((__packed__));

struct gwrat_msg_shell_exec {
	__be64	cmd_id;
	__be32	cmd_len;
	__be32	__resv;
	u8	cmd[];
} __attribute__((__packed__));

struct gwrat_msg_shell_exec_res {
	__be64	cmd_id;
	__be32	res_len;
	__be32	__resv;
	u8	res[];
} __attribute__((__packed__));


union gwrat_msg_data {
	struct gwrat_msg_handshake	handshake;
	struct gwrat_msg_device_info	device_info;
	struct gwrat_msg_close		close;
} __attribute__((__packed__));


struct gwrat_msg {
	struct gwrat_msg_hdr	hdr;
	union gwrat_msg_data	data;
} __attribute__((__packed__));

#endif /* #ifndef GWRAT_H */
