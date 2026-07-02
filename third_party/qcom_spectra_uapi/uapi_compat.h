#pragma once
/*
 * Compat for building the vendored camera_kt v1.0.3 UAPI headers against
 * older /usr/include kernel headers (device ships pre-5.16 headers that
 * lack __DECLARE_FLEX_ARRAY). Definition mirrors linux/stddef.h.
 */
#include <linux/stddef.h>
#ifndef __DECLARE_FLEX_ARRAY
#define __DECLARE_FLEX_ARRAY(TYPE, NAME) \
	struct { \
		struct { } __empty_ ## NAME; \
		TYPE NAME[]; \
	}
#endif
