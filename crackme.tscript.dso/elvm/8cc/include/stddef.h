// Copyright 2012 Rui Ueyama. Released under the MIT license.

#ifndef __STDDEF_H
#define __STDDEF_H

#define NULL ((void *)0)

typedef unsigned long size_t;
typedef long ptrdiff_t;
typedef unsigned int wchar_t;
typedef long double max_align_t;

#define offsetof(type, member) ((size_t)&(((type *)0)->member))

#endif
