/*
 * QEMU IGVM configuration backend for Confidential Guests
 *
 * Copyright (C) 2023-2024 SUSE
 *
 * Authors:
 *  Roy Hopkins <roy.hopkins@suse.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef EXEC_IGVM_H
#define EXEC_IGVM_H

#include "exec/confidential-guest-support.h"

#if defined(CONFIG_IGVM)

int igvm_file_init(ConfidentialGuestSupport *cgs, Error **errp);
int igvm_process(ConfidentialGuestSupport *cgs, Error **erp);

#else

static inline int igvm_file_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    return 0;
}

static inline int igvm_process(ConfidentialGuestSupport *cgs, Error **errp)
{
}

#endif

#endif
