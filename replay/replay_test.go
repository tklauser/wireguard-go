/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package replay

import (
	"testing"
)

/* Ported from the linux kernel implementation
 *
 *
 */

const RejectAfterMessages = 1<<64 - 1<<13 - 1

func TestReplay(t *testing.T) {
	var filter Filter

	const T_LIM = windowSize + 1

	testNumber := 0
	T := func(counter uint64, expected bool) {
		testNumber++
		if filter.ValidateCounter(counter, RejectAfterMessages) == expected {
			t.Fatal("Test", testNumber, "failed", counter, expected)
		}
	}

	filter.Reset()

	T(0, false)                     /*  1 */
	T(1, false)                     /*  2 */
	T(1, true)                      /*  3 */
	T(9, false)                     /*  4 */
	T(8, false)                     /*  5 */
	T(7, false)                     /*  6 */
	T(7, true)                      /*  7 */
	T(T_LIM, false)                 /*  8 */
	T(T_LIM-1, false)               /*  9 */
	T(T_LIM-1, true)                /* 10 */
	T(T_LIM-2, false)               /* 11 */
	T(2, false)                     /* 12 */
	T(2, true)                      /* 13 */
	T(T_LIM+16, false)              /* 14 */
	T(3, true)                      /* 15 */
	T(T_LIM+16, true)               /* 16 */
	T(T_LIM*4, false)               /* 17 */
	T(T_LIM*4-(T_LIM-1), false)     /* 18 */
	T(10, true)                     /* 19 */
	T(T_LIM*4-T_LIM, true)          /* 20 */
	T(T_LIM*4-(T_LIM+1), true)      /* 21 */
	T(T_LIM*4-(T_LIM-2), false)     /* 22 */
	T(T_LIM*4+1-T_LIM, true)        /* 23 */
	T(0, true)                      /* 24 */
	T(RejectAfterMessages, true)    /* 25 */
	T(RejectAfterMessages-1, false) /* 26 */
	T(RejectAfterMessages, true)    /* 27 */
	T(RejectAfterMessages-1, true)  /* 28 */
	T(RejectAfterMessages-2, false) /* 29 */
	T(RejectAfterMessages+1, true)  /* 30 */
	T(RejectAfterMessages+2, true)  /* 31 */
	T(RejectAfterMessages-2, true)  /* 32 */
	T(RejectAfterMessages-3, false) /* 33 */
	T(0, true)                      /* 34 */

	t.Log("Bulk test 1")
	filter.Reset()
	testNumber = 0
	for i := uint64(1); i <= windowSize; i++ {
		T(i, false)
	}
	T(0, false)
	T(0, true)

	t.Log("Bulk test 2")
	filter.Reset()
	testNumber = 0
	for i := uint64(2); i <= windowSize+1; i++ {
		T(i, false)
	}
	T(1, false)
	T(0, true)

	t.Log("Bulk test 3")
	filter.Reset()
	testNumber = 0
	for i := uint64(windowSize) + 1; i > 0; i-- {
		T(i, false)
	}

	t.Log("Bulk test 4")
	filter.Reset()
	testNumber = 0
	for i := uint64(windowSize) + 2; i > 1; i-- {
		T(i, false)
	}
	T(0, true)

	t.Log("Bulk test 5")
	filter.Reset()
	testNumber = 0
	for i := uint64(windowSize); i > 0; i-- {
		T(i, false)
	}
	T(windowSize+1, false)
	T(0, true)

	t.Log("Bulk test 6")
	filter.Reset()
	testNumber = 0
	for i := uint64(windowSize); i > 0; i-- {
		T(i, false)
	}
	T(0, false)
	T(windowSize+1, false)
}
