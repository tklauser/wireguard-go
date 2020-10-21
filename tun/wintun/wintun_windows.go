/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type loggerLevel int

const (
	logInfo loggerLevel = iota
	logWarn
	logErr
)

const (
	MAX_POOL         = 256
	MAX_ADAPTER_NAME = 128
)

type Pool [MAX_POOL]uint16
type Adapter uintptr

var (
	modwintun = newLazyDLL("wintun.dll")

	procWintunSetLogger              = modwintun.NewProc("WintunSetLogger")
	procWintunFreeAdapter            = modwintun.NewProc("WintunFreeAdapter")
	procWintunGetAdapter             = modwintun.NewProc("WintunGetAdapter")
	procWintunCreateAdapter          = modwintun.NewProc("WintunCreateAdapter")
	procWintunDeleteAdapter          = modwintun.NewProc("WintunDeleteAdapter")
	procWintunEnumAdapters           = modwintun.NewProc("WintunEnumAdapters")
	procWintunGetAdapterName         = modwintun.NewProc("WintunGetAdapterName")
	procWintunSetAdapterName         = modwintun.NewProc("WintunSetAdapterName")
	procWintunGetVersion             = modwintun.NewProc("WintunGetVersion")
	procWintunGetAdapterDeviceObject = modwintun.NewProc("WintunGetAdapterDeviceObject")
	procWintunGetAdapterGUID         = modwintun.NewProc("WintunGetAdapterGUID")
	procWintunGetAdapterLUID         = modwintun.NewProc("WintunGetAdapterLUID")
)

func init() {
	syscall.Syscall(procWintunSetLogger.Addr(), 1, uintptr(windows.NewCallback(func(level loggerLevel, msg *uint16) int {
		log.Println("[Wintun]", windows.UTF16ToString((*[(1 << 30) - 1]uint16)(unsafe.Pointer(msg))[:]))
		return 0
	})), 0, 0)
}

func MakePool(poolName string) (pool Pool) {
	poolName16 := windows.StringToUTF16(poolName)
	if len(poolName16) > MAX_POOL {
		poolName16 = append(poolName16[:MAX_POOL-1], 0)
	}
	copy(pool[:], poolName16)
	return
}

func (pool Pool) String() string {
	return windows.UTF16ToString(pool[:])
}

// Close releases the Wintun adapter resources.
func (wintun Adapter) Close() {
	syscall.Syscall(procWintunFreeAdapter.Addr(), 1, uintptr(wintun), 0, 0)
}

// Adapter finds a Wintun adapter by its name. This function returns the adapter if found, or
// windows.ERROR_FILE_NOT_FOUND otherwise. If the adapter is found but not a Wintun-class or a
// member of the pool, this function returns windows.ERROR_ALREADY_EXISTS. The adapter must be
// released after use.
func (pool Pool) Adapter(ifname string) (adapter Adapter, err error) {
	ifname16, err := windows.UTF16PtrFromString(ifname)
	if err != nil {
		return 0, err
	}
	r0, _, _ := syscall.Syscall(procWintunGetAdapter.Addr(), 3, uintptr(unsafe.Pointer(&pool[0])), uintptr(unsafe.Pointer(ifname16)), uintptr(unsafe.Pointer(&adapter)))
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}

// CreateAdapter creates a Wintun adapter. ifname is the requested name of the adapter, while
// requestedGUID is the GUID of the created network adapter, which then influences NLA generation
// deterministically. If it is set to nil, the GUID is chosen by the system at random, and hence a
// new NLA entry is created for each new adapter. It is called "requested" GUID because the API it
// uses is completely undocumented, and so there could be minor interesting complications with its
// usage. This function returns the network adapter ID and a flag if reboot is required.
func (pool Pool) CreateAdapter(ifname string, requestedGUID *windows.GUID) (wintun Adapter, rebootRequired bool, err error) {
	var ifname16 *uint16
	ifname16, err = windows.UTF16PtrFromString(ifname)
	if err != nil {
		return
	}
	var _p0 uint32
	r0, _, _ := syscall.Syscall6(procWintunCreateAdapter.Addr(), 5, uintptr(unsafe.Pointer(&pool[0])), uintptr(unsafe.Pointer(ifname16)), uintptr(unsafe.Pointer(requestedGUID)), uintptr(unsafe.Pointer(&wintun)), uintptr(unsafe.Pointer(&_p0)), 0)
	rebootRequired = _p0 != 0
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}

// Delete deletes a Wintun adapter. This function succeeds if the adapter was not found. It returns
// a bool indicating whether a reboot is required.
func (wintun Adapter) Delete() (rebootRequired bool, err error) {
	var _p0 uint32
	r0, _, _ := syscall.Syscall(procWintunDeleteAdapter.Addr(), 2, uintptr(wintun), uintptr(unsafe.Pointer(&_p0)), 0)
	rebootRequired = _p0 != 0
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}

// DeleteMatchingAdapters deletes all Wintun adapters, which match
// given criteria, and returns which ones it deleted, whether a reboot
// is required after, and which errors occurred during the process.
func (pool Pool) DeleteMatchingAdapters(matches func(adapter Adapter) bool) (adaptersDeleted []windows.GUID, rebootRequired bool, errors []error) {
	cb := func(adapter Adapter, _ uintptr) int {
		if !matches(adapter) {
			return 1
		}
		rebootRequired2, err := adapter.Delete()
		if err != nil {
			errors = append(errors, err)
			return 1
		}
		rebootRequired = rebootRequired || rebootRequired2
		adaptersDeleted = append(adaptersDeleted, adapter.GUID())
		return 1
	}
	r0, _, _ := syscall.Syscall(procWintunEnumAdapters.Addr(), 3, uintptr(unsafe.Pointer(&pool[0])), uintptr(windows.NewCallback(cb)), 0)
	if r0 != 0 {
		errors = append(errors, syscall.Errno(r0))
	}
	return
}

// Name returns the name of the Wintun adapter.
func (wintun Adapter) Name() (ifname string, err error) {
	var ifname16 [MAX_ADAPTER_NAME]uint16
	r0, _, _ := syscall.Syscall(procWintunGetAdapterName.Addr(), 2, uintptr(wintun), uintptr(unsafe.Pointer(&ifname16[0])), 0)
	if r0 != 0 {
		return "", syscall.Errno(r0)
	}
	ifname = windows.UTF16ToString(ifname16[:])
	return
}

// SetName sets name of the Wintun adapter.
func (wintun Adapter) SetName(ifname string) (err error) {
	ifname16, err := windows.UTF16FromString(ifname)
	if err != nil {
		return err
	}
	if len(ifname16) > MAX_ADAPTER_NAME {
		ifname16 = append(ifname16[:MAX_ADAPTER_NAME-1], 0)
	}
	r0, _, _ := syscall.Syscall(procWintunSetAdapterName.Addr(), 2, uintptr(wintun), uintptr(unsafe.Pointer(&ifname16[0])), 0)
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}

// Version returns the version of the Wintun driver and NDIS system currently loaded.
func Version() (driverVersion string, ndisVersion string, err error) {
	var driverMajor, driverMinor, ndisMajor, ndisMinor uint32
	r0, _, _ := syscall.Syscall6(procWintunGetVersion.Addr(), 4, uintptr(unsafe.Pointer(&driverMajor)), uintptr(unsafe.Pointer(&driverMinor)), uintptr(unsafe.Pointer(&ndisMajor)), uintptr(unsafe.Pointer(&ndisMinor)), 0, 0)
	if r0 != 0 {
		err = syscall.Errno(r0)
		return
	}
	driverVersion = fmt.Sprintf("%d.%d", driverMajor, driverMinor)
	ndisVersion = fmt.Sprintf("%d.%d", ndisMajor, ndisMinor)
	return
}

// handle returns a handle to the adapter device object. Release handle with windows.CloseHandle
func (wintun Adapter) handle() (handle windows.Handle, err error) {
	r0, _, _ := syscall.Syscall(procWintunGetAdapterDeviceObject.Addr(), 2, uintptr(wintun), uintptr(unsafe.Pointer(&handle)), 0)
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}

// GUID returns the GUID of the adapter.
func (wintun Adapter) GUID() (guid windows.GUID) {
	syscall.Syscall(procWintunGetAdapterGUID.Addr(), 2, uintptr(wintun), uintptr(unsafe.Pointer(&guid)), 0)
	return
}

// LUID returns the LUID of the adapter.
func (wintun Adapter) LUID() (luid uint64) {
	syscall.Syscall(procWintunGetAdapterLUID.Addr(), 2, uintptr(wintun), uintptr(unsafe.Pointer(&luid)), 0)
	return
}
