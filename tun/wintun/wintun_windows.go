/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"log"
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

//sys	wintunSetLogger(logger uintptr) = wintun.WintunSetLogger

func init() {
	logger := func(level loggerLevel, msg *uint16) int {
		log.Println("[Wintun]", windows.UTF16ToString((*[(1 << 30) - 1]uint16)(unsafe.Pointer(msg))[:]))
		return 0
	}
	wintunSetLogger(windows.NewCallback(logger))
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

//sys	wintunFreeAdapter(adapter Adapter) = wintun.WintunFreeAdapter

// Close releases the Wintun adapter resources.
func (wintun Adapter) Close() {
	wintunFreeAdapter(wintun)
}

//sys	wintunGetAdapter(pool *uint16, name *uint16, adapter *Adapter) (ret error) = wintun.WintunGetAdapter

// Adapter finds a Wintun adapter by its name. This function returns the adapter if found, or
// windows.ERROR_FILE_NOT_FOUND otherwise. If the adapter is found but not a Wintun-class or a
// member of the pool, this function returns windows.ERROR_ALREADY_EXISTS. The adapter must be
// released after use.
func (pool Pool) Adapter(ifname string) (adapter Adapter, err error) {
	ifname16, err := windows.UTF16PtrFromString(ifname)
	if err != nil {
		return 0, err
	}
	err = wintunGetAdapter(&pool[0], ifname16, &adapter)
	return
}

//sys	wintunCreateAdapter(pool *uint16, name *uint16, requestedGUID *windows.GUID, adapter *Adapter, rebootRequired *bool) (ret error) = wintun.WintunCreateAdapter

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
	err = wintunCreateAdapter(&pool[0], ifname16, requestedGUID, &wintun, &rebootRequired)
	return
}

//sys	wintunDeleteAdapter(adapter Adapter, rebootRequired *bool) (ret error) = wintun.WintunDeleteAdapter

// Delete deletes a Wintun adapter. This function succeeds if the adapter was not found. It returns
// a bool indicating whether a reboot is required.
func (wintun Adapter) Delete() (rebootRequired bool, err error) {
	err = wintunDeleteAdapter(wintun, &rebootRequired)
	return
}

//sys	wintunEnumAdapters(pool *uint16, cb uintptr, param uintptr) (ret error) = wintun.WintunEnumAdapters

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
	err := wintunEnumAdapters(&pool[0], windows.NewCallback(cb), 0)
	if err != nil {
		errors = append(errors, err)
	}
	return
}

//sys	wintunGetAdapterName(adapter Adapter, name *uint16) (ret error) = wintun.WintunGetAdapterName

// Name returns the name of the Wintun adapter.
func (wintun Adapter) Name() (ifname string, err error) {
	var ifname16 [MAX_ADAPTER_NAME]uint16
	err = wintunGetAdapterName(wintun, &ifname16[0])
	if err != nil {
		return "", err
	}
	ifname = windows.UTF16ToString(ifname16[:])
	return
}

//sys	wintunSetAdapterName(adapter Adapter, name *uint16) (ret error) = wintun.WintunSetAdapterName

// SetName sets name of the Wintun adapter.
func (wintun Adapter) SetName(ifname string) error {
	ifname16, err := windows.UTF16FromString(ifname)
	if err != nil {
		return err
	}
	if len(ifname16) > MAX_ADAPTER_NAME {
		ifname16 = append(ifname16[:MAX_ADAPTER_NAME-1], 0)
	}
	return wintunSetAdapterName(wintun, &ifname16[0])
}

//sys	wintunGetVersion(driverVersionMaj *uint32, driverVersionMin *uint32, ndisVersionMaj *uint32, ndisVersionMin *uint32) (ret error) = wintun.WintunGetVersion

// Version returns the version of the Wintun driver and NDIS system currently loaded.
func Version() (driverVersion string, ndisVersion string, err error) {
	var driverMajor, driverMinor, ndisMajor, ndisMinor uint32
	err = wintunGetVersion(&driverMajor, &driverMinor, &ndisMajor, &ndisMinor)
	if err != nil {
		return
	}
	driverVersion = fmt.Sprintf("%d.%d", driverMajor, driverMinor)
	ndisVersion = fmt.Sprintf("%d.%d", ndisMajor, ndisMinor)
	return
}

//sys	wintunGetAdapterDeviceObject(adapter Adapter, handle *windows.Handle) (ret error) = wintun.WintunGetAdapterDeviceObject

// handle returns a handle to the adapter device object. Release handle with windows.CloseHandle
func (wintun Adapter) handle() (handle windows.Handle, err error) {
	err = wintunGetAdapterDeviceObject(wintun, &handle)
	return
}

//sys	wintunGetAdapterGUID(adapter Adapter, guid *windows.GUID) = wintun.WintunGetAdapterGUID

// GUID returns the GUID of the adapter.
func (wintun Adapter) GUID() (guid windows.GUID) {
	wintunGetAdapterGUID(wintun, &guid)
	return
}

//sys	wintunGetAdapterLUID(adapter Adapter, luid *uint64) = wintun.WintunGetAdapterLUID

// LUID returns the LUID of the adapter.
func (wintun Adapter) LUID() (luid uint64) {
	wintunGetAdapterLUID(wintun, &luid)
	return
}
