/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"syscall"
	"unsafe"
)

type Session uintptr

const (
	PacketSizeMax   = 0xffff    // Maximum packet size
	RingCapacityMin = 0x20000   // Minimum ring capacity (128 kiB)
	RingCapacityMax = 0x4000000 // Maximum ring capacity (64 MiB)
)

// Packet with data
type Packet struct {
	Next *Packet              // Pointer to next packet in queue
	Size uint32               // Size of packet (max WINTUN_MAX_IP_PACKET_SIZE)
	Data *[PacketSizeMax]byte // Pointer to layer 3 IPv4 or IPv6 packet
}

var (
	procWintunStartSession       = modwintun.NewProc("WintunStartSession")
	procWintunEndSession         = modwintun.NewProc("WintunEndSession")
	procWintunIsPacketAvailable  = modwintun.NewProc("WintunIsPacketAvailable")
	procWintunWaitForPacket      = modwintun.NewProc("WintunWaitForPacket")
	procWintunReceivePacket      = modwintun.NewProc("WintunReceivePacket")
	procWintunReceiveRelease     = modwintun.NewProc("WintunReceiveRelease")
	procWintunAllocateSendPacket = modwintun.NewProc("WintunAllocateSendPacket")
	procWintunSendPacket         = modwintun.NewProc("WintunSendPacket")
)

func (wintun Adapter) StartSession(capacity uint32) (session Session, err error) {
	r0, _, _ := syscall.Syscall(procWintunStartSession.Addr(), 3, uintptr(wintun), uintptr(capacity), uintptr(unsafe.Pointer(&session)))
	if r0 != 0 {
		session = 0
		err = syscall.Errno(r0)
	}
	return
}

func (session Session) End() {
	syscall.Syscall(procWintunEndSession.Addr(), 1, uintptr(session), 0, 0)
}

func (session Session) IsPacketAvailable() bool {
	r0, _, _ := syscall.Syscall(procWintunIsPacketAvailable.Addr(), 1, uintptr(session), 0, 0)
	return r0 != 0
}

func (session Session) WaitForPacket(milliseconds uint32) (err error) {
	r0, _, _ := syscall.Syscall(procWintunWaitForPacket.Addr(), 2, uintptr(session), uintptr(milliseconds), 0)
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}

func (session Session) ReceivePacket() (packet []byte, err error) {
	var p *[PacketSizeMax]byte
	var size uint32
	r0, _, _ := syscall.Syscall(procWintunReceivePacket.Addr(), 3, uintptr(session), uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&size)))
	if r0 != 0 {
		err = syscall.Errno(r0)
		return
	}
	packet = p[:size]
	return
}

func (session Session) ReceiveRelease(packet []byte) {
	syscall.Syscall(procWintunReceiveRelease.Addr(), 2, uintptr(session), uintptr(unsafe.Pointer(&packet[0])), 0)
}

func (session Session) AllocateSendPacket(size int) (packet []byte, err error) {
	var p *[PacketSizeMax]byte
	r0, _, _ := syscall.Syscall(procWintunAllocateSendPacket.Addr(), 3, uintptr(session), uintptr(size), uintptr(unsafe.Pointer(unsafe.Pointer(&p))))
	if r0 != 0 {
		err = syscall.Errno(r0)
		return
	}
	packet = p[:size]
	return
}

func (session Session) SendPacket(packet []byte) {
	syscall.Syscall(procWintunSendPacket.Addr(), 2, uintptr(session), uintptr(unsafe.Pointer(&packet[0])), 0)
}
