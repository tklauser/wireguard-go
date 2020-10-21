/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 WireGuard LLC. All Rights Reserved.
 *
 * Ported from: Memory DLL loading code 0.0.4 by Joachim Bauch <mail@joachim-bauch.de>
 */

package memmod

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type addressList struct {
	next    *addressList
	address uintptr
}

func (head *addressList) free() {
	for node := head; node != nil; node = node.next {
		windows.VirtualFree(node.address, 0, windows.MEM_RELEASE)
	}
}

type Module struct {
	headers       *IMAGE_NT_HEADERS
	codeBase      uintptr
	modules       []windows.Handle
	initialized   bool
	isDLL         bool
	isRelocated   bool
	nameExports   map[string]uint16
	entry         uintptr
	pageSize      uint32
	blockedMemory *addressList
}

func (module *Module) headerDirectory(idx int) *IMAGE_DATA_DIRECTORY {
	return &module.headers.OptionalHeader.DataDirectory[idx]
}

func (module *Module) copySections(address uintptr, size uintptr, old_headers *IMAGE_NT_HEADERS) error {
	sections := module.headers.Sections()
	for i := range sections {
		if sections[i].SizeOfRawData == 0 {
			// section doesn't contain data in the dll itself, but may define
			// uninitialized data
			section_size := old_headers.OptionalHeader.SectionAlignment
			if section_size == 0 {
				continue
			}
			dest, err := windows.VirtualAlloc(module.codeBase+uintptr(sections[i].VirtualAddress),
				uintptr(section_size),
				windows.MEM_COMMIT,
				windows.PAGE_READWRITE)
			if err != nil {
				return fmt.Errorf("Error allocating section: %v", err)
			}

			// Always use position from file to support alignments smaller
			// than page size (allocation above will align to page size).
			dest = module.codeBase + uintptr(sections[i].VirtualAddress)
			// NOTE: On 64bit systems we truncate to 32bit here but expand
			// again later when "PhysicalAddress" is used.
			sections[i].SetPhysicalAddress((uint32)(dest & 0xffffffff))
			dst := (*[1 << 30]byte)(a2p(dest))[:section_size]
			for j := range dst {
				dst[j] = 0
			}
			continue
		}

		if size < uintptr(sections[i].PointerToRawData+sections[i].SizeOfRawData) {
			return errors.New("Incomplete section")
		}

		// commit memory block and copy data from dll
		dest, err := windows.VirtualAlloc(module.codeBase+uintptr(sections[i].VirtualAddress),
			uintptr(sections[i].SizeOfRawData),
			windows.MEM_COMMIT,
			windows.PAGE_READWRITE)
		if err != nil {
			return fmt.Errorf("Error allocating memory block: %v", err)
		}

		// Always use position from file to support alignments smaller
		// than page size (allocation above will align to page size).
		memcpy(
			module.codeBase+uintptr(sections[i].VirtualAddress),
			address+uintptr(sections[i].PointerToRawData),
			uintptr(sections[i].SizeOfRawData))
		// NOTE: On 64bit systems we truncate to 32bit here but expand
		// again later when "PhysicalAddress" is used.
		sections[i].SetPhysicalAddress((uint32)(dest & 0xffffffff))
	}

	return nil
}

func (module *Module) realSectionSize(section *IMAGE_SECTION_HEADER) uintptr {
	size := section.SizeOfRawData
	if size != 0 {
		return uintptr(size)
	}
	if (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
		return uintptr(module.headers.OptionalHeader.SizeOfInitializedData)
	}
	if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 {
		return uintptr(module.headers.OptionalHeader.SizeOfUninitializedData)
	}
	return 0
}

type sectionFinalizeData struct {
	address         uintptr
	alignedAddress  uintptr
	size            uintptr
	characteristics uint32
	last            bool
}

func (module *Module) finalizeSection(sectionData *sectionFinalizeData) error {
	if sectionData.size == 0 {
		return nil
	}

	if (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 {
		// section is not needed any more and can safely be freed
		if sectionData.address == sectionData.alignedAddress &&
			(sectionData.last ||
				module.headers.OptionalHeader.SectionAlignment == module.pageSize ||
				(sectionData.size%uintptr(module.pageSize)) == 0) {
			// Only allowed to decommit whole pages
			windows.VirtualFree(sectionData.address, sectionData.size, windows.MEM_DECOMMIT)
		}
		return nil
	}

	// determine protection flags based on characteristics
	var ProtectionFlags = [8]uint32{
		windows.PAGE_NOACCESS,          // not writeable, not readable, not executable
		PAGE_EXECUTE,                   // not writeable, not readable, executable
		windows.PAGE_READONLY,          // not writeable, readable, not executable
		windows.PAGE_EXECUTE_READ,      // not writeable, readable, executable
		windows.PAGE_WRITECOPY,         // writeable, not readable, not executable
		windows.PAGE_EXECUTE_WRITECOPY, // writeable, not readable, executable
		windows.PAGE_READWRITE,         // writeable, readable, not executable
		windows.PAGE_EXECUTE_READWRITE, // writeable, readable, executable
	}
	protect := ProtectionFlags[sectionData.characteristics>>29]
	if (sectionData.characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0 {
		protect |= PAGE_NOCACHE
	}

	// change memory access flags
	var oldProtect uint32
	err := windows.VirtualProtect(sectionData.address, sectionData.size, protect, &oldProtect)
	if err != nil {
		return fmt.Errorf("Error protecting memory page: %v", err)
	}

	return nil
}

func (module *Module) finalizeSections() error {
	sections := module.headers.Sections()
	imageOffset := module.headers.OptionalHeader.imageOffset()
	sectionData := sectionFinalizeData{}
	sectionData.address = uintptr(sections[0].PhysicalAddress()) | imageOffset
	sectionData.alignedAddress = alignDown(sectionData.address, uintptr(module.pageSize))
	sectionData.size = module.realSectionSize(&sections[0])
	sectionData.characteristics = sections[0].Characteristics

	// loop through all sections and change access flags
	for i := uint16(1); i < module.headers.FileHeader.NumberOfSections; i++ {
		sectionAddress := uintptr(sections[i].PhysicalAddress()) | imageOffset
		alignedAddress := alignDown(sectionAddress, uintptr(module.pageSize))
		sectionSize := module.realSectionSize(&sections[i])
		// Combine access flags of all sections that share a page
		// TODO(fancycode): We currently share flags of a trailing large section
		//   with the page of a first small section. This should be optimized.
		if sectionData.alignedAddress == alignedAddress || sectionData.address+sectionData.size > alignedAddress {
			// Section shares page with previous
			if (sections[i].Characteristics&IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics&IMAGE_SCN_MEM_DISCARDABLE) == 0 {
				sectionData.characteristics = (sectionData.characteristics | sections[i].Characteristics) &^ IMAGE_SCN_MEM_DISCARDABLE
			} else {
				sectionData.characteristics |= sections[i].Characteristics
			}
			sectionData.size = sectionAddress + sectionSize - sectionData.address
			continue
		}

		err := module.finalizeSection(&sectionData)
		if err != nil {
			return fmt.Errorf("Error finalizing section: %v", err)
		}
		sectionData.address = sectionAddress
		sectionData.alignedAddress = alignedAddress
		sectionData.size = sectionSize
		sectionData.characteristics = sections[i].Characteristics
	}
	sectionData.last = true
	err := module.finalizeSection(&sectionData)
	if err != nil {
		return fmt.Errorf("Error finalizing section: %v", err)
	}
	return nil
}

func (module *Module) executeTLS() {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_TLS)
	if directory.VirtualAddress == 0 {
		return
	}

	tls := (*IMAGE_TLS_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	callback := tls.AddressOfCallBacks
	if callback != 0 {
		for {
			f := *(*uintptr)(a2p(callback))
			if f == 0 {
				break
			}
			syscall.Syscall(f, 3, module.codeBase, uintptr(DLL_PROCESS_ATTACH), uintptr(0))
			callback += unsafe.Sizeof(f)
		}
	}
}

func (module *Module) performBaseRelocation(delta uintptr) bool {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
	if directory.Size == 0 {
		return delta == 0
	}

	relocation := (*IMAGE_BASE_RELOCATION)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	for relocation.VirtualAddress > 0 {
		dest := module.codeBase + uintptr(relocation.VirtualAddress)

		relInfos := (*[1 << 29]uint16)(a2p(uintptr(unsafe.Pointer(relocation)) + unsafe.Sizeof(IMAGE_BASE_RELOCATION{})))[:(relocation.SizeOfBlock-uint32(unsafe.Sizeof(IMAGE_BASE_RELOCATION{})))/2]
		for _, relInfo := range relInfos {
			// the upper 4 bits define the type of relocation
			relType := relInfo >> 12
			// the lower 12 bits define the offset
			relOffset := uintptr(relInfo & 0xfff)

			switch relType {
			case IMAGE_REL_BASED_ABSOLUTE:
				// skip relocation

			case IMAGE_REL_BASED_HIGHLOW:
				// change complete 32 bit address
				{
					patchAddrHL := (*uint32)(a2p(dest + relOffset))
					*patchAddrHL += uint32(delta)
				}

			case IMAGE_REL_BASED_DIR64:
				{
					patchAddr64 := (*uint64)(a2p(dest + relOffset))
					*patchAddr64 += uint64(delta)
				}
			}
		}

		// advance to next relocation block
		relocation = (*IMAGE_BASE_RELOCATION)(a2p(uintptr(unsafe.Pointer(relocation)) + uintptr(relocation.SizeOfBlock)))
	}
	return true
}

func (module *Module) buildImportTable() error {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT)
	if directory.Size == 0 {
		return nil
	}

	module.modules = make([]windows.Handle, 0, 16)
	importDescs := (*[1 << 26]IMAGE_IMPORT_DESCRIPTOR)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	for i := 0; !isBadReadPtr(uintptr(unsafe.Pointer(&importDescs[i])), unsafe.Sizeof(IMAGE_IMPORT_DESCRIPTOR{})) && importDescs[i].Name != 0; i++ {
		handle, err := loadLibraryA((*byte)(a2p(module.codeBase + uintptr(importDescs[i].Name))))
		if err != nil {
			return fmt.Errorf("Error loading module: %v", err)
		}
		var thunkRefs, funcRefs *[1 << 28]uintptr
		if importDescs[i].OriginalFirstThunk() != 0 {
			thunkRefs = (*[1 << 28]uintptr)(a2p(module.codeBase + uintptr(importDescs[i].OriginalFirstThunk())))
			funcRefs = (*[1 << 28]uintptr)(a2p(module.codeBase + uintptr(importDescs[i].FirstThunk)))
		} else {
			// no hint table
			thunkRefs = (*[1 << 28]uintptr)(a2p(module.codeBase + uintptr(importDescs[i].FirstThunk)))
			funcRefs = (*[1 << 28]uintptr)(a2p(module.codeBase + uintptr(importDescs[i].FirstThunk)))
		}
		for j := 0; thunkRefs[j] != 0; j++ {
			if IMAGE_SNAP_BY_ORDINAL(thunkRefs[j]) {
				funcRefs[j], err = getProcAddress(handle, (*byte)(a2p(IMAGE_ORDINAL(thunkRefs[j]))))
			} else {
				thunkData := (*IMAGE_IMPORT_BY_NAME)(a2p(module.codeBase + thunkRefs[j]))
				funcRefs[j], err = getProcAddress(handle, &thunkData.Name[0])
			}
			if err != nil {
				windows.FreeLibrary(handle)
				return fmt.Errorf("Error getting function address: %v", err)
			}
		}
		module.modules = append(module.modules, handle)
	}
	return nil
}

func (module *Module) buildNameExports() error {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	if directory.Size == 0 {
		return errors.New("No export table found")
	}
	exports := (*IMAGE_EXPORT_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	if exports.NumberOfNames == 0 || exports.NumberOfFunctions == 0 {
		return errors.New("No functions exported")
	}
	if exports.NumberOfNames == 0 {
		return errors.New("No functions exported by name")
	}
	nameRefs := (*[1 << 28]uint32)(a2p(module.codeBase + uintptr(exports.AddressOfNames)))[:exports.NumberOfNames]
	ordinals := (*[1 << 29]uint16)(a2p(module.codeBase + uintptr(exports.AddressOfNameOrdinals)))[:exports.NumberOfNames]
	module.nameExports = make(map[string]uint16)
	for i := range nameRefs {
		nameArray := (*[1 << 30]byte)(a2p(module.codeBase + uintptr(nameRefs[i])))
		for nameLen := 0; ; nameLen++ {
			if nameLen >= len(nameArray) || nameArray[nameLen] == 0 {
				module.nameExports[string(nameArray[:nameLen])] = ordinals[i]
				break
			}
		}
	}
	return nil
}

// LoadLibrary loads module image to memory.
func LoadLibrary(data []byte) (module *Module, err error) {
	addr := uintptr(unsafe.Pointer(&data[0]))
	size := uintptr(len(data))
	if size < unsafe.Sizeof(IMAGE_DOS_HEADER{}) {
		return nil, errors.New("Incomplete IMAGE_DOS_HEADER")
	}
	dos_header := (*IMAGE_DOS_HEADER)(a2p(addr))
	if dos_header.E_magic != IMAGE_DOS_SIGNATURE {
		return nil, fmt.Errorf("Not an MS-DOS binary (provided: %x, expected: %x)", dos_header.E_magic, IMAGE_DOS_SIGNATURE)
	}
	if (size < uintptr(dos_header.E_lfanew)+unsafe.Sizeof(IMAGE_NT_HEADERS{})) {
		return nil, errors.New("Incomplete IMAGE_NT_HEADERS")
	}
	old_header := (*IMAGE_NT_HEADERS)(a2p(addr + uintptr(dos_header.E_lfanew)))
	if old_header.Signature != IMAGE_NT_SIGNATURE {
		return nil, fmt.Errorf("Not an NT binary (provided: %x, expected: %x)", old_header.Signature, IMAGE_NT_SIGNATURE)
	}
	if old_header.FileHeader.Machine != imageFileProcess {
		return nil, fmt.Errorf("Foreign platform (provided: %x, expected: %x)", old_header.FileHeader.Machine, imageFileProcess)
	}
	if (old_header.OptionalHeader.SectionAlignment & 1) != 0 {
		return nil, errors.New("Unaligned section")
	}
	lastSectionEnd := uintptr(0)
	sections := old_header.Sections()
	optionalSectionSize := old_header.OptionalHeader.SectionAlignment
	for i := range sections {
		var endOfSection uintptr
		if sections[i].SizeOfRawData == 0 {
			// Section without data in the DLL
			endOfSection = uintptr(sections[i].VirtualAddress) + uintptr(optionalSectionSize)
		} else {
			endOfSection = uintptr(sections[i].VirtualAddress) + uintptr(sections[i].SizeOfRawData)
		}
		if endOfSection > lastSectionEnd {
			lastSectionEnd = endOfSection
		}
	}
	var sysInfo SYSTEM_INFO
	getNativeSystemInfo(&sysInfo)
	alignedImageSize := alignUp(uintptr(old_header.OptionalHeader.SizeOfImage), uintptr(sysInfo.PageSize))
	if alignedImageSize != alignUp(lastSectionEnd, uintptr(sysInfo.PageSize)) {
		return nil, errors.New("Section is not page-aligned")
	}

	module = &Module{
		isDLL:    (old_header.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0,
		pageSize: sysInfo.PageSize,
	}
	defer func() {
		if err != nil {
			module.Free()
			module = nil
		}
	}()

	// reserve memory for image of library
	// XXX: is it correct to commit the complete memory region at once?
	//      calling DllEntry raises an exception if we don't...
	module.codeBase, err = windows.VirtualAlloc(old_header.OptionalHeader.ImageBase,
		alignedImageSize,
		windows.MEM_RESERVE|windows.MEM_COMMIT,
		windows.PAGE_READWRITE)
	if err != nil {
		// try to allocate memory at arbitrary position
		module.codeBase, err = windows.VirtualAlloc(0,
			alignedImageSize,
			windows.MEM_RESERVE|windows.MEM_COMMIT,
			windows.PAGE_READWRITE)
		if err != nil {
			err = fmt.Errorf("Error allocating code: %v", err)
			return
		}
	}
	err = module.check4GBBoundaries(alignedImageSize)
	if err != nil {
		err = fmt.Errorf("Error reallocating code: %v", err)
		return
	}

	if size < uintptr(old_header.OptionalHeader.SizeOfHeaders) {
		err = errors.New("Incomplete headers")
		return
	}
	// commit memory for headers
	headers, err := windows.VirtualAlloc(module.codeBase,
		uintptr(old_header.OptionalHeader.SizeOfHeaders),
		windows.MEM_COMMIT,
		windows.PAGE_READWRITE)
	if err != nil {
		err = fmt.Errorf("Error allocating headers: %v", err)
		return
	}
	// copy PE header to code
	memcpy(headers, addr, uintptr(old_header.OptionalHeader.SizeOfHeaders))
	module.headers = (*IMAGE_NT_HEADERS)(a2p(headers + uintptr(dos_header.E_lfanew)))

	// update position
	module.headers.OptionalHeader.ImageBase = module.codeBase

	// copy sections from DLL file block to new memory location
	err = module.copySections(addr, size, old_header)
	if err != nil {
		err = fmt.Errorf("Error copying sections: %v", err)
		return
	}

	// adjust base address of imported data
	locationDelta := module.headers.OptionalHeader.ImageBase - old_header.OptionalHeader.ImageBase
	if locationDelta != 0 {
		module.isRelocated = module.performBaseRelocation(locationDelta)
	} else {
		module.isRelocated = true
	}

	// load required dlls and adjust function table of imports
	err = module.buildImportTable()
	if err != nil {
		err = fmt.Errorf("Error building import table: %v", err)
		return
	}

	// mark memory pages depending on section headers and release
	// sections that are marked as "discardable"
	err = module.finalizeSections()
	if err != nil {
		err = fmt.Errorf("Error finalizing sections: %v", err)
		return
	}

	// TLS callbacks are executed BEFORE the main loading
	module.executeTLS()

	// get entry point of loaded module
	if module.headers.OptionalHeader.AddressOfEntryPoint != 0 {
		module.entry = module.codeBase + uintptr(module.headers.OptionalHeader.AddressOfEntryPoint)
		if module.isDLL {
			// notify library about attaching to process
			r0, _, _ := syscall.Syscall(module.entry, 3, module.codeBase, uintptr(DLL_PROCESS_ATTACH), 0)
			successfull := r0 != 0
			if !successfull {
				err = windows.ERROR_DLL_INIT_FAILED
				return
			}
			module.initialized = true
		}
	}

	module.buildNameExports()
	return
}

// Free releases module resources and unloads it.
func (module *Module) Free() {
	if module.initialized {
		// notify library about detaching from process
		syscall.Syscall(module.entry, 3, module.codeBase, uintptr(DLL_PROCESS_DETACH), 0)
		module.initialized = false
	}
	if module.modules != nil {
		// free previously opened libraries
		for _, handle := range module.modules {
			windows.FreeLibrary(handle)
		}
		module.modules = nil
	}
	if module.codeBase != 0 {
		windows.VirtualFree(module.codeBase, 0, windows.MEM_RELEASE)
		module.codeBase = 0
	}
	if module.blockedMemory != nil {
		module.blockedMemory.free()
		module.blockedMemory = nil
	}
}

// ProcAddressByName returns function address by exported name.
func (module *Module) ProcAddressByName(name string) (uintptr, error) {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	if directory.Size == 0 {
		return 0, errors.New("No export table found")
	}
	exports := (*IMAGE_EXPORT_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	if module.nameExports == nil {
		return 0, errors.New("No functions exported by name")
	}
	if idx, ok := module.nameExports[name]; ok {
		if uint32(idx) > exports.NumberOfFunctions {
			return 0, errors.New("Ordinal number too high")
		}
		// AddressOfFunctions contains the RVAs to the "real" functions
		return module.codeBase + uintptr(*(*uint32)(a2p(module.codeBase + uintptr(exports.AddressOfFunctions) + uintptr(idx)*4))), nil
	}
	return 0, errors.New("Function not found by name")
}

// ProcAddressByOrdinal returns function address by exported ordinal.
func (module *Module) ProcAddressByOrdinal(ordinal uint16) (uintptr, error) {
	directory := module.headerDirectory(IMAGE_DIRECTORY_ENTRY_EXPORT)
	if directory.Size == 0 {
		return 0, errors.New("No export table found")
	}
	exports := (*IMAGE_EXPORT_DIRECTORY)(a2p(module.codeBase + uintptr(directory.VirtualAddress)))
	if uint32(ordinal) < exports.Base {
		return 0, errors.New("Ordinal number too low")
	}
	idx := ordinal - uint16(exports.Base)
	if uint32(idx) > exports.NumberOfFunctions {
		return 0, errors.New("Ordinal number too high")
	}
	// AddressOfFunctions contains the RVAs to the "real" functions
	return module.codeBase + uintptr(*(*uint32)(a2p(module.codeBase + uintptr(exports.AddressOfFunctions) + uintptr(idx)*4))), nil
}

func alignDown(value, alignment uintptr) uintptr {
	return value & ^(alignment - 1)
}

func alignUp(value, alignment uintptr) uintptr {
	return (value + alignment - 1) & ^(alignment - 1)
}

func a2p(addr uintptr) unsafe.Pointer {
	return unsafe.Pointer(addr)
}
