// Package elfy provides a simple interface for manipulating ELF files
// Supports both 32-bit (unstested) and 64-bit ELF files.
package elfy

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// ListSections returns a slice of section names present in the provided ELF data.
// It parses the ELF file and extracts the names of all sections.
//
// Parameters:
//   - elfData: A byte slice containing the raw ELF file data.
//
// Returns:
//   - A slice of strings containing the names of all sections.
//   - An error if the ELF data is invalid or cannot be parsed.
func ListSections(elfData []byte) ([]string, error) {
	r := bytes.NewReader(elfData)
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("error parsing ELF data: %v", err)
	}
	sections := make([]string, 0, len(f.Sections)) // Pre-allocate to reduce resizing
	for _, sec := range f.Sections {
		sections = append(sections, sec.Name)
	}
	return sections, nil
}

// ReadSection retrieves the content of the specified section from the ELF data.
// The section is identified by its name, and the function returns the raw bytes of the section's content.
//
// Parameters:
//   - elfData: A byte slice containing the raw ELF file data.
//   - name: The name of the section to read (e.g., ".text", ".data").
//
// Returns:
//   - A byte slice containing the section's data.
//   - An error if the ELF data is invalid, the section is not found, or the section data cannot be read.
func ReadSection(elfData []byte, name string) ([]byte, error) {
	r := bytes.NewReader(elfData)
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("error parsing ELF data: %v", err)
	}
	sec := f.Section(name)
	if sec == nil {
		return nil, fmt.Errorf("section %s not found", name)
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("error reading section data: %v", err)
	}
	return data, nil
}

// AddOrReplaceSection adds a new section or replaces an existing one in the ELF data.
// The new section is created with the provided name and data.
//
// Parameters:
//   - elfData: A byte slice containing the raw ELF file data.
//   - sectionName: The name of the section to add or replace.
//   - sectionData: The raw bytes to write as the section's content.
//
// Returns:
//   - A byte slice containing the modified ELF file data.
//   - An error if the ELF data is invalid or the operation fails.
func AddOrReplaceSection(elfData []byte, sectionName string, sectionData []byte) ([]byte, error) {
	r := bytes.NewReader(elfData)
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("error parsing ELF data: %v", err)
	}
	byteOrder := elfFile.ByteOrder

	var is64Bit bool
	var hdr32 *elf.Header32
	var hdr64 *elf.Header64
	var sectionHeaders32 []elf.Section32
	var sectionHeaders64 []elf.Section64
	var shstrtabIdx int

	if elfFile.Class == elf.ELFCLASS64 {
		is64Bit = true
		hdr64 = &elf.Header64{}
		r.Seek(0, io.SeekStart)
		if err := binary.Read(r, byteOrder, hdr64); err != nil {
			return nil, fmt.Errorf("error reading ELF header: %v", err)
		}
		sectionHeaders64 = make([]elf.Section64, hdr64.Shnum)
		r.Seek(int64(hdr64.Shoff), io.SeekStart)
		for i := range sectionHeaders64 {
			if err := binary.Read(r, byteOrder, &sectionHeaders64[i]); err != nil {
				return nil, fmt.Errorf("error reading section header: %v", err)
			}
		}
		shstrtabIdx = int(hdr64.Shstrndx)
	} else if elfFile.Class == elf.ELFCLASS32 {
		is64Bit = false
		hdr32 = &elf.Header32{}
		r.Seek(0, io.SeekStart)
		if err := binary.Read(r, byteOrder, hdr32); err != nil {
			return nil, fmt.Errorf("error reading ELF header: %v", err)
		}
		sectionHeaders32 = make([]elf.Section32, hdr32.Shnum)
		r.Seek(int64(hdr32.Shoff), io.SeekStart)
		for i := range sectionHeaders32 {
			if err := binary.Read(r, byteOrder, &sectionHeaders32[i]); err != nil {
				return nil, fmt.Errorf("error reading section header: %v", err)
			}
		}
		shstrtabIdx = int(hdr32.Shstrndx)
	} else {
		return nil, fmt.Errorf("unsupported ELF class: %v", elfFile.Class)
	}

	if (is64Bit && shstrtabIdx >= len(sectionHeaders64)) || (!is64Bit && shstrtabIdx >= len(sectionHeaders32)) {
		return nil, fmt.Errorf("invalid .shstrtab index")
	}

	var shstrtabOffset, shstrtabSize uint64
	if is64Bit {
		shstrtabOffset = sectionHeaders64[shstrtabIdx].Off
		shstrtabSize = sectionHeaders64[shstrtabIdx].Size
	} else {
		shstrtabOffset = uint64(sectionHeaders32[shstrtabIdx].Off)
		shstrtabSize = uint64(sectionHeaders32[shstrtabIdx].Size)
	}

	r.Seek(int64(shstrtabOffset), io.SeekStart)
	shstrtabData := make([]byte, shstrtabSize)
	if _, err := r.Read(shstrtabData); err != nil {
		return nil, fmt.Errorf("error reading .shstrtab: %v", err)
	}

	// Find or append section name in .shstrtab
	nameOffset := findStringOffset(shstrtabData, sectionName)
	if nameOffset == -1 {
		nameOffset = len(shstrtabData)
		shstrtabData = append(shstrtabData, sectionName...)
		shstrtabData = append(shstrtabData, 0)
	}

	// Check if section exists
	sectionIndex := -1
	if is64Bit {
		for i, s := range sectionHeaders64 {
			if s.Name == uint32(nameOffset) {
				sectionIndex = i
				break
			}
		}
	} else {
		for i, s := range sectionHeaders32 {
			if s.Name == uint32(nameOffset) {
				sectionIndex = i
				break
			}
		}
	}

	isReplacing := sectionIndex != -1
	sectionSize := uint64(len(sectionData))

	var maxOffset uint64
	if is64Bit {
		for _, s := range sectionHeaders64 {
			if s.Type != uint32(elf.SHT_NOBITS) && s.Off+s.Size > maxOffset {
				maxOffset = s.Off + s.Size
			}
		}
	} else {
		for _, s := range sectionHeaders32 {
			if s.Type != uint32(elf.SHT_NOBITS) && uint64(s.Off)+uint64(s.Size) > maxOffset {
				maxOffset = uint64(s.Off) + uint64(s.Size)
			}
		}
	}

	// Align to 4 bytes for 32-bit, 8 bytes for 64-bit
	alignment := uint64(8)
	if !is64Bit {
		alignment = 4
	}
	if maxOffset%alignment != 0 {
		maxOffset += alignment - (maxOffset % alignment)
	}
	newSectionOff := maxOffset

	if isReplacing {
		if is64Bit {
			sectionHeaders64[sectionIndex].Off = newSectionOff
			sectionHeaders64[sectionIndex].Size = sectionSize
		} else {
			sectionHeaders32[sectionIndex].Off = uint32(newSectionOff)
			sectionHeaders32[sectionIndex].Size = uint32(sectionSize)
		}
	} else {
		if is64Bit {
			sectionHeaders64 = append(sectionHeaders64, elf.Section64{
				Name:      uint32(nameOffset),
				Type:      uint32(elf.SHT_PROGBITS),
				Flags:     uint64(elf.SHF_ALLOC),
				Off:       newSectionOff,
				Size:      sectionSize,
				Addralign: 1,
			})
			hdr64.Shnum++
		} else {
			sectionHeaders32 = append(sectionHeaders32, elf.Section32{
				Name:      uint32(nameOffset),
				Type:      uint32(elf.SHT_PROGBITS),
				Flags:     uint32(elf.SHF_ALLOC),
				Off:       uint32(newSectionOff),
				Size:      uint32(sectionSize),
				Addralign: 1,
			})
			hdr32.Shnum++
		}
	}

	// Always place .shstrtab after new section data
	newShstrtabOff := newSectionOff + sectionSize
	if newShstrtabOff%alignment != 0 {
		newShstrtabOff += alignment - (newShstrtabOff % alignment)
	}
	if is64Bit {
		sectionHeaders64[shstrtabIdx].Off = newShstrtabOff
		if nameOffset == len(shstrtabData)-len(sectionName)-1 {
			sectionHeaders64[shstrtabIdx].Size = uint64(len(shstrtabData))
		}
	} else {
		sectionHeaders32[shstrtabIdx].Off = uint32(newShstrtabOff)
		if nameOffset == len(shstrtabData)-len(sectionName)-1 {
			sectionHeaders32[shstrtabIdx].Size = uint32(len(shstrtabData))
		}
	}

	newShoff := newShstrtabOff + uint64(len(shstrtabData))
	if newShoff%alignment != 0 {
		newShoff += alignment - (newShoff % alignment)
	}
	if is64Bit {
		hdr64.Shoff = newShoff
	} else {
		hdr32.Shoff = uint32(newShoff)
	}

	var buf bytes.Buffer
	buf.Grow(int(maxOffset + sectionSize + uint64(len(shstrtabData)) + newShoff)) // Pre-allocate buffer
	if err := writePaddedData(&buf, elfData[:maxOffset], sectionData, newShstrtabOff-(maxOffset+sectionSize)); err != nil {
		return nil, err
	}
	if err := writePaddedData(&buf, shstrtabData, nil, newShoff-(newShstrtabOff+uint64(len(shstrtabData)))); err != nil {
		return nil, err
	}

	if is64Bit {
		for _, s := range sectionHeaders64 {
			if err := binary.Write(&buf, byteOrder, &s); err != nil {
				return nil, fmt.Errorf("error writing section header: %v", err)
			}
		}
		var hdrBuf bytes.Buffer
		if err := binary.Write(&hdrBuf, byteOrder, hdr64); err != nil {
			return nil, fmt.Errorf("error writing ELF header: %v", err)
		}
		bufBytes := buf.Bytes()
		copy(bufBytes[:hdrBuf.Len()], hdrBuf.Bytes())
		return bufBytes, nil
	}
	for _, s := range sectionHeaders32 {
		if err := binary.Write(&buf, byteOrder, &s); err != nil {
			return nil, fmt.Errorf("error writing section header: %v", err)
		}
	}
	var hdrBuf bytes.Buffer
	if err := binary.Write(&hdrBuf, byteOrder, hdr32); err != nil {
		return nil, fmt.Errorf("error writing ELF header: %v", err)
	}
	bufBytes := buf.Bytes()
	copy(bufBytes[:hdrBuf.Len()], hdrBuf.Bytes())
	return bufBytes, nil
}

// RemoveSection removes the specified section from the ELF data.
//
// Parameters:
//   - elfData: A byte slice containing the raw ELF file data.
//   - sectionName: The name of the section to remove.
//
// Returns:
//   - A byte slice containing the modified ELF file data.
//   - An error if the ELF data is invalid, the section is not found, or the operation fails.
func RemoveSection(elfData []byte, sectionName string) ([]byte, error) {
	r := bytes.NewReader(elfData)
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("error parsing ELF data: %v", err)
	}
	byteOrder := elfFile.ByteOrder

	var is64Bit bool
	var hdr32 *elf.Header32
	var hdr64 *elf.Header64
	var sectionHeaders32 []elf.Section32
	var sectionHeaders64 []elf.Section64
	var shstrtabIdx int

	if elfFile.Class == elf.ELFCLASS64 {
		is64Bit = true
		hdr64 = &elf.Header64{}
		r.Seek(0, io.SeekStart)
		if err := binary.Read(r, byteOrder, hdr64); err != nil {
			return nil, fmt.Errorf("error reading ELF header: %v", err)
		}
		sectionHeaders64 = make([]elf.Section64, hdr64.Shnum)
		r.Seek(int64(hdr64.Shoff), io.SeekStart)
		for i := range sectionHeaders64 {
			if err := binary.Read(r, byteOrder, &sectionHeaders64[i]); err != nil {
				return nil, fmt.Errorf("error reading section header: %v", err)
			}
		}
		shstrtabIdx = int(hdr64.Shstrndx)
	} else if elfFile.Class == elf.ELFCLASS32 {
		is64Bit = false
		hdr32 = &elf.Header32{}
		r.Seek(0, io.SeekStart)
		if err := binary.Read(r, byteOrder, hdr32); err != nil {
			return nil, fmt.Errorf("error reading ELF header: %v", err)
		}
		sectionHeaders32 = make([]elf.Section32, hdr32.Shnum)
		r.Seek(int64(hdr32.Shoff), io.SeekStart)
		for i := range sectionHeaders32 {
			if err := binary.Read(r, byteOrder, &sectionHeaders32[i]); err != nil {
				return nil, fmt.Errorf("error reading section header: %v", err)
			}
		}
		shstrtabIdx = int(hdr32.Shstrndx)
	} else {
		return nil, fmt.Errorf("unsupported ELF class: %v", elfFile.Class)
	}

	if (is64Bit && shstrtabIdx >= len(sectionHeaders64)) || (!is64Bit && shstrtabIdx >= len(sectionHeaders32)) {
		return nil, fmt.Errorf("invalid .shstrtab index")
	}

	var shstrtabOffset, shstrtabSize uint64
	if is64Bit {
		shstrtabOffset = sectionHeaders64[shstrtabIdx].Off
		shstrtabSize = sectionHeaders64[shstrtabIdx].Size
	} else {
		shstrtabOffset = uint64(sectionHeaders32[shstrtabIdx].Off)
		shstrtabSize = uint64(sectionHeaders32[shstrtabIdx].Size)
	}

	r.Seek(int64(shstrtabOffset), io.SeekStart)
	shstrtabData := make([]byte, shstrtabSize)
	if _, err := r.Read(shstrtabData); err != nil {
		return nil, fmt.Errorf("error reading .shstrtab: %v", err)
	}

	// Find section index
	sectionIndex := -1
	if is64Bit {
		for i, s := range sectionHeaders64 {
			nameOffset := s.Name
			if nameOffset >= uint32(len(shstrtabData)) {
				continue
			}
			name := string(shstrtabData[nameOffset:])
			if nullPos := strings.IndexByte(name, 0); nullPos != -1 {
				name = name[:nullPos]
			}
			if name == sectionName {
				sectionIndex = i
				break
			}
		}
	} else {
		for i, s := range sectionHeaders32 {
			nameOffset := s.Name
			if nameOffset >= uint32(len(shstrtabData)) {
				continue
			}
			name := string(shstrtabData[nameOffset:])
			if nullPos := strings.IndexByte(name, 0); nullPos != -1 {
				name = name[:nullPos]
			}
			if name == sectionName {
				sectionIndex = i
				break
			}
		}
	}
	if sectionIndex == -1 {
		return nil, fmt.Errorf("section %s not found", sectionName)
	}

	// Remove the section header
	var newSectionHeaders32 []elf.Section32
	var newSectionHeaders64 []elf.Section64
	if is64Bit {
		newSectionHeaders64 = make([]elf.Section64, 0, len(sectionHeaders64)-1)
		newSectionHeaders64 = append(newSectionHeaders64, sectionHeaders64[:sectionIndex]...)
		newSectionHeaders64 = append(newSectionHeaders64, sectionHeaders64[sectionIndex+1:]...)
		hdr64.Shnum = uint16(len(newSectionHeaders64))
	} else {
		newSectionHeaders32 = make([]elf.Section32, 0, len(sectionHeaders32)-1)
		newSectionHeaders32 = append(newSectionHeaders32, sectionHeaders32[:sectionIndex]...)
		newSectionHeaders32 = append(newSectionHeaders32, sectionHeaders32[sectionIndex+1:]...)
		hdr32.Shnum = uint16(len(newSectionHeaders32))
	}

	var maxOffset uint64
	if is64Bit {
		for _, s := range newSectionHeaders64 {
			if s.Type != uint32(elf.SHT_NOBITS) && s.Off+s.Size > maxOffset {
				maxOffset = s.Off + s.Size
			}
		}
	} else {
		for _, s := range newSectionHeaders32 {
			if s.Type != uint32(elf.SHT_NOBITS) && uint64(s.Off)+uint64(s.Size) > maxOffset {
				maxOffset = uint64(s.Off) + uint64(s.Size)
			}
		}
	}

	// Align to 4 bytes for 32-bit, 8 bytes for 64-bit
	alignment := uint64(8)
	if !is64Bit {
		alignment = 4
	}
	if maxOffset%alignment != 0 {
		maxOffset += alignment - (maxOffset % alignment)
	}
	if is64Bit {
		hdr64.Shoff = maxOffset
	} else {
		hdr32.Shoff = uint32(maxOffset)
	}

	var buf bytes.Buffer
	buf.Grow(int(maxOffset)) // Pre-allocate buffer
	if maxOffset > uint64(len(elfData)) {
		maxOffset = uint64(len(elfData))
	}
	if _, err := buf.Write(elfData[:maxOffset]); err != nil {
		return nil, fmt.Errorf("error writing output: %v", err)
	}

	if is64Bit {
		for _, s := range newSectionHeaders64 {
			if err := binary.Write(&buf, byteOrder, &s); err != nil {
				return nil, fmt.Errorf("error writing section header: %v", err)
			}
		}
		var hdrBuf bytes.Buffer
		if err := binary.Write(&hdrBuf, byteOrder, hdr64); err != nil {
			return nil, fmt.Errorf("error writing ELF header: %v", err)
		}
		bufBytes := buf.Bytes()
		copy(bufBytes[:hdrBuf.Len()], hdrBuf.Bytes())
		return bufBytes, nil
	}
	for _, s := range newSectionHeaders32 {
		if err := binary.Write(&buf, byteOrder, &s); err != nil {
			return nil, fmt.Errorf("error writing section header: %v", err)
		}
	}
	var hdrBuf bytes.Buffer
	if err := binary.Write(&hdrBuf, byteOrder, hdr32); err != nil {
		return nil, fmt.Errorf("error writing ELF header: %v", err)
	}
	bufBytes := buf.Bytes()
	copy(bufBytes[:hdrBuf.Len()], hdrBuf.Bytes())
	return bufBytes, nil
}

// writePaddedData writes data to the buffer with optional padding.
// If nextData is non-nil, it writes data followed by nextData with padding to reach targetOffset.
// If nextData is nil, it writes data with padding to reach targetOffset.
//
// Parameters:
//   - buf: The buffer to write to.
//   - data: The primary data to write.
//   - nextData: Optional secondary data to write after data.
//   - padding: The number of padding bytes to write.
//
// Returns:
//   - An error if writing fails.
func writePaddedData(buf *bytes.Buffer, data, nextData []byte, padding uint64) error {
	if _, err := buf.Write(data); err != nil {
		return fmt.Errorf("error writing data: %v", err)
	}
	if nextData != nil {
		if _, err := buf.Write(nextData); err != nil {
			return fmt.Errorf("error writing next data: %v", err)
		}
	}
	if padding > 0 {
		if _, err := buf.Write(make([]byte, padding)); err != nil {
			return fmt.Errorf("error writing padding: %v", err)
		}
	}
	return nil
}

func findStringOffset(data []byte, str string) int {
	for i := 0; i < len(data); {
		j := i
		for j < len(data) && data[j] != 0 {
			j++
		}
		if j < len(data) && string(data[i:j]) == str {
			return i
		}
		i = j + 1
	}
	return -1
}
