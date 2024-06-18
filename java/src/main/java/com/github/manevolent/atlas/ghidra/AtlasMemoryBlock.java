package com.github.manevolent.atlas.ghidra;


import com.github.manevolent.atlas.model.MemorySection;
import com.github.manevolent.atlas.model.MemoryType;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import org.jetbrains.annotations.NotNull;

import java.io.InputStream;
import java.math.BigInteger;
import java.util.Collections;
import java.util.List;

/**
 * Part of the Ghidra<->Atlas bridge.
 *
 * Bridges a Ghidra memory block to an Atlas section
 */
public class AtlasMemoryBlock implements MemoryBlock {
    private final MemorySection section;
    private final Program program;
    private final AddressSpace addressSpace;

    public AtlasMemoryBlock(MemorySection section, Program program, AddressSpace addressSpace) {
        this.section = section;
        this.program = program;
        this.addressSpace = addressSpace;
    }

    @Override
    public int getPermissions() {
        switch (section.getMemoryType()) {
            case RAM -> {
                return MemoryBlock.EXECUTE | MemoryBlock.READ | MemoryBlock.WRITE | MemoryBlock.VOLATILE;
            }
            case CODE -> {
                return MemoryBlock.READ | MemoryBlock.EXECUTE;
            }
            case EEPROM -> {
                return MemoryBlock.READ | MemoryBlock.WRITE;
            }
        }

        throw new UnsupportedOperationException(section.getMemoryType().name());
    }

    @Override
    public InputStream getData() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean contains(Address address) {
        return section.contains(address.getOffset());
    }

    @Override
    public Address getStart() {
        return addressSpace.getAddress(section.getBaseAddress());
    }

    @Override
    public Address getEnd() {
        return addressSpace.getAddress(section.getEndAddress());
    }

    @Override
    public AddressRange getAddressRange() {
        return new AddressRangeImpl(getStart(), getEnd());
    }

    @Override
    public long getSize() {
        return section.getDataLength();
    }

    @Override
    public BigInteger getSizeAsBigInteger() {
        return BigInteger.valueOf(getSize());
    }

    @Override
    public String getName() {
        return section.getName();
    }

    @Override
    public void setName(String s) throws IllegalArgumentException, LockException {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getComment() {
        return null;
    }

    @Override
    public void setComment(String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isRead() {
        return true;
    }

    @Override
    public void setRead(boolean b) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isWrite() {
        return section.getMemoryType() == MemoryType.EEPROM || section.getMemoryType() == MemoryType.RAM;
    }

    @Override
    public void setWrite(boolean b) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isExecute() {
        return section.getMemoryType() == MemoryType.CODE || section.getMemoryType() == MemoryType.RAM;
    }

    @Override
    public void setExecute(boolean b) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setPermissions(boolean b, boolean b1, boolean b2) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isVolatile() {
        return section.getMemoryType() == MemoryType.RAM;
    }

    @Override
    public void setVolatile(boolean b) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getSourceName() {
        return "Atlas";
    }

    @Override
    public void setSourceName(String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte getByte(Address address) throws MemoryAccessException {
        return 1;
    }

    @Override
    public int getBytes(Address address, byte[] bytes) throws MemoryAccessException {
        return 1;
    }

    @Override
    public int getBytes(Address address, byte[] bytes, int i, int i1) throws IndexOutOfBoundsException, MemoryAccessException {
        return 1;
    }

    @Override
    public void putByte(Address address, byte b) throws MemoryAccessException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int putBytes(Address address, byte[] bytes) throws MemoryAccessException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int putBytes(Address address, byte[] bytes, int i, int i1)
            throws IndexOutOfBoundsException, MemoryAccessException {
        throw new UnsupportedOperationException();
    }

    @Override
    public MemoryBlockType getType() {
        return MemoryBlockType.DEFAULT;
    }

    @Override
    public boolean isInitialized() {
        return true;
    }

    @Override
    public boolean isMapped() {
        return false;
    }

    @Override
    public boolean isOverlay() {
        return false;
    }

    @Override
    public boolean isLoaded() {
        return true;
    }

    @Override
    public List<MemoryBlockSourceInfo> getSourceInfos() {
        return Collections.emptyList();
    }

    @Override
    public int compareTo(@NotNull MemoryBlock o) {
        //TODO?
        throw new UnsupportedOperationException();
    }
}
