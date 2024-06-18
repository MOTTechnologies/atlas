package com.github.manevolent.atlas.model;

import com.github.manevolent.atlas.model.crypto.MemoryEncryption;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.model.source.EncryptionCacheSource;

import java.io.IOException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

public class MemorySection extends AbstractAnchored implements Editable<MemorySection> {
    /**
     * A map of calibrations to memory sources that helps alleviate CPU pressure when reading encrypted backing data
     */
    private final Map<Calibration, MemorySource> cacheMap = new HashMap<>();

    private String name;
    private MemoryType memoryType;
    private MemoryEncryptionType encryptionType;
    private MemoryEncryption encryption;
    private MemoryByteOrder byteOrder;
    private Object cacheLock = new Object();
    private long baseAddress;
    private int dataLength;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public MemoryType getMemoryType() {
        return memoryType;
    }

    public void setMemoryType(MemoryType memoryType) {
        this.memoryType = memoryType;
    }

    public MemoryEncryptionType getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(MemoryEncryptionType type) {
        this.encryptionType = type;
    }

    public long getBaseAddress() {
        return baseAddress;
    }

    public long getEndAddress() {
        return getBaseAddress() + getDataLength();
    }

    public MemoryAddress toBaseMemoryAddress(Variant variant) {
        return MemoryAddress.builder().withSection(this).withOffset(variant, baseAddress).build();
    }

    public void setBaseAddress(long baseAddress) {
        this.baseAddress = baseAddress;
    }

    public int getDataLength() {
        return dataLength;
    }

    public void setDataLength(int dataLength) {
        this.dataLength = dataLength;
    }

    /**
     * Sets up this memory section when a ROM/project is loaded
     * @param project ROM loaded
     */
    public void setup(Project project) {
        if (encryptionType != null && encryptionType != MemoryEncryptionType.NONE) {
            encryption = encryptionType.getFactory().create();
        } else {
            encryption = null;
        }

        synchronized (cacheLock) {
            cacheMap.clear();
        }
    }

    /**
     * Creates a new cached memory source for a given calibration.
     * @param calibration calibration to create a cached memory source for.
     * @return cached MemorySource instance.
     */
    private MemorySource newSource(Calibration calibration) throws IOException {
        if (encryption == null) {
            return calibration.getSource();
        } else {
            EncryptionCacheSource cache = new EncryptionCacheSource(calibration, encryption);
            cache.load();
            return cache;
        }
    }

    /**
     * Gets a cached memory source for a given calibration, creating one if necessary.
     * @param calibration calibration to retrieve a memory source for.
     * @return cached MemorySource instance.
     */
    private MemorySource getSource(Calibration calibration) {
        synchronized (cacheLock) {
            return cacheMap.computeIfAbsent(calibration, c -> {
                try {
                    return this.newSource(c);
                } catch (IOException e) {
                    throw new RuntimeException("Problem loading cached data from encrypted source", e);
                }
            });
        }
    }

    public int read(Calibration calibration, byte[] dst, long memoryOffs, int offs, int len) throws IOException {
        if (memoryOffs < baseAddress || memoryOffs + len > baseAddress + dataLength) {
            throw new ArrayIndexOutOfBoundsException(Long.toString(memoryOffs));
        }

        return getSource(calibration).read(dst, memoryOffs, offs, len);
    }

    public void write(Calibration calibration, byte[] src, long memoryOffs, int offs, int len) throws IOException {
        if (memoryOffs < baseAddress || memoryOffs + len > baseAddress + dataLength) {
            throw new ArrayIndexOutOfBoundsException(Long.toString(memoryOffs));
        }

        getSource(calibration).write(src, memoryOffs, offs, len);
    }

    public int read(Calibration calibration, long position) throws IOException {
        int readAddress = (int) (position - baseAddress);
        if (readAddress < 0 || readAddress >= dataLength) {
            throw new ArrayIndexOutOfBoundsException(readAddress);
        }

        return getSource(calibration).read(position);
    }

    public MemoryByteOrder getByteOrder() {
        return byteOrder;
    }

    public void setByteOrder(MemoryByteOrder byteOrder) {
        this.byteOrder = byteOrder;
    }

    @Override
    public String toString() {
        if (dataLength == 0) {
            return name + " [0x" + HexFormat.of().toHexDigits((int) baseAddress).toUpperCase() + "]";
        } else {
            return name + " [0x" + HexFormat.of().toHexDigits((int) baseAddress).toUpperCase() + "-" +
                    "0x" + HexFormat.of().toHexDigits((int) (baseAddress + dataLength)).toUpperCase() + "]";
        }
    }

    @Override
    public MemorySection copy() {
        MemorySection copy = new MemorySection();
        copy.setDataLength(getDataLength());
        copy.setBaseAddress(getBaseAddress());
        copy.setName(getName());
        copy.setByteOrder(getByteOrder());
        copy.setMemoryType(getMemoryType());
        copy.setEncryptionType(getEncryptionType());
        return copy;
    }

    @Override
    public void apply(MemorySection other) {
        setDataLength(other.getDataLength());
        setBaseAddress(other.getBaseAddress());
        setName(other.getName());
        setByteOrder(other.getByteOrder());
        setMemoryType(other.getMemoryType());
        setEncryptionType(other.getEncryptionType());
    }

    public boolean intersects(long baseAddress, int dataLength) {
        long otherStart = baseAddress;
        long otherEnd = baseAddress + dataLength;

        long myStart = this.baseAddress;
        long myEnd = this.baseAddress + this.dataLength;

        return (myStart <= otherEnd) && (myEnd >= otherStart);
    }

    public boolean intersects(MemorySection other) {
        return intersects(other.getBaseAddress(), other.getDataLength());
    }

    public boolean contains(long offs) {
        return intersects(offs, 0);
    }

    public boolean contains(MemoryAddress address) {
        return address.getOffsets().values().stream().anyMatch(this::contains);
    }

    public boolean contains(MemoryReference reference) {
        return contains(reference.getAddress());
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private final MemorySection section = new MemorySection();

        public Builder withName(String name) {
            section.setName(name);
            return this;
        }

        public Builder withByteOrder(MemoryByteOrder byteOrder) {
            section.setByteOrder(byteOrder);
            return this;
        }

        public Builder withBaseAddress(long baseAddress) {
            section.setBaseAddress(baseAddress);
            return this;
        }

        public Builder withLength(int length) {
            section.setDataLength(length);
            return this;
        }

        public Builder withEndAddress(long endAddress) {
            section.setDataLength((int) (endAddress - section.getBaseAddress()));
            return this;
        }

        public Builder withEncryptionType(MemoryEncryptionType type) {
            section.setEncryptionType(type);
            return this;
        }

        public Builder withType(MemoryType type) {
            section.setMemoryType(type);
            return this;
        }

        public MemorySection build() {
            return section;
        }
    }
}
