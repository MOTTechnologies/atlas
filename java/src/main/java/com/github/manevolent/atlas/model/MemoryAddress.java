package com.github.manevolent.atlas.model;

import java.io.IOException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

public class MemoryAddress extends AbstractAnchored implements Editable<MemoryAddress> {
    private MemorySection section;
    private Map<Variant, Long> offsets = new HashMap<>();

    public MemoryAddress() {

    }

    public MemoryAddress(MemorySection section, Variant variant, long offset) {
        this.section = section;
        this.offsets.put(variant, offset);
    }

    public static MemoryAddress of(Calibration calibration, long offset) {
        return MemoryAddress.builder()
                .withSection(calibration.getSection())
                .withOffset(calibration.getVariant(), offset).build();
    }

    public MemorySection getSection() {
        return section;
    }

    public void setSection(MemorySection section) {
        this.section = section;
    }

    public long getOffset(Variant variant) {
        Long value = offsets.get(variant);
        if (value == null) {
            Variant matched = offsets.keySet().stream()
                    .filter(v -> v.get_anchor().equals(variant.get_anchor()))
                    .findFirst().orElse(null);
            value = offsets.get(matched);
        }

        if (value == null) {
            throw new UnsupportedOperationException(variant.getName() + " is not supported");
        }
        return value;
    }

    public long getOffset(Calibration calibration) {
        return getOffset(calibration.getVariant());
    }

    public void setOffset(Variant variant, long offset) {
        this.offsets.put(variant, offset);
    }

    public Long removeOffset(Variant variant) {
        return this.offsets.remove(variant);
    }

    public void setOffset(Calibration calibration, long offset) {
        setOffset(calibration.getVariant(), offset);
    }

    public boolean hasOffset(Variant variant) {
        if ( this.offsets.containsKey(variant)) {
            return true;
        } else {
            return offsets.keySet().stream()
                    .anyMatch(v -> v.get_anchor().equals(variant.get_anchor()));
        }
    }

    public boolean hasOffset(Calibration calibration) {
        return hasOffset(calibration.getVariant());
    }

    public String toString(Variant variant) {
        return "0x" + HexFormat.of().toHexDigits((int) getOffset(variant)).toUpperCase();
    }

    public float read(MemorySource source, int index, DataFormat format) throws IOException {
        byte[] data = new byte[format.getSize()];
        source.read(data, getOffset(source.getVariant()) + ((long) index * format.getSize()), 0, format.getSize());
        return format.convertFromBytes(data, getSection().getByteOrder().getByteOrder());
    }

    public int read(MemorySource source, byte[] buffer, int offs, int length) throws IOException {
        return source.read(buffer, getOffset(source.getVariant()), offs, length);
    }

    public static Builder builder() {
        return new Builder();
    }

    public void write(MemorySource source, int index, float data, DataFormat format) throws IOException {
        byte[] bytes = format.convertToBytes(data, getSection().getByteOrder().getByteOrder());
        source.write(bytes, getOffset(source.getVariant()) + ((long) index * format.getSize()), 0, bytes.length);
    }

    @Override
    public MemoryAddress copy() {
        MemoryAddress copy = new MemoryAddress();
        copy.section = section;
        copy.offsets = new HashMap<>(offsets);
        return copy;
    }

    public Map<Variant, Long> getOffsets() {
        return offsets;
    }

    public void setOffsets(Map<Variant, Long> offsets) {
        this.offsets = offsets;
    }

    @Override
    public void apply(MemoryAddress other) {
        this.section = other.section;
        this.offsets = new HashMap<>(other.offsets);
    }

    /**
     * A small helper method to assist in applying a memory address to a given Addressed object.
     * @param addressed addressed object to apply this memory address to.
     */
    public void applyTo(Addressed addressed) {
        if (addressed.getAddress() == null) {
            // Apply this memory address directly.
            addressed.setAddress(this);
        } else {
            // Apply all available non-null offsets.
            for (Variant variant : offsets.keySet()) {
                Long offset = offsets.get(variant);
                if (offset == null) {
                    continue;
                }

                MemoryAddress otherAddress = addressed.getAddress();
                Variant key = otherAddress.offsets.keySet()
                        .stream()
                        .filter(v -> v.get_anchor().equals(variant.get_anchor()))
                        .findFirst()
                        .orElse(variant);

                addressed.getAddress().setOffset(key, offset);
            }
        }
    }

    public static class Builder {
        private final MemoryAddress address;

        public Builder() {
            this.address = new MemoryAddress();
        }

        public Builder withSection(MemorySection section) {
            address.setSection(section);
            return this;
        }

        public Builder withOffset(Variant variant, long offset) {
            address.setOffset(variant, offset);
            return this;
        }

        public MemoryAddress build() {
            return address;
        }
    }
}
