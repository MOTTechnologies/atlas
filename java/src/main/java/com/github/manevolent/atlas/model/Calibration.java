package com.github.manevolent.atlas.model;


import com.github.manevolent.atlas.logic.OS;
import com.github.manevolent.atlas.model.source.ArraySource;
import com.google.errorprone.annotations.Var;
import org.checkerframework.checker.units.qual.K;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.UUID;

public class Calibration extends AbstractAnchored implements MemorySource, Editable<Calibration>, Secured {
    private UUID uuid;
    private String name;
    private boolean active;
    private boolean readonly;
    private boolean confidential;
    private MemorySource source;
    private MemorySection section;
    private KeySet keySet;
    private Variant variant;
    private OS os;

    public Calibration() {
        this.uuid = UUID.randomUUID();
        this.keySet = new KeySet();
    }

    public Calibration(String name) {
        this();

        this.name = name;
    }

    public void updateSource(byte[] data) {
        updateSource(data, data.length);
    }

    public void updateSource(byte[] data, int length) {
        updateSource(data, 0, length);
    }

    public void updateSource(byte[] data, int offset, int length) {
        updateSource(new ArraySource(section.getBaseAddress(), data, offset, length));
    }

    public void updateSource(MemorySource source) {
        this.source = source;
    }

    public OS getOS() throws IOException {
        if (os == null) {
            os = getVariant().getOSType().createOS(this);
        }

        return os;
    }

    public MemorySource getSource() {
        return this.source;
    }

    public boolean hasData() {
        return getSource() != null;
    }

    public boolean isConfidential() {
        return confidential;
    }

    public void setConfidential(boolean confidential) {
        this.confidential = confidential;
        if (this.keySet != null) {
            this.keySet.setConfidential(confidential);
        }
    }

    public int copyTo(OutputStream outputStream) throws IOException {
        int length = source.getLength();
        long base = source.getBaseAddress();
        for (int i = 0; i < length; i ++) {
            outputStream.write(source.read(base + i) & 0xFF);
        }
        return length;
    }

    public int dereferenceData() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int dataLength = copyTo(baos);
        updateSource(baos.toByteArray());
        return dataLength;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isReadonly() {
        return readonly;
    }

    public void setReadonly(boolean readonly) {
        this.readonly = readonly;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public MemorySection getSection() {
        return section;
    }

    public void setSection(MemorySection section) {
        this.section = section;
    }

    public Calibration copy() {
        Calibration copy = new Calibration();
        copy.setReadonly(isReadonly());
        copy.setConfidential(isConfidential());
        copy.setName(getName());
        copy.setSection(getSection());
        copy.source = source;
        copy.keySet = keySet.copy();
        copy.variant = variant;
        return copy;
    }

    public void apply(Calibration other) {
        this.setName(other.getName());
        this.setSection(other.getSection());
        this.setConfidential(other.isConfidential());
        this.setReadonly(other.isReadonly());
        this.getKeySet().apply(other.getKeySet());
        this.setVariant(other.variant);
        if (other.source != null && other.source != source) {
            source = other.source;
        }
    }

    public void setVariant(Variant variant) {
        if (this.variant != variant) {
            this.variant = variant;
            this.os = null;
        }
    }

    @Override
    public Variant getVariant() {
        return variant;
    }

    @Override
    public long getBaseAddress() {
        return section.getBaseAddress();
    }

    @Override
    public int getLength() {
        return source.getLength();
    }

    @Override
    public int read(byte[] dst, long memoryBase, int offs, int len) throws IOException {
        return getSection().read(this, dst, memoryBase, offs, len);
    }

    @Override
    public int read(long position) throws IOException {
        return getSection().read(this, position);
    }

    @Override
    public void write(byte[] bytes, long memoryBase, int offs, int len) throws IOException {
        if (isReadonly()) {
            throw new IOException(getName() + " is read-only");
        }

        getSection().write(this, bytes, memoryBase, offs, len);
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public boolean isLocal() {
        return MemorySource.super.isLocal();
    }

    @Override
    public int hashCode() {
        return uuid.hashCode();
    }

    public static Calibration.Builder builder() {
        return new Calibration.Builder();
    }

    public MemoryAddress getAddress() {
        return getSection().toBaseMemoryAddress(getVariant());
    }

    public KeySet getKeySet() {
        return keySet;
    }

    public void setKeySet(KeySet keySet) {
        this.keySet = keySet;
        this.keySet.setConfidential(isConfidential());
    }

    public static class Builder {
        private final Calibration calibration = new Calibration();

        public Calibration.Builder withName(String name) {
            calibration.setName(name);
            return this;
        }

        public Calibration.Builder withReadOnly(boolean readOnly) {
            calibration.setReadonly(readOnly);
            return this;
        }

        public Calibration.Builder withConfidential(boolean confidential) {
            calibration.setReadonly(confidential);
            return this;
        }

        public Calibration.Builder withSection(MemorySection section) {
            calibration.setSection(section);
            return this;
        }

        public Calibration.Builder withSource(MemorySource source) {
            calibration.source = source;
            return this;
        }

        public Calibration.Builder withVariant(Variant variant) {
            calibration.variant = variant;
            return this;
        }

        public Calibration build() {
            return calibration;
        }
    }
}
