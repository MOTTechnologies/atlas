package com.github.manevolent.atlas.model.source;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.MemorySource;
import com.github.manevolent.atlas.model.Variant;
import com.github.manevolent.atlas.model.crypto.MemoryEncryption;

import java.io.IOException;

public class EncryptionCacheSource implements MemorySource {
    private final Calibration backing;
    private final MemoryEncryption encryption;
    private ArraySource cleartextSource;

    public EncryptionCacheSource(Calibration backing, MemoryEncryption encryption) throws IOException {
        this.backing = backing;
        this.encryption = encryption;
    }

    public ArraySource load() throws IOException {
        byte[] cleartextData = loadCleartextData();
        this.cleartextSource = new ArraySource(backing.getBaseAddress(), cleartextData, 0, cleartextData.length);
        return this.cleartextSource;
    }

    private byte[] loadCleartextData() throws IOException {
        byte[] data = backing.getSource().readFully();

        // Decrypt data fully
        encryption.decrypt(backing, data);

        return data;
    }

    @Override
    public Variant getVariant() {
        return backing.getVariant();
    }

    @Override
    public long getBaseAddress() {
        return backing.getBaseAddress();
    }

    @Override
    public int getLength() {
        return backing.getLength();
    }

    @Override
    public int read(byte[] dst, long memoryBase, int offs, int len) throws IOException {
        // Read from the cache
        return cleartextSource.read(dst, memoryBase, offs, len);
    }

    @Override
    public int read(long position) throws IOException {
        // Read from the cache
        return cleartextSource.read(position);
    }

    @Override
    public void write(byte[] src, long memoryBase, int offs, int len) throws IOException {
        // Write encrypted data to the calibration immediately
        encryption.write(backing, memoryBase, src, offs, len);

        // Update cache
        cleartextSource.write(src, memoryBase, offs, len);
    }
}
