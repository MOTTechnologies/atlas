package com.github.manevolent.atlas.model;

import aQute.lib.io.IO;
import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface MemorySource {

    Variant getVariant();

    long getBaseAddress();

    int getLength();

    int read(byte[] dst, long memoryBase, int offs, int len) throws IOException;

    int read(long position) throws IOException;

    default BitReader bitReader(long position) throws IOException {
        return new BitReader(new InputStream() {
            private int offs = 0;
            @Override
            public int read() throws IOException {
                int b = MemorySource.this.read(position + offs) & 0xFF;
                offs ++;
                return b;
            }
        });
    }

    default BitWriter bitWriter(long position) throws IOException {
        return new BitWriter(new OutputStream() {
            private int offs = 0;

            @Override
            public void write(int b) throws IOException {
                MemorySource.this.write(position + offs, b);
                offs ++;
            }
        });
    }

    default byte[] read(long position, int length) throws IOException {
        byte[] buffer = new byte[length];
        read(buffer, position, 0, length);
        return buffer;
    }

    void write(byte[] bytes, long memoryBase, int offs, int len) throws IOException;

    default void write(long memoryBase, int b) throws IOException {
        if (b < 0 || b > 0xFF) {
            throw new IllegalArgumentException(Integer.toString(b));
        }
        byte[] bytes = new byte[] { (byte) (b & 0xFF) };
        write(bytes, memoryBase, 0, 1);
    }

    default byte[] readFully() throws IOException {
        byte[] data = new byte[getLength()];
        read(data, getBaseAddress(), 0, data.length);
        return data;
    }

    default boolean isLocal() {
        return true;
    }

}
