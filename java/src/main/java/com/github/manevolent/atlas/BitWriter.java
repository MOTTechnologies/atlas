package com.github.manevolent.atlas;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class BitWriter extends OutputStream implements Closeable {
    private OutputStream outputStream;

    private byte buffer;
    private int offs;

    public BitWriter(int size) {
        this.outputStream = new ByteArrayOutputStream(size);
    }

    public BitWriter(OutputStream outputStream) {
        this.outputStream = outputStream;
    }

    public void write(boolean bit) throws IOException {
        if (bit) {
            buffer = (byte) (buffer | (0x1<<(7 - offs)));
        }

        offs ++;

        if (offs >= 8) {
            outputStream.write(buffer & 0xFF);
            offs = 0;
            buffer = 0x00;
        }
    }

    public void write(boolean[] bits) throws IOException {
        for (boolean bit : bits) {
            write(bit);
        }
    }

    public void writeNibble(byte nibble) throws IOException {
        boolean[] bits = new boolean[4];
        for (int n = 0; n < bits.length; n ++) {
            bits[bits.length - n - 1] = (nibble>>n & 0x1) == 0x1;
        }
        write(bits);
    }

    @Override
    public void write(int i) throws IOException {
        byte b = (byte) (0xFF & i);
        boolean[] bits = new boolean[8];
        for (int n = 0; n < bits.length; n ++) {
            bits[bits.length - n - 1] = (b>>n & 0x1) == 0x1;
        }
        write(bits);
    }

    public void writeShort(short s) throws IOException {
        write((byte) (s>>8 & 0xFF));
        write((byte) (s & 0xFF));
    }

    public void writeInt(int i) throws IOException {
        write((byte) (i>>24 & 0xFF));
        write((byte) (i>>16 & 0xFF));
        write((byte) (i>>8 & 0xFF));
        write((byte) (i & 0xFF));
    }

    public void writeLong(long l) throws IOException {
        write((byte) (l>>56 & 0xFF));
        write((byte) (l>>48 & 0xFF));
        write((byte) (l>>32 & 0xFF));
        write((byte) (l>>16 & 0xFF));
        write((byte) (l>>8 & 0xFF));
        write((byte) (l & 0xFF));
    }

    public void writeFloatBE(float value) throws IOException {
        write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putFloat(value).array());
    }

    public void writeFloatLE(float value) throws IOException {
        write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putFloat(value).array());
    }

    public void writeLSB(int data, int nbits) throws IOException {
        boolean[] bits = new boolean[nbits];
        for (int n = 0; n < bits.length; n ++) {
            bits[bits.length - n - 1] = (data>>n & 0x1) == 0x1;
        }
        write(bits);
    }

    @Override
    public void flush() throws IOException {
        outputStream.flush();
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }
}