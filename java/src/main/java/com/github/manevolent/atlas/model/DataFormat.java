package com.github.manevolent.atlas.model;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.util.function.BiFunction;

public enum DataFormat {

    UBYTE(1, false, 0f, 255f, Precision.WHOLE_NUMBER, (data, byteOrder) -> {
        byte b = data[0];
        int i = b & 0xFF;
        return (float) i;
    }, (f, byteOrder) -> {
        f = Math.min(255, Math.max(0, f));
        int i = (int) Math.floor(f);
        if (i > 0xFF) {
            i = 0xFF;
        } else if (i < 0) {
            i = 0;
        }
        return new byte[] { (byte) i };
    }),

    SBYTE(1, true, Byte.MIN_VALUE, Byte.MAX_VALUE, Precision.WHOLE_NUMBER, (data, byteOrder) -> {
        byte b = data[0];
        return (float) b;
    }, (f, byteOrder) -> {
        f = Math.min(Byte.MAX_VALUE, Math.max(Byte.MIN_VALUE, f));
        int i = (int) Math.floor(f);
        if (i < Byte.MIN_VALUE) {
            i = Byte.MIN_VALUE;
        } else if (i > Byte.MAX_VALUE) {
            i = Byte.MAX_VALUE;
        }
        return new byte[] { (byte) i };
    }),

    USHORT(2, false, 0f, 65535f, Precision.WHOLE_NUMBER, (data, byteOrder) -> {
        int low;
        int high;

        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            low = data[0] & 0xFF;
            high = data[1] & 0xFF;
        } else {
            high = data[0] & 0xFF;
            low = data[1] & 0xFF;
        }

        int combined = low | (high << 8);
        return (float) (combined & 0xFFFF);
    }, (f, byteOrder) -> {
        f = Math.min(65535, Math.max(0, f));
        int s = ((int)Math.floor(f)) & 0xFFFF;
        byte[] data = new byte[2];
        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            data[0] = (byte) (s & 0xFF);
            data[1] = (byte) (s >> 8 & 0xFF);
        } else {
            data[1] = (byte) (s & 0xFF);
            data[0] = (byte) (s >> 8 & 0xFF);
        }
        return data;
    }),

    SSHORT(2, true, Short.MIN_VALUE, Short.MAX_VALUE, Precision.WHOLE_NUMBER, (data, byteOrder) -> {
        int low, high;
        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            low = data[0] & 0xFF;
            high = data[1] & 0xFF;
        } else {
            high = data[0] & 0xFF;
            low = data[1] & 0xFF;
        }
        int combined = low | (high << 8);
        return (float) (short) (combined & 0xFFFF);
    }, (f, byteOrder) -> {
        f = Math.min(Short.MAX_VALUE, Math.max(Short.MIN_VALUE, f));
        short s = (short)Math.floor(f);
        byte[] data = new byte[2];
        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            data[0] = (byte) (s & 0xFF);
            data[1] = (byte) (s >> 8 & 0xFF);
        } else {
            data[1] = (byte) (s & 0xFF);
            data[0] = (byte) (s >> 8 & 0xFF);
        }
        return data;
    }),

    UINT(4, false, 0f, (float) (Math.pow(2, 32) - 1), Precision.WHOLE_NUMBER, (data, byteOrder) -> {
        int a, b, c, d;

        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            a = data[0] & 0xFF;
            b = data[1] & 0xFF;
            c = data[2] & 0xFF;
            d = data[3] & 0xFF;
        } else {
            d = data[0] & 0xFF;
            c = data[1] & 0xFF;
            b = data[2] & 0xFF;
            a = data[3] & 0xFF;
        }

        long combined = a | (b << 8)| (c << 16)| ((long) d << 24);
        return (float) (combined & 0xFFFFFFFFL);
    }, (f, byteOrder) -> {
        f = Math.min((float) Math.pow(2, 32) - 1f, Math.max(0, f));
        long s = ((int)Math.floor(f)) & 0xFFFFFFFFL;
        byte[] data = new byte[4];
        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            data[0] = (byte) (s & 0xFF);
            data[1] = (byte) (s >> 8 & 0xFF);
            data[2] = (byte) (s >> 16 & 0xFF);
            data[3] = (byte) (s >> 24 & 0xFF);
        } else {
            data[3] = (byte) (s & 0xFF);
            data[2] = (byte) (s >> 8 & 0xFF);
            data[1] = (byte) (s >> 16 & 0xFF);
            data[0] = (byte) (s >> 24 & 0xFF);
        }
        return data;
    }),

    SINT(4, true, Short.MIN_VALUE, Short.MAX_VALUE, Precision.WHOLE_NUMBER, (data, byteOrder) -> {
        int a, b, c, d;

        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            a = data[0] & 0xFF;
            b = data[1] & 0xFF;
            c = data[2] & 0xFF;
            d = data[3] & 0xFF;
        } else {
            d = data[0] & 0xFF;
            c = data[1] & 0xFF;
            b = data[2] & 0xFF;
            a = data[3] & 0xFF;
        }

        int combined = a | (b << 8)| (c << 16)| (d << 24);
        return (float) combined;
    }, (f, byteOrder) -> {
        f = Math.min((float) Integer.MAX_VALUE, Math.max(Integer.MIN_VALUE, f));
        int s = (int) Math.floor(f);
        byte[] data = new byte[4];
        if (byteOrder == ByteOrder.LITTLE_ENDIAN) {
            data[0] = (byte) (s & 0xFF);
            data[1] = (byte) (s >> 8 & 0xFF);
            data[2] = (byte) (s >> 16 & 0xFF);
            data[3] = (byte) (s >> 24 & 0xFF);
        } else {
            data[3] = (byte) (s & 0xFF);
            data[2] = (byte) (s >> 8 & 0xFF);
            data[1] = (byte) (s >> 16 & 0xFF);
            data[0] = (byte) (s >> 24 & 0xFF);
        }
        return data;
    }),

    FLOAT(4, true, Float.MIN_VALUE, Float.MAX_VALUE, Precision.FLOATING_POINT,
            (data, byteOrder) -> ByteBuffer.wrap(data).order(byteOrder).asFloatBuffer().get(),
            (f, byteOrder) -> ByteBuffer.allocate(4).order(byteOrder).putFloat(f).array());

    private static byte[] expectLength(byte[] array, int length) {
        if (array.length != length) {
            throw new IllegalArgumentException("Invalid data array size: " +
                    array.length + " != " + length);
        }

        return array;
    }

    private final BiFunction<byte[], ByteOrder, Float> convertFromBytes;
    private final BiFunction<Float, ByteOrder, byte[]> convertToBytes;
    private final int size;
    private final Precision precision;
    private final boolean signed;
    private final float min, max;

    DataFormat(int size, boolean signed,
               float min, float max, Precision precision,
               BiFunction<byte[], ByteOrder, Float> convertFromBytes,
               BiFunction<Float, ByteOrder, byte[]> convertToBytes) {
        this.min = min;
        this.max = max;
        this.size = size;
        this.convertFromBytes = convertFromBytes;
        this.convertToBytes = convertToBytes;
        this.precision = precision;
        this.signed = signed;
    }

    public boolean isSigned() {
        return signed;
    }

    public byte[] convertToBytes(float f, ByteOrder byteOrder) {
        return convertToBytes.apply(f, byteOrder);
    }

    public float convertFromBytes(byte[] data, ByteOrder byteOrder) {
        expectLength(data, getSize());
        return convertFromBytes.apply(data, byteOrder);
    }

    public int getSize() {
        return size;
    }

    public Precision getPrecision() {
        return precision;
    }

    public float convertToScalar(float value) {
        return (value - getMin()) / (getMax() - getMin());
    }

    @Override
    public String toString() {
        return name().toLowerCase();
    }

    public float getMin() {
        return min;
    }

    public float getMax() {
        return max;
    }
}
