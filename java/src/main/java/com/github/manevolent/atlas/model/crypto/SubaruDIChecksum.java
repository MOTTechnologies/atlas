package com.github.manevolent.atlas.model.crypto;

import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Checksum;
import com.github.manevolent.atlas.model.MemoryByteOrder;

import java.io.IOException;

public class SubaruDIChecksum implements Checksum {
    /**
     * The expected sum for the calibration file's data (as a stream of shorts)
     */
    private static final int expectedSum = 0x5aa5;

    /**
     * The offset where checksum correction should occur
     */
    private final long checksumOffset;

    public SubaruDIChecksum(long checksumOffset) {
        if (checksumOffset % 2 != 0) {
            throw new IllegalArgumentException("Bad checksum offset");
        }

        this.checksumOffset = checksumOffset;
    }

    private int readShort(Calibration calibration, long offset) throws IOException {
        byte[] buffer = new byte[2];
        calibration.read(buffer, offset, 0, 2);

        if (calibration.getSection().getByteOrder() == MemoryByteOrder.LITTLE_ENDIAN) {
            return ((buffer[0] & 0xFF) | (((buffer[1] & 0xFF) << 8)));
        } else {
            return ((buffer[1] & 0xFF) | (((buffer[0] & 0xFF) << 8)));
        }
    }

    private void writeShort(Calibration calibration, long offset, int data) throws IOException {
        if (data < 0 || data > 0xFFFF) {
            throw new IllegalArgumentException(Integer.toString(data));
        }

        byte[] buffer = new byte[2];
        if (calibration.getSection().getByteOrder() == MemoryByteOrder.LITTLE_ENDIAN) {
            buffer[0] = (byte) (data & 0xFF);
            buffer[1] = (byte) ((data >> 8) & 0xFF);
        } else {
            buffer[1] = (byte) (data & 0xFF);
            buffer[0] = (byte) ((data >> 8) & 0xFF);
        }

        calibration.write(buffer, offset, 0, 2);
    }

    private int calculateChecksum(Calibration calibration) throws IOException {
        long offset = calibration.getBaseAddress();
        long end = calibration.getBaseAddress() + calibration.getLength();
        int csum = 0x0000;
        for (; offset < end; offset += 2) {
            int s = readShort(calibration, offset);
            csum += s;
            csum = csum & 0xFFFF;
        }

        return csum;
    }

    @Override
    public boolean validate(Calibration calibration) throws IOException {
        byte[] magic = calibration.read(calibration.getBaseAddress(), 2);
        if (magic[0] != 0x55 || magic[1] != 0x55) {
            throw new IllegalArgumentException("invalid magic header: " + Frame.toHexString(magic));
        }

        return calculateChecksum(calibration) == expectedSum;
    }

    @Override
    public void correct(Calibration calibration) throws IOException {
        int currentChecksum = calculateChecksum(calibration);
        if (currentChecksum == expectedSum) {
            return;
        }

        int currentValue = readShort(calibration, checksumOffset);
        int baseChecksum = (currentChecksum - currentValue) & 0xFFFF;
        int neededValue = (expectedSum - baseChecksum) & 0xFFFF;

        int newChecksum = ((baseChecksum + neededValue) & 0xFFFF);
        if (newChecksum != expectedSum) {
            // Internal validation/double-check to be absolutely sure we have come up with the right value
            throw new IllegalArgumentException("Bad checksum calculated");
        }

        writeShort(calibration, checksumOffset, neededValue);
    }
}
