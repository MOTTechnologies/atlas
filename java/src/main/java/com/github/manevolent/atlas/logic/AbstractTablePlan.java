package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

public abstract class AbstractTablePlan implements TablePlan {

    protected long followPointer(long offset) throws IOException {
        byte[] data = getCalibration().read(offset, 4);
        return ByteBuffer.wrap(data).order(getOS().getByteOrder()).getInt() & 0xFFFFFFFFL;
    }

    protected DataFormat guessAxisFormat(long pointer, int length, int bytes) throws IOException {
        Calibration calibration = getCalibration();

        Series series = new Series();
        series.setAddress(MemoryAddress.of(calibration, pointer));
        series.setLength(length);

        for (DataFormat format : Arrays.stream(DataFormat.values())
                .filter(f -> f.getSize() == bytes)
                .sorted(Comparator.comparingInt(f -> f.isSigned() ? 1 : 0)).toList()) {
            series.setScale(Scale.getNone(format));

            float[] values = series.getAll(calibration);
            float lastValue = 0, value;
            boolean good = true;
            int direction = -1;
            for (int i = 0; i < values.length; i ++) {
                value = values[i];
                if (direction < 0 && i > 0 && value != lastValue) {
                    if (value > lastValue) {
                        direction = 1;
                    } else {
                        direction = 0;
                    }
                }

                if (direction >= 0 && (direction == 1 ? lastValue > value : lastValue < value)) {
                    good = false;
                    break;
                }
                lastValue = value;
            }

            if (good) {
                return format;
            }
        }

        throw new IllegalArgumentException("Failed to guess format of pointer " + Long.toHexString(pointer)
                + " on plan " + toString());
    }
}
