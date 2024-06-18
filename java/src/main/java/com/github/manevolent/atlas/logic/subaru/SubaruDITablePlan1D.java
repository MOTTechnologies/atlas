package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.logic.*;
import com.github.manevolent.atlas.model.*;

import java.io.IOException;
import java.util.*;

public class SubaruDITablePlan1D extends AbstractTablePlan {
    private final OS os;
    private final TableFunction function;
    private final int x_size_offset, x_data_offset, data_offset, data_bytes, x_bytes;

    public SubaruDITablePlan1D(OS os, TableFunction function,
                               int x_size_offset, int x_data_offset, int data_offset,
                               int data_bytes, int x_bytes) {
        this.os = os;
        this.function = function;

        this.x_size_offset = x_size_offset;
        this.x_data_offset = x_data_offset;
        this.data_offset = data_offset;
        this.data_bytes = data_bytes;
        this.x_bytes = x_bytes;
    }

    @Override
    public OS getOS() {
        return os;
    }

    @Override
    public int getDimensions() {
        return 1;
    }

    @Override
    public TableStructure getStructure(TableExecution execution) throws IOException {
        long data_offset = execution.getDataOffset() + this.data_offset;
        long x_offset = execution.getDataOffset() + this.x_data_offset;
        long length_offset = execution.getDataOffset() + this.x_size_offset;

        int x_axis_length = getCalibration().read(length_offset) & 0xFF;

        data_offset = followPointer(data_offset);
        x_offset = followPointer(x_offset);

        DataFormat data_format = guessDataFormat(data_offset, x_axis_length, data_bytes);
        DataFormat x_axis_format = guessAxisFormat(x_offset, x_axis_length, x_bytes);

        Map<Axis, Integer> lengths = Collections.singletonMap(Axis.X, x_axis_length);
        Map<Axis, Long> offsets = Collections.singletonMap(Axis.X, x_offset);
        Map<Axis, DataFormat> formats = Collections.singletonMap(Axis.X, x_axis_format);

        return new DefaultTableStructure(os, function, execution,
                execution.getDataOffset(), data_offset, data_format, lengths, offsets, formats);
    }

    /**
     * Guess the data format for a given pointer to a data array.
     * @param data_offset memory location that the array starts at (target of the pointer)
     * @param length the number of strides in the array (i.e. if array size is 40 bytes, data type is short (16bit), then length is 20)
     * @param bytes length, if known, or -1 otherwise. For example, this would be '2' for a short (16bit).
     * @return the guessed data format of the array.
     * @throws IOException if there is a problem reading calibration data.
     * @throws IllegalArgumentException if the format couldn't be guessed.
     */
    private DataFormat guessDataFormat(long data_offset, int length, int bytes) throws IOException {
        Calibration calibration = getCalibration();
        List<Weight> weights = new ArrayList<>();

        // Find what data formats would normally be supported for a possible known data stride length
        List<DataFormat> supportedFormats = Arrays.stream(DataFormat.values())
                .filter(f -> bytes == -1 || f.getSize() == bytes).toList();

        for (DataFormat format : supportedFormats) {
            float min = format.getMin();
            float max = format.getMax();

            Series series = new Series();
            series.setScale(Scale.getNone(format));
            series.setAddress(MemoryAddress.of(calibration, data_offset));
            series.setLength(length);

            float[] values = series.getAll(calibration);
            float value, diff, sum = 0, last = 0;
            int num = 0;
            for (int i = 0; i < values.length; i ++) {
                value = values[i];
                value = (value - min) / (max - min);
                if (i > 0) {
                    diff = (float) Math.pow(value - last, 2);
                    sum += diff;
                    num++;
                }
                last = value;
            }

            float rms = (float) Math.sqrt(sum / num);

            if (format.isSigned()) {
                rms += 0.00001f;
            }

            Weight weight = new Weight();
            weight.format = format;
            weight.variance_rms = rms;
            weights.add(weight);
        }

        Weight picked = weights.stream().min(Comparator.comparingDouble(w -> w.variance_rms))
                .orElseThrow(() -> new IllegalArgumentException("Failed to guess format of pointer"
                        + " 0x" + Long.toHexString(data_offset)
                        + " on layout " + this.toString()));

        return picked.format;
    }

    private class Weight {
        DataFormat format;
        float variance_rms;
    }

    @Override
    public String toString() {
        return "Func{" + function.toString() + "} " +
                "X{sz=+" + x_size_offset + " data=+" + x_data_offset + " len=" + x_bytes + "} " +
                "Data{data=+" + data_offset + " len=" + data_bytes + "}";
    }
}
