package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.logic.*;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.layout.TableLayout;
import com.google.common.collect.Maps;

import java.io.IOException;
import java.util.*;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;

public class SubaruDITablePlan2D extends AbstractTablePlan {
    private final OS os;
    private final TableFunction function;
    private final int x_size_offset, y_size_offset, x_data_offset, y_data_offset, data_offset,
            data_bytes, x_bytes, y_bytes;

    public SubaruDITablePlan2D(TableFunction function,
                               int x_size_offset, int y_size_offset,
                               int x_data_offset, int y_data_offset,
                               int data_offset,
                               int data_bytes, int x_bytes, int y_bytes) {
        this.os = function.getOS();
        this.function = function;
        this.x_size_offset = x_size_offset;
        this.y_size_offset = y_size_offset;
        this.x_data_offset = x_data_offset;
        this.y_data_offset = y_data_offset;
        this.data_offset = data_offset;
        this.data_bytes = data_bytes;
        this.x_bytes = x_bytes;
        this.y_bytes = y_bytes;
    }

    @Override
    public OS getOS() {
        return os;
    }

    @Override
    public int getDimensions() {
        return 2;
    }

    private DataFormat guessDataFormat(long data_offset, int size_x, int size_y, int bytes) throws IOException {
        Calibration calibration = getCalibration();

        List<Weight> weights = new ArrayList<>();

        Series dataSeries = new Series();
        dataSeries.setAddress(MemoryAddress.of(calibration, data_offset));
        dataSeries.setLength(size_x * size_y);

        for (DataFormat format : Arrays.stream(DataFormat.values())
                .filter(f -> f.getSize() == bytes)
                .sorted(Comparator.comparingInt(f -> f.isSigned() ? 1 : 0)).toList()) {
            if (format == DataFormat.FLOAT) {
                continue;
            }

            dataSeries.setScale(Scale.getNone(format));

            float min = format.getMin();
            float max = format.getMax();

            float[] data = dataSeries.getAll(calibration);

            double value, diff;
            double sum = 0;
            int num = 0;

            for (int y = 0; y < size_y; y ++) {
                double last = 0;
                int offs = y * size_x;

                for (int x = 0; x < size_x; x ++) {
                    value = data[offs + x];
                    value = (value - min) / (max - min);

                    if (x > 0) {
                        diff = Math.pow(last - value, 2f);
                        sum += diff;
                        num ++;
                    }

                    last = value;
                }
            }

            for (int x = 0; x < size_x; x ++) {
                double last = 0;

                for (int y = 0; y < size_y; y ++) {
                    value = data[(y * size_x) + x];
                    value = (value - min) / (max - min);

                    if (y > 0) {
                        diff = Math.pow(last - value, 2f);
                        sum += diff;
                        num ++;
                    }

                    last = value;
                }
            }

            double rms = Math.sqrt(sum / num);

            if (format.isSigned()) {
                rms += 0.00001f;
            }

            Weight weight = new Weight();
            weight.format = format;
            weight.variance_rms = rms;
            weights.add(weight);
        }

        Weight picked = weights.stream().min(Comparator.comparingDouble(w -> w.variance_rms)).orElse(null);
        if (picked == null) {
            throw new NullPointerException("weight");
        }

        return picked.format;
    }


    @Override
    public TableStructure getStructure(TableExecution execution) throws IOException {
        long offset = execution.getDataOffset();

        long data_offset = offset + this.data_offset;
        long x_data_offset = offset + this.x_data_offset;
        long y_data_offset = offset + this.y_data_offset;
        long x_size_offset = offset + this.x_size_offset;
        long y_size_offset = offset + this.y_size_offset;

        int x_axis_length = getCalibration().read(x_size_offset) & 0xFF;
        int y_axis_length = getCalibration().read(y_size_offset) & 0xFF;

        data_offset = followPointer(data_offset);
        x_data_offset = followPointer(x_data_offset);
        y_data_offset = followPointer(y_data_offset);

        // NOTE: Atlas defines tables backwards (x=y, y=x)
        DataFormat data_format = guessDataFormat(data_offset, y_axis_length, x_axis_length, data_bytes);
        DataFormat x_axis_format = guessAxisFormat(x_data_offset, x_axis_length, x_bytes);
        DataFormat y_axis_format = guessAxisFormat(y_data_offset, y_axis_length, y_bytes);

        Map<Axis, Integer> lengths = Maps.newHashMap();
        lengths.put(Y, x_axis_length);
        lengths.put(X, y_axis_length);
        Map<Axis, Long> offsets = Maps.newHashMap();
        offsets.put(Y, x_data_offset);
        offsets.put(X, y_data_offset);
        Map<Axis, DataFormat> formats = Maps.newHashMap();
        formats.put(Y, x_axis_format);
        formats.put(X, y_axis_format);

        return new DefaultTableStructure(os, function, execution,
                offset, data_offset, data_format, lengths, offsets, formats);
    }

    class Weight {
        DataFormat format;
        double variance_rms;
    }

    @Override
    public String toString() {
        return  "Func{" + function.toString() + "} " +
                "X{sz=+" + x_size_offset + " data=+" + x_data_offset + " len=" + x_bytes + "} " +
                "Y{sz=+" + y_size_offset + " data=+" + y_data_offset + " len=" + y_bytes + "} " +
                "Data{data=+" + data_offset + " len=" + data_bytes + "}";
    }
}
