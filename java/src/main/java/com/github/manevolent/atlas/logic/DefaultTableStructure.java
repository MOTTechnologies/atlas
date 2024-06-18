package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.layout.TableLayoutType;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

public class DefaultTableStructure implements TableStructure {
    private final OS os;
    private final TableFunction function;
    private final TableExecution execution;
    private final long rootOffset, dataOffset;
    private final DataFormat dataFormat;

    private final Map<Axis, Integer> lengths;
    private final Map<Axis, Long> offsets;
    private final Map<Axis, DataFormat> dataFormats;

    public DefaultTableStructure(OS os, TableFunction function, TableExecution execution,
                                 long rootOffset, long dataOffset, DataFormat dataFormat,
                                 Map<Axis, Integer> lengths,
                                 Map<Axis, Long> offsets,
                                 Map<Axis, DataFormat> dataFormats) {
        this.os = os;
        this.function = function;
        this.execution = execution;
        this.rootOffset = rootOffset;
        this.dataOffset = dataOffset;
        this.dataFormat = dataFormat;
        this.lengths = lengths;
        this.offsets = offsets;
        this.dataFormats = dataFormats;
    }

    @Override
    public OS getOS() {
        return os;
    }

    @Override
    public TableFunction getFunction() {
        return function;
    }

    @Override
    public TableExecution getExecution() {
        return execution;
    }

    @Override
    public Set<Axis> getAxes() {
        return lengths.keySet();
    }

    @Override
    public DataFormat getDataFormat(Axis axis) {
        return dataFormats.get(axis);
    }

    @Override
    public DataFormat getDataFormat() {
        return dataFormat;
    }

    @Override
    public int getSeriesLength(Axis axis) {
        return lengths.get(axis);
    }

    @Override
    public long getSeriesOffset(Axis axis) {
        return offsets.get(axis);
    }

    @Override
    public long getDataOffset() {
        return dataOffset;
    }

    @Override
    public long getRootOffset() {
        return rootOffset;
    }

    @Override
    public Table createTable(Calibration calibration) throws IOException {
        Table.Builder builder = Table.builder().withName("0x" + Long.toHexString(getRootOffset()).toUpperCase());

        builder.withLayoutType(TableLayoutType.STANDARD);

        builder.withData(Series.builder()
                .withAddress(MemoryAddress.of(calibration, getDataOffset()))
                .withScale(Scale.getNone(getDataFormat()))
                .build());

        for (Axis axis : getAxes()) {
            builder.withAxis(axis, Series.builder()
                    .withAddress(MemoryAddress.of(calibration, getSeriesOffset(axis)))
                    .withScale(Scale.getNone(getDataFormat(axis)))
                    .withLength(getSeriesLength(axis))
                    .build()
            );
        }

        return builder.build();
    }
}
