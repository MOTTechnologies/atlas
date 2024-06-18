package com.github.manevolent.atlas.model;

import java.io.IOException;
import java.util.stream.IntStream;

public class Series extends AbstractAnchored implements Editable<Series>, Addressed {
    private String name;
    private int length;
    private MemoryAddress address;
    private Scale scale;
    private MemoryParameter parameter;

    /**
     * Gets the minimum value in this series.
     * @param source memory source to search for values in.
     * @return minimum value in the series.
     */
    public float getMin(MemorySource source) {
        return (float) IntStream.range(0, length).mapToDouble(index -> {
            try {
                return get(source, index);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).min().orElseThrow();
    }

    public float getMinPreferred(MemorySource source) {
        return getUnit().convertToPreferred(getMin(source));
    }

    /**
     * Gets the maximum value in this series.
     * @param source memory source to search for values in.
     * @return maximum value in the series.
     */
    public float getMax(MemorySource source) {
        return (float) IntStream.range(0, length).mapToDouble(index -> {
            try {
                return get(source, index);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).max().orElseThrow();
    }

    public float getMaxPreferred(MemorySource source) {
        return getUnit().convertToPreferred(getMax(source));
    }

    /**
     * Gets the partial index for a given value. This is used to calculate where to draw in a table when live parameters
     * are active in the table editor.
     * @param source the memory source to read from.
     * @param value the table value to search for.
     * @return the partial index between two indices in a table if the value lies between them, or 0 or
     *          length - 1 if the value is outside the bounds of the table.
     * @throws IOException if there is a problem reading data from the memory source.
     */
    public float getIndex(MemorySource source, float value) throws IOException {
        int length = getLength();
        int lowIndex = 0, highIndex = 0;
        float lowValue = 0f, highValue = 0f;
        for (highIndex = 0; highIndex < length; highIndex ++) {
            highValue = get(source, highIndex);
            if (highValue > value) {
                break;
            } else if (highValue == value) {
                return highIndex;
            }

            lowValue = highValue;
            lowIndex = highIndex;
        }

        // Before left of table
        if (lowIndex == highIndex && highIndex == 0) {
            return 0f;
        }

        // Past right side of table
        if (highValue <= value && highIndex == length - 1) {
            return highIndex;
        }

        // Catch any unusual scenarios where the high value isn't > low value
        if (highValue <= lowValue) {
            return lowIndex;
        }

        // Produce a partial index
        float delta = highValue - lowValue;
        return lowIndex + ((value - lowValue) / delta);
    }

    public float get(MemorySource source, int index) throws IOException {
        if (length > 0 && (index >= length || index < 0)) {
            throw new ArrayIndexOutOfBoundsException(index);
        }

        float data = address.read(source, index, scale.getFormat());
        return scale.forward(data);
    }

    public float getPreferred(MemorySource source, int index) throws IOException {
        return scale.getUnit().convertToPreferred(get(source, index));
    }

    public String format(MemorySource source, int index) throws IOException {
        return scale.format(get(source, index));
    }

    public String formatPreferred(MemorySource source, int index) throws IOException {
        return scale.formatPreferred(get(source, index));
    }

    public String format(MemorySource source, float indexGradient) throws IOException {
        indexGradient = Math.max(0f, Math.min(1f, indexGradient));
        float scaled = indexGradient * (length - 1);
        int lowIndex = (int) Math.floor(scaled);
        int highIndex = (int) Math.ceil(scaled);
        float remainder = scaled - lowIndex;
        float lowValue = get(source, lowIndex);
        float highValue = get(source, highIndex);
        float value = ((highValue - lowValue) * remainder) + lowValue;
        return getScale().format(value);
    }

    public int get(MemorySource source, float[] floats, int offs, int len) throws IOException {
        int i = 0;
        for (; i < len; i ++) {
            floats[offs + i] = get(source, i);
        }
        return i;
    }

    public float[] getNum(MemorySource source, int numCells) throws IOException {
        float[] cells = new float[numCells];
        get(source, cells, 0, numCells);
        return cells;
    }

    public float[] getAll(MemorySource source) throws IOException {
        return getNum(source, length);
    }

    public void setAll(MemorySource source, float[] data) throws IOException {
        if (data.length != length) {
            throw new ArrayIndexOutOfBoundsException(data.length);
        }

        for (int i = 0; i < data.length; i ++) {
            float value = scale.reverse(data[i]);
            address.write(source, i, value, scale.getFormat());
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public Unit getUnit() {
        return scale.getUnit();
    }

    public Scale getScale() {
        return scale;
    }

    public void setScale(Scale scale) {
        this.scale = scale;
    }

    public DataFormat getFormat() {
        return scale.getFormat();
    }

    public MemoryAddress getAddress() {
        return address;
    }

    public Long getOffset(Calibration calibration) {
        return address.getOffset(calibration);
    }

    public Long getOffset(Variant variant) {
        return address.getOffset(variant);
    }

    public void setAddress(MemoryAddress address) {
        this.address = address;
    }

    public MemoryParameter getParameter() {
        return parameter;
    }

    public void setParameter(MemoryParameter parameter) {
        this.parameter = parameter;
    }

    public static Builder builder() {
        return new Builder();
    }

    public float set(MemorySource source, int index, float value) throws IOException {
        float data = scale.reverse(value);
        address.write(source, index, data, scale.getFormat());
        return get(source, index);
    }

    @Override
    public Series copy() {
        Series copy = new Series();
        copy.scale = scale;
        copy.name = name;
        copy.length = length;
        copy.address = address.copy();
        copy.parameter = parameter;
        return copy;
    }

    @Override
    public void apply(Series other) {
        scale = other.scale;
        name = other.name;
        length = other.length;
        address.apply(other.address);
        parameter = other.parameter;
    }

    public static class Builder {
        private final Series series = new Series();

        public Builder() {
            series.setScale(Scale.getNone(DataFormat.UBYTE));
        }

        public Builder withName(String name) {
            this.series.setName(name);
            return this;
        }

        public Builder withAddress(MemoryAddress address) {
            this.series.setAddress(address);
            return this;
        }

        public Builder withAddress(MemorySection section, Variant variant, int offset) {
            return withAddress(MemoryAddress.builder()
                    .withSection(section)
                    .withOffset(variant, offset)
                    .build());
        }

        public Builder withScale(Scale scale) {
            this.series.setScale(scale);
            return this;
        }

        public Builder withScale(Scale.Builder scale) {
            return withScale(scale.build());
        }

        public Builder withLength(int length) {
            this.series.setLength(length);
            return this;
        }

        public Builder withParameter(MemoryParameter parameter) {
            this.series.setParameter(parameter);
            return this;
        }

        public Series build() {
            if (series.address == null) {
                throw new NullPointerException("address");
            }

            if (series.length < 0) {
                throw new ArrayIndexOutOfBoundsException("length");
            }

            return series;
        }
    }
}
