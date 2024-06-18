package com.github.manevolent.atlas.model.layout;

import com.github.manevolent.atlas.model.Axis;
import com.github.manevolent.atlas.model.MemorySource;
import com.github.manevolent.atlas.model.Series;
import com.github.manevolent.atlas.model.Table;

import java.io.IOException;
import java.util.Map;

public abstract class AbstractTableLayout implements TableLayout {

    /**
     * Gets the memory access offset in the data series of an object for a given coordinate.
     * The unit used by this method has a base address of the data series and a scan size that equals the data length
     * of an individual value in the data series. Therefore, returning 1 from this method will equal a binary offset of
     * +2 bytes relative to the base address described by the MemorySource and the table's data series offset assuming
     * the format of the data series is USHORT or SHORT, as those data types are 2 bytes long.
     *
     * The byte order of the associated data will be dictated by the memory source's selected endianness.
     *
     * @param source the memory source (i.e. Calibration) to access
     * @param object the object being accessed
     * @param coordinates the coordinates being accessed
     * @return the data-specific offset relative to the base address of table's data series.
     * @throws IllegalArgumentException if the coordinates are invalid.
     */
    protected abstract int getOffset(MemorySource source, Table object, Map<Axis, Integer> coordinates)
        throws IllegalArgumentException;

    @Override
    public float get(MemorySource source, Table table, Map<Axis, Integer> coordinates)
            throws IOException, IllegalArgumentException {
        Series data = table.getData();
        if (data == null) {
            throw new NullPointerException(table.getName() + " has no data series");
        }
        int offset = getOffset(source, table, coordinates);
        return data.get(source, offset);
    }

    @Override
    public float set(MemorySource source, Table table, float value, Map<Axis, Integer> coordinates)
            throws IOException, IllegalArgumentException {
        Series data = table.getData();
        if (data == null) {
            throw new NullPointerException(table.getName() + " has no data series");
        }
        int offset = getOffset(source, table, coordinates);
        return data.set(source, offset, value);
    }

}
