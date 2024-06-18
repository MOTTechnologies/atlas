package com.github.manevolent.atlas.model.layout;

import com.github.manevolent.atlas.model.Axis;
import com.github.manevolent.atlas.model.MemorySource;
import com.github.manevolent.atlas.model.Table;

import java.io.IOException;
import java.util.Map;

/**
 * Describes a memory layout scheme for a Table. These are necessary as not all ECUs will lay out table data in a
 * consistent manner platform-to-platform. For example, a 4x4 table such as,
 *      X
 *   1 1 1 1
 * Y 2 2 2 2
 *   3 3 3 3
 *   4 4 4 4
 *
 * Can be laid out in different ways in memory:
 * 1111222233334444,
 * 1234123412341234,
 * 4444333322221111,
 * ... and so on
 *
 * This interface allows for customizable layouts to be declared, and the Table API will use it accordingly.
 */
public interface TableLayout {

    /**
     * Gets a scaled value
     * @param source the memory source (i.e. Calibration) to read from
     * @param table the table to use when reading the value
     * @param coordinates the coordinates of the cell to read
     * @return scaled value
     */
    float get(MemorySource source, Table table, Map<Axis, Integer> coordinates)
            throws IOException, IllegalArgumentException;

    /**
     * Sets a scaled value. Handling the return value may be important, as the return value will reflect the
     * final value stored in the object and MAY change from the input value.
     *
     * @param source the memory source (i.e. Calibration) to write to
     * @param table the table to use when writing the value
     * @param coordinates the coordinates (in order: X, Y, Z) of the cell to write
     * @return the new scaled value, possibly changed from the input based on scaling/data format constraints
     */
    float set(MemorySource source, Table table, float value, Map<Axis, Integer> coordinates)
            throws IOException, IllegalArgumentException;

}
