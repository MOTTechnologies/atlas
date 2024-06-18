package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.*;

import java.io.IOException;
import java.util.Set;

public interface TableStructure {

    OS getOS();

    TableFunction getFunction();

    TableExecution getExecution();

    /**
     * Gets the axes this table has.
     *
     * @return
     */
    Set<Axis> getAxes();

    /**
     * Gets the data format for a particular series.
     * @param axis axis.
     * @return data format for the series backing the provided axis.
     */
    DataFormat getDataFormat(Axis axis);

    /**
     * Gets the data format for the data seres.
     * @return data format for the data series.
     */
    DataFormat getDataFormat();

    int getSeriesLength(Axis axis);

    /**
     * Gets a data pointer to a given axis series.
     * @param axis axis.
     * @return pointer to the axis series.
     */
    long getSeriesOffset(Axis axis);

    /**
     * Gets a data pointer to the data series.
     * @return pointer to the data series.
     */
    long getDataOffset();

    /**
     * Gets a data pointer to the root of the structure.
     * @return pointer to the root of the structure.
     */
    long getRootOffset();

    /**
     * Creates a table instance for this structure.
     * @param calibration calibration to create the table for.
     * @return Table object
     */
    Table createTable(Calibration calibration) throws IOException;

}
