package com.github.manevolent.atlas.logic;

/**
 * Accurately models a table function in an OS with  adherence to OS logic/behavior.
 */
public interface TableFunction {

    /**
     * Gets the OS the function corresponds to.
     * @return OS instance.
     */
    OS getOS();

    /**
     * Gets the entry-point offset for this function
     * @return
     */
    long getOffset();

    /**
     * Gets the dimensions for this function.
     * @return
     */
    int getDimensions();

    /**
     * Creates a table inspector for this function.
     * @return TableInspector instance.
     * @throws UnsupportedOperationException if this function isn't supported for inspection.
     */
    TableInspector createInspector();

    /**
     * Inspects the plan for this table function, attempting to discern what structure layout in memory this table
     * function executes for. This is critical in automatically finding/defining table structures.
     * @return TablePlan instance if the inspection was successful.
     * @throws UnsupportedOperationException if this function isn't supported for inspection.
     */
    default TablePlan inspect() {
        return createInspector().inspect();
    }

    /**
     * Computes, either by informed model or by direct instruction emulation, the OS-accurate value of a cell in this table.
     * @param structureAddress the location of the address for the table structure or data.
     * @param coordinates the coordinates (in order x, y, z) of the table to look up.
     * @return the cell at the location requested, interpolated and processed as according to OS behavior.
     */
    float compute(long structureAddress, int... coordinates);

    default float compute(TableExecution execution, int... coordinates) {
        return compute(execution.getDataOffset(), coordinates);
    }

}
