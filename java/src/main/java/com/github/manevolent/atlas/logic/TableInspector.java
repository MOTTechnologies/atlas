package com.github.manevolent.atlas.logic;

public interface TableInspector {

    /**
     * Gets the table function associated with this inspector.
     * @return TableFunction instance being inspected.
     */
    TableFunction getFunction();

    /**
     * Fire emulation of the table in a manner that proves its axis cardinality. This emulation will record the
     * memory access to this helper class. We can store the state of the memory access in fields and retrieve it to
     * discern not only the table structure layout, but also data formats and such.
     * @return TableLayout modeling the struct offsets for this function.
     */
    TablePlan inspect();

}
