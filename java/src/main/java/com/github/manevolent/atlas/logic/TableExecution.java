package com.github.manevolent.atlas.logic;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Table;

import java.io.IOException;

public class TableExecution {
    private final TableFunction function;
    private final long data;

    public TableExecution(TableFunction function, long data) {
        this.function = function;
        this.data = data;
    }

    public Table createTable(Calibration calibration) throws IOException {
        return getFunction().createInspector().inspect().getStructure(this).createTable(calibration);
    }

    public TableFunction getFunction() {
        return function;
    }

    public long getDataOffset() {
        return data;
    }

    public boolean equals(TableExecution e) {
        return data == e.data && e.function.getOffset() == function.getOffset();
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof TableExecution e && equals(e);
    }

    @Override
    public int hashCode() {
        return Long.hashCode(data) ^ Long.hashCode(function.getOffset());
    }

    @Override
    public String toString() {
        return function.toString() + " data=0x" + Long.toHexString(data);
    }
}
