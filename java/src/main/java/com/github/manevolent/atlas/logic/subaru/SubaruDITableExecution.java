package com.github.manevolent.atlas.logic.subaru;

import com.github.manevolent.atlas.logic.TableExecution;
import com.github.manevolent.atlas.logic.TableFunction;

public class SubaruDITableExecution extends TableExecution {
    /**
     * The location of the MOV statement (calling function)
     */
    private final long movLocation;

    public SubaruDITableExecution(TableFunction function, long data, long movLocation) {
        super(function, data);
        this.movLocation = movLocation;
    }

    public long getMovLocation() {
        return movLocation;
    }

    @Override
    public int hashCode() {
        return Long.hashCode(movLocation);
    }

    @Override
    public String toString() {
        return super.toString() + " mov=0x" + Long.toHexString(movLocation);
    }
}
