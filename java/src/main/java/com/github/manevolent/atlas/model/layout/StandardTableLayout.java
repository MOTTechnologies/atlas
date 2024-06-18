package com.github.manevolent.atlas.model.layout;

import com.github.manevolent.atlas.model.*;

import java.util.Map;

import static com.github.manevolent.atlas.model.Axis.*;

public class StandardTableLayout extends AbstractTableLayout {
    @Override
    protected int getOffset(MemorySource source, Table table, Map<Axis, Integer> coordinates)
            throws IllegalArgumentException {
        if (coordinates.isEmpty()) {
            return 0;
        }

        Map<Axis, Series> axes = table.getAxes();
        Series x = null, y = null, z = null, w = null;

        int offset = 0;

        if (coordinates.containsKey(X)) {
            x = axes.get(X);
            int x_value = coordinates.get(X);
            if (x_value < 0) {
                throw new ArrayIndexOutOfBoundsException(x_value);
            } else if (x_value > 0 && x == null) {
                throw new IllegalArgumentException(table.getName() + " does not have " + X.name() + " axis");
            }

            offset += x_value;
        }

        if (coordinates.containsKey(Y)) {
            y = axes.get(Y);
            int scan;
            int y_value = coordinates.get(Y);
            if (y_value < 0) {
                throw new ArrayIndexOutOfBoundsException(y_value);
            } else if (y_value > 0 && !axes.containsKey(Y)) {
                throw new IllegalArgumentException(table.getName() + " does not have " + Y.name() + " axis");
            } else if (y_value > 0) {
                if (x == null) {
                    throw new IllegalArgumentException(table.getName() + " does not have " + X.name() + " axis");
                }

                offset += (x.getLength() * y_value);
            }

        }

        if (coordinates.containsKey(Z)) {
            z = axes.get(Z);
            int z_value = coordinates.get(Z);
            int scan = 0;
            if (z_value < 0) {
                throw new ArrayIndexOutOfBoundsException(z_value);
            } else if (z_value > 0) {
                if (z == null) {
                    throw new IllegalArgumentException(table.getName() + " does not have " + Z.name() + " axis");
                } else if (y == null) {
                    throw new IllegalArgumentException(table.getName() + " does not have " + Y.name() + " axis");
                } else if (x == null) {
                    throw new IllegalArgumentException(table.getName() + " does not have " + X.name() + " axis");
                }

                offset += ((x.getLength() * y.getLength()) * z_value);
            }
        }

        return offset;
    }

    public static class Factory implements TableLayoutFactory {
        @Override
        public TableLayout create() {
            return new StandardTableLayout();
        }
    }
}
