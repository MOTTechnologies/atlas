package com.github.manevolent.atlas.model;

public enum Axis {
    /**
     * The horizontal axis of a table.
     */
    X(0),

    /**
     * The vertical axis of a table.
     */
    Y(1),

    /**
     * The Z axis of a table, often used for learning maps, etc. in some ECUs.
     */
    Z(2),

    /**
     * An extra 4th axis for future support, if necessary.
     */
    W(3);

    private final int index;

    Axis(int index) {
        this.index = index;
    }

    public int getIndex() {
        return index;
    }
}
