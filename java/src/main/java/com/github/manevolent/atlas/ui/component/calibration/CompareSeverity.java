package com.github.manevolent.atlas.ui.component.calibration;

import java.awt.*;

public enum CompareSeverity {
    MATCH(1, Color.GREEN),
    CHANGED(2, Color.YELLOW),
    ERROR(3, Color.RED);

    private final int ordinal;
    private final Color color;

    CompareSeverity(int ordinal, Color color) {
        this.ordinal = ordinal;
        this.color = color;
    }

    public Color getColor() {
        return color;
    }

    public int getOrdinal() {
        return ordinal;
    }
}
