package com.github.manevolent.atlas.ui.component.table;

import org.checkerframework.checker.units.qual.A;

import java.util.ArrayList;
import java.util.List;

public class AxisGroup {
    private final int low, high;

    public AxisGroup(int low, int high) {
        this.low = low;
        this.high = high;
    }

    public int getLow() {
        return low;
    }

    public int getHigh() {
        return high;
    }

    public static List<AxisGroup> getGroups(int[] selection) {
        List<AxisGroup> groups = new ArrayList<>();
        if (selection.length == 0) {
            return groups;
        }

        Integer low = null;

        for (int i = 0; i < selection.length; i ++) {
            int idx = selection[i];
            if (low == null) {
                low = idx;
            }

            boolean end = i + 1 >= selection.length;
            boolean continuous = !end && selection[i + 1] - idx <= 1;

            if (end || !continuous) {
                groups.add(new AxisGroup(low, idx));
                low = null;
            }
        }

        return groups;
    }
}
