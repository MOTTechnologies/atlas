
package com.github.manevolent.atlas.ui.component.calibration;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import ghidra.trace.model.time.schedule.CompareResult;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ComparedTable implements ComparedItem {
    private final Table table;
    private final Calibration source, target;
    private final List<Comparison> comparisons;

    public ComparedTable(Table table,
                         Calibration source, Calibration target,
                         List<Comparison> comparisons) {
        this.table = table;
        this.source = source;
        this.target = target;
        this.comparisons = comparisons;
    }

    @Override
    public Table getItem() {
        return table;
    }

    public Calibration getSource() {
        return source;
    }

    public Calibration getTarget() {
        return target;
    }

    public List<Comparison> getComparisons() {
        return comparisons;
    }

    @Override
    public void apply() throws IOException {
        table.forEach(coordinates -> {
            float source_value = table.getCalculatedCell(source,
                    table.convertCoordinatesToAnchors(target, coordinates));
            table.setCell(target, source_value, coordinates);
        });
    }

    public static ComparedTable compare(Table table, Calibration source, Calibration target) throws IOException {
        return new ComparedTable(table, source, target, Comparisons.compareTables(table, source, target));
    }
}