package com.github.manevolent.atlas.ui.component.calibration;

import com.github.manevolent.atlas.model.*;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

public class Comparisons {

    public static List<Comparison> compareTables(Table table, Calibration a, Calibration b) throws IOException {
        List<Comparison> comparisons = new ArrayList<>();
        comparisons.addAll(compareAxes(table, a, b));
        comparisons.addAll(compareData(table, a, b));
        comparisons.addAll(compareScales(table, a, b));
        return comparisons;
    }

    public static Collection<Comparison> compareAxes(Table table, Calibration a, Calibration b) throws IOException {
        List<Comparison> comparisons = new ArrayList<>();

        for (Axis axis : table.getSupportedAxes().stream().sorted(Comparator.comparing(Axis::getIndex)).toList()) {
            Series series = table.getSeries(axis);

            for (int i = 0; i < series.getLength(); i ++) {
                if (series.get(a, i) != series.get(b, i)) {
                    comparisons.add(new DefaultComparison(CompareSeverity.CHANGED,
                            CarbonIcons.COMPARE, String.format("%s axis changed", axis.name())));
                    break;
                }
            }
        }

        return comparisons;
    }

    public static Collection<Comparison> compareData(Table table, Calibration a, Calibration b) throws IOException {
        List<Comparison> comparisons = new ArrayList<>();

        AtomicReference<Float> delta_sum = new AtomicReference<>(0f);
        AtomicReference<Integer> num = new AtomicReference<>(0);

        table.forEach(b_coordinates -> {
            Map<Axis, Float> a_coordinates = table.convertCoordinatesToAnchors(b, b_coordinates);

            Scale scale_a = table.getData().getScale();
            Scale scale_b = table.getData().getScale();
            float a_cell = scale_a.range(table.getCalculatedCell(a, a_coordinates));
            float b_cell = scale_b.range(table.getCell(b, b_coordinates));
            float delta = Math.abs(a_cell - b_cell);

            delta_sum.set(delta_sum.get() + delta);
            num.set(num.get() + 1);
        });

        if (delta_sum.get() == 0) {
            comparisons.add(new DefaultComparison(CompareSeverity.MATCH,
                    CarbonIcons.CHECKMARK, "Data matches"));
        } else {
            float change = delta_sum.get() / (float) num.get();
            comparisons.add(new DefaultComparison(CompareSeverity.CHANGED,
                    CarbonIcons.COMPARE, String.format("Data changed by %.2f%%", change * 100f)));
        }

        return comparisons;
    }

    public static Collection<Comparison> compareScales(Table table, Calibration a, Calibration b) throws IOException {
        List<Comparison> comparisons = new ArrayList<>();

        return comparisons;
    }

}
