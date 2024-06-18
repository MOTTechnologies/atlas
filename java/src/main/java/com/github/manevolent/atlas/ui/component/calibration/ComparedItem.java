package com.github.manevolent.atlas.ui.component.calibration;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.ui.component.tab.TreeTab;

import java.io.IOException;
import java.util.List;

public interface ComparedItem {
    Calibration getSource();
    Calibration getTarget();
    TreeTab.Item getItem();
    List<Comparison> getComparisons();
    void apply() throws IOException;
}
