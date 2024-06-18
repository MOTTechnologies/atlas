package com.github.manevolent.atlas.ui.behavior;

import com.github.manevolent.atlas.model.GaugeSet;

public interface GaugeSetListener {

    void onGaugeSetChanged(GaugeSet oldGaugeSet, GaugeSet newGaugeSet);

    void onGaugeSetModified(GaugeSet gaugeSet);

}
