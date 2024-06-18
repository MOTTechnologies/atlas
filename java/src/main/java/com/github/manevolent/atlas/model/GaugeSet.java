package com.github.manevolent.atlas.model;

import java.util.ArrayList;
import java.util.List;

public class GaugeSet extends AbstractAnchored {
    private String name;
    private List<Gauge> gauges = new ArrayList<>();

    public List<Gauge> getGauges() {
        return gauges;
    }

    public void setGauges(List<Gauge> gauges) {
        this.gauges = gauges;
    }

    public void addGauge(Gauge gauge) {
        this.gauges.add(gauge);
    }

    public void removeGauge(Gauge gauge) {
        this.gauges.remove(gauge);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String toString() {
        return name;
    }

    public static class Builder {
        private final GaugeSet gaugeSet;

        public Builder() {
            this.gaugeSet = new GaugeSet();
            this.gaugeSet.gauges = new ArrayList<>();
        }

        public Builder withName(String name) {
            this.gaugeSet.name = name;
            return this;
        }

        public Builder withGauge(Gauge gauge) {
            this.gaugeSet.addGauge(gauge);
            return this;
        }

        public GaugeSet build() {
            return gaugeSet;
        }
    }
}
