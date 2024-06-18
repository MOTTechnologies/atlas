package com.github.manevolent.atlas.model;

public class Gauge extends AbstractAnchored implements Editable<Gauge> {
    private MemoryParameter parameter;
    private GaugeDisplayType displayType;

    private Float minimum, maximum;

    private Color minimumColor;
    private Color maximumColor;

    public Gauge() {

    }

    public Color getMaximumColor() {
        return maximumColor;
    }

    public void setMaximumColor(Color maximumColor) {
        this.maximumColor = maximumColor;
    }

    public Color getMinimumColor() {
        return minimumColor;
    }

    public void setMinimumColor(Color minimumColor) {
        this.minimumColor = minimumColor;
    }

    public float getMaximum() {
        return maximum != null ? maximum : parameter.getScale().getMaximum();
    }

    public void setMaximum(float maximum) {
        this.maximum = maximum;
    }

    public float getMinimum() {
        return minimum != null ? minimum : parameter.getScale().getMinimum();
    }

    public void setMinimum(float minimum) {
        this.minimum = minimum;
    }

    public GaugeDisplayType getDisplayType() {
        return displayType;
    }

    public void setDisplayType(GaugeDisplayType displayType) {
        this.displayType = displayType;
    }

    public MemoryParameter getParameter() {
        return parameter;
    }

    public void setParameter(MemoryParameter parameter) {
        this.parameter = parameter;
    }

    public Gauge copy() {
        Gauge copy = new Gauge();
        copy.parameter = this.parameter;
        copy.maximum = this.maximum;
        copy.minimum = this.minimum;
        copy.maximumColor = this.maximumColor.copy();
        copy.minimumColor = this.minimumColor.copy();
        copy.displayType = this.displayType;
        return copy;
    }

    public void apply(Gauge other) {
        this.parameter = other.parameter;
        this.maximum = other.maximum;
        this.minimum = other.minimum;
        this.maximumColor.apply(other.maximumColor);
        this.minimumColor.apply(other.minimumColor);
        this.displayType = other.displayType;
    }

    @Override
    public String toString() {
        return parameter.getName();
    }

    public static Builder builder() {
        return new Builder();
    }

    public String getName() {
        return getParameter().getName();
    }

    public static class Builder {
        private final Gauge gauge;

        public Builder() {
            this.gauge = new Gauge();

            this.gauge.displayType = GaugeDisplayType.DIAL;
            this.gauge.minimumColor = Color.fromAwtColor(java.awt.Color.RED);
            this.gauge.maximumColor = Color.fromAwtColor(java.awt.Color.GREEN);
        }

        public Gauge build() {
            return gauge;
        }

        public Builder withParameter(MemoryParameter parameter) {
            gauge.parameter = parameter;
            return this;
        }
    }
}
