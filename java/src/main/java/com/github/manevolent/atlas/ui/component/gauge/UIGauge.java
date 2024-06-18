package com.github.manevolent.atlas.ui.component.gauge;

import com.github.manevolent.atlas.model.Gauge;
import com.github.manevolent.atlas.model.Scale;
import com.github.manevolent.atlas.model.Unit;
import com.github.manevolent.atlas.ui.util.Colors;

import javax.swing.*;

public interface UIGauge {

    /**
     * Creates a UI element that corresponds to the given input gauge model
     * @param gauge gauge model object
     * @return UIGauge instance
     */
    static UIGauge createUi(Gauge gauge) {
        switch (gauge.getDisplayType()) {
            case DIAL:
                return new RPMUIGauge(gauge);
            case NUMBER:
                return new NumberUIGauge(gauge);
            default:
                throw new UnsupportedOperationException(gauge.getDisplayType().name());
        }
    }

    /**
     * Gets the model object associated with this gauge.
     * @return gauge model object.
     */
    Gauge getGauge();

    default Scale getScale() {
        return getGauge().getParameter().getScale();
    }

    /**
     * Gets the Swing component associated with this UI element.
     * @return Swing component.
     */
    UIGaugeComponent getComponent();

    /**
     * Gets the currently reported value on this gauge
     * @return gauge value
     */
    float getValue();

    /**
     * Sets the currently reported value on this gauge
     * @param value gauge value
     */
    void setValue(float value);

    default void setValue(double value) {
        setValue((float) value);
    }

    default Unit getUnit() {
        return getGauge().getParameter().getScale().getUnit();
    }

    default float getMaximumValue() {
        return getGauge().getMaximum();
    }

    default float getMinimumValue() {
        return getGauge().getMinimum();
    }

    default java.awt.Color getMaximumColor() {
        return getGauge().getMaximumColor().toAwtColor();
    }

    default java.awt.Color getMinimumColor() {
        return getGauge().getMinimumColor().toAwtColor();
    }

    default java.awt.Color getColor(float value) {
        Gauge gauge = getGauge();
        return Colors.interpolate(
                gauge.getMinimum(), gauge.getMinimumColor().toAwtColor(),
                gauge.getMaximum(), gauge.getMaximumColor().toAwtColor(),
                value);
    }

}
