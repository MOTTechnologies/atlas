package com.github.manevolent.atlas.model;

import java.util.function.Supplier;

public enum Unit {
    NONE(() -> UnitClass.NONE, ""),
    DEGREES(() -> UnitClass.NONE, "\u00B0"),
    PERCENT(() -> UnitClass.NONE, "%", GaugeDisplayType.DIAL),
    STEPS(() -> UnitClass.NONE, "steps", GaugeDisplayType.NUMBER),

    REV_PER_KM(() -> UnitClass.VEHICLE_SPEED, "rev/km", GaugeDisplayType.DIAL),
    REV_PER_MI(() -> UnitClass.VEHICLE_SPEED, "rev/mi", GaugeDisplayType.DIAL),

    AFR_GASOLINE(() -> UnitClass.AIR_FUEL_RATIO, "afrG", GaugeDisplayType.DIAL),
    AFR_E85(() -> UnitClass.AIR_FUEL_RATIO, "afrE85", GaugeDisplayType.DIAL),
    AFR_E100(() -> UnitClass.AIR_FUEL_RATIO, "afrE100", GaugeDisplayType.DIAL),
    AFR_METHANOL(() -> UnitClass.AIR_FUEL_RATIO, "afrM", GaugeDisplayType.DIAL),
    AFR_EQ(() -> UnitClass.AIR_FUEL_RATIO, "afrEQ", GaugeDisplayType.DIAL),
    AFR_DIESEL(() -> UnitClass.AIR_FUEL_RATIO, "afrD", GaugeDisplayType.DIAL), // lmao... imagine if someone needed this
    LAMBDA(() -> UnitClass.AIR_FUEL_RATIO, "\u03BB", GaugeDisplayType.DIAL),

    CELSIUS(() -> UnitClass.TEMPERATURE, "\u00B0C", GaugeDisplayType.DIAL),
    FAHRENHEIT(() -> UnitClass.TEMPERATURE, "\u00B0F", GaugeDisplayType.DIAL),
    KELVIN(() -> UnitClass.TEMPERATURE, "K", GaugeDisplayType.DIAL),

    RPM(() -> UnitClass.NONE, "RPM", GaugeDisplayType.DIAL),

    INCH(() -> UnitClass.DISTANCE, "in", GaugeDisplayType.NUMBER),
    FOOT(() -> UnitClass.DISTANCE, "ft", GaugeDisplayType.NUMBER),

    FT_LB(() -> UnitClass.TORQUE, "ft-lb", GaugeDisplayType.NUMBER),
    IN_LB(() -> UnitClass.TORQUE, "in-lb", GaugeDisplayType.NUMBER),
    NM(() -> UnitClass.TORQUE, "Nm", GaugeDisplayType.NUMBER),

    PASCAL(() -> UnitClass.PRESSURE, "Pa", GaugeDisplayType.DIAL),
    KPA(() -> UnitClass.PRESSURE, "kPa", GaugeDisplayType.DIAL),
    MPA(() -> UnitClass.PRESSURE, "mPa", GaugeDisplayType.DIAL),
    PSI(() -> UnitClass.PRESSURE, "psi", GaugeDisplayType.DIAL),
    IN_HG(() -> UnitClass.PRESSURE, "inHg", GaugeDisplayType.DIAL),
    ATMOSPHERES(() -> UnitClass.PRESSURE, "atm", GaugeDisplayType.DIAL),

    VOLTS(() -> UnitClass.NONE, "V", GaugeDisplayType.DIAL),
    MILLIVOLT(() -> UnitClass.NONE, "mV", GaugeDisplayType.DIAL),

    AMPERE(() -> UnitClass.CURRENT, "A", GaugeDisplayType.DIAL),
    MILLIAMPERE(() -> UnitClass.CURRENT, "mA", GaugeDisplayType.DIAL),

    OHM(() -> UnitClass.RESISTANCE, "\u2126", GaugeDisplayType.NUMBER),
    MILLIOHM(() -> UnitClass.RESISTANCE, "m\u2126", GaugeDisplayType.NUMBER),

    HZ(() -> UnitClass.NONE, "Hz", GaugeDisplayType.DIAL),

    G_PER_REV(() -> UnitClass.FLOW_PER_REV, "g/rev", GaugeDisplayType.DIAL),
    MG_PER_REV(() -> UnitClass.FLOW_PER_REV, "mg/rev", GaugeDisplayType.DIAL),

    G_PER_SEC(() -> UnitClass.FLOW, "g/sec", GaugeDisplayType.DIAL),
    MG_PER_SEC(() -> UnitClass.FLOW, "mg/sec", GaugeDisplayType.DIAL),
    LB_PER_SEC(() -> UnitClass.FLOW, "lb/sec", GaugeDisplayType.DIAL),
    OZ_PER_SEC(() -> UnitClass.FLOW, "oz/sec", GaugeDisplayType.DIAL),

    METER(() -> UnitClass.DISTANCE, "m", GaugeDisplayType.NUMBER),
    KILOMETER(() -> UnitClass.DISTANCE, "km", GaugeDisplayType.NUMBER),
    CENTIMETER(() -> UnitClass.DISTANCE, "cm", GaugeDisplayType.NUMBER),
    MILLIMETER(() -> UnitClass.DISTANCE, "mm", GaugeDisplayType.NUMBER),

    KMH(() -> UnitClass.SPEED, "kmh", GaugeDisplayType.DIAL),
    MPH(() -> UnitClass.SPEED, "mph", GaugeDisplayType.DIAL),
    M_PER_SEC(() -> UnitClass.SPEED, "m/s", GaugeDisplayType.DIAL),

    KILOWATT(() -> UnitClass.POWER, "kW", GaugeDisplayType.DIAL),
    HORSEPOWER(() -> UnitClass.POWER, "HP", GaugeDisplayType.DIAL),
    WATT(() -> UnitClass.POWER, "W", GaugeDisplayType.DIAL),
    JOULE_PER_SEC(() -> UnitClass.POWER, "J/s", GaugeDisplayType.DIAL),

    SECOND(() -> UnitClass.TIME, "s", GaugeDisplayType.NUMBER),
    MILLISECOND(() -> UnitClass.TIME, "ms", GaugeDisplayType.NUMBER),
    MICROSECOND(() -> UnitClass.TIME, "us", GaugeDisplayType.NUMBER),
    MINUTE(() -> UnitClass.TIME, "min", GaugeDisplayType.NUMBER),
    HOUR(() -> UnitClass.TIME, "hr", GaugeDisplayType.NUMBER),

    G(() -> UnitClass.FORCE, "g", GaugeDisplayType.DIAL);

    private final Supplier<UnitClass> unitClass;
    private final String text;
    private final GaugeDisplayType defaultDisplayType;

    Unit(Supplier<UnitClass> unitClass, String text, GaugeDisplayType defaultDisplayType) {
        this.unitClass = unitClass;
        this.text = text;
        this.defaultDisplayType = defaultDisplayType;
    }

    Unit(Supplier<UnitClass> unitClass, String text) {
        this.unitClass = unitClass;
        this.text = text;
        this.defaultDisplayType = GaugeDisplayType.NUMBER;
    }

    public static Unit asPreferred(Unit unit) {
        if (unit == null) {
            return null;
        } else {
            return unit.getPreferredUnit();
        }
    }

    public GaugeDisplayType getDefaultDisplayType() {
        return defaultDisplayType;
    }

    public UnitClass getUnitClass() {
        return unitClass.get();
    }

    public float convert(float value, Unit target) {
        return getUnitClass().convert(this, value, target);
    }

    public void convert(float[] values, Unit target) {
        for (int i = 0; i < values.length; i ++) {
            values[i] = convert(values[i], target);
        }
    }

    public String getText() {
        return text;
    }

    @Override
    public String toString() {
        return getText();
    }

    public Unit getPreferredUnit() {
        if (unitClass == null || unitClass.get() == UnitClass.NONE) {
            return this;
        }

        Unit preferred = unitClass.get().getPreferredUnit();
        if (preferred == null) {
            return this;
        } else {
            return preferred;
        }
    }

    public static float convertToPreferred(float value, Unit source) {
        if (source == null || source == NONE) {
            return value;
        }

        UnitClass unitClass = source.getUnitClass();
        if (unitClass == null || unitClass == UnitClass.NONE) {
            return value;
        }

        return unitClass.convert(source, value, unitClass.getPreferredUnit());
    }

    @SuppressWarnings("MalformedFormatString")
    public static String formatAsPreferred(float value, Unit source, int significant) {
        if (source == null || source == NONE) {
            return String.format("%." + significant + "f", value);
        }

        UnitClass unitClass = source.getUnitClass();
        if (unitClass == null || unitClass == UnitClass.NONE) {
            return String.format("%." + significant + "f", value);
        }

        return unitClass.format(source, value, unitClass.getPreferredUnit(), significant);
    }

    public float convertToPreferred(float value) {
        return convert(value, getPreferredUnit());
    }
}
