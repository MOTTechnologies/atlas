package com.github.manevolent.atlas.model;

import com.github.manevolent.atlas.settings.Settings;

import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

import static com.github.manevolent.atlas.model.Unit.*;

/**
 * Having all these random units is more of a joke than anything else.
 * Most people probably would prefer to use the majority of SI units anyways.
 */
public enum UnitClass {

    NONE("None"),

    AIR_FUEL_RATIO("Air Fuel Ratio", () -> LAMBDA,
            conversions().with(AFR_GASOLINE, (value) -> value * 14.70f)
                    .with(AFR_E85, (value) -> value * 9.76f)
                    .with(AFR_E100, (value) -> value * 8.98f)
                    .with(AFR_METHANOL, (value) -> value * 6.46f)
                    .with(AFR_DIESEL, (value) -> value * 14.50f)
                    .with(AFR_EQ, (value) -> 1f / value),
            conversions().with(AFR_GASOLINE, (value) -> value / 14.70f)
                    .with(AFR_E85, (value) -> value / 9.76f)
                    .with(AFR_E100, (value) -> value / 8.98f)
                    .with(AFR_METHANOL, (value) -> value / 6.46f)
                    .with(AFR_DIESEL, (value) -> value / 14.50f)
                    .with(AFR_EQ, (value) -> 1f / value)),
    TEMPERATURE("Temperature",
            () -> Unit.CELSIUS,
            conversions().with(Unit.FAHRENHEIT, (value) -> (value * 9f / 5f) + 32f)
                    .with(Unit.KELVIN, (value) -> value - 273.15f),
            conversions().with(Unit.FAHRENHEIT, (value) -> (value - 32f) * 5f / 9f)
                    .with(Unit.KELVIN, (value) -> value + 273.15f)),
    SPEED("Speed",
            () -> Unit.KMH,
            conversions().with(Unit.MPH, (value) -> value / 1.60934f)
                    .with(Unit.M_PER_SEC, (value) -> value / 3.6f),
            conversions().with(Unit.MPH, (value) -> value * 1.60934f)
                    .with(Unit.M_PER_SEC, (value) -> value * 3.6f)),
    POWER("Power",
            () -> JOULE_PER_SEC,
            conversions().with(Unit.WATT, (value) -> value)
                    .with(Unit.KILOWATT, (value) -> value / 1000f)
                    .with(HORSEPOWER, (value) -> value / 745.7f),
            conversions().with(Unit.WATT, (value) -> value)
                    .with(Unit.KILOWATT, (value) -> value * 1000f)
                    .with(HORSEPOWER, (value) -> value * 745.7f)),
    FORCE("Specific Force", () -> Unit.G),
    VEHICLE_SPEED("Vehicle Speed",
            () -> Unit.REV_PER_KM,
            conversions().with(REV_PER_MI, (value) -> value * 1.60934f),
            conversions().with(REV_PER_MI, (value) -> value / 1.60934f)),
    TORQUE("Torque", () -> Unit.NM,
            conversions().with(Unit.FT_LB, (value) -> value * 0.7375621493f)
                    .with(Unit.IN_LB, (value) -> value * 8.8507457676f),
            conversions().with(Unit.FT_LB, (value) -> value / 0.7375621493f)
                    .with(Unit.IN_LB, (value) -> value / 8.8507457676f)),
    PRESSURE("Pressure", () -> Unit.PASCAL,
            conversions().with(KPA, (value) -> value / 1000)
                    .with(MPA, (value) -> value / 1000 / 1000)
                    .with(PSI, (value) -> value * 0.000145038f)
                    .with(IN_HG, (value) -> value * 0.0002952998057228486f)
                    .with(ATMOSPHERES, (value) -> value * 0.00000987923f),
            conversions().with(KPA, (value) -> value * 1000)
                    .with(MPA, (value) -> value * 1000 * 1000)
                    .with(PSI, (value) -> value / 0.000145038f)
                    .with(IN_HG, (value) -> value / 0.0002952998057228486f)
                    .with(ATMOSPHERES, (value) -> value / 0.00000987923f)),
    DISTANCE("Distance", () -> Unit.METER,
            conversions().with(Unit.MILLIMETER, (value) -> value * 1000f)
                    .with(Unit.CENTIMETER, (value) -> value * 100f)
                    .with(Unit.FOOT, (value) -> value * 3.28084f)
                    .with(Unit.INCH, (value) -> value * 39.37008f)
                    .with(Unit.KILOMETER, (value) -> value / 1000f),
            conversions().with(Unit.MILLIMETER, (value) -> value / 1000f)
                    .with(Unit.CENTIMETER, (value) -> value / 100f)
                    .with(Unit.FOOT, (value) -> value / 3.28084f)
                    .with(Unit.INCH, (value) -> value / 39.37008f)
                    .with(Unit.KILOMETER, (value) -> value * 1000f)),
    POTENTIAL("Electric Potential", () -> VOLTS,
            conversions().with(MILLIVOLT, (value) -> value * 1000f),
            conversions().with(MILLIVOLT, (value) -> value / 1000f)),
    CURRENT("Electric Current", () -> Unit.AMPERE,
            conversions().with(Unit.MILLIAMPERE, (value) -> value * 1000f),
            conversions().with(Unit.MILLIAMPERE, (value) -> value / 1000f)),
    RESISTANCE("Electric Resistance", () -> OHM,
            conversions().with(MILLIOHM, (value) -> value * 1000f),
            conversions().with(MILLIOHM, (value) -> value / 1000f)),
    FLOW_PER_REV("Flow per rev", () -> Unit.G_PER_REV,
            conversions().with(MG_PER_REV, (value) -> value * 1000),
            conversions().with(MG_PER_REV, (value) -> value / 1000)),
    FLOW("Flow", () -> Unit.G_PER_SEC,
            conversions().with(LB_PER_SEC, (value) -> value * 0.00220462f)
                    .with(OZ_PER_SEC, (value) -> value * 0.035274f)
                    .with(MG_PER_SEC, (value) -> value * 1000),
            conversions().with(LB_PER_SEC, (value) -> value / 0.00220462f)
                    .with(OZ_PER_SEC, (value) -> value / 0.035274f)
                    .with(MG_PER_SEC, (value) -> value / 1000)),
    TIME("Time",
            () -> Unit.SECOND,
            conversions().with(Unit.MILLISECOND, (value) -> value * 1000f)
                    .with(MICROSECOND, (value) -> value * 1000_000f)
                    .with(MINUTE, (value) -> value / 60f)
                    .with(HOUR, (value) -> value / 3600f),
            conversions().with(Unit.MILLISECOND, (value) -> value / 1000f)
                    .with(MICROSECOND, (value) -> value / 1000_000f)
                    .with(MINUTE, (value) -> value * 60f)
                    .with(HOUR, (value) -> value * 3600f));

    private final String name;
    private final Supplier<Unit> commonUnit;
    private final Map<Unit, Function<Float, Float>> conversionsFromCommon;
    private final Map<Unit, Function<Float, Float>> conversionsToCommon;

    UnitClass(String name,
              Supplier<Unit> commonUnit,
              Map<Unit, Function<Float, Float>> conversionsFromCommon,
              Map<Unit, Function<Float, Float>> conversionsToCommon) {
        this.name = name;
        this.commonUnit = commonUnit;
        this.conversionsFromCommon = conversionsFromCommon;
        this.conversionsToCommon = conversionsToCommon;
    }

    public Set<Unit> getUnits() {
        Set<Unit> unitSet = new HashSet<>();
        if (commonUnit != null && commonUnit.get() != null) {
            unitSet.add(commonUnit.get());
        }
        if (conversionsFromCommon != null) {
            unitSet.addAll(conversionsFromCommon.keySet());
        }
        return unitSet;
    }

    UnitClass(String name, Supplier<Unit> commonUnit, ConversionBuilder toCommon, ConversionBuilder fromCommon) {
        this(name, commonUnit, toCommon.build(), fromCommon.build());
    }

    UnitClass(String name, Supplier<Unit> commonUnit) {
        this(name, commonUnit, conversions(), conversions());
    }

    UnitClass(String name) {
        this.name = name;
        this.commonUnit = null;
        this.conversionsToCommon = null;
        this.conversionsFromCommon = null;
    }

    public String getName() {
        return name;
    }

    public String autoFormat(Unit source, float value, int significant) {
        Unit target = source.getPreferredUnit();
        return format(source, value, target, significant);
    }

    public String format(Unit source, float value, Unit target, int significant) {
        float converted = convert(source, value, target);

        //noinspection MalformedFormatString
        return String.format("%." + significant + "f%s", converted, target.getText());
    }

    public float convert(Unit source, float value, Unit target) {
        if (source == target) {
            return value;
        }

        if (source.getUnitClass() != target.getUnitClass()) {
            throw new UnsupportedOperationException("no common unit class: " +
                    source.getUnitClass() + " != " + target.getUnitClass());
        }

        if (this.commonUnit == null) {
            throw new UnsupportedOperationException("no common unit");
        }

        Unit commonUnit = this.commonUnit.get();
        if (commonUnit == null) {
            throw new UnsupportedOperationException("no common unit");
        }

        float common = source == commonUnit ? value :
                this.conversionsToCommon.get(source).apply(value);

        if (target == commonUnit) {
            return common;
        } else {
            return this.conversionsFromCommon.get(target).apply(common);
        }
    }

    private static ConversionBuilder conversions() {
        return new ConversionBuilder();
    }

    public Unit getDefaultUnit() {
        return commonUnit != null ? commonUnit.get() : null;
    }

    public Unit getPreferredUnit() {
        return Settings.getPreferredUnit(this);
    }

    public static class ConversionBuilder {
        private final Map<Unit, Function<Float, Float>> conversions;

        public ConversionBuilder() {
            conversions = new HashMap<>();
        }

        public ConversionBuilder with(Unit unit, Function<Float, Float> function) {
            this.conversions.put(unit, function);
            return this;
        }

        public Map<Unit, Function<Float, Float>> build() {
            return conversions;
        }
    }

}
