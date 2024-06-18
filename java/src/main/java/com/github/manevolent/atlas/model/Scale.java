package com.github.manevolent.atlas.model;

import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import com.github.manevolent.atlas.ui.settings.SettingObject;
import com.github.manevolent.atlas.ui.settings.field.*;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.util.*;

public class Scale extends AbstractAnchored
        implements TreeTab.Item, SettingObject, Editable<Scale> {
    public static String NONE_NAME = "None";
    private static Map<DataFormat, Scale> noneScales = new HashMap<>();

    static {
        for (DataFormat format : DataFormat.values()) {
            noneScales.put(format, Scale.builder().withFormat(format).withName(NONE_NAME).withUnit(Unit.NONE).build());
        }
    }

    public static Map<DataFormat, Scale> NONE_SCALES = Collections.unmodifiableMap(noneScales);

    public static Scale getNone(DataFormat format) {
        return noneScales.get(format);
    }

    public static java.awt.Color treeColor = new java.awt.Color(89, 192, 230);

    private List<ScalingOperation> operations;
    private Unit unit;
    private DataFormat format;
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public float forward(float a) {
        for (ScalingOperation operation : operations) {
            a = operation.getOperation().forward(a, operation.getCoefficient());
        }

        return a;
    }

    public float reverse(float a) {
        ListIterator<ScalingOperation> listIterator =
                operations.listIterator(operations.size());

        while (listIterator.hasPrevious()) {
            ScalingOperation operation = listIterator.previous();
            a = operation.getOperation().reverse(a, operation.getCoefficient());
        }

        return a;
    }

    public void setOperations(List<ScalingOperation> operations) {
        this.operations = operations;
    }

    public Unit getUnit() {
        return unit;
    }

    public void setUnit(Unit unit) {
        this.unit = unit;
    }

    public DataFormat getFormat() {
        return format;
    }

    @Override
    public Scale copy() {
        Scale copy = new Scale();

        copy.operations = Editable.copy(getOperations());
        copy.unit = getUnit();
        copy.name = getName();
        copy.format = getFormat();

        return copy;
    }

    @Override
    public void apply(Scale other) {
        Editable.apply(operations, other.getOperations());

        unit = other.unit;
        name = other.name;
        format = other.format;
    }

    public static Builder builder() {
        return new Builder();
    }

    public float getPrecision() {
        float a = forward(1);
        float b = forward(2);
        return Math.abs(a - b);
    }

    public float getPreferredPrecision() {
        float a = forward(1);
        float b = forward(2);
        return convert(Math.abs(a - b));
    }

    private float convert(float value) {
        Unit preferred = unit.getPreferredUnit();
        return unit.convert(value, preferred);
    }

    public String getValueFormat() {
        return getPrecision() % 1f == 0.0f ? "%.0f" : "%.2f";
    }

    public String getPreferredValueFormat() {
        return getPreferredPrecision() % 1f == 0.0f ? "%.0f" : "%.2f";
    }

    public String format(float value) {
        return String.format(getValueFormat(), value);
    }

    public String formatPreferred(float value) {
        return String.format(getPreferredValueFormat(), convert(value));
    }

    public float getMinimum() {
        return forward(format.getMin());
    }

    public float getMaximum() {
        return forward(format.getMax());
    }

    @Override
    public String toString() {
        String formatString = getUnit().getText() + ", " + getFormat().name().toLowerCase();
        if (name == null) {
            return formatString;
        } else if (getUnit() == Unit.NONE) {
            return name + " (" + getFormat().name().toLowerCase() + ")";
        } else {
            return name + " (" + formatString + ")";
        }
    }

    public void setFormat(DataFormat format) {
        this.format = format;
    }

    public List<ScalingOperation> getOperations() {
        return Collections.unmodifiableList(operations);
    }

    public void removeOperation(ScalingOperation operation) {
        operations.remove(operation);
    }

    public void addOperation(ScalingOperation after, ScalingOperation operation) {
        if (after == null) {
            operations.add(operation);
        } else {
            operations.add(operations.indexOf(after) + 1, operation);
        }
    }

    public void addOperation(ScalingOperation operation) {
        addOperation(null, operation);
    }

    public void moveOperationDown(ScalingOperation operation) {
        int index = operations.indexOf(operation);
        if (index < 0 || index >= operations.size() - 1) {
            return;
        }

        operations.remove(operation);
        operations.add(index+1, operation);
    }

    public void moveOperationUp(ScalingOperation operation) {
        int index = operations.indexOf(operation);
        if (index <= 0 || index > operations.size() - 1) {
            return;
        }

        operations.remove(operation);
        operations.add(index-1, operation);
    }

    @Override
    public String getTreeName() {
        return toString();
    }

    @Override
    public Ikon getTreeIcon() {
        return CarbonIcons.DATA_SET;
    }

    @Override
    public int getTreeOrdinal() {
        return 3;
    }

    @Override
    public java.awt.Color getTreeIconColor() {
        return treeColor;
    }

    @Override
    public List<SettingField> createFields(Project project, Variant variant) {
        return List.of(
                new StringSettingField("Name", "The name of this format", getName(), v -> true, this::setName),
                new EnumSettingField<>("Unit", "The resulting unit for values scaled by this format",
                        Unit.class,
                        getUnit(),
                        v -> true, this::setUnit),
                new EnumSettingField<>("Data Type", "The binary data type for values read from and written to " +
                        "ROM data in this format",
                        DataFormat.class,
                        getFormat(),
                        v -> true, this::setFormat),
                new OperationsSettingField("Operations", "The operations to perform when scaling values", this)
        );
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T extends SettingObject> T createWorkingCopy() {
        return (T) copy();
    }

    @Override
    public <T extends SettingObject> void applyWorkingCopy(T workingCopy) {
        apply((Scale) workingCopy);
    }

    public float range(float value) {
        float min = getMinimum();
        return (value - min) / (getMaximum() - min);
    }

    public static class Builder {
        private final Scale scale = new Scale();

        public Builder() {
            this.scale.setOperations(new ArrayList<>());
        }

        public Builder withName(String name) {
            scale.name = name;
            return this;
        }

        public Builder withOperation(ScalingOperation operation) {
            scale.operations.add(operation);
            return this;
        }

        public Builder withOperation(ArithmeticOperation operation, float coefficient) {
           return withOperation(ScalingOperation.builder()
                   .withOperation(operation)
                   .withCoefficient(coefficient)
                   .build());
        }

        public Builder withOperation(ArithmeticOperation operation, int coefficient) {
            return withOperation(ScalingOperation.builder()
                    .withOperation(operation)
                    .withCoefficient((float) coefficient)
                    .build());
        }

        public Builder withOperations(ScalingOperation... operations) {
            scale.operations.addAll(Arrays.asList(operations));
            return this;
        }

        public Builder withOperations(Scale scale) {
            this.scale.operations.addAll(scale.operations);
            return this;
        }

        public Builder withOperations(Scale.Builder builder) {
            this.scale.operations.addAll(builder.scale.operations);
            if (builder.scale.unit != null) {
                withUnit(builder.scale.unit);
            }
            if (builder.scale.format != null && this.scale.format == null) {
                withFormat(builder.scale.format);
            }
            return this;
        }

        public Builder withUnit(Unit unit) {
            this.scale.unit = unit;
            return this;
        }

        public Builder withFormat(DataFormat format) {
            this.scale.format = format;
            return this;
        }

        public Scale build() {
            return scale;
        }
    }
}
