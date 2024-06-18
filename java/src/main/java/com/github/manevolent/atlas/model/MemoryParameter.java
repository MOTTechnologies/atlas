package com.github.manevolent.atlas.model;

import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import com.github.manevolent.atlas.ui.settings.SettingObject;
import com.github.manevolent.atlas.ui.settings.field.*;
import com.google.errorprone.annotations.Var;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class MemoryParameter extends AbstractAnchored
        implements TreeTab.Item, SettingObject, Editable<MemoryParameter>, Addressed {
    public static java.awt.Color treeColor = new java.awt.Color(83, 230, 66);

    private String name;
    private MemoryAddress address;
    private Scale scale;
    private Color color = Color.fromAwtColor(java.awt.Color.WHITE);

    public Scale getScale() {
        if (scale == null) {
            return Scale.NONE_SCALES.get(DataFormat.UBYTE);
        }

        return scale;
    }

    public void setScale(Scale scale) {
        this.scale = scale;
    }

    public MemoryAddress getAddress() {
        return address;
    }

    public void setAddress(MemoryAddress address) {
        this.address = address;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Color getColor() {
        return color == null ? Color.fromAwtColor(java.awt.Color.WHITE) : color;
    }

    public void setColor(Color color) {
        this.color = color;
    }

    public String toString() {
        Scale scale = getScale();
        if (scale.getUnit() == Unit.NONE) {
            return name + " (" + scale.getFormat() + ")";
        } else {
            return name + " (" + scale.getUnit().getText() + ", " + scale.getFormat() + ")";
        }
    }

    @Override
    public MemoryParameter copy() {
        MemoryParameter copy = new MemoryParameter();
        copy.name = name;
        copy.scale = scale;
        copy.address = address;
        copy.color = color != null ? color.copy() : null;
        return copy;
    }

    @Override
    public void apply(MemoryParameter parameter) {
        this.name = parameter.name;
        this.scale = parameter.scale;
        this.address = parameter.address;

        if (this.color == null) {
            this.color = parameter.getColor().copy();
        } else {
            this.color.apply(parameter.getColor());
        }
    }

    @Override
    public boolean isVariantSupported(Variant variant) {
        return getAddress().hasOffset(variant);
    }

    public static Builder builder() {
        return new Builder();
    }

    public byte[] newBuffer() {
        return new byte[getScale().getFormat().getSize()];
    }

    public float getValue(byte[] data) {
        float unscaled = getScale().getFormat().convertFromBytes(
                data,
                getAddress().getSection().getByteOrder().getByteOrder()
        );

        return getScale().forward(unscaled);
    }

    @Override
    public String getTreeName() {
        Scale scale = getScale();
        if (scale.getUnit() == Unit.NONE) {
            return getName() + " (" + getScale().getFormat() + ")";
        } else {
            return getName() + " (" + getScale().getUnit() + ", " + getScale().getFormat() + ")";
        }
    }

    @Override
    public Ikon getTreeIcon() {
        return CarbonIcons.SUMMARY_KPI;
    }

    @Override
    public java.awt.Color getTreeColor() {
        if (color == null) {
            return java.awt.Color.WHITE;
        } else {
            return color.toAwtColor();
        }
    }

    @Override
    public java.awt.Color getTreeIconColor() {
        return treeColor;
    }

    @Override
    public <T extends SettingObject> T createWorkingCopy() {
        //noinspection unchecked
        return (T) copy();
    }

    @Override
    public <T extends SettingObject> void applyWorkingCopy(T workingCopy) {
        apply((MemoryParameter) workingCopy);
    }

    @Override
    public int getTreeOrdinal() {
        return 2;
    }

    @Override
    public List<SettingField> createFields(Project project, Variant variant) {
        return List.of(
                new StringSettingField("Name", "The name of this memory parameter", getName(), v -> true, this::setName),
                new ColorSettingField("Color", "The color of this memory parameter in data logs",
                        getColor(), v -> true, this::setColor),
                new MemoryAddressSettingField(project, variant,
                        "Address", "The memory address for this memory parameter",
                        getAddress(), EnumSet.of(MemoryType.RAM, MemoryType.EEPROM), v -> true, address ->
                        this.getAddress().setOffset(variant, address.getOffset(variant))),
                new ListSettingField<>("Format", "The format of this memory parameter",
                        project.getScales(), scale, v -> true, this::setScale)
        );
    }

    public Set<Variant> getSupportedVariants() {
        return address.getOffsets().keySet();
    }

    public static class Builder {
        private final MemoryParameter parameter = new MemoryParameter();

        public Builder withScale(Scale scale) {
            this.parameter.setScale(scale);
            return this;
        }

        public Builder withScale(Scale.Builder scale) {
            return withScale(scale.build());
        }

        public Builder withName(String name) {
            this.parameter.setName(name);
            return this;
        }

        public Builder withAddress(MemoryAddress address) {
            this.parameter.setAddress(address);
            return this;
        }

        public Builder withAddress(MemorySection section, Variant variant, int address) {
            this.parameter.setAddress(MemoryAddress.builder()
                    .withOffset(variant, address)
                    .withSection(section)
                    .build());
            return this;
        }

        public MemoryParameter build() {
            return parameter;
        }
    }
}
