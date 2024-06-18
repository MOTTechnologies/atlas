package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryption;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.ui.settings.field.*;
import com.github.manevolent.atlas.ui.util.Labels;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class VariantSettingPage extends BasicSettingPage {
    private final Frame parent;
    private final Project project;

    private final Variant real;
    private final Variant variant;

    public VariantSettingPage(Frame parent, Project project,
                              Variant real, Variant variant) {
        super(parent, CarbonIcons.PARENT_CHILD, "Variant - " + variant.getName());

        this.project = project;
        this.parent = parent;
        this.real = real;
        this.variant = variant;
    }

    public Variant getRealVariant() {
        return real;
    }

    public Variant getWorkingVariant() {
        return variant;
    }

    @Override
    protected List<SettingField> createFields() {
        List<SettingField> elements = new ArrayList<>();

        elements.add(new StringSettingField(
                "Name", "The name of this variant",
                variant.getName(),
                v -> true,
                variant::setName
        ));

        elements.add(new EnumSettingField<>(
                "OS", "The vendor-specific OS of this variant",
                OSType.class,
                variant.getOSType(),
                v -> true,
                variant::setOSType
        ));

        return elements;
    }

    @Override
    public boolean isDirty() {
        return !project.getVariants().contains(real) || super.isDirty();
    }
}
