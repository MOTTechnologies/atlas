package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.model.MemoryAddress;
import com.github.manevolent.atlas.model.MemoryType;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.Variant;
import com.github.manevolent.atlas.ui.component.field.MemoryAddressField;

import javax.swing.*;
import java.util.EnumSet;
import java.util.function.Consumer;
import java.util.function.Function;

public class MemoryAddressSettingField extends AbstractSettingField {
    private final Function<MemoryAddress, Boolean> apply;
    private final MemoryAddressField memoryAddressField;
    private boolean dirty;

    public MemoryAddressSettingField(Project project,
                                     Variant variant,
                                     String name,
                                     String tooltip,
                                     MemoryAddress defaultValue,
                                     EnumSet<MemoryType> types,
                                     Function<MemoryAddress, Boolean> apply,
                                     Consumer<MemoryAddress> change) {
        super(name, tooltip);

        this.apply = apply;
        this.memoryAddressField = new MemoryAddressField(project, variant, defaultValue, types, var -> {
            change.accept(var);
            dirty = true;
            fireFieldChanged();
        });
    }

    @Override
    public JComponent getInputComponent() {
        return memoryAddressField;
    }

    @Override
    public boolean apply() {
        MemoryAddress value = memoryAddressField.getDataAddress();
        boolean applied = apply.apply(value);
        if (applied) {
            dirty = false;
        }
        return applied;
    }

    @Override
    public boolean isDirty() {
        return dirty;
    }
}