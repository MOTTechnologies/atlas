package com.github.manevolent.atlas.ui.settings.field;

import javax.swing.*;
import java.util.concurrent.atomic.AtomicReference;

public interface SettingField {

    /**
     * Gets the human-readable name of this setting field.
     * @return name.
     */
    String getName();

    /**
     * Gets the hover tooltip for this setting field.
     * @return tooltip.
     */
    String getTooltip();

    /**
     * Gets the component displayed alongside the name of the setting that is used for user input when changing the
     * setting represented by this field.
     * @return input component.
     */
    JComponent getInputComponent();

    /**
     * Called by the setting page or dialog when the changed value on this setting field should be applied/saved.
     * @return true if application was successful, false if application failed and the dialog should abort closing.
     */
    boolean apply();

    /**
     * Determines if this setting sfield has un-applied changes.
     * @return true if the setting field is dirty, false otherwise.
     */
    boolean isDirty();

    /**
     * Gets the desired vertical label alignment for this setting field; see SwingConstants class.
     * @return alignment constant.
     */
    default int getLabelAlignment() {
        return SwingConstants.CENTER;
    }

    void addChangeListener(FieldChangeListener listener);

    void removeChangeListener(FieldChangeListener listener);

    @SuppressWarnings("unchecked")
    static <T> SettingField create(Class<T> valueClass, String name, String tooltip,
                                   AtomicReference<T> reference) {
        if (valueClass.equals(String.class)) {
            return new StringSettingField(name, tooltip, (String) reference.get(), value -> true,
                    value -> reference.set((T) value));
        } else if (valueClass.equals(Boolean.class)) {
            return new CheckboxSettingField(name, tooltip, (Boolean) reference.get(), value -> true,
                    value -> reference.set((T) value));
        } else {
            throw new UnsupportedOperationException(valueClass.getName());
        }
    }

}