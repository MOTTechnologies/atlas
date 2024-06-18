package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.Variant;
import com.github.manevolent.atlas.ui.settings.field.SettingField;

import java.util.List;

public interface SettingObject {

    /**
     * Creates a list of fields for this setting object.
     * @param project the project instance for which setting fields are being created.
     * @return a list of fields that allow changing this object.
     */
    List<SettingField> createFields(Project project, Variant variant);

    /**
     * Creates a working copy of this setting object.
     * @return working copy instance.
     * @param <T> type of object being copied.
     */
    <T extends SettingObject> T createWorkingCopy();

    /**
     * Applies a changed working copy to this setting object.
     * @param workingCopy working copy to apply changes from.
     * @param <T> type of object being applied.
     */
    <T extends SettingObject> void applyWorkingCopy(T workingCopy);

}
