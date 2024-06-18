package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.ui.Editor;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.util.Arrays;
import java.util.List;

public class ProjectSettingsDialog extends SettingsDialog<Project> {
    private final Editor parent;

    public ProjectSettingsDialog(Editor parent, Project object) {
        super(CarbonIcons.PRODUCT, "Project Settings", parent, object);

        this.parent = parent;
    }

    @Override
    protected List<SettingPage> createPages() {
        return Arrays.asList(
                new ConnectionSettingPage(parent, getSettingObject()),
                new KeySetListSettingPage(parent, getSettingObject()),
                new MemoryRegionListSettingPage(parent, getSettingObject()),
                new VariantListSettingPage(parent, getSettingObject()),
                new CalibrationListSettingPage(parent, getSettingObject())
        );
    }

    @Override
    protected ApplyResult apply() {
        ApplyResult applied = super.apply();
        if (applied != ApplyResult.FAILED_VALIDATION && applied != ApplyResult.NOTHING_APPLIED) {
            parent.setDirty(true); // Dirty because any applications could still have succeeded
        }
        return applied;
    }
}
