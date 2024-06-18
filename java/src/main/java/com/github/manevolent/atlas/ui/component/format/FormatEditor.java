package com.github.manevolent.atlas.ui.component.format;

import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.Scale;
import com.github.manevolent.atlas.model.Variant;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.behavior.ModelChangeListener;
import com.github.manevolent.atlas.ui.settings.SettingPage;
import com.github.manevolent.atlas.ui.settings.SettingsWindow;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.event.InternalFrameEvent;

public class FormatEditor extends SettingsWindow<Scale> implements ModelChangeListener {
    public FormatEditor(Editor editor, Scale parameter) {
        super(false, editor, parameter, CarbonIcons.DATA_SET, parameter.getName());
    }

    public Scale getFormat() {
        return getItem();
    }

    @Override
    protected void onApplied() {
        super.onApplied();

        Scale scale = getFormat();
        Project project = getProject();
        if (!project.hasScale(scale)) {
            project.addScale(scale);
            getEditor().fireModelChange(Model.PARAMETER, ChangeType.ADDED);
        } else {
            getEditor().fireModelChange(Model.PARAMETER, ChangeType.MODIFIED);
        }
    }

    @Override
    public void internalFrameActivated(InternalFrameEvent e) {
        super.internalFrameActivated(e);

        if (Settings.AUTO_SELECT_ITEM.get()) {
            getEditor().getProjectTreeTab().onItemOpened(getItem());
        }
    }

    @Override
    public void onModelChanged(Model model, ChangeType changeType) {
        if (model == Model.FORMAT) {
            reinitialize();
        }
    }
}
