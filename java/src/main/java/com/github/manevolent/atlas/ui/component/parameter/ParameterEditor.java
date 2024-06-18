package com.github.manevolent.atlas.ui.component.parameter;

import com.github.manevolent.atlas.model.MemoryParameter;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.model.Variant;

import com.github.manevolent.atlas.ui.Editor;

import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.behavior.ModelChangeListener;

import com.github.manevolent.atlas.ui.util.Errors;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.event.InternalFrameEvent;

public class ParameterEditor extends com.github.manevolent.atlas.ui.settings.SettingsWindow<MemoryParameter>
        implements ModelChangeListener {

    public ParameterEditor(Editor editor, MemoryParameter parameter) {
        super(true, editor, parameter, CarbonIcons.SUMMARY_KPI, parameter.getName());
    }

    public MemoryParameter getParameter() {
        return getItem();
    }

    @Override
    protected boolean isVariantSupported(Variant variant) {
        return getWorkingCopy().isVariantSupported(variant);
    }

    @Override
    protected void addVariant(Variant variant) {
        MemoryParameter workingCopy = getWorkingCopy();

        // Set up the variant, if necessary
        if (!workingCopy.isVariantSupported(variant)) {
            long offset = workingCopy.getAddress().getOffset(getVariant());
            workingCopy.getAddress().setOffset(variant, offset);
        }

        super.addVariant(variant);
    }

    @Override
    protected void deleteVariant(Variant variant) {
        MemoryParameter workingCopy = getWorkingCopy();

        if (!workingCopy.isVariantSupported(variant)) {
            return;
        }

        if (workingCopy.getSupportedVariants().size() <= 1) {
            Errors.show(getParent(), "Delete Variant Failed",
                    "You cannot remove the default variant of " + workingCopy.getName() + ".");
            return;
        }

        workingCopy.getAddress().removeOffset(variant);

        super.deleteVariant(variant);
    }

    @Override
    protected void onApplied() {
        super.onApplied();

        MemoryParameter parameter = getParameter();
        Project project = getProject();
        if (!project.hasParameter(parameter)) {
            project.addParameter(parameter);
            getEditor().fireModelChange(Model.PARAMETER, ChangeType.ADDED);
        } else {
            getEditor().fireModelChange(Model.PARAMETER, ChangeType.MODIFIED);
        }
    }

    @Override
    public void internalFrameActivated(InternalFrameEvent e) {
        super.internalFrameActivated(e);
        getEditor().getProjectTreeTab().onItemOpened(getItem());
    }

    @Override
    public void onModelChanged(Model model, ChangeType changeType) {
        if (model == Model.FORMAT || model == Model.PARAMETER) {
            reinitialize();
        }
    }
}
