package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.toolbar.MemoryRegionListToolbar;
import com.github.manevolent.atlas.ui.component.toolbar.VariantListToolbar;
import com.github.manevolent.atlas.ui.settings.validation.ValidationSeverity;
import com.github.manevolent.atlas.ui.settings.validation.ValidationState;
import com.github.manevolent.atlas.ui.util.Errors;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static javax.swing.JOptionPane.QUESTION_MESSAGE;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class VariantListSettingPage extends ListSettingPage<Variant, VariantSettingPage> {
    private final Editor editor;
    private final Project project;

    protected VariantListSettingPage(Editor editor, Project project) {
        super(CarbonIcons.PARENT_CHILD, "Variants");

        this.editor = editor;
        this.project = project;
    }

    public Editor getEditor() {
        return editor;
    }

    @Override
    protected JToolBar initToolBar() {
        return new VariantListToolbar(this).getComponent();
    }

    public void newVariant() {
        String newVariantName = (String) JOptionPane.showInputDialog(editor,
                "Specify a name", "New Variant",
                QUESTION_MESSAGE, null, null, "New Variant");

        if (newVariantName == null || newVariantName.isBlank()) {
            return;
        }

        Variant variant = Variant.builder()
                .withName(newVariantName)
                .build();

        add(variant);
    }

    public void copyVariant() {
        VariantSettingPage settingPage = getSettingPage();
        if (settingPage == null) {
            return;
        }

        Variant source = settingPage.getRealVariant();

        String newVariantName = (String) JOptionPane.showInputDialog(editor,
                "Specify a name", "Copy Variant",
                QUESTION_MESSAGE, null, null, source.getName() + " (Copy)");

        if (newVariantName == null || newVariantName.isBlank()) {
            return;
        }

        Variant copy = source.copy();
        copy.setName(newVariantName);
        add(copy);
    }

    public void deleteVariant() {
        VariantSettingPage settingPage = getSettingPage();
        if (settingPage == null) {
            return;
        }

        Variant realSection = settingPage.getRealVariant();
        Variant workingSection = settingPage.getWorkingVariant();

        if (project.getCalibrations().stream().anyMatch(c -> c.getVariant() == realSection)) {
            Errors.show(null, "Delete Variant Failed", "Variant \"" + workingSection.getName()
                    + "\" is in use by other calibrations, and cannot be deleted.");
            return;
        }

        remove(workingSection);
    }

    @Override
    protected Variant createWorkingCopy(Variant real) {
        return real.copy();
    }

    @Override
    protected List<Variant> getList() {
        return project.getVariants();
    }

    @Override
    public boolean apply() {
        boolean applied = super.apply();

        if (applied) {
            getWorkingCopies().forEach(Variant::apply);

            getWorkingCopies().forEach((real, workingCopy) -> {
                if (!project.getVariants().contains(real)) {
                    project.addVariant(real);
                }
            });

            new ArrayList<>(project.getVariants())
                    .stream()
                    .filter(cal -> !getWorkingCopies().containsKey(cal))
                    .forEach(project::removeVariant);
        }

        return applied;
    }

    @Override
    protected VariantSettingPage createSettingPage(Variant real, Variant workingCopy) {
        return new VariantSettingPage(editor, project, real, workingCopy) {
            @Override
            public void reinitialize() {
                apply(); // This is fine as we are using a copied region; we are only applying back to the copy
                super.reinitialize();
            }

            @Override
            public boolean apply() {
                boolean applied = super.apply();
                updateListModel();
                return applied;
            }
        };
    }

    @Override
    public void validate(ValidationState validation) {
        Map<Variant, Variant> workingCopies = getWorkingCopies();

        if (workingCopies.isEmpty()) {
            validation.add(this, ValidationSeverity.WARNING, "No variants have been defined. Having at least one " +
                    "variant is required to define a calibration.");
        }
    }
}
