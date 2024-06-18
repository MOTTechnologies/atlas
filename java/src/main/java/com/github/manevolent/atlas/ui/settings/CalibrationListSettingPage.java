package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.ui.Editor;

import com.github.manevolent.atlas.ui.ZeroDividerSplitPane;
import com.github.manevolent.atlas.ui.component.toolbar.CalibrationListToolbar;
import com.github.manevolent.atlas.ui.settings.field.FieldChangeListener;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import com.github.manevolent.atlas.ui.settings.validation.ValidationSeverity;
import com.github.manevolent.atlas.ui.settings.validation.ValidationState;
import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.Color;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import static javax.swing.JOptionPane.QUESTION_MESSAGE;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class CalibrationListSettingPage extends ListSettingPage<Calibration, CalibrationSettingPage> {
    private final Editor editor;
    private final Project project;

    protected CalibrationListSettingPage(Editor editor, Project project) {
        super(CarbonIcons.CATALOG, "Calibrations");

        this.editor = editor;
        this.project = project;
    }

    public Editor getEditor() {
        return editor;
    }

    @Override
    protected JToolBar initToolBar() {
        return new CalibrationListToolbar(this).getComponent();
    }

    public void newCalibration() {
        MemorySection codeSection = project.getSections().stream()
                .filter(section -> section.getMemoryType() == MemoryType.CODE)
                .findFirst().orElse(null);

        if (codeSection == null) {
            JOptionPane.showMessageDialog(editor,
                    "Failed to create new calibration!\r\nYou must define a " + MemoryType.CODE + " memory region " +
                            "before creating a calibration.",
                    "Create failed",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        String newCalibrationName = (String) JOptionPane.showInputDialog(editor,
                "Specify a name", "New Calibration",
                QUESTION_MESSAGE, null, null, "New Calibration");

        if (newCalibrationName == null || newCalibrationName.isBlank()) {
            return;
        }

        Calibration calibration = Calibration.builder()
                .withName(newCalibrationName)
                .withReadOnly(false)
                .withSection(codeSection)
                .build();

        add(calibration);
    }

    public void copyCalibration() {
        CalibrationSettingPage settingPage = getSettingPage();
        if (settingPage == null) {
            return;
        }

        Calibration source = settingPage.getRealSection();

        String newCalibrationName = (String) JOptionPane.showInputDialog(editor,
                "Specify a name", "Copy Calibration",
                QUESTION_MESSAGE, null, null, source.getName() + " (Copy)");

        if (newCalibrationName == null || newCalibrationName.isBlank()) {
            return;
        }

        Calibration copy = source.copy();
        try {
            copy.dereferenceData();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        copy.setName(newCalibrationName);
        add(copy);
    }

    public void deleteCalibration() {
        CalibrationSettingPage settingPage = getSettingPage();
        if (settingPage == null) {
            return;
        }

        Calibration realCalibration = settingPage.getRealSection();
        Calibration workingCalibration = settingPage.getWorkingSection();

        if (JOptionPane.showConfirmDialog(editor,
                "WARNING!\r\nAre you sure you want to delete " + realCalibration.getName() + "?\r\n" +
                        "Doing so will PERMANENTLY remove any table data associated with this calibration.",
                "Delete Calibration",
                JOptionPane.YES_NO_OPTION,
                WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        remove(workingCalibration);
    }

    @Override
    protected Calibration createWorkingCopy(Calibration real) {
        return real.copy();
    }

    @Override
    protected List<Calibration> getList() {
        return project.getCalibrations();
    }

    @Override
    public boolean apply() {
        boolean applied = super.apply();

        if (applied) {
            getWorkingCopies().forEach(Calibration::apply);

            getWorkingCopies().forEach((real, workingCopy) -> {
                if (!project.getCalibrations().contains(real)) {
                    project.addCalibration(real);
                }
            });

            new ArrayList<>(project.getCalibrations())
                    .stream()
                    .filter(cal -> !getWorkingCopies().containsKey(cal))
                    .forEach(project::removeCalibration);
        }

        return applied;
    }

    @Override
    protected CalibrationSettingPage createSettingPage(Calibration real, Calibration workingCopy) {
        return new CalibrationSettingPage(editor, project, real, workingCopy) {
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
        super.validate(validation);

        Map<Calibration, Calibration> workingCopies = getWorkingCopies();
        if (workingCopies.isEmpty()) {
            validation.add(this, ValidationSeverity.WARNING, "No calibrations have been defined. Having at least one " +
                    "calibration is required to edit and define tables.");
        }

        workingCopies.values().stream().filter(calibration -> !calibration.hasData()).forEach(calibration -> {
            validation.add(this, ValidationSeverity.ERROR, "Calibration \"" + calibration.getName() + "\"" +
                    " does not have any backing ROM data. Make sure to supply a ROM file for this calibration, " +
                    "or copy another existing calibration first.");
        });

        workingCopies.values().stream().filter(calibration -> calibration.getVariant() == null).forEach(calibration -> {
            validation.add(this, ValidationSeverity.ERROR, "Calibration \"" + calibration.getName() + "\"" +
                    " does not have a variant. Make sure to select a variant for this calibration first.");
        });
    }
}
