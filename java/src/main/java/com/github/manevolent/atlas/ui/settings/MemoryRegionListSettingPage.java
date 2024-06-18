package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.ZeroDividerSplitPane;
import com.github.manevolent.atlas.ui.component.toolbar.CalibrationListToolbar;
import com.github.manevolent.atlas.ui.component.toolbar.MemoryRegionListToolbar;
import com.github.manevolent.atlas.ui.settings.field.FieldChangeListener;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import com.github.manevolent.atlas.ui.settings.validation.ValidationSeverity;
import com.github.manevolent.atlas.ui.settings.validation.ValidationState;
import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.Color;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import static javax.swing.JOptionPane.QUESTION_MESSAGE;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class MemoryRegionListSettingPage extends ListSettingPage<MemorySection, MemoryRegionSettingPage> {
    private final Editor editor;
    private final Project project;

    protected MemoryRegionListSettingPage(Editor editor, Project project) {
        super(CarbonIcons.CHIP, "Memory Regions");

        this.editor = editor;
        this.project = project;
    }

    public Editor getEditor() {
        return editor;
    }

    @Override
    protected JToolBar initToolBar() {
        return new MemoryRegionListToolbar(this).getComponent();
    }

    public void newRegion() {
        String newSectionName = (String) JOptionPane.showInputDialog(editor,
                "Specify a name", "New Memory Region",
                QUESTION_MESSAGE, null, null, "New Memory Region");

        if (newSectionName == null || newSectionName.isBlank()) {
            return;
        }

        MemorySection section = MemorySection.builder()
                .withName(newSectionName)
                .withBaseAddress(0x00000000)
                .withLength(0)
                .withByteOrder(MemoryByteOrder.LITTLE_ENDIAN)
                .withEncryptionType(MemoryEncryptionType.NONE)
                .withType(MemoryType.RAM)
                .build();

        add(section);
    }

    public void copyRegion() {
        MemoryRegionSettingPage settingPage = getSettingPage();
        if (settingPage == null) {
            return;
        }

        MemorySection source = settingPage.getRealSection();

        String newSectionName = (String) JOptionPane.showInputDialog(editor,
                "Specify a name", "Copy Memory Region",
                QUESTION_MESSAGE, null, null, source.getName() + " (Copy)");

        if (newSectionName == null || newSectionName.isBlank()) {
            return;
        }

        MemorySection copy = source.copy();
        copy.setName(newSectionName);
        add(copy);
    }

    public void deleteRegion() {
        MemoryRegionSettingPage settingPage = getSettingPage();
        if (settingPage == null) {
            return;
        }

        MemorySection realSection = settingPage.getRealSection();
        MemorySection workingSection = settingPage.getWorkingSection();

        long references = project.getMemoryReferences().stream()
                .filter(ref -> ref.getAddress().getSection().equals(realSection))
                .count();

        if (references > 0) {
            JOptionPane.showMessageDialog(editor, "Cannot delete memory region " + realSection.getName() + "!\r\n" +
                            "Memory region is in use by " + references + " references and cannot be deleted.",
                    "Delete failed",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (JOptionPane.showConfirmDialog(editor,
                "Are you sure you want to delete " + realSection.getName() + "?",
                "Delete Memory Region",
                JOptionPane.YES_NO_OPTION,
                WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        remove(workingSection);
    }

    @Override
    protected MemorySection createWorkingCopy(MemorySection real) {
        return real.copy();
    }

    @Override
    protected List<MemorySection> getList() {
        return project.getSections();
    }

    @Override
    public boolean apply() {
        boolean applied = super.apply();

        if (applied) {
            getWorkingCopies().forEach(MemorySection::apply);

            getWorkingCopies().forEach((real, workingCopy) -> {
                if (!project.getSections().contains(real)) {
                    project.addSection(real);
                }
            });

            new ArrayList<>(project.getSections())
                    .stream()
                    .filter(cal -> !getWorkingCopies().containsKey(cal))
                    .forEach(project::removeSection);
        }

        return applied;
    }

    @Override
    protected MemoryRegionSettingPage createSettingPage(MemorySection real, MemorySection workingCopy) {
        return new MemoryRegionSettingPage(editor, project, real, workingCopy) {
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
        Map<MemorySection, MemorySection> workingCopies = getWorkingCopies();

        long codeSections = workingCopies.values().stream()
                .filter(x -> x.getMemoryType() == MemoryType.CODE).count();

        if (codeSections <= 0) {
            validation.add(this, ValidationSeverity.ERROR, "At least one " +
                    MemoryType.CODE + " memory region must be defined.");
        } else if (codeSections > 1) {
            validation.add(this, ValidationSeverity.ERROR, "Only one " +
                    MemoryType.CODE + " memory region can be defined.");
        }

        workingCopies.forEach((real, workingCopy) -> {
            if (workingCopy.getName().isBlank()) {
                validation.add(this, ValidationSeverity.ERROR, "Memory region name cannot be left blank");
            }

            java.util.List<MemorySection> collisions = workingCopies.values().stream()
                    .filter(s -> s != workingCopy)
                    .filter(s -> s.intersects(workingCopy))
                    .toList();

            if (!collisions.isEmpty()) {
                validation.add(this, ValidationSeverity.ERROR, "Memory region " + workingCopy.getName() +
                        " would intersect with " +
                        "other defined memory regions.\r\n" +
                        "Regions: " + collisions.stream().map(MemorySection::getName).collect(Collectors.joining(", ")) + ".");
            }

            java.util.List<MemoryReference> references = project.getMemoryReferences().stream()
                    .filter(real::contains)
                    .toList();

            List<MemoryReference> broken = references.stream()
                    .filter(ref -> !workingCopy.contains(ref))
                    .sorted(Comparator.comparing(MemoryReference::getName))
                    .toList();

            if (!broken.isEmpty()) {
                validation.add(this, ValidationSeverity.ERROR, "Memory region " + workingCopy.getName()
                        + " would break " + broken.size()
                        + " memory reference(s):\r\n" +
                        broken.stream().limit(20)
                                .map(MemoryReference::toString)
                                .collect(Collectors.joining(", ")) + ".\r\n" +
                        "More references could become broken; only the first 20 will be shown.");
            }
        });
    }
}
