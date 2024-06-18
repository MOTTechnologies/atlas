package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.toolbar.KeySetListToolbar;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

import static javax.swing.JOptionPane.QUESTION_MESSAGE;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class KeySetListSettingPage extends ListSettingPage<KeySet, KeySetSettingPage> {
    private final Editor editor;
    private final Project project;

    protected KeySetListSettingPage(Editor editor, Project project) {
        super(CarbonIcons.PASSWORD, "Key Sets");

        this.editor = editor;
        this.project = project;
    }

    public Editor getEditor() {
        return editor;
    }

    @Override
    protected JToolBar initToolBar() {
        return new KeySetListToolbar(this).getComponent();
    }

    public void newKeySet() {
        String newKeySetName = (String) JOptionPane.showInputDialog(editor,
                "Specify a name", "New Key Set",
                QUESTION_MESSAGE, null, null, "New Key Set");

        if (newKeySetName == null || newKeySetName.isBlank()) {
            return;
        }

        KeySet keySet = new KeySet();
        keySet.setName(newKeySetName);
        keySet.setConfidential(true);
        add(keySet);
    }

    public void copyKeySet() {
        KeySetSettingPage settingPage = getSettingPage();
        if (settingPage == null) {
            return;
        }

        KeySet source = settingPage.getRealKeySet();

        String newKeySetName = (String) JOptionPane.showInputDialog(editor,
                "Specify a name", "Copy Key Set",
                QUESTION_MESSAGE, null, null, source.getName() + " (Copy)");

        if (newKeySetName == null || newKeySetName.isBlank()) {
            return;
        }

        KeySet copy = source.copy();
        copy.setName(newKeySetName);
        add(copy);
    }

    public void deleteKeySet() {
        KeySetSettingPage settingPage = getSettingPage();
        if (settingPage == null) {
            return;
        }

        KeySet realKeyset = settingPage.getRealKeySet();
        KeySet workingKeySet = settingPage.getWorkingKeySet();

        if (JOptionPane.showConfirmDialog(editor,
                "Are you sure you want to delete " + realKeyset.getName() + "?",
                "Delete Key Set",
                JOptionPane.YES_NO_OPTION,
                WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        remove(workingKeySet);
    }

    @Override
    protected KeySet createWorkingCopy(KeySet real) {
        return real.copy();
    }

    @Override
    protected List<KeySet> getList() {
        return project.getKeySets();
    }

    @Override
    public boolean apply() {
        boolean applied = super.apply();

        if (applied) {
            getWorkingCopies().forEach(KeySet::apply);

            getWorkingCopies().forEach((real, workingCopy) -> {
                if (!project.getKeySets().contains(real)) {
                    project.addKeySet(real);
                }
            });

            new ArrayList<>(project.getKeySets())
                    .stream()
                    .filter(cal -> !getWorkingCopies().containsKey(cal))
                    .forEach(project::removeKeySet);
        }

        return applied;
    }

    @Override
    protected KeySetSettingPage createSettingPage(KeySet real, KeySet workingCopy) {
        return new KeySetSettingPage(editor, project, real, workingCopy) {
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
}
