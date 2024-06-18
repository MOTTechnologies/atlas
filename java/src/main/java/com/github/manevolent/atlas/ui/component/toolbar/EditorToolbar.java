package com.github.manevolent.atlas.ui.component.toolbar;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.behavior.EditHistory;
import com.github.manevolent.atlas.ui.behavior.WindowHistory;

import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;

import java.util.List;

public class EditorToolbar extends CalibrationToolbar<Editor> {
    private JButton left, right;
    private JButton undo, redo;
    private JButton save;

    public EditorToolbar(Editor editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent();
    }

    @Override
    protected void initLeftComponent(JToolBar toolbar) {
        toolbar.add(makeSmallButton(FontAwesomeSolid.FOLDER_OPEN, "open", "Open project...", e -> {
            getParent().openProject(ProjectStorageType.getDefault());
        }));
        toolbar.add(save = makeSmallButton(FontAwesomeSolid.SAVE, "save", "Save project", e -> {
            getParent().saveProject();
        }));

        toolbar.addSeparator();

        toolbar.add(left = makeSmallButton(FontAwesomeSolid.ARROW_LEFT, "left", "Last location", e -> {
            getParent().getWindowHistory().undo();
            update();
        }));

        toolbar.add(right = makeSmallButton(FontAwesomeSolid.ARROW_RIGHT, "right", "Next location", e -> {
            getParent().getWindowHistory().redo();
            update();
        }));

        toolbar.addSeparator();

        toolbar.add(undo = makeSmallButton(FontAwesomeSolid.UNDO, "undo", "Undo", e -> {
            getParent().getEditHistory().undo();
            update();
        }));

        toolbar.add(redo = makeSmallButton(FontAwesomeSolid.REDO, "redo", "Redo", e -> {
            getParent().getEditHistory().redo();
            update();
        }));

        toolbar.addSeparator();

        toolbar.add(makeButton(CarbonIcons.DATA_SET, "newformat", "New Format...", e -> {
            getParent().newFormat();
        }));

        toolbar.add(makeButton(CarbonIcons.CHART_CUSTOM, "newparameter", "New Parameter...", e -> {
            getParent().newParameter();
        }));

        toolbar.add(makeButton(CarbonIcons.DATA_TABLE_REFERENCE, "newtable", "New Table...", e -> {
            getParent().newTable();
        }));

        toolbar.add(makeButton(CarbonIcons.DATA_VIS_3, "newgraph", "New Graph...", e -> {
            getParent().newGraph();
        }));

        toolbar.addSeparator();

        toolbar.add(makeButton(CarbonIcons.WARNING_OTHER, "dtcs", "Enable/Disable DTCs", e -> {
            getParent().openDTCs();
        }));

        toolbar.add(makeButton(CarbonIcons.CHART_AVERAGE, "datalogging", "Open Data Logging", e -> {
            getParent().openDataLogging();
        }));

        toolbar.add(makeButton(CarbonIcons.DEBUG, "canlogging", "Open CAN Debugging", e -> {
            getParent().openCanLogging();
        }));

        toolbar.addSeparator();

        toolbar.add(makeButton(CarbonIcons.CHIP, "flash", "Flash Calibration...", e -> {
            getParent().flashCalibration();
        }));

        update();
    }

    @Override
    protected Calibration setCalibration(Calibration calibration) {
        getParent().setCalibration(calibration);
        return calibration;
    }

    @Override
    protected Calibration getCalibration() {
        return getParent().getCalibration();
    }

    @Override
    protected List<Calibration> getCalibrations() {
        return getParent().getProject().getCalibrations();
    }

    public void update() {
        super.update();

        save.setEnabled(getEditor().isDirty());

        EditHistory editHistory = getParent().getEditHistory();
        undo.setEnabled(editHistory != null && editHistory.canUndo());
        redo.setEnabled(editHistory != null && editHistory.canRedo());

        WindowHistory windowHistory = getParent().getWindowHistory();
        left.setEnabled(windowHistory != null && windowHistory.canUndo());
        right.setEnabled(windowHistory != null && windowHistory.canRedo());
    }
}
