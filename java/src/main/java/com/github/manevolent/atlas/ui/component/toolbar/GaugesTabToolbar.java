package com.github.manevolent.atlas.ui.component.toolbar;

import com.github.manevolent.atlas.model.GaugeSet;
import com.github.manevolent.atlas.ui.Editor;

import com.github.manevolent.atlas.ui.component.datalog.DatalogWindow;
import com.github.manevolent.atlas.ui.component.tab.GaugesTab;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;

public class GaugesTabToolbar extends Toolbar<GaugesTab> {
    private JButton recordButton;
    private JButton addButton;
    private JButton renameButton;
    private JButton newButton;
    private JButton deleteButton;
    private JComboBox<GaugeSet> comboBox;

    public GaugesTabToolbar(GaugesTab editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    private JComboBox<GaugeSet> initGaugeSetList() {
        JComboBox<GaugeSet> comboBox = Inputs.comboBox("The current gauge set",
                getProject().getGaugeSets(), getProject().getActiveGaugeSet(), false,
                selected -> getEditor().setGaugeSet(selected));

        Layout.preferWidth(comboBox, 150);

        comboBox.setMaximumSize(new Dimension(200, Integer.MAX_VALUE));
        comboBox.setFocusable(false);

        return comboBox;
    }

    @Override
    protected void initComponent(JToolBar toolbar) {
        toolbar.add(addButton = makeButton(CarbonIcons.ADD, "add", "Add gauge...", (e) -> {
            getParent().addGauge();
        }));

        toolbar.add(recordButton = makeButton(CarbonIcons.RECORDING_FILLED, "record", "Record new datalog", (e) -> {
            DatalogWindow datalogWindow = getEditor().openDataLogging();
            datalogWindow.startRecording();
        }));

        toolbar.addSeparator();

        toolbar.add(comboBox = initGaugeSetList());

        toolbar.add(newButton = makeButton(CarbonIcons.DOCUMENT, "new", "New gauge set...", (e) -> {
            getParent().newGaugeSet();
        }));
        toolbar.add(renameButton = makeButton(CarbonIcons.EDIT, "rename", "Rename gauge set...", (e) -> {
            getParent().renameGaugeSet();
        }));
        toolbar.add(deleteButton = makeButton(CarbonIcons.TRASH_CAN, "delete", "Delete gauge set", (e) -> {
            getParent().deleteGaugeSet();
        }));
    }

    public void setActiveGaugeSet(GaugeSet gaugeSet) {
        addButton.setEnabled(gaugeSet != null);
        recordButton.setEnabled(gaugeSet != null);
        renameButton.setEnabled(gaugeSet != null);
        deleteButton.setEnabled(gaugeSet != null);

        if (gaugeSet != null) {
            recordButton.setEnabled(!gaugeSet.getGauges().isEmpty());
        } else {
            recordButton.setEnabled(false);
        }

        comboBox.setSelectedItem(gaugeSet);
    }
}
