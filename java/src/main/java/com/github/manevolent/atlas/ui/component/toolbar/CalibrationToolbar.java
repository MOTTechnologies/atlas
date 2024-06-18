package com.github.manevolent.atlas.ui.component.toolbar;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.ui.util.Layout;

import javax.swing.*;
import java.awt.*;
import java.util.Comparator;

/**
 * A toolbar that supports changing calibrations
 * @param <T> parent type
 */
public abstract class CalibrationToolbar<T> extends Toolbar<T> {
    private JComboBox<Calibration> comboBox;

    private boolean updating;

    protected CalibrationToolbar(T parent) {
        super(parent);
    }

    private DefaultComboBoxModel<Calibration> initModel() {
        DefaultComboBoxModel<Calibration> model = new DefaultComboBoxModel<>();

        getCalibrations().stream()
                .sorted(Comparator.comparing(Calibration::getName))
                .forEach(model::addElement);

        return model;
    }

    private JComboBox<Calibration> initCalibrationsList() {
        comboBox = new JComboBox<>(initModel());
        comboBox.setSelectedItem(getCalibration());

        comboBox.addItemListener(e -> onSelected((Calibration) e.getItem()));

        Layout.preferWidth(comboBox, 150);

        comboBox.setMaximumSize(new Dimension(200, Integer.MAX_VALUE));
        comboBox.setFocusable(false);
        comboBox.setToolTipText("Active calibration");

        return comboBox;
    }

    private void onSelected(Calibration selected) {
        if (updating) {
            return;
        }

        Calibration decided;
        if (selected != getCalibration()) {
            decided = getEditor().withWaitCursor(() -> setCalibration(selected));
        } else {
            decided = selected;
        }
        if (decided != selected) {
            SwingUtilities.invokeLater(() -> {
                try {
                    updating = true;
                    comboBox.setSelectedItem(decided);
                } finally {
                    updating = false;
                }
            });
        }
    }

    @Override
    protected void initComponent(JToolBar toolBar) {
        initLeftComponent(toolBar);

        toolBar.add(Box.createHorizontalGlue());
        toolBar.add(initCalibrationsList());
    }

    public void update() {
        if (comboBox == null) {
            return;
        }

        Object selected = comboBox.getSelectedItem();

        try {
            updating = true;
            comboBox.setModel(initModel());
            if (comboBox.getSelectedItem() != selected) {
                comboBox.setSelectedItem(selected);
            }
        } finally {
            updating = false;
        }

        SwingUtilities.invokeLater(() -> {
            comboBox.revalidate();
            comboBox.repaint();
        });
    }

    /**
     * Initializes the left side of the toolbar component
     * @param toolBar toolBar to initialize
     */
    protected abstract void initLeftComponent(JToolBar toolBar);

    /**
     * Called when the selected calibration changes.
     * @param calibration selected calibration.
     * @return calibration to set on the toolbar.
     */
    protected abstract Calibration setCalibration(Calibration calibration);

    /**
     * Gets the current calibration.
     * @return current calibration.
     */
    protected abstract Calibration getCalibration();

    /**
     * Gets the list of all available calibrations.
     * @return calibration list.
     */
    protected abstract java.util.List<Calibration> getCalibrations();


}
