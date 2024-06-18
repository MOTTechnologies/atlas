package com.github.manevolent.atlas.ui.component.tab;

import com.github.manevolent.atlas.connection.MemoryFrame;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.behavior.*;
import com.github.manevolent.atlas.ui.component.gauge.UIGauge;
import com.github.manevolent.atlas.ui.component.gauge.UIGaugeComponent;
import com.github.manevolent.atlas.ui.component.popupmenu.gauge.GaugePopupMenu;
import com.github.manevolent.atlas.ui.component.toolbar.GaugesTabToolbar;
import com.github.manevolent.atlas.ui.dialog.GaugeDialog;
import com.github.manevolent.atlas.ui.util.Icons;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import static javax.swing.JOptionPane.QUESTION_MESSAGE;

public class GaugesTab extends Tab implements GaugeSetListener, MemoryFrameListener, ModelChangeListener,
        CalibrationListener {
    private JPanel gaugePanel;
    private GaugesTabToolbar toolbar;
    private Map<Gauge, UIGauge> gauges = new LinkedHashMap<>();

    public GaugesTab(Editor editor, JTabbedPane pane) {
        super(editor, pane);
    }

    private void removeGuage(UIGauge ui) {
        gauges.remove(ui.getGauge());

        if (ui instanceof Component component) {
            gaugePanel.remove(component);
        }

        gaugePanel.revalidate();
        gaugePanel.repaint();
    }

    private UIGauge createUi(Gauge gauge) {
        UIGauge ui = UIGauge.createUi(gauge);

        UIGaugeComponent component = ui.getComponent();
        component.setCalibration(getEditor().getCalibration());
        component.setComponentPopupMenu(new GaugePopupMenu(this, ui).getComponent());
        component.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getButton() == MouseEvent.BUTTON1 && e.getClickCount() > 1) {
                    editGauge(ui);
                }
            }
        });

        return ui;
    }

    private void addGauge(UIGauge ui) {
        gauges.put(ui.getGauge(), ui);

        UIGaugeComponent component = ui.getComponent();
        component.setCalibration(getEditor().getCalibration());

        gaugePanel.add(component);

        SwingUtilities.invokeLater(() -> {
            gaugePanel.scrollRectToVisible(component.getBounds());
        });
    }

    private void addGauge(Gauge gauge) {
        addGauge(createUi(gauge));
    }

    private void updateGauge(Gauge gauge) {
        UIGauge oldUi = gauges.remove(gauge);
        if (oldUi == null) {
            return;
        }

        int index = Arrays.asList(gaugePanel.getComponents()).indexOf(oldUi);
        if (index >= 0) {
            gaugePanel.remove(index);
        } else {
            index = 0;
        }

        UIGauge ui = createUi(gauge);
        gaugePanel.add(ui.getComponent(), index);
        gauges.put(gauge, ui);

        gaugePanel.revalidate();
        gaugePanel.repaint();
    }

    public void addGauge(MemoryParameter parameter) {
        GaugeSet gaugeSet = getProject().getActiveGaugeSet();
        if (gaugeSet == null) {
            return;
        }

        focus();

        Gauge template = Gauge.builder().withParameter(parameter).build();
        template.setDisplayType(parameter.getScale().getUnit().getDefaultDisplayType());
        Gauge newGauge = GaugeDialog.show(getEditor(), template);
        if (newGauge != null) {
            gaugeSet.addGauge(newGauge);
            addGauge(newGauge);
            toolbar.reinitialize();
            getEditor().fireModelChange(Model.GAUGE, ChangeType.ADDED);
        }
    }

    public void addGauge() {
        GaugeSet gaugeSet = getProject().getActiveGaugeSet();
        if (gaugeSet == null) {
            return;
        }

        focus();

        Gauge newGauge = GaugeDialog.show(getEditor());
        if (newGauge != null) {
            gaugeSet.addGauge(newGauge);
            addGauge(newGauge);
            toolbar.reinitialize();
            getEditor().fireModelChange(Model.GAUGE, ChangeType.ADDED);
        }
    }

    public void newGaugeSet() {
        String newGaugeSetName = (String) JOptionPane.showInputDialog(getEditor(),
                "Specify a name", "New Gauge Set",
                QUESTION_MESSAGE, null, null, "New Gauge Set");

        if (newGaugeSetName == null || newGaugeSetName.isBlank()) {
            return;
        }

        GaugeSet newGaugeSet = GaugeSet.builder().withName(newGaugeSetName).build();
        getProject().addGaugeSet(newGaugeSet);
        toolbar.reinitialize();

        getEditor().setDirty(true);
        getEditor().setGaugeSet(newGaugeSet);
    }

    public void renameGaugeSet() {
        GaugeSet activeGaugeSet = getProject().getActiveGaugeSet();
        if (activeGaugeSet == null) {
            return;
        }

        String oldGaugeSetName = activeGaugeSet.getName();
        String newGaugeSetName  = (String) JOptionPane.showInputDialog(getEditor(),
                "Specify a new name",
                "Rename Gauge Set",
                QUESTION_MESSAGE, null, null, oldGaugeSetName);

        if (newGaugeSetName == null) {
            return;
        }

        if (!newGaugeSetName.equals(oldGaugeSetName)) {
            activeGaugeSet.setName(newGaugeSetName);
            getEditor().setDirty(true);
            toolbar.reinitialize();
        }
    }

    public void deleteGaugeSet() {
        GaugeSet activeGaugeSet = getProject().getActiveGaugeSet();
        if (activeGaugeSet == null) {
            return;
        }

        if (JOptionPane.showConfirmDialog(getParent(),
                "Are you sure you want to delete " + activeGaugeSet.getName() + "?",
                "Delete Gauge Set",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        getProject().removeGaugeSet(activeGaugeSet);
        getEditor().setDirty(true);

        toolbar.reinitialize();

        getEditor().setGaugeSet(getProject().getGaugeSets().stream().findFirst().orElse(null));
    }

    public void editGauge(UIGauge ui) {
        GaugeSet gaugeSet = getProject().getActiveGaugeSet();
        if (gaugeSet == null) {
            return;
        }

        Gauge exitingGauge = ui.getGauge();
        Gauge modifiedGauge = GaugeDialog.show(getEditor(), exitingGauge);

        if (modifiedGauge != null) {
            exitingGauge.apply(modifiedGauge);
            if (gaugeSet.getGauges().contains(exitingGauge)) {
                updateGauge(exitingGauge);
                getEditor().fireModelChange(Model.GAUGE, ChangeType.MODIFIED);
            }
        }
    }

    public void deleteGauge(UIGauge ui) {
        GaugeSet gaugeSet = getProject().getActiveGaugeSet();
        if (gaugeSet == null) {
            return;
        }

        Gauge exitingGauge = ui.getGauge();

        if (JOptionPane.showConfirmDialog(getParent(),
                "Are you sure you want to delete " + exitingGauge.getName() + "?",
                "Delete Gauge",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        if (gaugeSet.getGauges().contains(exitingGauge)) {
            gaugeSet.removeGauge(exitingGauge);
            getEditor().fireModelChange(Model.GAUGE, ChangeType.REMOVED);
        }

        removeGuage(ui);

        toolbar.reinitialize();
    }

    public void copyGauge(UIGauge ui) {
        GaugeSet gaugeSet = getProject().getActiveGaugeSet();
        if (gaugeSet == null) {
            return;
        }

        Gauge exitingGauge = ui.getGauge();
        Gauge copiedGauge = GaugeDialog.show(getEditor(), exitingGauge.copy(), "Copy Gauge");

        if (copiedGauge != null) {
            addGauge(copiedGauge);
            gaugeSet.addGauge(copiedGauge);
            getEditor().fireModelChange(Model.GAUGE, ChangeType.ADDED);
        }
    }

    private JComponent initToolbar() {
        return (toolbar = new GaugesTabToolbar(this)).getComponent();
    }

    @Override
    protected void initComponent(JPanel component) {
        gaugePanel = new JPanel();
        gaugePanel.setLayout(new WrapLayout());
        gaugePanel.setTransferHandler(new TransferHandler());

        JScrollPane scrollPane = new JScrollPane(gaugePanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());

        component.removeAll();
        component.setLayout(new BorderLayout());
        component.add(initToolbar(), BorderLayout.NORTH);
        component.add(scrollPane, BorderLayout.CENTER);
    }

    @Override
    protected void postInitComponent(JPanel component) {
        super.postInitComponent(component);

        onGaugeSetChanged(null, getProject().getActiveGaugeSet());
    }

    @Override
    public String getTitle() {
        return "Gauges";
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.METER);
    }

    @Override
    public void onGaugeSetChanged(GaugeSet oldGaugeSet, GaugeSet newGaugeSet) {
        toolbar.setActiveGaugeSet(newGaugeSet);

        gauges.clear();
        gaugePanel.removeAll();

        if (newGaugeSet != null) {
            newGaugeSet.getGauges().forEach(this::addGauge);
        }

        SwingUtilities.invokeLater(() -> {
            gaugePanel.revalidate();
            gaugePanel.repaint();
        });
    }

    @Override
    public void onGaugeSetModified(GaugeSet gaugeSet) {

    }

    @Override
    public void onMemoryFrame(MemoryFrame frame) {
        Calibration calibration = getEditor().getCalibration();
        gauges.forEach((gauge, ui) -> {
            if (ui.getComponent().getCalibration() != calibration) {
                ui.getComponent().setReceivingData(false);
                return;
            }

            Float value = frame.getValue(ui.getGauge().getParameter());

            if (value != null) {
                ui.setValue(value);
            } else {
                ui.getComponent().setReceivingData(false);
            }
        });
    }

    @Override
    public void onModelChanged(Model model, ChangeType changeType) {
        super.onModelChanged(model, changeType);

        if (model == Model.PARAMETER || model == Model.GAUGE) {
            SwingUtilities.invokeLater(() -> {
                toolbar.reinitialize();

                gaugePanel.revalidate();
                gaugePanel.repaint();
            });
        }
    }

    @Override
    public void onCalibrationChanged(Calibration oldCalibration, Calibration newCalibration) {
        gauges.values().forEach(ui -> ui.getComponent().setCalibration(newCalibration));
        getComponent().repaint();
    }

    private class TransferHandler extends javax.swing.TransferHandler {
        @Override
        public boolean canImport(TransferSupport support) {
            TreeTab.Item item = getItem(support);
            return item != null;
        }

        private TreeTab.Item getItem(TransferSupport support) {
            Object object;
            try {
                object = support.getTransferable().getTransferData(TreeTab.ITEM_DATA_FLAVOR);
            } catch (UnsupportedFlavorException | IOException e) {
                return null;
            }

            TreeTab.Item item = (TreeTab.Item) object;
            if (item instanceof MemoryParameter) {
                return item;
            } else {
                return null;
            }
        }

        @Override
        public boolean importData(TransferSupport support) {
            TreeTab.Item item = getItem(support);
            if (item == null) {
                return false;
            }

            GaugeSet gaugeSet = getProject().getActiveGaugeSet();
            if (gaugeSet == null) {
                return false;
            }

            if (item instanceof MemoryParameter parameter) {
                Gauge gauge = Gauge.builder().withParameter(parameter).build();
                gauge.setDisplayType(parameter.getScale().getUnit().getDefaultDisplayType());
                gaugeSet.addGauge(gauge);
                addGauge(gauge);
                toolbar.reinitialize();
                getEditor().fireModelChange(Model.GAUGE, ChangeType.ADDED);
            } else {
                return false;
            }

            return true;
        }
    }
}
