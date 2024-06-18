package com.github.manevolent.atlas.ui.component.table;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.layout.TableLayoutType;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.behavior.CalibrationListener;
import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.behavior.ModelChangeListener;
import com.github.manevolent.atlas.ui.component.field.MemoryAddressField;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.toolbar.VariantToolbar;
import com.github.manevolent.atlas.ui.util.*;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.*;
import java.awt.Color;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;
import static com.github.manevolent.atlas.model.MemoryType.CODE;
import static com.github.manevolent.atlas.ui.util.Fonts.bold;
import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;

public class TableDefinitionEditor extends Window
        implements InternalFrameListener, ModelChangeListener, ListSelectionListener, CalibrationListener {
    private final Table realTable;
    private final Map<Axis, JCheckBox> axisCheckboxes = new HashMap<>();
    private JButton swapButton;

    private Calibration calibration;
    private Variant variant;

    private Table workingTable;
    private JPanel rootPanel;
    private JScrollPane scrollPane;
    private TableEditor preview;
    private boolean dirty = false;

    private final boolean nested;

    private JLabel calibrationLabel;

    private JButton save, open, copy, reset;
    private JList<Variant> variantList;

    public TableDefinitionEditor(Editor editor, Table table) {
        this(editor, table, editor.getCalibration().getVariant());
    }

    public TableDefinitionEditor(Editor editor, Table table, Variant variant) {
        this(editor, table, editor.getCalibration().getVariant(), false);
    }

    public TableDefinitionEditor(Editor editor, Table table, Variant variant, boolean nested) {
        super(editor);

        this.realTable = table;
        this.workingTable = nested ? table : table.copy();
        this.variant = pickVariant(variant);
        this.calibration = pickCalibration(this.variant);
        this.nested = nested;
    }

    private Variant pickVariant(Variant desired) {
        if (workingTable.isVariantSupported(desired)) {
            return desired;
        } else {
            return workingTable.getSupportedVariants().getFirst();
        }
    }

    private Calibration pickCalibration(Variant variant) {
        java.util.List<Calibration> supportedCalibrations = getProject().getCalibrations()
                .stream().filter(c -> c.getVariant().get_anchor().equals(variant.get_anchor())).toList();

        if (supportedCalibrations.isEmpty()) {
            return null;
        }

        if (calibration != null && supportedCalibrations.contains(calibration)) {
            return calibration;
        }

        Calibration currentCalibration = getEditor().getCalibration();
        if (supportedCalibrations.contains(currentCalibration)) {
            return currentCalibration;
        } else {
            return supportedCalibrations.getFirst();
        }
    }

    public Calibration getCalibration() {
        return calibration;
    }

    private Calibration setCalibration(Calibration calibration) {
        if (this.calibration != calibration) {
            // Check if the calibration is supported
            if (!workingTable.isVariantSupported(calibration)) {
                return calibration;
            }

            this.calibration = calibration;

            if (this.calibrationLabel != null) {
                this.calibrationLabel.setText("Showing Calibration: " + calibration.getName());
            }

            // We either need to reload the entire editor, or just the preview
            if (variant != calibration.getVariant() &&
                    !variant.get_anchor().equals(calibration.getVariant().get_anchor())) {
                setVariant(variant);
            }

            if (preview.setCalibration(calibration)) {
                preview.reload();
            }
        }

        return this.calibration;
    }

    public Variant getVariant() {
        return variant;
    }

    private void setVariant(Variant variant) {
        if (this.variant != variant) {
            this.variant = variant;

            if (this.variantList.getSelectedValue() != variant) {
                this.variantList.setSelectedValue(variant, true);
            }

            setCalibration(pickCalibration(variant));
            reload();
        }
    }

    public Variant getSelectedVariant() {
        return variantList.getSelectedValue();
    }
    
    public Project getProject() {
        return getParent().getProject();
    }

    public Table getTable() {
        return realTable;
    }

    private void setDirty(boolean dirty) {
        if (this.dirty != dirty) {
            if (!nested) {
                copy.setEnabled(!dirty);
                save.setEnabled(dirty);
                reset.setEnabled(dirty);
                open.setEnabled(getProject().getTables().contains(realTable));
            }
            this.dirty = dirty;
        }
    }

    private JPanel createSaveRow() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

        panel.add(reset = Inputs.nofocus(Inputs.button(CarbonIcons.RESET, "Reset", "Reset entered values", () -> {
            if (JOptionPane.showConfirmDialog(getComponent(),
                    "Are you sure you want to reset " +
                    workingTable.getName() + "?",
                    "Reset",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
                return;
            }

            workingTable.apply(realTable);
            workingTable.setup(getProject());

            setDirty(false);
            Log.ui().log(Level.INFO, "Reset table definition back to project copy.");
            reinitialize();
            updateTitle();
        })));

        panel.add(save = Inputs.nofocus(Inputs.button(CarbonIcons.SAVE, "Save", "Save entered values", this::save)));

        panel.add(copy = Inputs.nofocus(Inputs.button(CarbonIcons.COPY, "Copy", "Copy this definition into a new table", () -> {
            String newTableName = (String) Inputs.showRenameDialog(getEditor(),
                    "Specify a name", "Copy Table", workingTable.getName());

            if (newTableName == null || newTableName.isBlank()) {
                return;
            }
            Table newTable = workingTable.copy();
            newTable.setName(newTableName);
            getParent().openTableDefinition(newTable);
        })));

        panel.add(open = Inputs.nofocus(Inputs.button(CarbonIcons.OPEN_PANEL_TOP, "Open", "Open table and edit cells",
                () -> getParent().openTable(realTable))));

        boolean isProjectTable = getProject().getTables().contains(realTable);
        if (!isProjectTable) {
            setDirty(true);
            updateTitle();
        }

        save.setEnabled(dirty);
        reset.setEnabled(dirty);
        copy.setEnabled(isProjectTable);
        open.setEnabled(isProjectTable);

        return panel;
    }

    private void save() {
        realTable.apply(workingTable);
        realTable.setup(getProject());

        getParent().setDirty(true);

        // Make sure the table is a part of the project
        if (!getProject().hasTable(realTable)) {
            getProject().addTable(realTable);
            Log.ui().log(Level.INFO, "Added new table definition of \"" + workingTable.getName()
                    + "\" to project.");
        }

        setDirty(false);
        updateTitle();
        Log.ui().log(Level.INFO, "Saved working table definition of \"" + workingTable.getName()
                + "\" to project.");

        // Reload various menus across the editor
        getParent().fireModelChange(Model.TABLE, ChangeType.MODIFIED);
        getParent().updateWindowTitles();
        getParent().getProjectTreeTab().update();
        getParent().getProjectTreeTab().onItemOpened(realTable);
    }

    private JPanel createTablePanel() {
        JPanel panel = Inputs.createEntryPanel();

        panel.add(Layout.emptyBorder(0, 0, 5, 0,
                        Layout.preferHeight(Labels.boldText(CarbonIcons.DATA_TABLE, "Table"), swapButton)),
                Layout.gridBagTop(2));

        Inputs.createEntryRow(
                panel, 1,
                "Name", "The name of this table",
                Inputs.textField(workingTable.getName(), (newName) -> {
                    if (!workingTable.getName().equals(newName)) {
                        workingTable.setName(newName);
                        definitionUpdated();
                    }
                })
        );

        panel.add(Layout.emptyBorder(0, 0, 1, 0,
                        Layout.preferHeight(Labels.boldText(CarbonIcons.PARENT_CHILD, "Variants"), swapButton)),
                Layout.gridBagHeader(2, 2));

        JPanel variantPanel = new JPanel(new BorderLayout());
        Layout.matteBorder(1, 1, 1, 1, Color.GRAY.darker(), variantPanel);

        variantPanel.add(initVariantToolbar(), BorderLayout.NORTH);
        if (variantList == null) {
            variantList = initVariantList();
        } else {
            reloadVariantList();
        }
        JScrollPane scrollPane = new JScrollPane(variantList);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        variantPanel.add(scrollPane, BorderLayout.CENTER);

        panel.add(variantPanel, Layout.gridBagConstraints(GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                0, 3, 2, 1, 1, 1));

        Layout.preferWidth(panel, 300);

        return panel;
    }

    private JPanel createSeriesPanel(Axis axis) {
        Series series;
        if (axis != null) {
            series = workingTable.getSeries(axis);
        } else {
            series = workingTable.getData();
        }

        JPanel panel = Inputs.createEntryPanel();

        EnumSet<MemoryType> allowedMemoryTypes = axis != null ? EnumSet.of(CODE)
                : EnumSet.of(CODE, MemoryType.EEPROM);

        MemoryAddressField memoryAddressField = Inputs.memoryAddressField(
                getProject(),
                getVariant(),
                series != null ? series.getAddress() : null,
                allowedMemoryTypes,
                (newAddress) -> {
            Series s = axis != null ? workingTable.getSeries(axis) : workingTable.getData();
            newAddress.applyTo(s);
            definitionUpdated();
        });

        JTextField nameField = Inputs.textField(series != null ? series.getName() : null, (newName) -> {
            Series s = axis != null ? workingTable.getSeries(axis) : workingTable.getData();
            if (s.getName() == null || !s.getName().equals(newName)) {
                s.setName(newName);
                definitionUpdated();
            }
        });

        JComboBox<Scale> scaleField = Inputs.scaleField(
                getProject(),
                series != null ? series.getScale() : null,
                "The data scale and format for this series",
                (newScale) -> {
                    Series s = axis != null ? workingTable.getSeries(axis) : workingTable.getData();

                    Scale oldScale = s.getScale();
                    s.setScale(newScale);

                    // Shortcut to set the name of a series
                    if (newScale.getName() != null && !newScale.getName().isBlank() &&
                            (nameField.getText() == null || nameField.getText().isBlank())) {
                        nameField.setText(newScale.getName());
                    } else if (oldScale != null && nameField.getText().equals(oldScale.getName())) {
                        nameField.setText(newScale.getName());
                    }

                    // Reinitialize so the parameter field can refresh
                    definitionUpdated();
                    reinitialize();
                }
        );

        boolean enabled;
        JSpinner memoryLengthField;
        JComboBox<TableLayoutType> layoutField;
        JComboBox<MemoryParameter> parameterField;
        
        if (axis != null) {
            memoryLengthField = Inputs.memoryLengthField(
                    series,
                    (newLength) -> {
                        Series currentSeries = workingTable.getSeries(axis);
                        if (currentSeries != null) {
                            currentSeries.setLength(newLength);
                            workingTable.updateLength();
                            definitionUpdated();
                        }
                    }
            );

            parameterField = Inputs.comboBox(
                    "The parameter associated with this data series",
                    getProject().getParameters((Scale) scaleField.getSelectedItem()),
                    series != null ? series.getParameter() : null,
                    true,
                    (value) -> {
                        Series currentSeries = workingTable.getSeries(axis);
                        if (currentSeries != null) {
                            currentSeries.setParameter(value);
                            definitionUpdated();
                        }
                    });

            JCheckBox checkBox = Inputs.checkbox(axis.name() + " axis",
                    workingTable.hasAxis(axis),
                    checked -> {
                        if (checked && !workingTable.hasAxis(axis)) {
                            // Try to automatically pick a scale if one isn't picked
                            Scale scale = (Scale) scaleField.getSelectedItem();
                            if (scale == null) {
                                scale = scaleField.getItemAt(0);
                            }

                            Series newSeries = Series.builder()
                                    .withName(nameField.getText())
                                    .withScale(scale)
                                    .withAddress(memoryAddressField.getDataAddress())
                                    .withLength((int) memoryLengthField.getValue())
                                    .build();

                            workingTable.setAxis(axis, newSeries);
                            scaleField.setSelectedItem(scale);
                        } else {
                            workingTable.removeAxis(axis);
                        }

                        workingTable.updateLength();

                        if (axis == Y) {
                            axisCheckboxes.get(X).setEnabled(!checked);
                            swapButton.setEnabled(checked);
                        } else if (axis == X) {
                            axisCheckboxes.get(Y).setEnabled(checked);
                            swapButton.setEnabled(workingTable.hasAxis(Y));
                        }

                        nameField.setEnabled(checked);
                        memoryAddressField.setEnabled(checked);
                        scaleField.setEnabled(checked);
                        memoryLengthField.setEnabled(checked);
                        parameterField.setEnabled(checked);

                        definitionUpdated();
                    });

            if (axis == X) {
                checkBox.setEnabled(!workingTable.hasAxis(Y));
            } else if (axis == Y) {
                checkBox.setEnabled(workingTable.hasAxis(X));
                swapButton.setEnabled(workingTable.hasAxis(Y));
            }

            checkBox.setFocusable(false);
            axisCheckboxes.put(axis, checkBox);

            if (axis == Y) {
                JPanel innerPanel = new JPanel(new BorderLayout());
                innerPanel.add(bold(checkBox), BorderLayout.WEST);
                innerPanel.add(swapButton, BorderLayout.EAST);
                panel.add(innerPanel, Layout.gridBagTop(2));
            } else {
                Layout.preferHeight(checkBox, swapButton);
                panel.add(Layout.emptyBorder(0, 0, 1, 0, bold(checkBox)), Layout.gridBagTop(2));
            }

            enabled = checkBox.isSelected();
            
            layoutField = null;
        } else {
            layoutField = Inputs.enumField("The memory layout of this table",
                    TableLayoutType.class, 
                    workingTable.getLayoutType(),
                    (v) -> {
                        workingTable.setLayoutType(v);
                        workingTable.setup(getProject());
                        definitionUpdated();
                    });

            parameterField = null;
            memoryLengthField = null;
            enabled = true;
            
            panel.add(Layout.emptyBorder(0, 0, 1, 0, Layout.preferHeight(
                    Labels.boldText(CarbonIcons.DATA_SET, "Data series"), swapButton)),
                    Layout.gridBagTop(2));
        }

        nameField.setEnabled(enabled);
        memoryAddressField.setEnabled(enabled);
        scaleField.setEnabled(enabled);
        if (memoryLengthField != null) {
            memoryLengthField.setEnabled(enabled);
        }
        if (parameterField != null) {
            parameterField.setEnabled(enabled);
        }

        int row = 1;

        Inputs.createEntryRow(panel, row++,
                "Name", axis != null ? "The name of this axis" : "The name of this series",
                nameField);

        Inputs.createEntryRow(panel, row++,
                "Address",
                "The data address for this series",
                memoryAddressField);

        if (memoryLengthField != null) {
            Inputs.createEntryRow(panel, row++,
                    "Length",
                    "The length of this axis",
                    memoryLengthField);
        }

        Inputs.createEntryRow(panel, row++,
                "Format",
                axis != null ? "The format of the data in this axis" : "The format of the data in this series",
                scaleField);

        if (parameterField != null) {
            Inputs.createEntryRow(panel, row++,
                    "Parameter",
                    "The parameter associated with this axis",
                    parameterField);
        }

        if (layoutField != null) {
            Inputs.createEntryRow(panel, row++,
                    "Layout",
                    "The memory layout of this table",
                    layoutField);
        }

        // Squeeze all those inputs upwards
        panel.add(Box.createVerticalGlue(), Layout.gridBagConstraints(
                GridBagConstraints.CENTER, GridBagConstraints.VERTICAL, 0, row++, 2, 1, 0, 100));

        Layout.preferWidth(panel, 200);

        return panel;
    }

    private void swapAxes() {
        Series x = workingTable.getSeries(X);
        Series y = workingTable.getSeries(Y);

        if (x == null || y == null) {
            return;
        }

        workingTable.setAxis(X, y);
        workingTable.setAxis(Y, x);
        setDirty(true);

        reinitialize();
    }

    private void updatePreview() {
        if (preview == null) {
            return;
        }

        preview.reload();
    }

    private void definitionUpdated() {
        setDirty(true);
        updateTitle();

        try {
            updatePreview();
        } catch (Exception ex) {
            Log.ui().log(Level.WARNING, "Problem updating table preview for table \"" +
                    getTable().getName() + "\"", ex);
        }
    }

    @Override
    protected void preInitComponent(JInternalFrame window) {
        window.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        window.addInternalFrameListener(this);
    }

    @Override
    protected void initComponent(JInternalFrame window) {
        updateTitle();

        if (rootPanel != null) {
            window.remove(rootPanel);
        }

        Color borderColor = Color.GRAY.darker();
        rootPanel = Layout.matteBorder(1, 0, 0, 0, borderColor, new JPanel(new BorderLayout()));

        swapButton = Inputs.button(CarbonIcons.ARROWS_HORIZONTAL, null, "Swap axes", this::swapAxes);

        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.X_AXIS));

        inputPanel.add(createTablePanel());
        inputPanel.add(Separators.vertical());
        inputPanel.add(createTableDataPanel());
        inputPanel.add(Separators.vertical());
        inputPanel.add(createSeriesPanel(X));
        inputPanel.add(Separators.vertical());
        inputPanel.add(createSeriesPanel(Y));

        Integer scrollBarPosition;
        if (scrollPane != null) {
            scrollBarPosition = scrollPane.getHorizontalScrollBar().getValue();
        } else {
            scrollBarPosition = null;
        }

        scrollPane = new JScrollPane(inputPanel);

        Layout.emptyBorder(scrollPane);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);

        JPanel inputPane = new JPanel(new BorderLayout());
        inputPane.add(scrollPane, BorderLayout.CENTER);

        JPanel buttonRow = new JPanel(new BorderLayout());
        buttonRow.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 1, 0, Color.GRAY.darker()),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));
        buttonRow.add(calibrationLabel = Labels.text(CarbonIcons.INFORMATION_FILLED,
                        "Showing Calibration: " + getCalibration().getName(),
                        Color.GRAY),
                BorderLayout.WEST);
        if (!nested) {
            buttonRow.add(createSaveRow(), BorderLayout.EAST);
        }

        inputPane.add(buttonRow, BorderLayout.SOUTH);

        rootPanel.add(inputPane, BorderLayout.NORTH);

        while (scrollBarPosition != null && scrollPane.getHorizontalScrollBar().getValue() != scrollBarPosition) {
            scrollPane.getHorizontalScrollBar().setValue(scrollBarPosition);
        }

        preview = new TableEditor(getParent(), workingTable, calibration, true);
        rootPanel.add(preview.getComponent().getContentPane(), BorderLayout.CENTER);

        window.add(rootPanel);
    }

    private JToolBar initVariantToolbar() {
        return new VariantToolbar<>(this) {
            @Override
            protected List<Variant> getSupportedVariants() {
                return workingTable.getSupportedVariants();
            }

            @Override
            protected Variant getCurrentVariant() {
                return TableDefinitionEditor.this.getVariant();
            }

            @Override
            protected void addVariant(Variant variant) {
                TableDefinitionEditor.this.addVariant(variant);
            }

            @Override
            protected void deleteVariant(Variant variant) {
                TableDefinitionEditor.this.deleteVariant(variant);
            }

            @Override
            public Editor getEditor() {
                return TableDefinitionEditor.this.getEditor();
            }
        }.getComponent();
    }

    private void deleteVariant(Variant variant) {
        if (!workingTable.isVariantSupported(variant)) {
            return;
        }

        if (workingTable.getSupportedVariants().size() <= 1) {
            Errors.show(getParent(), "Delete Variant Failed",
                    "You cannot remove the default variant of " + getTable().getName() + ".");
            return;
        }

        workingTable.getData().getAddress().removeOffset(variant);
        workingTable.getAllAxes().forEach(series -> series.getAddress().removeOffset(variant));

        reloadVariantList();
        setVariant(workingTable.getSupportedVariants().getFirst());
        setDirty(true);
    }

    private void addVariant(Variant variant) {
        // Set up the variant, if necessary
        if (!workingTable.isVariantSupported(variant)) {
            long offset = getEditor().getDefaultMemoryAddress(getCalibration(), CODE).getOffset(getVariant());
            workingTable.getData().getAddress().setOffset(variant, offset);
            workingTable.getAllAxes().forEach(series -> series.getAddress().setOffset(variant, offset));
        }

        setDirty(true);
        reloadVariantList();
        setVariant(variant);
    }

    private void reloadVariantList() {
        variantList.removeListSelectionListener(this);
        variantList.setModel(createVariantListModel());
        variantList.setSelectedValue(variant, true);
        variantList.addListSelectionListener(this);
    }

    protected ListModel<Variant> createVariantListModel() {
        DefaultListModel<Variant> model = new DefaultListModel<>();

        workingTable.getSupportedVariants()
                .stream().sorted(Comparator.comparing(Variant::getName))
                .forEach(model::addElement);

        return model;
    }

    private JList<Variant> initVariantList() {
        JList<Variant> list = new JList<>(createVariantListModel());
        Layout.emptyBorder(list);
        list.setBackground(new JPanel().getBackground());
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        Layout.preferWidth(list, 200);

        if (list.getModel().getSize() > 0) {
            list.setSelectedValue(variant, true);
        }

        list.addListSelectionListener(this);

        return list;
    }

    @Override
    public void valueChanged(ListSelectionEvent e) {
        Variant variant = getSelectedVariant();
        setVariant(variant);
    }

    private Component createTableDataPanel() {
        return createSeriesPanel(null); // null implies table data series
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.CHART_CUSTOM, getTextColor());
    }

    @Override
    public void reload() {
        if (!dirty) {
            if (nested) {
                workingTable = realTable;
            } else {
                workingTable = realTable.copy();
            }
        }

        getEditor().withWaitCursor(() -> {
            reinitialize();
            updatePreview();
            updateTitle();
        });
    }

    @Override
    public String getTitle() {
        return "Define Table - " + workingTable.getName() + (dirty ? "*" : "");
    }

    @Override
    public void internalFrameOpened(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameClosing(InternalFrameEvent e) {
        if (dirty) {
            focus();

            boolean isProjectTable = getProject().hasTable(realTable);

            String message = isProjectTable ?
                "You have unsaved changes to " + workingTable.getName() + " that will be lost. Save before closing?" :
                    "You haven't saved the new table " + workingTable.getName() + " yet. Save before closing?";

            int answer = JOptionPane.showConfirmDialog(getParent(),
                    message,
                    "Unsaved changes",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE
            );

            switch (answer) {
                case JOptionPane.YES_OPTION:
                    save();
                case JOptionPane.NO_OPTION:
                    getComponent().dispose();
                    break;
                case JOptionPane.CANCEL_OPTION:
                    return;
            }
        } else {
            getComponent().dispose();
        }
    }

    @Override
    public void internalFrameClosed(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameIconified(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameDeiconified(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameActivated(InternalFrameEvent e) {
        if (Settings.AUTO_SELECT_ITEM.get()) {
            getEditor().getProjectTreeTab().onItemOpened(getTable());
        }
    }

    @Override
    public void internalFrameDeactivated(InternalFrameEvent e) {

    }

    @Override
    public void onModelChanged(Model model, ChangeType changeType) {
        if (!nested && (model == Model.PARAMETER || model == Model.FORMAT)) {
            reload();
        }
    }

    @Override
    public void onCalibrationChanged(Calibration oldCalibration, Calibration newCalibration) {
        if (!nested && this.calibration == oldCalibration) {
            setCalibration(newCalibration);
        }
    }
}
