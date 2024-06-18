package com.github.manevolent.atlas.ui.component.dtc;

import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.logic.SupportedDTC;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.DTC;
import com.github.manevolent.atlas.model.Series;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.ColumnsAutoSizer;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.table.TableComparer;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.util.Errors;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;

import javax.swing.table.*;

import java.awt.*;
import java.awt.event.*;

import java.io.IOException;
import java.util.EventObject;
import java.util.List;
import java.util.logging.Level;

import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;

public class DTCEditor extends Window {
    private final Calibration calibration;
    private final List<SupportedDTC> supportedDTCs;

    private JTable tableComponent;

    public DTCEditor(Editor editor, Calibration calibration, List<SupportedDTC> supportedDTCs) {
        super(editor);

        this.calibration = calibration;
        this.supportedDTCs = supportedDTCs;
    }

    @Override
    public String getTitle() {
        return "DTCs - " + calibration.getName();
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.WARNING_OTHER, getTextColor());
    }

    private JCheckBox createCheckbox() {
        JCheckBox checkBox = new JCheckBox();
        checkBox.setAlignmentX(0.5f);
        checkBox.setHorizontalAlignment(SwingConstants.CENTER);
        checkBox.addActionListener(e -> {
            int row = tableComponent.getSelectedRow();
            int column = tableComponent.getSelectedColumn();
            Boolean selected = (Boolean) tableComponent.getValueAt(row, column);

            if (selected == null) {
                return;
            }

            SupportedDTC supportedDTC = supportedDTCs.get(row);
            boolean enabled;
            try {
                enabled = supportedDTC.isEnabled();
            } catch (Exception ex) {
                Errors.show(getParent(), "Change DTC Failed", "Failed to read DTC status!", ex);
                tableComponent.getCellEditor().stopCellEditing();
                return;
            }

            if (enabled != selected) {
                try {
                    supportedDTC.setEnabled(selected);
                } catch (Exception ex) {
                    tableComponent.setValueAt(enabled, row, column);
                    Errors.show(getParent(), "Change DTC Failed", "Failed to change DTC status!", ex);
                    tableComponent.getCellEditor().stopCellEditing();
                }
            }
        });
        return checkBox;
    }

    private Object[] generateColumns() {
        return new Object[] {"Code", "Description", "Passed", "Enabled"};
    }

    private TableModel generateTableModel() {
        int x_size = 4;
        int y_size = supportedDTCs.size();
        Object[][] data = new Object[y_size][x_size];

        for (int i = 0; i < supportedDTCs.size(); i ++) {
            SupportedDTC supportedDTC = supportedDTCs.get(i);
            Boolean enabled;

            try {
                enabled = supportedDTC.isEnabled();
            } catch (Exception ex) {
                Log.ui().log(Level.SEVERE, "Problem loading DTC enabled state for "
                        + supportedDTC.getDTC().getName(), ex);
                enabled = null;
            }

            DTC dtc = supportedDTC.getDTC();
            data[i][0] = dtc.getName();
            data[i][1] = dtc.getFriendlyName();
            data[i][2] = "";
            data[i][3] = enabled;
        }

        return new DefaultTableModel(data, generateColumns());
    }

    @Override
    protected void initComponent(JInternalFrame frame) {
        tableComponent = new JTable() {
            @Override
            public boolean isCellEditable(int row, int col)
            {
                SupportedDTC supportedDTC = supportedDTCs.get(row);
                return col == 3 && !supportedDTC.getDTC().isEmissionsRelated();
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return getValueAt(0, columnIndex).getClass();
            }
        };

        tableComponent.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                ColumnsAutoSizer.sizeColumnsToFit(tableComponent);
            }
        });

        tableComponent.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        tableComponent.setBorder(BorderFactory.createEmptyBorder());
        tableComponent.getTableHeader().setReorderingAllowed(false);
        tableComponent.getTableHeader().setResizingAllowed(true);
        tableComponent.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tableComponent.setRowSelectionAllowed(true);

        tableComponent.setDefaultRenderer(Object.class, new DTCEditor.TableCellRenderer());
        tableComponent.setDefaultRenderer(String.class, new DTCEditor.TableCellRenderer());

        tableComponent.setModel(generateTableModel());

        TableColumn codeColumn = tableComponent.getColumnModel().getColumn(0);
        TableColumn passedColumn = tableComponent.getColumnModel().getColumn(2);
        TableColumn enabledColumn = tableComponent.getColumnModel().getColumn(3);

        codeColumn.setMaxWidth(128);
        codeColumn.setPreferredWidth(128);

        passedColumn.setMaxWidth(64);
        passedColumn.setPreferredWidth(64);

        enabledColumn.setMaxWidth(64);
        enabledColumn.setPreferredWidth(64);

        enabledColumn.setCellEditor(new DefaultCellEditor(createCheckbox()) {
            @Override
            public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
                boolean selected = isSelected || table.isRowSelected(row);

                Component c = super.getTableCellEditorComponent(table, value, selected, row, column);

                c.setBackground(table.getSelectionBackground());
                c.setForeground(table.getSelectionForeground());

                SupportedDTC supportedDTC = supportedDTCs.get(row);
                c.setEnabled(!supportedDTC.getDTC().isEmissionsRelated());

                return c;
            }
        });

        JScrollPane scrollPane = new JScrollPane(tableComponent);
        Layout.emptyBorder(scrollPane);

        frame.add(scrollPane);
    }

    @Override
    protected void postInitComponent(JInternalFrame component) {
        super.postInitComponent(component);

        ColumnsAutoSizer.sizeColumnsToFit(tableComponent);
    }

    @Override
    public void reload() {

    }

    public Calibration getCalibration() {
        return calibration;
    }

    private class TableCellRenderer extends DefaultTableCellRenderer {
        public TableCellRenderer() {
            setVerticalAlignment(JLabel.CENTER);
            setHorizontalAlignment(JLabel.CENTER);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int col) {
            SupportedDTC supportedDTC = supportedDTCs.get(row);
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);

            c.setEnabled(!supportedDTC.getDTC().isEmissionsRelated());

            if (c instanceof JLabel label) {
                label.setIcon(null);
            }

            if (col == 2) {
                if (c instanceof JLabel label) {
                    label.setIcon(Icons.get(CarbonIcons.UNKNOWN_FILLED, Color.YELLOW));
                    label.setEnabled(true);
                }

                if (c instanceof JComponent jComponent) {
                    jComponent.setAlignmentX(0.5f);
                }

                if (c instanceof JLabel label) {
                    label.setHorizontalAlignment(JLabel.CENTER);
                }
            } else if (col == 0 || col == 1) {
                if (c instanceof JComponent jComponent) {
                    jComponent.setAlignmentX(0);
                }

                if (c instanceof JLabel label) {
                    label.setHorizontalAlignment(JLabel.LEFT);
                }
            }

            return c;
        }
    }
}
