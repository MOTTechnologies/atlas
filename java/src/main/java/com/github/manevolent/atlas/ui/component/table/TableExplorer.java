package com.github.manevolent.atlas.ui.component.table;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Series;
import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.ZeroDividerSplitPane;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.util.Errors;
import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Inputs;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;

import javax.swing.event.InternalFrameAdapter;
import javax.swing.event.InternalFrameEvent;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;
import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;

public class TableExplorer extends Window implements ListSelectionListener {
    private final Calibration calibration;
    private final List<Table> tables = new ArrayList<>();
    private final List<Table> approvedTables = new ArrayList<>();
    private final List<Table> rejectedTables = new ArrayList<>();

    private final Consumer<Table> apply;

    private JPanel rootPanel;
    private JPanel contentPanel;
    private JTable listComponent;
    private JButton accept;

    private int selectedIndex = -1;

    public TableExplorer(Editor editor, Calibration calibration, Collection<Table> tables, Consumer<Table> apply) {
        super(editor);

        tables = tables.stream().sorted(Comparator.comparing(Table::getName)).toList();

        this.calibration = calibration;
        this.tables.addAll(tables);

        this.apply = apply;
    }

    private Object[] getColumns() {
        return new String[] { "Name", "X", "Y", "Status" };
    }

    private TableModel generateTableModel() throws IOException {
        Object[] columns = getColumns();
        Object[][] data = new String[tables.size()][columns.length];

        for (int i = 0; i < tables.size(); i ++) {
            Table table = tables.get(i);
            data[i][0] = table.getName();

            Series x = table.getSeries(X);
            if (x != null) {
                data[i][1] = x.getLength() + " (" + x.getAddress().toString(calibration.getVariant()) + ")";
            }

            Series y = table.getSeries(Y);
            if (y != null) {
                data[i][2] = y.getLength() + " (" + y.getAddress().toString(calibration.getVariant())  + ")";
            }
        }

        return new DefaultTableModel(data, columns);
    }

    @Override
    protected void preInitComponent(JInternalFrame component) {
        super.preInitComponent(component);

        component.setDefaultCloseOperation(JInternalFrame.DO_NOTHING_ON_CLOSE);
        component.addInternalFrameListener(new InternalFrameAdapter() {
            @Override
            public void internalFrameClosing(InternalFrameEvent e) {
                cancel();
            }
        });
    }

    private void apply() {
        if (JOptionPane.showConfirmDialog(getComponent(),
                "Apply " + approvedTables.size() + " approved table(s)?",
                "Apply",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.INFORMATION_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        getEditor().withWaitCursor(() -> {
            for (Table table : approvedTables) {
                try {
                    apply.accept(table);
                } catch (Exception ex) {
                    Errors.show(getParent(), "Apply failed", "Failed to apply " + table.getName() + "!", ex);
                    return;
                }
            }

            dispose();
        });
    }

    private void cancel() {
        if (JOptionPane.showConfirmDialog(getComponent(),
                "Are you sure you want to exit " + getTitle() + "? You will lose any un-applied changes.",
                "Cancel",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        dispose();
    }

    @Override
    protected void initComponent(JInternalFrame frame) {
        listComponent = new JTable() {
            @Override
            public boolean isCellEditable(int row, int cols)
            {
                return false;
            }
        };

        listComponent.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        listComponent.setBorder(BorderFactory.createEmptyBorder());
        listComponent.getTableHeader().setReorderingAllowed(false);
        listComponent.getTableHeader().setResizingAllowed(false);
        listComponent.setColumnSelectionAllowed(false);
        listComponent.setRowSelectionAllowed(true);
        listComponent.setDefaultRenderer(Object.class, new Renderer());
        listComponent.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        listComponent.getSelectionModel().addListSelectionListener(this);

        //listComponent.setComponentPopupMenu(new TableEditorPopupMenu(this).getComponent());

        try {
            listComponent.setModel(generateTableModel());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        JScrollPane scrollPaneLeft = new JScrollPane(listComponent,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPaneLeft.setBorder(BorderFactory.createEmptyBorder());

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(scrollPaneLeft, BorderLayout.CENTER);

        JPanel finishPanel = new JPanel(new BorderLayout());
        finishPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY.darker()),
                BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));
        JPanel finishButtonRow = new JPanel();
        finishButtonRow.setLayout(new BoxLayout(finishButtonRow, BoxLayout.X_AXIS));
        finishButtonRow.add(Inputs.button("Cancel", this::cancel));
        accept = Inputs.button("Apply", this::apply);
        accept.setEnabled(false);
        frame.getRootPane().setDefaultButton(accept);
        finishButtonRow.add(accept);
        finishPanel.add(finishButtonRow, BorderLayout.EAST);
        leftPanel.add(finishPanel, BorderLayout.SOUTH);

        contentPanel = new JPanel(new BorderLayout());

        JSplitPane splitPane = new ZeroDividerSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                leftPanel, contentPanel);

        if (rootPanel == null) {
            rootPanel = new JPanel(new BorderLayout());
        } else {
            rootPanel.removeAll();
        }

        rootPanel.add(splitPane, BorderLayout.CENTER);

        frame.add(rootPanel);
    }

    @Override
    protected void postInitComponent(JInternalFrame component) {
        super.postInitComponent(component);

        setSelectedIndex(0);
    }

    @Override
    public String getTitle() {
        return "Table Explorer - " + tables.size() + " Tables (" + calibration.getName() + ")";
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.SEARCH, getTextColor());
    }

    @Override
    public void reload() {
        // Do nothing
    }

    @Override
    public void valueChanged(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) {
            return;
        }

        setSelectedIndex(listComponent.getSelectedRow());
    }

    private void setTable(Table table) {
        TableDefinitionEditor definitionEditor;
        try {
            definitionEditor = new TableDefinitionEditor(getEditor(), table, calibration.getVariant(), true);
        } catch (Exception ex) {
            Errors.show(getParent(), "Open Table Failed", "Failed to open table!", ex);
            return;
        }

        contentPanel.removeAll();
        contentPanel.add(definitionEditor.getComponent().getContentPane(), BorderLayout.CENTER);

        JPanel reviewPanel = new JPanel(new BorderLayout());
        reviewPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY.darker()),
                BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));
        JPanel reviewButtonRow = new JPanel();
        reviewButtonRow.setLayout(new BoxLayout(reviewButtonRow, BoxLayout.X_AXIS));

        AtomicReference<JButton> approve = new AtomicReference<>();
        AtomicReference<JButton> reject = new AtomicReference<>();

        approve.set(Inputs.button(CarbonIcons.CHECKMARK, "Approve", () -> {
            if (!approvedTables.contains(table)) {
                rejectedTables.remove(table);
                approvedTables.add(table);
                approve.get().setEnabled(false);
                reject.get().setEnabled(true);
                accept.setEnabled(!approvedTables.isEmpty());
                next();
                listComponent.revalidate();
                listComponent.repaint();
            }
        }));

        reject.set(Inputs.button(CarbonIcons.CLOSE, "Reject", () -> {
            if (!rejectedTables.contains(table)) {
                approvedTables.remove(table);
                rejectedTables.add(table);
                approve.get().setEnabled(true);
                reject.get().setEnabled(false);
                accept.setEnabled(!approvedTables.isEmpty());
                next();
                listComponent.revalidate();
                listComponent.repaint();
            }
        }));

        if (approvedTables.contains(table)) {
            approve.get().setEnabled(false);
        }

        if (rejectedTables.contains(table)) {
            reject.get().setEnabled(false);
        }

        reviewButtonRow.add(approve.get());
        reviewButtonRow.add(reject.get());
        reviewPanel.add(reviewButtonRow, BorderLayout.EAST);

        contentPanel.add(reviewPanel, BorderLayout.SOUTH);
    }

    private void next() {
        int nextIndex = listComponent.getSelectedRow() + 1;

        if (listComponent.getRowCount() <= nextIndex) {
            return;
        }

        setSelectedIndex(nextIndex);
    }

    private void setSelectedIndex(int index) {
        if (this.selectedIndex != index) {
            this.selectedIndex = index;

            if (listComponent.getSelectedRow() != index) {
                listComponent.setRowSelectionInterval(index, index);
                listComponent.scrollRectToVisible(listComponent.getCellRect(index, 0, true));
            }

            getEditor().withWaitCursor(() -> {
                Table table = tables.get(this.selectedIndex);
                SwingUtilities.invokeLater(() -> setTable(table));
            });
        }
    }

    private class Renderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable tableComponent, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int col) {
            Component c = super.getTableCellRendererComponent(tableComponent, value, isSelected, hasFocus,
                    row, col);

            Table table = tables.get(row);

            if (c instanceof JLabel label) {
                if (approvedTables.contains(table)) {
                    c.setForeground(Color.GREEN);

                    if (col == 3) {
                        label.setIcon(Icons.get(CarbonIcons.CHECKMARK, Color.GREEN));
                        label.setText("Approved");
                    }
                } else if (rejectedTables.contains(table)) {
                    c.setForeground(Color.RED);

                    if (col == 3) {
                        label.setIcon(Icons.get(CarbonIcons.CLOSE, Color.RED));
                        label.setText("Rejected");
                    }
                } else {
                    c.setForeground(Fonts.getTextColor());

                    if (col == 3) {
                        label.setIcon(null);
                        label.setText("");
                    }
                }

                if (col != 3) {
                    label.setIcon(null);
                }
            }

            return c;
        }
    }
}
