package com.github.manevolent.atlas.ui.component.table;

import com.github.manevolent.atlas.checked.CheckedBiFunction;
import com.github.manevolent.atlas.checked.CheckedRunnable;
import com.github.manevolent.atlas.connection.MemoryFrame;
import com.github.manevolent.atlas.math.InterpolationType;
import com.github.manevolent.atlas.math.TableInterpolation;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.ZeroDividerSplitPane;
import com.github.manevolent.atlas.ui.behavior.*;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.popupmenu.table.TableEditorPopupMenu;
import com.github.manevolent.atlas.ui.dialog.VariableInputDialog;
import com.github.manevolent.atlas.ui.util.*;
import com.github.manevolent.atlas.ui.component.JRotateLabel;
import com.github.manevolent.atlas.ui.component.RowNumberTable;
import com.github.manevolent.atlas.ui.component.footer.TableEditorFooter;
import com.github.manevolent.atlas.ui.component.menu.table.*;
import com.github.manevolent.atlas.ui.component.toolbar.TableEditorToolbar;
import com.github.manevolent.atlas.ui.Editor;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.*;

import java.awt.*;
import java.awt.Color;
import java.awt.event.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.stream.IntStream;

import static com.github.manevolent.atlas.model.Axis.X;
import static com.github.manevolent.atlas.model.Axis.Y;
import static com.github.manevolent.atlas.ui.util.Fonts.bold;
import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;
import static java.awt.event.KeyEvent.*;

public class TableEditor extends Window implements
        FocusListener, TableModelListener, ListSelectionListener,
        MemoryFrameListener, CalibrationListener, ModelChangeListener, LiveWindow {

    private static final Set<Integer> navigationKeys = Set.of(
            VK_LEFT, VK_KP_LEFT,
            VK_RIGHT, VK_KP_RIGHT,
            VK_UP, VK_KP_UP,
            VK_DOWN, VK_KP_DOWN
    );

    private final Table table;
    private static final int crossHairSize = 4;

    private ThreadLocal<Boolean> selfUpdate = new ThreadLocal<>();
    private RowNumberTable rowNumberTable;
    private JPanel rootPanel;
    private JPanel tablePanel;
    private JTable tableComponent;
    private TableEditorFooter footer;
    private JLabel x_label;
    private JRotateLabel y_label;
    private JScrollPane scrollPane;
    private JSplitPane splitPane;
    private JSplitPane visualizationSplitPane;
    private int[] lastSelectionRows = new int[0], lastSelectionColumns = new int[0];
    private MemoryFrame lastFrame;

    private float min, selMin, max, selMax;

    private FileMenu fileMenu;
    private EditMenu editMenu;
    private ToolsMenu toolsMenu;
    private HelpMenu helpMenu;

    private TableStackedVisualizer stackedVisualizer;
    private Table3DVisualizer threeDVisualizer;
    private TableEditorToolbar toolbar;
    private Calibration calibration;

    private boolean needsCrosshairUpdate = true;

    private final boolean nested;

    private Animation glowAnimation;
    private List<Point> glowingDataIndices = new CopyOnWriteArrayList<>();
    private float glowAmount = 0f;

    private List<Rectangle> selectionRectangles = new ArrayList<>();

    public TableEditor(Editor editor, Table table, Calibration calibration, boolean nested) {
        super(editor);

        this.calibration = calibration;
        this.nested = nested;
        this.selfUpdate.set(false);
        this.table = table;
    }

    public TableEditor(Editor editor, Table table, boolean nested) {
        this(editor, table, editor.getCalibration(), nested);
    }

    public TableEditor(Editor editor, Table table) {
        this(editor, table, false);
    }

    @Override
    public String getTitle() {
        return table.getName() + " (" + calibration.getName() + ")";
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.DATA_TABLE, getTextColor());
    }

    public Calibration getCalibration() {
        return calibration;
    }

    public boolean setCalibration(Calibration calibration) {
        if (this.calibration != calibration) {
            if (!table.isVariantSupported(calibration)) {
                Errors.show(getEditor(), "Open failed",
                        "Failed to change table \"" + table.getName() + "\"!\r\nThis table does not support the " +
                                calibration.getName() + " calibration's variant ("
                                + calibration.getVariant().getName() + ").");
                return false;
            }

            this.calibration = calibration;

            updateTitle();
            updateData();
            updateMinMax();
            updateSelection();
            updateRowHeaders();
            updateColumns();

            return true;
        } else {
            return false;
        }
    }

    @Override
    protected void preInitComponent(JInternalFrame frame) {
        super.preInitComponent(frame);

        frame.addInternalFrameListener(new InternalFrameAdapter() {
            @Override
            public void internalFrameActivated(InternalFrameEvent e) {
                if (Settings.AUTO_SELECT_ITEM.get()) {
                    getEditor().getProjectTreeTab().onItemOpened(getTable());
                }
            }
        });

        getHistory().addListener(new HistoryListener<>() {
            @Override
            public void onUndoStarted(Edit action) {
                if (glowAnimation != null) {
                    glowAnimation.cancel();
                    glowAnimation = null;
                }
            }

            @Override
            public void onRedoStarted(Edit action) {
                if (glowAnimation != null) {
                    glowAnimation.cancel();
                    glowAnimation = null;
                }
            }
        });
    }

    @Override
    protected void initComponent(JInternalFrame window) {
        window.addFocusListener(this);

        tableComponent = new JTable() {
            @Override
            public boolean isCellEditable(int row, int cols)
            {
                return !nested;
            }

            @Override
            public void paint(Graphics g) {
                super.paint(g);

                try {
                    paintTableOverlay(g);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void editingStopped(ChangeEvent e) {
                TableEditor.this.editingStopped(e);
            }
        };

        tableComponent.setBackground(Color.GRAY.darker().darker());
        tableComponent.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        tableComponent.setBorder(BorderFactory.createEmptyBorder());
        tableComponent.getTableHeader().setReorderingAllowed(false);
        tableComponent.getTableHeader().setResizingAllowed(false);
        tableComponent.setColumnSelectionAllowed(true);
        tableComponent.setRowSelectionAllowed(true);
        tableComponent.getTableHeader().setFont(getValueFont());
        tableComponent.setComponentPopupMenu(new TableEditorPopupMenu(this).getComponent());

        // Possibly add X series headers
        tableComponent.setModel(generateTableModel());

        updateData();
        updateMinMax();

        // Set the renderer for cells
        tableComponent.setDefaultRenderer(Object.class, new TableCellRenderer());
        tableComponent.setDefaultRenderer(String.class, new TableCellRenderer());
        tableComponent.setDefaultRenderer(Float.class, new TableCellRenderer());

        // Set a default editor, so we can control cell edit functions
        tableComponent.setDefaultEditor(Object.class, new TableCellEditor());
        tableComponent.setDefaultEditor(String.class, new TableCellEditor());
        tableComponent.setDefaultEditor(Float.class, new TableCellEditor());

        tableComponent.addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseDragged(MouseEvent e) {
                updateSelection();
            }
        });

        tableComponent.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                updateSelection();
            }
        });

        tableComponent.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                updateSelectionRectangles();
            }
        });

        Inputs.bind(tableComponent, "selectAll", () -> SwingUtilities.invokeLater(this::selectAll),
                KeyStroke.getKeyStroke(VK_A, KeyEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(VK_A, KeyEvent.META_DOWN_MASK));

        Inputs.bind(tableComponent, "scale", () -> SwingUtilities.invokeLater(this::scaleSelection),
                KeyStroke.getKeyStroke('s'),
                KeyStroke.getKeyStroke('%'));

        Inputs.bind(tableComponent, "add", () -> SwingUtilities.invokeLater(this::addSelection),
                KeyStroke.getKeyStroke('+'));

        Inputs.bind(tableComponent, "multiply", () -> SwingUtilities.invokeLater(this::multiplySelection),
                KeyStroke.getKeyStroke('*'));

        Inputs.bind(tableComponent, "divide", () -> SwingUtilities.invokeLater(this::divideSelection),
                KeyStroke.getKeyStroke('/'));

        Inputs.bind(tableComponent, "interpolate", () -> SwingUtilities.invokeLater(this::interpolateSelection),
                KeyStroke.getKeyStroke('i'));

        Inputs.bind(tableComponent, "average", () -> SwingUtilities.invokeLater(this::averageSelection),
                KeyStroke.getKeyStroke('v'));

        tableComponent.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (navigationKeys.contains(e.getKeyCode())) {
                    SwingUtilities.invokeLater(() -> updateSelection());
                }
            }

            @Override
            public void keyTyped(KeyEvent e) {
                updateSelection();
            }

            @Override
            public void keyReleased(KeyEvent e) {
                updateSelection();
            }
        });

        if (!nested) {
            JPanel north = new JPanel();
            north.setLayout(new GridLayout(2, 1));

            north.add(initMenuBar());
            north.add(initToolbar());

            window.add(north, BorderLayout.NORTH);
        }

        scrollPane = new JScrollPane(tableComponent);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        updateRowHeaders();

        rootPanel = new JPanel(new BorderLayout());
        tablePanel = new JPanel(new BorderLayout());
        updateAxisNames();

        tablePanel.add(scrollPane, BorderLayout.CENTER);

        if (isNested()) {
            rootPanel.add(tablePanel, BorderLayout.CENTER);
        } else {
            boolean show3D = Settings.get(Settings.TABLE_EDITOR_3D_VIEW);
            boolean showStacked = Settings.get(Settings.TABLE_EDITOR_STACKED_VIEW);

            JComponent panel;

            if (showStacked && show3D) {
                visualizationSplitPane = new ZeroDividerSplitPane(JSplitPane.VERTICAL_SPLIT,
                        init3DVisualizer(), initStackedVisualizer());
                visualizationSplitPane.setResizeWeight(0.5f);

                splitPane = new ZeroDividerSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, visualizationSplitPane);
                panel = splitPane;
            } else if (showStacked) {
                splitPane = new ZeroDividerSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, initStackedVisualizer());
                panel = splitPane;
            } else if (show3D) {
                splitPane = new ZeroDividerSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, init3DVisualizer());
                panel = splitPane;
            } else {
                panel = tablePanel;
            }

            if (splitPane != null) {
                splitPane.setResizeWeight(1f);
            }

            rootPanel.add(panel, BorderLayout.CENTER);
        }

        // Create the footer bar that displays some state data as well as
        // some quick calculations about the table and/or its selection.
        footer = new TableEditorFooter(this);
        rootPanel.add(footer.getComponent(), BorderLayout.SOUTH);

        window.add(rootPanel);

        tableComponent.getModel().addTableModelListener(this);
        tableComponent.setColumnSelectionInterval(0, 0);
        tableComponent.setRowSelectionInterval(0, 0);
        tableComponent.getSelectionModel().addListSelectionListener(this);
        tableComponent.putClientProperty("terminateEditOnFocusLost", true);

        if (nested) {
            tableComponent.setEnabled(false);
        } else {
            tableComponent.setEnabled(true);
        }

        updateCellWidth();
    }

    private void selectAll() {
        tableComponent.selectAll();
        updateSelection();
    }

    private void paintUpdatedCells(Graphics g) {
        if (glowAmount <= 0) {
            return;
        }

        Graphics2D g2d = (Graphics2D) g;

        g2d.setColor(Colors.withAlpha(Color.YELLOW.darker(), (int) (200 * glowAmount)));

        for (Point glowingCell : glowingDataIndices) {
            g2d.fill(tableComponent.getCellRect(glowingCell.y, glowingCell.x, true));
        }
    }

    private void paintCrosshair(Graphics g) throws IOException {
        needsCrosshairUpdate = false;

        Float x_value, y_value;
        MemoryFrame frame = lastFrame;

        if (frame == null) {
            return;
        }

        if (!getParent().getConnectionManager().isConnected()) {
            return;
        }

        Series x = table.getSeries(X);
        Series y = table.getSeries(Y);

        if (x != null && x.getParameter() != null) {
            x_value = frame.getValue(x.getParameter());
        } else {
            x_value = null;
        }

        if (y != null && y.getParameter() != null) {
            y_value = frame.getValue(y.getParameter());
        } else {
            y_value = null;
        }

        g.setColor(Colors.withAlpha(Color.WHITE, 64));

        if (x_value != null) {
            float partialIndex = x.getIndex(getCalibration(), x_value);
            Rectangle lowRectangle = tableComponent.getCellRect(0, (int) Math.floor(partialIndex), true);
            Rectangle highRectangle = tableComponent.getCellRect(0, (int) Math.ceil(partialIndex), true);
            double low_x = lowRectangle.getCenterX();
            double high_x = highRectangle.getCenterX();
            double remainder = partialIndex % 1.0f;
            double draw_x = low_x + ((high_x - low_x) * remainder);
            g.fillRect((int) (float) draw_x - (crossHairSize / 2), 0, crossHairSize, tableComponent.getHeight());
        }

        if (y_value != null) {
            float partialIndex = y.getIndex(getCalibration(), y_value);
            Rectangle lowRectangle = tableComponent.getCellRect((int) Math.floor(partialIndex), 0, true);
            Rectangle highRectangle = tableComponent.getCellRect((int) Math.ceil(partialIndex), 0, true);
            double low_y = lowRectangle.getCenterY();
            double high_y = highRectangle.getCenterY();
            double remainder = partialIndex % 1.0f;
            double draw_y = low_y + ((high_y - low_y) * remainder);
            g.fillRect(0, (int) (float) draw_y - (crossHairSize / 2), tableComponent.getWidth(), crossHairSize);
        }
    }

    private void updateSelectionRectangles() {
        List<AxisGroup> colGroups = AxisGroup.getGroups(tableComponent.getSelectedColumns());
        List<AxisGroup> rowGroups = AxisGroup.getGroups(tableComponent.getSelectedRows());

        selectionRectangles.clear();
        for (AxisGroup colGroup : colGroups) {
            for (AxisGroup rowGroup : rowGroups) {
                Rectangle upperLeft = tableComponent.getCellRect(rowGroup.getLow(), colGroup.getLow(), true);
                Rectangle lowerRight = tableComponent.getCellRect(rowGroup.getHigh(), colGroup.getHigh(), true);

                selectionRectangles.add(new Rectangle(
                        upperLeft.x, upperLeft.y,
                        (lowerRight.x + lowerRight.width) - upperLeft.x,
                        (lowerRight.y + lowerRight.height) - upperLeft.y
                ));
            }
        }

        SwingUtilities.invokeLater(() -> tableComponent.repaint());
    }

    private void paintSelection(Graphics g) {
        g.setColor(Colors.withAlpha(new Color(0x3080dd), 230));

        if (g instanceof Graphics2D g2d) {
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2d.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
            g2d.setStroke(new BasicStroke(2.25f, BasicStroke.CAP_SQUARE, BasicStroke.JOIN_MITER));
        }

        for (Rectangle selectionRectangle : selectionRectangles) {
            g.drawRoundRect(
                    selectionRectangle.x, selectionRectangle.y,
                    selectionRectangle.width - 2, selectionRectangle.height - 2,
                    8, 8);
        }
    }

    private void paintTableOverlay(Graphics g) throws IOException {
        paintUpdatedCells(g);
        paintSelection(g);
        paintCrosshair(g);
    }

    @Override
    protected void opened() {
        if (splitPane != null) {
            splitPane.setDividerLocation(0.80f);
        }

        if (visualizationSplitPane != null) {
            visualizationSplitPane.setDividerLocation(0.5D);
        }
    }

    @Override
    protected void postInitComponent(JInternalFrame frame) {
        super.postInitComponent(frame);

        tableComponent.clearSelection();
    }

    public void averageSelection() {
        int[] selectedRows = tableComponent.getSelectedRows();
        int[] selectedColumns = tableComponent.getSelectedColumns();
        float sum = 0;
        for (int selectedRow : selectedRows) {
            for (int selectedColumn : selectedColumns) {
                try {
                    sum += table.getCell(getCalibration(), selectedColumn, selectedRow);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        float avg = sum / (selectedRows.length * selectedColumns.length);
        processSelection(x -> avg);

        updateCellWidth();
        updateMinMax();
        updateSelectionMinMax();
        footer.reinitialize();
    }

    public void interpolateSelection() {
        if (getCalibration().isReadonly()) {
            Errors.show(getEditor(), "Edit Failed",
                    "Calibration \"" + getCalibration().getName() + "\" is read-only.");
            return;
        }

        int[] selectedRows = tableComponent.getSelectedRows();
        int[] selectedColumns = tableComponent.getSelectedColumns();
        try {
            remember(() -> TableInterpolation.interpolate(
                    Settings.TABLE_EDITOR_INTERP_TYPE.getAsEnum(InterpolationType.class),
                    table, getCalibration(), selectedRows, selectedColumns));
        } finally {
            updateRowHeaders();
            updateMinMax();
            updateData();
            updateVisualizations();
            footer.reinitialize();
        }
    }

    public void addSelection() {
        Double answer = VariableInputDialog.show(getParent(), "Add",
                "Enter value to add to cells", 0D);
        if (answer == null) {
            return;
        }
        float coefficient = answer.floatValue();
        processSelection((value) -> value + coefficient);
    }

    public void subtractSelection() {
        Double answer = VariableInputDialog.show(getParent(), "Subtract",
                "Enter value to subtract from cells", 0D);
        if (answer == null) {
            return;
        }
        float coefficient = answer.floatValue();
        processSelection((value) -> value - coefficient);
    }

    public void scaleSelection() {
        Double answer = VariableInputDialog.show(getParent(), "Scale",
                "Enter percentage to scale cells by", 100D);
        if (answer == null) {
            return;
        }
        float coefficient = answer.floatValue() / 100f;
        processSelection((value) -> value * coefficient);
    }

    public void multiplySelection() {
        Double answer = VariableInputDialog.show(getParent(), "Multiply",
                "Enter value to multiply cells by", 1D);
        if (answer == null) {
            return;
        }
        float coefficient = answer.floatValue();
        processSelection((value) -> value * coefficient);
    }

    public void divideSelection() {
        Double answer = VariableInputDialog.show(getParent(), "Divide",
                "Enter value to divide cells by", 1D);
        if (answer == null) {
            return;
        }
        float coefficient = answer.floatValue();
        processSelection((value) -> value / coefficient);
    }

    public void processSelection(float constant) {
        processSelection((x, y) -> constant);
    }

    public void processSelection(Function<Float, Float> function) {
        processSelection((x, y) -> {
            float data;
            try {
                data = function.apply(table.getCell(getCalibration(), x, y));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            return data;
        });
    }

    public void processSelection(CheckedBiFunction<Integer, Integer, Float, IOException> function) {
        if (getCalibration().isReadonly()) {
            Errors.show(getEditor(), "Edit Failed",
                    "Calibration \"" + getCalibration().getName() + "\" is read-only.");
            return;
        }

        remember(() -> {
            if (tableComponent.getSelectedColumns().length == 0 && tableComponent.getSelectedRows().length == 0) {
                tableComponent.grabFocus();
                tableComponent.selectAll();
            }

            int[] selectedRows = tableComponent.getSelectedRows();
            int[] selectedColumns = tableComponent.getSelectedColumns();

            for (int selectedRow : selectedRows) {
                for (int selectedColumn : selectedColumns) {
                    float processed = function.apply(selectedColumn, selectedRow);
                    tableComponent.getModel().setValueAt(processed, selectedRow, selectedColumn);
                }
            }

            updateCellWidth();
            updateMinMax();
            updateSelectionMinMax();
            footer.reinitialize();
        });
    }

    protected void remember(CheckedRunnable<Exception> action) {
        float[] before, after;
        int[] selectedRowsBefore, selectedColumnsBefore, selectedRowsAfter, selectedColumnsAfter;

        try {
            before = table.getData().getAll(calibration);
            selectedRowsBefore = tableComponent.getSelectedRows();
            selectedColumnsBefore = tableComponent.getSelectedColumns();

            getEditor().withWaitCursorChecked(action);

            after = table.getData().getAll(calibration);
            selectedRowsAfter = tableComponent.getSelectedRows();
            selectedColumnsAfter = tableComponent.getSelectedColumns();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

        // If nothing changed in the table, don't remember this action
        if (Arrays.equals(before, after)) {
            return;
        }

        Edit edit = new Edit() {
            @Override
            public boolean undo() {
                try {
                    table.getData().setAll(calibration, before);

                    tableComponent.clearSelection();
                    for (int row : selectedRowsAfter) {
                        tableComponent.addRowSelectionInterval(row, row);
                    }
                    for (int col : selectedColumnsAfter) {
                        tableComponent.addColumnSelectionInterval(col, col);
                    }

                    updateSelection();
                    updateRowHeaders();
                    updateMinMax();
                    updateData();
                    updateVisualizations();
                    footer.reinitialize();

                    return true;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public boolean redo() {
                try {
                    table.getData().setAll(calibration, after);

                    tableComponent.clearSelection();
                    for (int row : selectedRowsAfter) {
                        tableComponent.addRowSelectionInterval(row, row);
                    }
                    for (int col : selectedColumnsAfter) {
                        tableComponent.addColumnSelectionInterval(col, col);
                    }

                    updateSelection();
                    updateRowHeaders();
                    updateMinMax();
                    updateData();
                    updateVisualizations();
                    footer.reinitialize();

                    return true;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };

        getHistory().remember(edit);
    }

    private Object[] generateColumns() {
        Object[] columns;

        Series x = table.getSeries(X);
        if (x != null) {
            columns = new Object[x.getLength()];
            for (int i = 0; i < x.getLength(); i ++) {
                try {
                    columns[i] = x.formatPreferred(getCalibration(), i);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        } else {
            columns = new Object[1];
        }

        return columns;
    }

    private TableModel generateTableModel() {
        int x_size = table.getSeries(X) == null ? 1 : table.getSeries(X).getLength();
        int y_size = table.getSeries(Y) == null ? 1 : table.getSeries(Y).getLength();
        Object[][] data = new Float[y_size][x_size];
        return new DefaultTableModel(data, generateColumns());
    }

    private JToolBar initToolbar() {
        return (toolbar = new TableEditorToolbar(this)).getComponent();
    }

    private JPanel init3DVisualizer() {
        return (threeDVisualizer = new Table3DVisualizer(this)).getComponent();
    }

    private JPanel initStackedVisualizer() {
        return (stackedVisualizer = new TableStackedVisualizer(this)).getComponent();
    }

    private JMenuBar initMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        menuBar.add((fileMenu = new FileMenu(this)).getComponent());
        menuBar.add((editMenu = new EditMenu(this)).getComponent());
        menuBar.add((toolsMenu = new ToolsMenu(this)).getComponent());
        menuBar.add((helpMenu = new HelpMenu(this)).getComponent());
        return menuBar;
    }

    private void updateVisualizations() {
        if (threeDVisualizer != null) {
            threeDVisualizer.dataChanged();
        }
        if (stackedVisualizer != null) {
            stackedVisualizer.dataChanged();
        }
    }

    private void updateCellWidth() {
        // Default to a minimum spacing of 6 characters
        int longestString = 0;

        FontMetrics metrics = Fonts.getFontMetrics(getValueFont());

        // Find the longest string in the columns (X axis)
        Series x = table.getSeries(X);
        if (x != null) {
            for (int i = 0; i < x.getLength(); i ++) {
                float data;
                try {
                    data = x.get(getCalibration(), i);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                String formattedString = x.getScale().formatPreferred(data);
                int width = metrics.stringWidth(formattedString);
                longestString = Math.max(longestString, width);
            }
        }

        // Find the longest string in the cells (table data)
        for (int i = 0; i < table.getData().getLength(); i ++) {
            float data;
            try {
                data = getValue(i);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            String formattedString = formatValue(data, table.getData().getUnit());
            int width = metrics.stringWidth(formattedString);
            longestString = Math.max(longestString, width);
        }

        // Get the ideal string width
        int stringWidth = longestString + metrics.stringWidth("  ");

        // Grab the margin
        int margin = tableComponent.getColumnModel().getColumnMargin() * 2;

        // Grab the cell components we'll generate and check the border insets
        Component cellComponent = tableComponent.getCellRenderer(0, 0)
                .getTableCellRendererComponent(tableComponent, 0.00f, false, true, 0, 0);
        if (cellComponent instanceof JComponent) {
            Border border = ((JComponent) cellComponent).getBorder();
            Insets insets = border.getBorderInsets(cellComponent);
            margin += insets.left + insets.right;
        }

        // Some extra spacing for comfort
        margin += 5;

        // Set all the calculated spacing across the table's columns
        int spacing = stringWidth + margin;
        for (int i = 0; i < tableComponent.getColumnModel().getColumnCount(); i ++) {
            var column = tableComponent.getColumnModel().getColumn(i);
            column.setMinWidth(spacing);
            column.setPreferredWidth(spacing);
            column.setWidth(spacing);
        }
    }

    private void updateColumns() {
        JTableHeader th = tableComponent.getTableHeader();
        TableColumnModel tcm = th.getColumnModel();

        Object[] columns = generateColumns();
        for (int i = 0; i < columns.length; i ++) {
            TableColumn tc = tcm.getColumn(i);
            tc.setHeaderValue(columns[i]);
        }
        th.repaint();
    }

    private void updateRowHeaders() {
        if (table.hasAxis(Y)) {
            if (rowNumberTable == null) {
                java.util.List<String> rowHeaders = generateRowHeaders();
                rowNumberTable = new RowNumberTable(tableComponent, rowHeaders);
                rowNumberTable.getTableHeader().setFont(getValueFont());
                rowNumberTable.updateWidth();

                scrollPane.setRowHeader(new JViewport());
                scrollPane.getRowHeader().add(rowNumberTable);
            }

            // Update row headers
            rowNumberTable.updateRowNames(generateRowHeaders());
        } else if (rowNumberTable != null) {
            scrollPane.setRowHeader(new JViewport());
            rowNumberTable.setVisible(false);
            rowNumberTable = null;
        }
    }

    public float getValue(Map<Axis, Integer> coordinates) throws IOException {
        Series data = table.getData();

        float value;

        if (data.getAddress().getSection().getMemoryType() == MemoryType.CODE) {
            value = table.getCell(getCalibration(), coordinates);
        } else {
            //TODO read data
            value = data.getScale().forward(0x00);
        }

        return value;
    }

    public float getValue(int index) throws IOException {
        Series data = table.getData();

        float value;

        if (data.getAddress().getSection().getMemoryType() == MemoryType.CODE) {
            value = data.get(getCalibration(), index);
        } else {
            //TODO read data
            value = data.getScale().forward(0x00);
        }

        return value;
    }

    public float getValue(int x, int y) throws IOException {
        Series data = table.getData();

        float value;

        if (data.getAddress().getSection().getMemoryType() == MemoryType.CODE) {
            value = table.getCell(getCalibration(), x, y);
        } else {
            //TODO read data
            value = data.getScale().forward(0x00);
        }

        return value;
    }

    private void updateData() {
        getEditor().withWaitCursor(() -> {
            Map<Axis, Integer> coordinates = new HashMap<>();
            int size = 1;

            for (Axis axis : table.getAxes().keySet()) {
                coordinates.put(axis, 0);
                size *= table.getSeries(axis).getLength();
            }

            java.util.List<Axis> orderedAxes = Arrays.stream(Axis.values())
                    .filter(coordinates::containsKey).toList();
            int read = 0;
            while (read < size) {
                float value;
                try {
                    value = getValue(coordinates);
                    setValue(coordinates, value, table.getData().getUnit());
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }

                read ++;

                // In the case of 1x1 tables (no axes)
                if (coordinates.isEmpty()) {
                    break;
                }

                // Advance
                boolean carry = true;
                for (Axis axis : orderedAxes) {
                    int index = coordinates.get(axis);

                    if (carry) {
                        index++;
                        carry = false;
                    }

                    if (table.getSeries(axis).getLength() <= index) {
                        carry = true;
                        index = 0;
                    }

                    coordinates.put(axis, index);
                }
            }

            updateVisualizations();
            updateCellWidth();
        });

        getComponent().repaint();
    }

    private void updateCrosshair() {
        if (!needsCrosshairUpdate) {
            needsCrosshairUpdate = true;
            SwingUtilities.invokeLater(() -> tableComponent.repaint());
        }
    }

    public String getSeriesHeaderString(Series series) {
        Unit unit = series.getUnit().getPreferredUnit();

        if (unit != null && (series.getName() == null || series.getName().isBlank())) {
            return unit.getText();
        } else if (unit != null && !series.getName().contains(unit.getText())) {
            return series.getName() + " (" + unit.getText() + ")";
        } else {
            return series.getName();
        }
    }

    private java.util.List<String> generateRowHeaders() {
        Series y = table.getSeries(Y);
        return IntStream.range(0, y.getLength())
                .mapToObj(index -> {
                    try {
                        return y.get(getCalibration(), index);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                })
                .map(value -> y.getScale().formatPreferred(value))
                .toList();
    }

    private void updateSelectionMinMax() {
        selMax = -Float.MAX_VALUE;
        selMin = Float.MAX_VALUE;

        int[] selectedRow = tableComponent.getSelectedRows();
        int[] selectedColumns = tableComponent.getSelectedColumns();

        for (int i = 0; i < selectedRow.length; i++) {
            for (int j = 0; j < selectedColumns.length; j++) {
                float data;
                try {
                    data = Unit.convertToPreferred(getValue(selectedColumns[j], selectedRow[i]),
                            table.getData().getUnit());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                selMax = Math.max(data, selMax);
                selMin = Math.min(data, selMin);
            }
        }

        if (selMin == -0) {
            selMin = 0;
        }

        if (selMax == -0) {
            selMax = 0;
        }
    }

    private void updateMinMax() {
        max = -Float.MAX_VALUE;
        min = Float.MAX_VALUE;

        for (int i = 0; i < table.getData().getLength(); i ++) {
            try {
                float data = Unit.convertToPreferred(getValue(i), table.getData().getUnit());
                max = Math.max(data, max);
                min = Math.min(data, min);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        if (min == -0) {
            min = 0;
        }

        if (max == -0) {
            max = 0;
        }
    }

    public float getMin() {
        return min;
    }

    public float getMax() {
        return max;
    }

    public float getSelectionMin() {
        return selMin;
    }

    public float getSelectionMax() {
        return selMax;
    }

    private Color getColor(float min, float value, float max) {
        if (min == max) {
            return Color.WHITE;
        } else if (table.getData().getLength() <= 1) {
            return Color.WHITE;
        }

        float green = (value - min) / (max - min);
        float red = 1f - green;

        green = Math.max(0, Math.min(1, green));
        red = Math.max(0, Math.min(1, red));

        return new Color(red, green, 0);
    }

    public Color scaleValueColor(float value) {
        float min = this.min, max = this.max;

        if (min == max) {
            return Color.WHITE;
        } else if (table.getData().getLength() <= 1) {
            return Color.WHITE;
        }

        float green = (value - min) / (max - min);
        float red = 1f - green;

        green = Math.max(0, Math.min(1, green));
        red = Math.max(0, Math.min(1, red));

        return new Color(red, green, 0);
    }

    private void updateAxisNames() {
        if (x_label != null) {
            tablePanel.remove(x_label);
        }
        if (y_label != null) {
            rootPanel.remove(y_label);
        }

        Series x = table.getSeries(X);
        Series y = table.getSeries(Y);

        if (y != null) {
            y_label = new JRotateLabel(getSeriesHeaderString(y));
            y_label.setFont(y_label.getFont().deriveFont(Font.ITALIC));
            y_label.setForeground(Color.GRAY);
            y_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            y_label.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    openScale(y.getScale());
                }
            });
            rootPanel.add(y_label, BorderLayout.WEST);
        } else {
            y_label = null;
        }

        if (x != null) {
            x_label = new JLabel(getSeriesHeaderString(x));
            x_label.setFont(x_label.getFont().deriveFont(Font.ITALIC));
            x_label.setHorizontalAlignment(JLabel.LEFT);
            x_label.setForeground(Color.GRAY);
            x_label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            x_label.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    openScale(x.getScale());
                }
            });

            int leftOffset;
            if (y_label != null) {
                leftOffset = (int) (y_label.getPreferredSize().width +
                        rowNumberTable.getPreferredSize().getWidth());
            } else {
                leftOffset = 5;
            }

            x_label.setBorder(BorderFactory.createEmptyBorder(
                    2,
                    leftOffset,
                    2,
                    0
            ));

            tablePanel.add(x_label, BorderLayout.NORTH);
        }

        if (y != null) {
            y_label.setBorder(BorderFactory.createEmptyBorder(
                    (int) (tableComponent.getTableHeader().getPreferredSize().getHeight()),
                    0,
                    0,
                    0
            ));
        }
    }

    /**
     * Used by the table definition editor when you change values in it
     */
    public void reload() {
        updateRowHeaders();
        updateMinMax();
        tableComponent.setModel(generateTableModel());
        updateData();
        updateVisualizations();
        footer.reinitialize();
        updateAxisNames();

        getComponent().getContentPane().revalidate();
        getComponent().getContentPane().repaint();
    }

    @Override
    public void focusGained(FocusEvent e) {
        getParent().tableFocused(table);
    }

    @Override
    public void focusLost(FocusEvent e) {

    }

    public Table getTable() {
        return table;
    }

    public void withSelfUpdate(boolean flag, Runnable runnable) {
        boolean before = selfUpdate.get();
        selfUpdate.set(flag);
        try {
            runnable.run();
        } finally {
            selfUpdate.set(before);
        }
    }

    @Override
    public void tableChanged(TableModelEvent e) {
        if (selfUpdate.get()) {
            return;
        }

        int row = e.getFirstRow();
        int col = e.getColumn();

        Object object = tableComponent.getValueAt(
                e.getFirstRow(),
                e.getColumn()
        );

        if (object == null) {
            float value;

            try {
                value = table.getCell(getCalibration(), col, row);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }

            setValue(row, col, value, table.getData().getUnit());
            return;
        }

        float value = (Float) object;

        Scale scale = table.getData().getScale();
        Unit unit = scale.getUnit();
        value = unit.getPreferredUnit().convert(value, unit);

        if (value == -0) {
            value = 0;
        }

        float newValue;
        float oldValue = 0;

        String valueString;

        try {
            oldValue = table.getCell(getCalibration(), col, row);
            String oldString = scale.formatPreferred(oldValue);
            valueString = scale.formatPreferred(value);

            if (!valueString.equals(oldString)) {
                newValue = table.setCell(getCalibration(), value, col, row);
                getParent().setDirty(true);
            } else {
                newValue = value;
            }
        } catch (IOException ex) {
            Log.ui().log(Level.SEVERE, "Failed to set data in cell [" + col + "," + row + "] on table "
                    + table.getName(), ex);
            setValue(row, col, oldValue, unit);
            return;
        }

        // If we're about to reposition the value due to the Table API precision,
        // we should let the user know that the scaling was adjusted.
        String newString = scale.format(newValue);

        boolean updateMinMax = (newValue > max || newValue < min) ||
                (oldValue <= min || oldValue >= max);

        if (updateMinMax) {
            updateMinMax();
            footer.reinitialize();
        }

        setValue(row, col, newValue, unit);

        if (scale.formatPreferred(newValue).length() != scale.formatPreferred(oldValue).length()) {
            updateCellWidth();
        }
    }

    @Override
    public void valueChanged(ListSelectionEvent e) {
        updateSelection();
    }

    public void setValue(Map<Axis, Integer> coordinates, float value, Unit unit) {
        setValue(coordinates.getOrDefault(Y, 0), coordinates.getOrDefault(X, 0), value, unit);
    }

    public void setValue(int row, int col, float value, Unit unit) {
        Unit preferredUnit = table.getData().getUnit().getPreferredUnit();
        float preferredValue = unit.convert(value, preferredUnit);

        withSelfUpdate(true, () -> {
            Object old = tableComponent.getModel().getValueAt(row, col);

            if (old instanceof Float) {
                float oldValue = (float) old;
                if (oldValue != preferredValue) {
                    glowingDataIndices.add(new Point(col, row));

                    if (glowAnimation == null || !glowAnimation.isAnimating()) {
                        glowAnimation = new TimedAnimation(tableComponent, 0.65D) {
                            @Override
                            protected void update(double position, JComponent component) {
                                glowAmount = (float) Math.pow(1f - (float) position, 2.75f);
                            }

                            @Override
                            protected void onComplete() {
                                glowingDataIndices.clear();
                            }
                        };

                        glowAnimation.start();
                    }
                }
            }

            tableComponent.getModel().setValueAt(preferredValue, row, col);
            tableComponent.revalidate();
            updateVisualizations();
        });
    }

    /**
     * Recalculates and updates the current selection
     */
    private void updateSelection() {
        int[] selectedRows = tableComponent.getSelectedRows();
        int[] selectedColumns = tableComponent.getSelectedColumns();
        boolean rowsEqual = Arrays.equals(selectedRows, lastSelectionRows);
        boolean columnsEqual = Arrays.equals(selectedColumns, lastSelectionColumns);
        if (!rowsEqual || !columnsEqual) {
            lastSelectionColumns = selectedColumns;
            lastSelectionRows = selectedRows;
        } else {
            // Selection hasn't actually changed; don't spend time calculating
            return;
        }

        //TODO Highlight columns
        for (int i = 0; i < tableComponent.getColumnModel().getColumnCount(); i ++) {
            var column = tableComponent.getColumnModel().getColumn(i);
        }

        updateSelectionMinMax();

        SwingUtilities.invokeLater(() -> footer.reinitialize());

        updateSelectionRectangles();
    }

    public JTable getJTable() {
        return tableComponent;
    }

    public Font getValueFont() {
        return Fonts.VALUE_FONT.deriveFont((float) Settings.TABLE_EDITOR_FONT_SIZE.get());
    }

    public String formatValue(float value, Unit unit) {
        Scale scale = table.getData().getScale();
        float scaled = unit.convert(value, scale.getUnit());
        String s = scale.formatPreferred(scaled);
        value = Float.parseFloat(s);
        if (Float.floatToIntBits(value) == 0x80000000) { // "-0.00" etc.
            value = 0;
            return formatValue(value, unit);
        } else {
            return s;
        }
    }

    public boolean isNested() {
        return nested;
    }

    public void editingStopped(ChangeEvent e) {
        javax.swing.table.TableCellEditor editor = tableComponent.getCellEditor();
        Object value;
        if (editor != null) {
            value = editor.getCellEditorValue();
            tableComponent.removeEditor();
        } else {
            return;
        }

        if (value == null) {
            return;
        }

        int[] selectedRows = tableComponent.getSelectedRows();
        int[] selectedColumns = tableComponent.getSelectedColumns();
        if ((selectedRows.length <= 1 && selectedColumns.length <= 1)) {
            return;
        }

        processSelection((Float) value);
    }

    public void openScale(Scale scale) {
        getParent().openScale(scale);
    }

    @Override
    public void onMemoryFrame(MemoryFrame frame) {
        lastFrame = frame;

        JInternalFrame component = getComponent();
        if (component.isVisible()) {
            updateCrosshair();
        }
    }

    @Override
    public void onCalibrationChanged(Calibration oldCalibration, Calibration newCalibration) {
        if (oldCalibration == getCalibration()) {
            if (!table.isVariantSupported(newCalibration)) {
                // Ignore this change
                Log.ui().log(Level.FINE, table.getName() + " is ignoring a calibration change " +
                        "as its variant is unsupported: " + newCalibration);
                return;
            }

            setCalibration(newCalibration);

            if (toolbar != null) {
                toolbar.reinitialize();
            }
        }
    }

    @Override
    public void onModelChanged(Model model, ChangeType changeType) {
        if (changeType == ChangeType.MODIFIED &&
                (model == Model.TABLE || model == Model.PARAMETER || model == Model.FORMAT)) {
            reload();
        }
    }

    public List<Calibration> getOtherCalibrations() {
        return getProject().getCalibrations().stream()
                .filter(c -> c != getCalibration())
                .filter(table::isVariantSupported)
                .sorted(Comparator.comparing(Calibration::getName)).toList();
    }

    public void applyCalibration() {
        Object[] options = getOtherCalibrations().toArray();

        Calibration selected = (Calibration) JOptionPane.showInputDialog(
                getEditor(),
                "Select a calibration to apply data from",
                "Select Calibration",
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                null
        );

        if (selected == null) {
            return;
        }

        if (selected == getCalibration()) {
            return;
        }

        Series x_series = table.getSeries(X);
        Series y_series = table.getSeries(Y);

        processSelection((x, y) -> {
            try {
                Map<Axis, Float> coordinates = new HashMap<>();

                if (x_series != null) {
                    coordinates.put(X, x_series.get(calibration, x));
                }

                if (y_series != null) {
                    coordinates.put(Y, y_series.get(calibration, x));
                }

                return table.getCalculatedCell(selected, coordinates);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private List<Table> getOtherTables() {
        return getProject().getTables().stream().filter(table -> {
            if (table == this.table) {
                return false;
            }

            if (!table.getData().getAddress().hasOffset(calibration)) {
                return false;
            }

            if (table.getData().getAddress().getOffset(calibration) ==
                    this.table.getData().getAddress().getOffset(calibration)) {
                return false;
            }

            if (table.getAllAxes().size() != this.table.getAllAxes().size()) {
                return false;
            }

            if (table.getData().getUnit().getUnitClass() != this.table.getData().getUnit().getUnitClass()) {
                return false;
            }

            return table.getAxes().keySet().stream().allMatch(
                    axis -> {
                        Series mine = this.table.getSeries(axis);
                        Series theirs = table.getSeries(axis);
                        return mine.getUnit().getUnitClass() == theirs.getUnit().getUnitClass();
                    }
            );
        }).toList();
    }

    /**
     * Request the user applies, to this table, data from another matching table (units and axes match).
     */
    public void applyTable() {
        if (getCalibration().isReadonly()) {
            Errors.show(getParent(), "Calibration is Read-only", "The current calibration \""
                    + getCalibration().getName() + "\" is read-only.");
            return;
        }

        List<Table> options = getOtherTables();
        Table source = Inputs.showOptionDialog(getEditor(),
                "Apply Different Table - " + getCalibration().getName(),
                "Select a table to apply values from:",
                options);

        if (source == null) {
            return;
        }

        // Apply table
        Series x = table.getSeries(X);
        Series y = table.getSeries(Y);

        processSelection((i, j) -> {
            Map<Axis, Float> coordinates = new HashMap<>();

            if (x != null) {
                coordinates.put(X, x.get(calibration, i));
            }

            if (y != null) {
                coordinates.put(Y, y.get(calibration, j));
            }

            float otherValue = source.getCalculatedCell(calibration, coordinates);
            return table.getData().getUnit().convert(otherValue, source.getData().getUnit());
        });
    }

    public static void exportTable(Frame parent, Table table, Calibration calibration) {
        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter def = new FileNameExtensionFilter("Comma-separated value file (*.csv)", "csv");
        fileChooser.addChoosableFileFilter(def);
        fileChooser.setFileFilter(def);
        fileChooser.setSelectedFile(new File(table.getName() +  ".csv"));
        fileChooser.setDialogTitle("Export Table - " + table.getName() + " (" + calibration.getName() + ")");
        if (fileChooser.showSaveDialog(parent) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (FileOutputStream fos = new FileOutputStream(file)) {
                table.writeCsv(calibration, fos, 4);
                Log.ui().log(Level.INFO, "Table \"" + table.getName() + "\" exported to " + file);
            } catch (IOException e) {
                Errors.show(parent, "Export Table Failed", "Problem exporting \"" + table.getName() + "\"", e);
            }
        }
    }

    @Override
    public Set<MemoryParameter> getParameters() {
        Set<MemoryParameter> parameters = new HashSet<>();

        table.getAllAxes().stream()
                .map(Series::getParameter)
                .filter(Objects::nonNull)
                .forEach(parameters::add);

        return parameters;
    }

    @Override
    public boolean isLive() {
        return Settings.TABLE_EDITOR_LIVE.get();
    }

    public void findTable() {
        Tools.findTable(getEditor(), table, calibration);
    }

    public void compareWithTable(TableComparer.CompareOperation operation) {
        List<Table> options = getOtherTables();

        Table table = Inputs.showOptionDialog(getEditor(),
                "Compare with Table - " + getCalibration().getName(),
                "Select a table to compare to:",
                options);

        if (table == null) {
            return;
        }

        compare(table, calibration, operation);
    }

    public void compareWithCalibration() {
        Object[] options = getOtherCalibrations().toArray();

        Calibration selected = (Calibration) JOptionPane.showInputDialog(
                getEditor(),
                "Select a calibration to compare to",
                "Select Calibration",
                JOptionPane.PLAIN_MESSAGE,
                null,
                options,
                null
        );

        if (selected == null) {
            return;
        }

        if (selected == getCalibration()) {
            return;
        }

        compare(table, selected, TableComparer.CompareOperation.SUBTRACT);
    }

    public void compare(Table table, Calibration calibration, TableComparer.CompareOperation operation) {
        TableComparer comparer = new TableComparer(getEditor(), this.table, this.calibration, table, calibration,
                operation);
        getEditor().openWindow(comparer);
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
            Component c = super.getTableCellRendererComponent(table, value, false, hasFocus || isSelected, row, col);
            c.setFont(getValueFont());

            if (value != null) {
                float v;

                if (value instanceof Float) {
                    v = (Float) value;
                } else {
                    v = Float.parseFloat(value.toString());
                }

                c.setForeground(getColor(min, v, max));

                if (c instanceof JLabel label) {
                    label.setText(formatValue(v, TableEditor.this.table.getData().getUnit().getPreferredUnit()));
                }

                if (c instanceof JComponent component) {
                    Border border;
                    border = BorderFactory.createMatteBorder(0, 0, 1, 1, Color.GRAY.darker());
                    component.setBorder(border);
                }
            }

            return c;
        }
    }

    private class TableCellEditor extends DefaultCellEditor implements javax.swing.table.TableCellEditor, KeyListener {
        private final JTextField textField;

        private TableCellEditor(JTextField textField) {
            super(textField);
            this.textField = textField;
            this.textField.addKeyListener(this);

            this.textField.setInputVerifier(new InputVerifier() {
                @Override
                public boolean verify(JComponent input) {
                    try {
                        String text = ((JTextField)input).getText();
                        if (text.isBlank()) {
                            return true;
                        }
                        Float.parseFloat(text);
                        return true;
                    } catch (Exception ex) {
                        return false;
                    }
                }
            });

            this.textField.addKeyListener(new KeyAdapter() {
                @Override
                public void keyPressed(KeyEvent e) {
                    if (e.getKeyCode() == VK_ESCAPE) {
                        tableComponent.removeEditor();
                    }
                }
            });
        }

        private TableCellEditor() {
            this(new JTextField());
        }

        @Override
        public boolean isCellEditable(EventObject e) {
            boolean acceptableKey = true;
            if (e instanceof KeyEvent keyEvent) {
                acceptableKey = Character.isDigit(keyEvent.getKeyChar())
                        || keyEvent.getKeyChar() == '.'
                        || keyEvent.getKeyChar() == '-'
                        || keyEvent.getKeyCode() == VK_BACK_SPACE
                        || keyEvent.getKeyCode() == VK_DELETE;
            }

            return super.isCellEditable(e) && acceptableKey && !getCalibration().isReadonly() && !isNested();
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
                                                     int row, int column) {
            this.textField.setFont(getValueFont());
            this.textField.setText("");
            SwingUtilities.invokeLater(this.textField::grabFocus);
            return textField;
        }

        @Override
        public Object getCellEditorValue() {
            if (textField.getText().isBlank()) {
                return null;
            }

            return Float.parseFloat(textField.getText());
        }

        @Override
        public void keyTyped(KeyEvent e) {

        }

        @Override
        public void keyPressed(KeyEvent e) {

        }

        @Override
        public void keyReleased(KeyEvent e) {

        }
    }
}
