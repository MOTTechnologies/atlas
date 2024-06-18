package com.github.manevolent.atlas.ui;

import com.formdev.flatlaf.util.SystemInfo;
import com.github.manevolent.atlas.checked.CheckedConsumer;
import com.github.manevolent.atlas.checked.CheckedRunnable;
import com.github.manevolent.atlas.checked.CheckedSupplier;
import com.github.manevolent.atlas.connection.*;
import com.github.manevolent.atlas.logic.OS;
import com.github.manevolent.atlas.logic.SupportedDTC;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.node.GraphModule;
import com.github.manevolent.atlas.model.node.GraphNode;
import com.github.manevolent.atlas.model.storage.ProjectStorage;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import com.github.manevolent.atlas.protocol.j2534.DeviceNotFoundException;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceProvider;
import com.github.manevolent.atlas.protocol.uds.UDSFrame;
import com.github.manevolent.atlas.protocol.uds.UDSNegativeResponseException;
import com.github.manevolent.atlas.protocol.uds.UDSSession;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.time.HighPrecisionThread;
import com.github.manevolent.atlas.ui.behavior.*;
import com.github.manevolent.atlas.ui.behavior.ConnectionListener;
import com.github.manevolent.atlas.ui.component.candebug.CANDebugWindow;
import com.github.manevolent.atlas.ui.component.datalog.DatalogWindow;
import com.github.manevolent.atlas.ui.component.dtc.DTCEditor;
import com.github.manevolent.atlas.ui.component.footer.EditorFooter;
import com.github.manevolent.atlas.ui.component.format.FormatEditor;
import com.github.manevolent.atlas.ui.component.graph.GraphEditor;
import com.github.manevolent.atlas.ui.component.menu.editor.*;
import com.github.manevolent.atlas.ui.component.parameter.ParameterEditor;
import com.github.manevolent.atlas.ui.component.tab.*;
import com.github.manevolent.atlas.ui.component.table.TableDefinitionEditor;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.component.toolbar.EditorToolbar;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.dialog.DeviceSettingsDialog;
import com.github.manevolent.atlas.ui.dialog.ProgressDialog;
import com.github.manevolent.atlas.ui.settings.EditorSettingsDialog;
import com.github.manevolent.atlas.ui.settings.ProjectSettingsDialog;
import com.github.manevolent.atlas.ui.settings.SettingPage;
import com.github.manevolent.atlas.ui.util.*;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.InternalFrameEvent;
import javax.swing.event.InternalFrameListener;
import java.awt.*;
import java.awt.Color;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.logging.Level;

import static com.github.manevolent.atlas.connection.ConnectionMode.IDLE;
import static javax.swing.JOptionPane.WARNING_MESSAGE;

/**
 *  This is the primary frame for the application
 *  It is launched via Main.java in this package
 */
public class Editor extends JFrame implements InternalFrameListener, MouseMotionListener, KeyListener,
        UDSConnectionListener, HistoryListener<Edit> {
    private static final Color splitPaneBorderColor = Color.GRAY.darker();
    private static final int DATA_TIMEOUT_MILLIS = 3000;

    // Desktop
    private JDesktopPane desktop;

    // Event listeners
    private List<ModelChangeListener> modelChangeListeners = new LinkedList<>();

    // Menus
    private JMenuBar menubar;
    private FileMenu fileMenu;
    private CalibrationMenu calibrationMenu;
    private WindowMenu windowMenu;
    private EditorToolbar toolbar;
    private EditorFooter footer;

    // Tabs
    private ProjectTreeTab projectTreeTab;
    private ConsoleTab consoleTab;
    private GaugesTab gaugesTab;
    private TimelineTab timelineTab;

    // Components
    private JSplitPane northSouthSplitPane;
    private JSplitPane eastWestSplitPaneOuter;
    private JSplitPane eastWestSplitPaneInner;
    private EditorTabbedPane bottomPane;
    private EditorTabbedPane leftPane;
    private EditorTabbedPane rightPane;

    // State variables (open windows, etc.)
    private File projectFile;
    private Project project;
    private final java.util.List<Window> openWindows = new ArrayList<>();
    private Map<Table, TableEditor> openedTables = new LinkedHashMap<>();
    private Map<GraphModule, GraphEditor> openedGraphs = new LinkedHashMap<>();
    private Map<Table, TableDefinitionEditor> openedTableDefs = new LinkedHashMap<>();
    private Map<MemoryParameter, ParameterEditor> openedParameters = new LinkedHashMap<>();
    private Map<Scale, FormatEditor> openedFormats = new LinkedHashMap<>();
    private Map<Calibration, DTCEditor> openedDTCs = new LinkedHashMap<>();

    private WindowHistory windowHistory;
    private Window activeWindow;
    private Window lastDeactivatedWindow;
    private Calibration activeCalibration;
    private boolean dirty;

    private Thread noDataThread;

    private final Object dataLock = new Object();
    private long lastFrameRead = 0L;

    // Vehicle connection
    private final ConnectionManager connectionManager = new ConnectionManager();

    private AutoConnectThread autoConnectThread;
    private HighPrecisionThread datalogThread;
    private boolean preventAutoDatalogging = false;

    public Editor(Project project) {
        // Just to make sure it shows up in the taskbar/dock/etc.
        setType(Type.NORMAL);

        if( SystemInfo.isMacFullWindowContentSupported ) {
            getRootPane().putClientProperty("apple.awt.fullWindowContent", true);
            getRootPane().putClientProperty("apple.awt.transparentTitleBar", true);
        }

        setProject(project);
        setDirty(false);

        initComponents();

        pack();

        setBackground(Color.BLACK);
        setExtendedState(java.awt.Frame.MAXIMIZED_BOTH);
        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        setLocationRelativeTo(null);
        addKeyListener(this);

        initKeybinds();

        windowHistory = new WindowHistory();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                exit();
            }

            @Override
            public void windowOpened(WindowEvent e) {
                northSouthSplitPane.setDividerLocation(0.8f);
            }
        });
    }

    /**
     * Gets the active parameter set, which is used across gauges, datalogs, etc. to dictate which parameters will be
     * polled and/or logged from the ECU. This object is unmodifiable.
     * @return current gauge set.
     */
    public Set<MemoryParameter> getLoggingParameters() {
        Set<MemoryParameter> parameters = new HashSet<>();

        if (activeWindow instanceof LiveWindow window && window.isLive()) {
            parameters.addAll(window.getParameters());
        }

        GaugeSet gaugeSet = getProject().getActiveGaugeSet();
        if (gaugeSet != null) {
            gaugeSet.getGauges()
                    .stream()
                    .map(Gauge::getParameter)
                    .forEach(parameters::add);
        }

        return parameters;
    }

    private void hideWindow() {
        desktop.moveToBack(desktop.getSelectedFrame());
    }

    private void focusSearch() {
        getProjectTreeTab().focus();
        getProjectTreeTab().focusSearch();
    }

    public Project getProject() {
        return project;
    }

    public Calibration getCalibration() {
        return activeCalibration;
    }

    public Variant getVariant() {
        Calibration calibration = getCalibration();
        if (calibration == null) {
            return null;
        }

        return calibration.getVariant();
    }

    public void setCalibration(Calibration calibration) {
        Calibration old = this.activeCalibration;

        if (this.activeCalibration != calibration) {
            this.activeCalibration = calibration;

            projectTreeTab.onCalibrationChanged(old, calibration);
            gaugesTab.onCalibrationChanged(old, calibration);

            getOpenWindows(CalibrationListener.class)
                    .forEach(listener -> listener.onCalibrationChanged(old, calibration));
        }
    }

    public void setGaugeSet(GaugeSet gaugeSet) {
        GaugeSet old = project.getActiveGaugeSet();
        if (project.getActiveGaugeSet() != gaugeSet) {
            project.setActiveGaugeSet(gaugeSet);

            getOpenWindows(GaugeSetListener.class)
                    .forEach(listener -> listener.onGaugeSetChanged(old, gaugeSet));

            gaugesTab.onGaugeSetChanged(old, gaugeSet);

            setDirty(true);

            updateParameters();
        }
    }

    public void postStatus(String status) {
        SwingUtilities.invokeLater(() -> {
            if (footer != null) {
                footer.setStatus(status);
                footer.getComponent().revalidate();
                footer.getComponent().repaint();
            }
        });
    }

    /**
     *
     * @return true if the editor is ready to close
     */
    public boolean closing() {
        getOpenWindows().forEach(window -> window.getComponent().doDefaultCloseAction());

        if (dirty) {
            String message = "You have unsaved changes to your project " +
                    "that will be lost. Save changes?";

            int answer = JOptionPane.showConfirmDialog(getParent(),
                    message,
                    "Unsaved changes",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    WARNING_MESSAGE
            );

            switch (answer) {
                case JOptionPane.CANCEL_OPTION:
                    return false;
                case JOptionPane.YES_OPTION:
                    return saveProject();
                case JOptionPane.NO_OPTION:
            }
        }

        return getOpenWindows().isEmpty();
    }

    @Override
    public void setCursor(Cursor cursor) {
        super.setCursor(cursor);
        getContentPane().setCursor(cursor);
        getOpenWindows().forEach(w -> w.getComponent().getContentPane().setCursor(cursor));
    }

    public Thread withWaitCursorAsync(CheckedRunnable runnable) {
        return Jobs.fork(() -> withWaitCursor(runnable));
    }

    public <R> R withWaitCursorChecked(CheckedSupplier<R, Exception> supplier) {
        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        try {
            return supplier.get();
        } finally {
            setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
    }

    public void withWaitCursorChecked(CheckedRunnable<Exception> supplier) {
        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        try {
            supplier.run();
        } finally {
            setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
    }

    public <R> R withWaitCursor(Supplier<R> supplier) {
        long gracePeriod = 50L;
        AtomicBoolean completed = new AtomicBoolean(false);

        try {
            Thread cursorThread = Jobs.fork(() -> {
                Cursor prior = Cursor.getDefaultCursor();

                try {
                    synchronized (completed) {
                        Thread.sleep(gracePeriod);

                        while (!completed.get()) {
                            setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
                            completed.wait(1000L);
                        }
                    }
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                } finally {
                    setCursor(prior);
                }
            });

            return supplier.get();
        } finally {
            synchronized (completed) {
                completed.set(true);
                completed.notifyAll();
            }
        }
    }

    public <R> void withWaitCursor(Runnable runnable) {
        Object ignored = withWaitCursor(() -> {
            runnable.run();
            return null;
        });
    }

    public void executeWithProgress(String title, String description,
                                    CheckedConsumer<ProgressDialog, Exception> action) {
        ProgressDialog progressDialog = new ProgressDialog(this, title, description, true);
        Thread thread = withWaitCursorAsync(() -> {
            try {
                action.accept(progressDialog);
            } catch (Throwable ex) {
                Errors.show(progressDialog, title, "Action failed unexpectedly", ex);
            } finally {
                progressDialog.dispose();
            }
        });

        Jobs.fork(() -> {
            progressDialog.setCancelCallback(() -> {
                thread.interrupt();
                progressDialog.dispose();
            });
            progressDialog.setVisible(true);

            if (thread.isAlive()) {
                thread.interrupt();
            }
        });
    }

    public boolean saveProject() {
        if (this.projectFile != null) {
            ProjectStorage storage = ProjectStorageType.detect(this.projectFile).getStorageFactory().createStorage();
            return saveProject(storage, this.projectFile);
        } else {
            return saveProjectAs(ProjectStorageType.getDefault());
        }
    }

    public boolean saveProjectAs(ProjectStorageType storageType) {
        ProjectStorage storage = storageType.getStorageFactory().createStorage();
        JFileChooser fileChooser = storage.createFileChooser();
        fileChooser.setDialogTitle("Save Project");
        String currentDirectory = Paths.get(".").toAbsolutePath().normalize().toString();
        fileChooser.setCurrentDirectory(projectFile != null ? projectFile.getParentFile() : new File(currentDirectory));
        if (fileChooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return false;
        }

        File file = fileChooser.getSelectedFile();
        return saveProject(storage, file);
    }


    public boolean saveProject(ProjectStorage projectStorage, File file) {
        postStatus("Saving project...");

        return withWaitCursor(() -> {
            try {
                projectStorage.save(project, file);

                if (projectStorage.isAutoLoading()) {
                    setDirty(false);
                    setProjectFile(file);
                }

                String message = "Project saved to " + file.getPath();
                Log.ui().log(Level.INFO, message);
                postStatus(message);
                return true;
            } catch (Exception e) {
                postStatus("Project save failed; see console output for details.");
                Errors.show(this, "Save Failed", "Failed to save project!", e);
                return false;
            }
        });
    }

    public void openProject(ProjectStorageType storageType) {
        if (!closing()) {
            return;
        }

        ProjectStorage storage = storageType.getStorageFactory().createStorage();

        JFileChooser fileChooser = storage.createFileChooser();
        fileChooser.setDialogTitle("Open Project");
        String currentDirectory = Paths.get(".").toAbsolutePath().normalize().toString();
        fileChooser.setCurrentDirectory(projectFile != null ? projectFile.getParentFile() : new File(currentDirectory));

        if (fileChooser.showOpenDialog(getParent()) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();
        boolean opened = withWaitCursor(() -> {
            try {
                setProject(storage.load(file));
                if (storage.isAutoLoading()) {
                    setProjectFile(file);
                }

                return true;
            } catch (Exception e) {
                postStatus("Open project failed; see console output for details.");
                Errors.show(this, "Open Project Failed", "Failed to open project!", e);
                return false;
            }
        });

        if (opened) {
            String message = "Project opened from " + file.getPath();
            Log.ui().log(Level.INFO, message);
            postStatus(message);
        }
    }

    public void setProjectFile(File file) {
        this.projectFile = file;
        updateTitle();

        Settings.set(Settings.LAST_OPENED_PROJECT, file.getAbsolutePath());
    }

    public File getProjectFile() {
        return projectFile;
    }

    public void setProject(Project project) {
        this.project = project;
        this.activeCalibration = this.project.getCalibrations().stream().findFirst().orElse(null);

        fireModelChange(Model.PROJECT, ChangeType.ADDED);
        ensureAutoConnecting();

        if (this.projectFile == null) {
            updateTitle();
        }
    }

    private void ensureAutoConnecting() {
        if (autoConnectThread == null || !autoConnectThread.isAlive()) {
            autoConnectThread = new AutoConnectThread();
            autoConnectThread.start();
        }
    }

    public void updateTitle() {
        String title;
        if (projectFile == null) {
            title = ("Atlas - New Project");
        } else {
            title = ("Atlas - " + projectFile.getName());
        }

        if (dirty) {
            title += "*";
        }

        setTitle(title);
    }

    public JDesktopPane getDesktop() {
        return desktop;
    }

    public ProjectTreeTab getProjectTreeTab() {
        return projectTreeTab;
    }

    public GaugesTab getGaugesTab() {
        return gaugesTab;
    }

    public WindowMenu getWindowMenu() {
        return windowMenu;
    }

    public void updateWindowTitles() {
        updateTitle();
        for (Window window : getOpenWindows()) {
            window.updateTitle();
        }
    }

    private void initComponents() {
        setIconImage(Icons.getImage(CarbonIcons.METER_ALT, Color.WHITE).getImage());
        setJMenuBar(menubar = initMenu());

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosed(WindowEvent e) {
                System.exit(0);
            }
        });

        this.desktop = initDesktop();

        eastWestSplitPaneInner = new ZeroDividerSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                this.desktop,
                (rightPane = initRightPane()).getComponent()
        );
        eastWestSplitPaneInner.setName("eastWestSplitPaneInner");
        eastWestSplitPaneInner.setResizeWeight(1f);

        eastWestSplitPaneOuter = new ZeroDividerSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                (leftPane = initLeftPane()).getComponent(),
                eastWestSplitPaneInner
        );
        eastWestSplitPaneOuter.setName("eastWestSplitPaneOuter");

        northSouthSplitPane = new ZeroDividerSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                eastWestSplitPaneOuter,
                (bottomPane = initBottomPane()).getComponent()
        );
        northSouthSplitPane.setResizeWeight(1f);
        northSouthSplitPane.setName("northSouthSplitPane");

        setLayout(new BorderLayout());

        JComponent topComponent = (toolbar = new EditorToolbar(this)).getComponent();
        topComponent.setBorder(BorderFactory.createCompoundBorder(topComponent.getBorder(),
                BorderFactory.createEmptyBorder(0, 4, 0, 4)));

        if (SystemInfo.isMacFullWindowContentSupported) {
            JPanel topPanel = new JPanel(new BorderLayout());
            topPanel.add(Box.createVerticalStrut(28), BorderLayout.NORTH);
            topPanel.add(topComponent, BorderLayout.SOUTH);
            topComponent = topPanel;
        }
        add(topComponent, BorderLayout.NORTH);

        add(northSouthSplitPane, BorderLayout.CENTER);

        add((footer = new EditorFooter(this)).getComponent(), BorderLayout.SOUTH);

        addMouseMotionListener(this);

        initKeybinds();
    }

    private void initKeybinds() {
        Inputs.bind(this, "undo", this::undo,
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.META_DOWN_MASK)); // OSX

        Inputs.bind(this, "redo", this::redo,
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.META_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)); // OSX

        Inputs.bind(this, "left_keybind", () -> {
                    if (windowHistory.canUndo()) {
                        windowHistory.undo();
                        toolbar.update();
                    }
                },
                KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, InputEvent.META_DOWN_MASK), // OSX
                KeyStroke.getKeyStroke(KeyEvent.VK_KP_LEFT, InputEvent.CTRL_DOWN_MASK));
        Inputs.bind(this, "right_keybind", () -> {
                    if (windowHistory.canRedo()) {
                        windowHistory.redo();
                        toolbar.update();
                    }
                },
                KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, InputEvent.META_DOWN_MASK), // OSX
                KeyStroke.getKeyStroke(KeyEvent.VK_KP_RIGHT, InputEvent.CTRL_DOWN_MASK));
        Inputs.bind(this, "newtable_keybind", this::newTable,
                KeyStroke.getKeyStroke(KeyEvent.VK_T, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_T, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this, "datalogging_keybind",
                this::openDataLogging,
                KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this, "search_keybind", this::focusSearch,
                KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this, "send_to_back", this::hideWindow,
                KeyStroke.getKeyStroke(KeyEvent.VK_H, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_H, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this, "save", this::saveProject,
                KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this, "newFormat", this::newFormat,
                KeyStroke.getKeyStroke(KeyEvent.VK_M, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_M, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this, "newParameter", this::newParameter,
                KeyStroke.getKeyStroke(KeyEvent.VK_P, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_P, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this, "console", () -> consoleTab.focus(),
                KeyStroke.getKeyStroke(KeyEvent.VK_F12, 0),
                KeyStroke.getKeyStroke(KeyEvent.VK_F12, 0)); // OSX
    }

    private JMenuBar initMenu() {
        JMenuBar menuBar;

        menuBar = new JMenuBar();

        menuBar.add((fileMenu = new FileMenu(this)).getComponent());
        menuBar.add((calibrationMenu = new CalibrationMenu(this)).getComponent());
        menuBar.add(new FormatMenu(this).getComponent());
        menuBar.add(new TableMenu(this).getComponent());

        windowMenu = new WindowMenu(this);
        menuBar.add(windowMenu.getComponent());

        menuBar.add(new HelpMenu(this).getComponent());

        return menuBar;
    }

    public boolean hasWindow(Window window) {
        return getOpenWindows().contains(window);
    }

    public Window getActiveWindow() {
        return activeWindow;
    }

    public Collection<Window> getOpenWindows() {
        synchronized (openWindows) {
            return Collections.unmodifiableCollection(new ArrayList<>(openWindows));
        }
    }

    public <T> Collection<T> getOpenWindows(Class<T> clazz) {
        //noinspection unchecked
        return getOpenWindows()
                .stream()
                .filter(w -> clazz.isAssignableFrom(w.getClass()))
                .map(w -> (T) w)
                .toList();
    }

    public Collection<Window> getOpenWindows(Table table) {
        return getOpenWindows().stream()
                .filter(w -> ((w instanceof TableEditor) && ((TableEditor) w).getTable() == table) ||
                        ((w instanceof TableDefinitionEditor) && ((TableDefinitionEditor) w).getTable() == table))
                .toList();
    }

    public Collection<Window> getOpenWindows(MemoryParameter parameter) {
        return getOpenWindows().stream()
                .filter(w -> w instanceof ParameterEditor && ((ParameterEditor) w).getParameter() == parameter)
                .toList();
    }

    /**
     * Opens a Window in the editor, keeping track of its state.
     * @param window Window to open.
     * @return opened Window.
     */
    public <T extends Window> T openWindow(T window) {
        Log.ui().log(Level.FINER, "Opening window \"" + window.getTitle() + "\" [" + window.getClass() + "]...");

        return withWaitCursor(() -> {
            JInternalFrame component = null;
            try {
                component = window.getComponent();

                window.getHistory().addListener(this);

                component.addInternalFrameListener(this);
                component.setFocusable(true);

                synchronized (openWindows) {
                    openWindows.add(window);
                    desktop.add(component);
                    component.setVisible(true);
                }

                postStatus("Opened " + window.getTitle());
                Log.ui().log(Level.FINER, "Opened window \"" + window.getTitle() + "\" [" + window.getClass() + "].");
            } catch (RuntimeException ex) {
                if (component != null) {
                    desktop.remove(component);
                }

                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(getParent(), "Problem opening " + window.getTitle() + "!\r\n" +
                                    ex.getMessage() + "\r\n"
                                    + "See console output (F12) for more details.",
                            "Window Open Error",
                            JOptionPane.ERROR_MESSAGE);
                });
                Log.ui().log(Level.FINER, "Problem opening window \"" + window.getTitle() + "\", "
                        + window.getClass() + "]", ex);
                throw ex;
            }

            windowMenu.update();

            return window;
        });
    }

    public void newTable() {
        getProjectTreeTab().newItem(Table.class);
    }

    public void newGraph() {
        getProjectTreeTab().newItem(GraphModule.class);
    }

    public void newParameter() {
        getProjectTreeTab().newItem(MemoryParameter.class);
    }

    public void newFormat() {
        getProjectTreeTab().newItem(Scale.class);
    }

    public void openTable(Table table) {
        if (activeCalibration == null) {
            Errors.show(this, "Open failed",
                    "Failed to open table \"" + table.getName() + "\"!\r\nNo calibration has been selected.");
            return;
        }

        if (!table.isVariantSupported(getVariant())) {
            Errors.show(this, "Open failed",
                    "Failed to open table \"" + table.getName() + "\"!\r\nThis table does not support the " +
                            "current variant (" + getVariant().getName() + ").");
            return;
        }

        TableEditor opened;

        opened = openedTables.get(table);

        if (opened == null) {
            opened = openWindow(new TableEditor(this, table));
        }

        opened.focus();

        openedTables.put(table, opened);
    }

    public GraphEditor openGraph(GraphModule module) {
        GraphEditor opened;

        opened = openedGraphs.get(module);

        if (opened == null) {
            opened = openWindow(new GraphEditor(this, module));
        }

        opened.focus();

        openedGraphs.put(module, opened);

        return opened;
    }

    public GraphEditor openNode(GraphNode node) {
        GraphModule module = node.getModule();
        if (module == null) {
            return null;
        }

        GraphEditor editor = openGraph(module);
        if (editor == null) {
            return null;
        }

        editor.findNode(node);
        return editor;
    }

    public void openTableDefinition(Table table) {
        if (activeCalibration == null) {
            JOptionPane.showMessageDialog(this,
                    "Failed to open table \"" + table.getName() + "\"!\r\nNo calibration has been selected. " +
                            "Please add a calibration using Project Settings before editing table data.",
                    "Open failed",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        TableDefinitionEditor opened;

        opened = openedTableDefs.get(table);

        if (opened == null) {
            opened = openWindow(new TableDefinitionEditor(this, table));
        }

        opened.focus();

        openedTableDefs.put(table, opened);
    }

    public void openParameter(MemoryParameter parameter) {
        ParameterEditor opened;

        opened = openedParameters.get(parameter);

        if (opened == null) {
            opened = openWindow(new ParameterEditor(this, parameter));
        }

        opened.focus();

        openedParameters.put(parameter, opened);
    }

    public void openScale(Scale scale) {
        FormatEditor opened;

        opened = openedFormats.get(scale);

        if (opened == null) {
            opened = openWindow(new FormatEditor(this, scale));
        }

        opened.focus();

        openedFormats.put(scale, opened);
    }

    public void openEditorSettings() {
        EditorSettingsDialog dialog = new EditorSettingsDialog(this);
        dialog.setVisible(true);
    }

    public <T extends SettingPage> void openEditorSettings(Class<T> pageClass) {
        EditorSettingsDialog dialog = new EditorSettingsDialog(this);
        dialog.selectPage(pageClass);
        dialog.setVisible(true);
    }

    public void openProjectSettings() {
        ProjectSettingsDialog dialog = new ProjectSettingsDialog(this, getProject());
        dialog.setVisible(true);
        toolbar.update();
    }

    public void openDeviceSettings() {
        DeviceSettingsDialog dialog = new DeviceSettingsDialog(this);
        dialog.setVisible(true);
    }

    private JDesktopPane initDesktop() {
        JDesktopPane desktop = new JDesktopPane();
        desktop.setMinimumSize(new Dimension(500, 500));
        return desktop;
    }

    private EditorTabbedPane initLeftPane() {
        EditorTabbedPane leftTabs = new EditorTabbedPane(this, SwingConstants.WEST);
        leftTabs.addTab(initTablesTab(leftTabs.getComponent()));
        return leftTabs;
    }

    private EditorTabbedPane initRightPane() {
        EditorTabbedPane rightTabs = new EditorTabbedPane(this, SwingConstants.EAST);
        rightTabs.addTab(initGaugesTab(rightTabs.getComponent()));
        return rightTabs;
    }

    private EditorTabbedPane initBottomPane() {
        EditorTabbedPane tabbedPane = new EditorTabbedPane(this, SwingConstants.SOUTH);
        tabbedPane.addTab(initTimelineTab(tabbedPane.getComponent()));
        tabbedPane.addTab(initConsoleTab(tabbedPane.getComponent()));
        return tabbedPane;
    }

    private Tab initTablesTab(JTabbedPane tabbedPane) {
        projectTreeTab = new ProjectTreeTab(this, tabbedPane);
        addModelChangeListener(projectTreeTab);
        return projectTreeTab;
    }

    private Tab initConsoleTab(JTabbedPane tabbedPane) {
        consoleTab = new ConsoleTab(this, tabbedPane);
        addModelChangeListener(consoleTab);
        return consoleTab;
    }

    private Tab initGaugesTab(JTabbedPane tabbedPane) {
        gaugesTab = new GaugesTab(this, tabbedPane);
        addModelChangeListener(gaugesTab);
        return gaugesTab;
    }

    private Tab initTimelineTab(JTabbedPane tabbedPane) {
        timelineTab = new TimelineTab(this, tabbedPane);
        addModelChangeListener(timelineTab);
        return timelineTab;
    }

    @Override
    public void dispose() {
        if (datalogThread != null) {
            datalogThread.cancel();
        }

        super.dispose();
    }

    public Window getWindowByComponent(JInternalFrame internalFrame) {
        return getOpenWindows().stream()
                .filter(x -> x.getComponent().equals(internalFrame))
                .findFirst().orElse(null);
    }

    public Window withWindowComponent(JInternalFrame internalFrame,
                                      Predicate<Window> predicate,
                                      Consumer<Window> action) {
        Window window = getWindowByComponent(internalFrame);

        if (window == null) {
            return null;
        }

        if (predicate.test(window)) {
            action.accept(window);
        }

        return window;
    }

    @SuppressWarnings("unchecked")
    public <W extends Window> W withWindowComponent(JInternalFrame internalFrame,
                                                    Class<W> windowClass,
                                                    Consumer<W> action) {
        Window window = getWindowByComponent(internalFrame);

        if (window == null) {
            return null;
        }

        if (!windowClass.isAssignableFrom(window.getClass())) {
            return null;
        }

        action.accept((W)window);

        return (W)window;
    }

    public Window withWindowComponent(JInternalFrame internalFrame,
                                      Consumer<Window> action) {
        return withWindowComponent(internalFrame, w -> true, action);
    }

    public EditHistory getEditHistory() {
        return activeWindow != null ? activeWindow.getHistory() : null;
    }

    public WindowHistory getWindowHistory() {
        return windowHistory;
    }

    @Override
    public void internalFrameOpened(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameClosing(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameClosed(InternalFrameEvent e) {
        withWindowComponent(e.getInternalFrame(), (window) -> {
            synchronized (openWindows) {
                openWindows.remove(window);
            }

            getWindowMenu().update();

            if (window instanceof TableEditor) {
                openedTables.remove(((TableEditor)window).getTable());
            } else if (window instanceof TableDefinitionEditor) {
                openedTableDefs.remove(((TableDefinitionEditor)window).getTable());
            } else if (window instanceof ParameterEditor) {
                openedParameters.remove(((ParameterEditor)window).getParameter());
            } else if (window instanceof FormatEditor) {
                openedFormats.remove(((FormatEditor)window).getFormat());
            } else if (window instanceof GraphEditor) {
                openedGraphs.remove(((GraphEditor) window).getGraph());
            } else if (window instanceof DTCEditor) {
                openedDTCs.remove(((DTCEditor) window).getCalibration());
            }
        });
    }

    private void setActiveWindow(Window window) {
        Window lastWindow = this.activeWindow;
        if (window != lastWindow) {
            boolean liveWindow = window instanceof LiveWindow || lastWindow instanceof LiveWindow;
            this.activeWindow = window;

            if (liveWindow) {
                updateParameters();
            }

            // The toolbar may care about undo/redo
            toolbar.update();
        }
    }

    @Override
    public void internalFrameIconified(InternalFrameEvent e) {
        if (this.activeWindow.getComponent() == e.getInternalFrame()) {
            setActiveWindow(null);
        }
    }

    @Override
    public void internalFrameDeiconified(InternalFrameEvent e) {
        Window window = getWindowByComponent(e.getInternalFrame());

        if (window != null && activeWindow != window) {
            if (!window.getComponent().isSelected()) {
                window.focus();
            }

            setActiveWindow(window);
        }
    }

    @Override
    public void internalFrameActivated(InternalFrameEvent e) {
        Window window = getWindowByComponent(e.getInternalFrame());

        if (window != null && lastDeactivatedWindow != window && windowHistory.isRemembering()) {
            windowHistory.remember(new WindowAction(this, lastDeactivatedWindow, window));
            toolbar.update();
        }

        getWindowMenu().update();

        if (window != null) {
            setActiveWindow(window);
        }

        withWindowComponent(e.getInternalFrame(), TableEditor.class, (w) -> tableFocused(w.getTable()));
    }

    @Override
    public void internalFrameDeactivated(InternalFrameEvent e) {
        if (windowHistory.isRemembering()) {
            lastDeactivatedWindow = getWindowByComponent(e.getInternalFrame());
        }
        getWindowMenu().update();
    }

    public void saveUiSettings() {
        Settings.getAll().save();
    }

    public void exit() {
        if (closing()) {
            saveUiSettings();
            dispose();
        }
    }

    public void undo() {
        Window focusedWindow = activeWindow;
        if (focusedWindow == null) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            withWaitCursor(() -> {
                try {
                    // Undo the last operation
                    focusedWindow.getHistory().undo();

                    // Make sure the window is focused
                    focusedWindow.focus();
                } catch (IllegalStateException ex) {
                    // Ignore; nothing to undo
                } catch (Exception ex) {
                    Log.ui().log(Level.WARNING,
                            "Problem undoing operation on window \"" + focusedWindow.getTitle() + "\"", ex);
                }
            });
        });
    }

    public void redo() {
        Window focusedWindow = activeWindow;
        if (focusedWindow == null) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            withWaitCursor(() -> {
                try {
                    // Redo the last un-did operation
                    focusedWindow.getHistory().redo();

                    // Make sure the window is focused
                    focusedWindow.focus();
                } catch (IllegalStateException ex) {
                    // Ignore; nothing to redo
                } catch (Exception ex) {
                    Log.ui().log(Level.WARNING,
                            "Problem redoing operation on window \"" + focusedWindow.getTitle() + "\"", ex);
                }
            });
        });
    }

    public void tableFocused(Table table) {
        projectTreeTab.onItemOpened(table);
    }

    public TableEditor getActiveTableEditor(Table realTable) {
        return openedTables.get(realTable);
    }

    public boolean isDirty() {
        return dirty;
    }

    public void setDirty(boolean dirty) {
        if (this.dirty != dirty) {
            this.dirty = dirty;
            updateTitle();
            toolbar.update();
        }
    }

    public GraphEditor getGraphWindow() {
        return getOpenWindows(GraphEditor.class).stream().findFirst().orElse(null);
    }

    public DatalogWindow getDataLoggingWindow() {
        return getOpenWindows(DatalogWindow.class).stream().findFirst().orElse(null);
    }

    public DatalogWindow openDataLogging() {
        DatalogWindow dataLoggingWindow = getDataLoggingWindow();

        if (dataLoggingWindow == null) {
            dataLoggingWindow = new DatalogWindow(this);
            openWindow(dataLoggingWindow);
        }

        dataLoggingWindow.focus();

        return dataLoggingWindow;
    }

    public CANDebugWindow getCanLoggingWindow() {
        return getOpenWindows(CANDebugWindow.class).stream().findFirst().orElse(null);
    }

    public void openCanLogging() {
        CANDebugWindow canLoggingWindow = getCanLoggingWindow();

        if (canLoggingWindow == null) {
            canLoggingWindow = new CANDebugWindow(this);
            openWindow(canLoggingWindow);
        }

        canLoggingWindow.focus();
    }

    public void openDTCs() {
        Calibration calibration = getCalibration();
        if (calibration == null) {
            Errors.show(this, "Failed to Open DTCs", "No calibration is selected.");
            return;
        }

        DTCEditor opened;

        opened = openedDTCs.get(calibration);

        if (opened == null) {
            opened = withWaitCursor(() -> {
                OS os;
                try {
                    os = calibration.getOS();
                } catch (Exception e) {
                    Errors.show(this, "Failed to Open DTCs", "Failed to load OS for calibration "
                            + calibration.getName() + "!", e);
                    return null;
                }

                List<SupportedDTC> supportedDTCS;
                try {
                    supportedDTCS = os.getSupportedDTC();
                } catch (Exception e) {
                    Errors.show(this, "Failed to Open DTCs", "Failed to load supported DTCs for calibration "
                            + calibration.getName() + "!", e);
                    return null;
                }

                return openWindow(new DTCEditor(this, calibration, supportedDTCS));
            });

            if (opened == null) {
                return;
            }
        }

        opened.focus();

        openedDTCs.put(calibration, opened);
    }

    public void flashCalibration() {
        withWaitCursorAsync(() -> getConnectionManager().requireConnection(SessionType.NORMAL).ifPresent(c -> {
            try {
                preventAutoDatalogging = true;
                flashCalibration(c);
            } finally {
                preventAutoDatalogging = false;
            }
        }));
    }

    private void flashCalibration(Connection connection) {
        try {
            connection.changeConnectionMode(IDLE);
        } catch (IOException | TimeoutException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        Platform platform;

        try {
            platform = connection.identify();
        } catch (Exception e) {
            Errors.show(this, "Problem Identifying Vehicle", "Failed to identify vehicle!", e);
            return;
        }

        /**
         * This shouldn't happen on any production connection types.
         */
        if (platform == null) {
            Errors.show(this, "Problem Identifying Vehicle", "Failed to identify vehicle!",
                    new NullPointerException("Identify platform returned null"));
            return;
        }

        Calibration calibration = getCalibration();

        boolean invalidChecksum = false;

        Checksum checksum = platform.getChecksum(calibration);
        if (checksum != null) {
            try {
                invalidChecksum = !checksum.validate(calibration);
            } catch (IOException e) {
                Errors.show(getParent(), "Invalid Checksum", "Problem validating checksum!", e);
                return;
            }

            if (invalidChecksum && calibration.isReadonly()) {
                Errors.show(getParent(), "Invalid Checksum", "The checksum for the " + calibration.getName() +
                        " calibration is invalid, but it is read-only, so it can't be corrected.");
                return;
            }

            if (invalidChecksum && JOptionPane.showConfirmDialog(this,
                    "<html>The checksum for the <b>" + calibration.getName() + "</b> calibration is incorrect.<br/>This can happen " +
                            "when you modify its contents. Would you like to correct the checksum?</html>",
                    "Start Recalibration",
                    JOptionPane.YES_NO_OPTION,
                    WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
                Log.ui().log(Level.INFO, "Recalibration canceled.");
                return;
            }
        }

        if (JOptionPane.showConfirmDialog(this,
                "<html>WARNING! You are about to flash a calibration to the currently connected vehicle:<br/><br/>" +
                        "Vehicle: <b>" + platform.getVehicle().toString() + "</b><br/>" +
                        "Calibration to send: <b>" + calibration.getName() + "</b><br/>" +
                        "Calibration's variant: <b>" + calibration.getVariant().getName() + "</b><br/>" +
                        "<br/>" +
                        "Please double-check that the above platform matches what you are connected to. DO NOT " +
                        "disconnect your OBD2 device or turn off the vehicle's power once recalibration starts.<br/>" +
                        "Start recalibration?</html>",
                "Start Recalibration",
                JOptionPane.YES_NO_OPTION,
                WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            Log.ui().log(Level.INFO, "Recalibration canceled.");
            return;
        }

        ProgressDialog progressDialog = new ProgressDialog(
                this,
                "Reprogramming vehicle",
                "Reprogramming vehicle with " + calibration + " calibration...",
                false
        );

        AtomicBoolean failed = new AtomicBoolean(false);
        Jobs.fork(() -> progressDialog.setVisible(true));

        if (invalidChecksum) {
            withWaitCursor(() -> {
                progressDialog.updateProgress("Correcting checksum...", 0f);
                try {
                    checksum.correct(calibration);
                } catch (Exception e) {
                    Errors.show(this, "Checksum Failure", "Failed to correct checksum!", e);
                    failed.set(true);
                }
            });
        }

        if (failed.get()) {
            progressDialog.setVisible(false);
            return;
        }

        if (failed.get()) {
            progressDialog.setVisible(false);
            return;
        }

        Thread flashThread = Jobs.fork(() -> withWaitCursor(() -> {
            try {
                connection.writeCalibration(platform, calibration, progressDialog);
            } catch (FlashException flashException) {
                Errors.show(this,
                        flashException.getResult().getState().getTitle(),
                        flashException.getResult().getState().getMessage(),
                        flashException);
                failed.set(true);
                return;
            } catch (Exception other) {
                Errors.show(this, "Problem Recalibrating Vehicle", "Failed to recalibrate vehicle!", other);
                failed.set(true);
                return;
            } finally {
                SwingUtilities.invokeLater(() -> progressDialog.setVisible(false));
            }

            if (!failed.get()) {
                JOptionPane.showConfirmDialog(null,
                        "<html>Recalibration of the <b>" + calibration.getName() + "</b> calibration is complete.<br/>" +
                                "It is typically recommended that you restart the vehicle to complete the re-flash process.</html>",
                        "Recalibration Complete",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.INFORMATION_MESSAGE);

                Jobs.fork(() -> {
                    try {
                        connection.changeConnectionMode(IDLE);
                    } catch (IOException | TimeoutException | InterruptedException e) {
                        Log.can().log(Level.WARNING,
                                "Failed to return to an idle connection after recalibration", e);
                    }
                });
            }
        }));

        Jobs.fork(() -> {
            try {
                Robot hal;
                hal = new Robot();

                Random random = new Random();
                while (flashThread.isAlive()) {
                    hal.delay(5_000);
                    Point point = MouseInfo.getPointerInfo().getLocation();

                    int x = random.nextBoolean() ? -1 : 1;
                    int y = random.nextBoolean() ? -1 : 1;

                    hal.mouseMove(point.x + x, point.y + y);
                    hal.mouseMove(point.x, point.y);
                }
            } catch (Exception e) {
                Log.ui().log(Level.WARNING, "Problem running robot thread to keep machine awake", e);
            }
        });
    }

    public void addModelChangeListener(ModelChangeListener listener) {
        this.modelChangeListeners.add(listener);
    }

    public void removeModelChangeListener(ModelChangeListener listener) {
        this.modelChangeListeners.remove(listener);
    }

    @Override
    public void mouseDragged(MouseEvent e) {

    }

    @Override
    public void mouseMoved(MouseEvent e) {

    }

    @Override
    public void keyTyped(KeyEvent e) {

    }

    @Override
    public void keyPressed(KeyEvent e) {
        if (e.isControlDown()) {
            if (e.getKeyCode() == KeyEvent.VK_LEFT) {
                if (windowHistory.canUndo()) {
                    windowHistory.undo();
                    toolbar.update();
                }
            } else if (e.getKeyCode() == KeyEvent.VK_RIGHT) {
                if (windowHistory.canRedo()) {
                    windowHistory.redo();
                    toolbar.update();
                }
            }
        }
    }

    @Override
    public void keyReleased(KeyEvent e) {

    }

    @Override
    public void onSessionOpened(UDSConnection connection, UDSSession session) {
        postStatus("Opened session with CAN device.");
    }

    public void updateParameters() {
        Jobs.fork(() -> {
            connectionManager.getConnection(ConnectionFeature.DATALOG).ifPresent(this::updateParameters);
        });
    }

    private void updateParameters(Connection connection) {
        try {
            if (connection.getSessionType() == SessionType.NORMAL) {
                connection.setParameters(getCalibration().getVariant(), getLoggingParameters());
            }
        } catch (Exception e) {
            Log.can().log(Level.WARNING, "Problem defining logging parameters with connection", e);
        }
    }

    @Override
    public void onConnectionModeChanged(UDSConnection connection, ConnectionMode oldMode, ConnectionMode newMode) {
        if (newMode != ConnectionMode.DISCONNECTED) {
            postStatus("Changed connection mode to " + newMode);
        }

        if (footer != null) {
            footer.setConnected(newMode != null && newMode != ConnectionMode.DISCONNECTED);
        }

        if (newMode == ConnectionMode.DATALOG) {
            updateParameters(connection);

            if (datalogThread == null || datalogThread.isCanceled()) {
                datalogThread = new HighPrecisionThread(5L, Settings.DATALOG_FREQUENCY::get, this::sendReadFrame);
                datalogThread.setPriority(Thread.MAX_PRIORITY);
                datalogThread.start();
            }

            if (noDataThread == null || !noDataThread.isAlive()) {
                noDataThread = new Thread(this::noDataThread);
                noDataThread.setName("No Data Thread");
                noDataThread.setDaemon(true);
                noDataThread.setPriority(Thread.MIN_PRIORITY);
                noDataThread.start();
            }
        } else {
            if (datalogThread != null) {
                datalogThread.cancel();
                datalogThread = null;
            }
        }
    }

    private void noDataThread() {
        while (isDisplayable()) {
            synchronized (dataLock) {
                try {
                    dataLock.wait(DATA_TIMEOUT_MILLIS);
                } catch (InterruptedException e) {
                    Log.ui().log(Level.SEVERE, "No data thread interrupted", e);
                }

                if (System.currentTimeMillis() - lastFrameRead >= DATA_TIMEOUT_MILLIS) {
                    onMemoryFrameRead(getConnectionManager().getConnection().orElse(null),
                            new MemoryFrame());
                }
            }
        }
    }

    /**
     * Called when Atlas intends to send a memory frame read request.
     */
    private void sendReadFrame() {
        if (preventAutoDatalogging) {
            return;
        }

        Connection connection = getConnectionManager().getConnection()
                .filter(c -> c.getConnectionMode() == ConnectionMode.DATALOG)
                .orElse(null);

        HighPrecisionThread datalogThread = this.datalogThread;

        if (connection == null) {
            // This indicates we are not actively in a datalog session, so cancel the parent thread
            if (Thread.currentThread() == datalogThread) {
                datalogThread.cancel();
            }
            return;
        }

        // Otherwise, if the connection mode isn't changing and isn't spying, request a memory frame to be read.
        if (!connection.isConnectionModeChanging() && !connection.isSpying()) {
            try {
                synchronized (dataLock) {
                    connection.readFrame();
                    dataLock.notify();
                }
            } catch (UDSNegativeResponseException nre) {
                Log.can().log(Level.FINE, "Problem reading frame", nre);
            } catch (Exception readException) {
                try {
                    connection.disconnect();
                } catch (Exception changeException) {
                    readException.addSuppressed(changeException);
                } finally {
                    if (datalogThread != null) {
                        datalogThread.cancel();
                    }
                }

                Log.can().log(Level.WARNING, "Problem reading memory frame", readException);
            }
        }
    }

    public ConnectionManager getConnectionManager() {
        return connectionManager;
    }

    /**
     * Fired when any memory frame is read and about to be returned to the caller of UDSConnection.readFrame().
     * This is important to be handled at the Editor level, as there are several features in Atlas that require hearing
     * about memory frames, i.e. table editors for live cross-hairs, gauges, and the data logger for recording them.
     *
     * @param connection connection firing the event.
     * @param frame memory frame that was read.
     */
    @Override
    public void onMemoryFrameRead(Connection connection, MemoryFrame frame) {
        if (frame.getParameters().isEmpty()) {
            return;
        }

        lastFrameRead = System.currentTimeMillis();

        getOpenWindows(MemoryFrameListener.class).forEach(w -> w.onMemoryFrame(frame));

        gaugesTab.onMemoryFrame(frame);
    }

    /**
     * Fired when any UDS frame is read and about to be handled on any connection we have attached a listener to so far.
     *
     * This method should discard any frames read from connections that are not the active connection.
     *
     * @param connection connection firing the event.
     * @param read frame that was read.
     */
    @Override
    public void onUDSFrameRead(UDSConnection connection, UDSFrame read) {
        CANDebugWindow canLoggingWindow = getCanLoggingWindow();
        if (canLoggingWindow != null) {
            canLoggingWindow.onUDSFrameRead(read);
        }
    }

    /**
     * Fired when any UDS frame is about to be written on any connection we have attached a listener to so far.
     *
     * This method should discard any frames written to connections that are not the active connection.
     *
     * @param connection connection firing the event.
     * @param write frame that will be written.
     */
    @Override
    public void onUDSFrameWrite(UDSConnection connection, UDSFrame write) {
        CANDebugWindow canLoggingWindow = getCanLoggingWindow();
        if (canLoggingWindow != null) {
            canLoggingWindow.onUDSFrameWrite(write);
        }
    }

    /**
     * Fired when the connection is about to close.
     * @param connection connection that closed
     */
    @Override
    public void onDisconnected(Connection connection) {
        footer.setConnected(false);

        getOpenWindows(ConnectionListener.class)
                .forEach(w -> w.onDisconnected(connection));

        postStatus("CAN device disconnected.");

        ensureAutoConnecting();
    }

    public void fireModelChange(Model model, ChangeType changeType) {
        if (model != Model.PROJECT || changeType != ChangeType.ADDED) {
            setDirty(true);
        }

        if (model == Model.GAUGE || model == Model.PROJECT
                || (model == Model.PARAMETER && changeType == ChangeType.MODIFIED)
                || (model == Model.FORMAT && changeType == ChangeType.MODIFIED)) {
            updateParameters();
        }

        getOpenWindows(ModelChangeListener.class).forEach(listener -> listener.onModelChanged(model, changeType));
        modelChangeListeners.forEach(listener -> listener.onModelChanged(model, changeType));
    }

    public MemoryAddress getDefaultMemoryAddress(MemoryType... types) {
        return getDefaultMemoryAddress(getCalibration(), types);
    }

    public MemoryAddress getDefaultMemoryAddress(Calibration calibration, MemoryType... types) {
        EnumSet<MemoryType> enumSet = EnumSet.noneOf(MemoryType.class);
        Collections.addAll(enumSet, types);
        return getDefaultMemoryAddress(calibration, enumSet);
    }

    public MemoryAddress getDefaultMemoryAddress(EnumSet<MemoryType> types) {
        return getDefaultMemoryAddress(getCalibration(), types);
    }

    public MemoryAddress getDefaultMemoryAddress(Calibration calibration, EnumSet<MemoryType> types) {
        MemorySection section = getProject().getSections().stream()
                .filter(s -> types.contains(s.getMemoryType()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No sections with defined type(s): " + types));

        return MemoryAddress.builder()
                .withSection(section)
                .withOffset(calibration.getVariant(), section.getBaseAddress())
                .build();
    }

    @Override
    public void onRemembered(Edit action) {
        toolbar.update();
    }

    @Override
    public void onUndoCompleted(Edit action) {
        toolbar.update();
    }

    @Override
    public void onRedoCompleted(Edit action) {
        toolbar.update();
    }

    public class ConnectionManager extends AbstractConnectionManager {
        @Override
        protected Project getProject() {
            return Editor.this.project;
        }

        @Override
        protected ConnectionType getConnectionType() {
            return Editor.this.getProject().getConnectionType();
        }

        @Override
        protected void handleException(Throwable ex) {
            Log.can().log(Level.SEVERE, "Problem establishing session with ECU", ex);

            Throwable rootCause = ExceptionUtils.getRootCause(ex);
            String message = rootCause instanceof DeviceNotFoundException dnfException ?
                    "Device not found: " + dnfException.getName() : ex.getMessage();

            Errors.show(getParent(), "Connection failed",
                    "Failed to establish connection with ECU!", message,
                    ex);
        }

        @Override
        protected Connection createConnection(ConnectionType type, J2534DeviceProvider<?> provider) {
            Connection connection = super.createConnection(type, provider);

            // Attach ourselves to a UDS session by adding Editor as a listener
            // This enables us to receive events that are useful for CAN debug, data logging, etc.
            if (connection instanceof UDSConnection udsConnection) {
                udsConnection.addListener(Editor.this);
            }

            return connection;
        }
    }

    private class AutoConnectThread extends Thread {
        AutoConnectThread() {
            setName("AutoConnect Thread");
            setDaemon(true);
        }

        @Override
        public void run() {
            long sleepTime;
            Connection connection;
            while (project != null && !interrupted()) {
                if (project.getConnectionType() != null && Settings.AUTO_CONNECT.get()) {
                    try {
                        connection = connectionManager.getConnection().orElse(null);
                        if (connection == null || ((connection.getConnectionMode() == ConnectionMode.DISCONNECTED ||
                            connection.getConnectionMode() == IDLE) && !connection.isConnectionModeChanging()
                            && connection.getSessionType() != SessionType.SPY && !preventAutoDatalogging)) {
                            connection = connectionManager.tryConnection(SessionType.NORMAL);
                            connection.changeConnectionMode(ConnectionMode.DATALOG);
                            continue;
                        } else {
                            sleepTime = 1000L;
                        }
                    } catch (Throwable e) {
                        Log.can().log(Level.FINE, "Problem auto-connecting", e);
                        sleepTime = 2000L;
                    }
                } else {
                    sleepTime = 4000L;
                }

                try {
                    sleep(sleepTime);
                } catch (InterruptedException e) {
                    break;
                }
            }
        }
    }
}
