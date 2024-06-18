package com.github.manevolent.atlas.ui.component.datalog;

import com.github.manevolent.atlas.connection.*;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.GaugeSet;
import com.github.manevolent.atlas.model.MemoryParameter;
import com.github.manevolent.atlas.settings.Setting;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.*;
import com.github.manevolent.atlas.ui.behavior.ConnectionListener;
import com.github.manevolent.atlas.ui.behavior.GaugeSetListener;
import com.github.manevolent.atlas.ui.behavior.MemoryFrameListener;
import com.github.manevolent.atlas.ui.component.menu.datalog.FileMenu;
import com.github.manevolent.atlas.ui.component.menu.datalog.ViewMenu;
import com.github.manevolent.atlas.ui.component.toolbar.DatalogToolbar;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.google.common.collect.Lists;
import org.apache.commons.lang.StringEscapeUtils;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.time.Instant;
import java.util.*;
import java.util.List;
import java.util.Timer;

import java.util.function.IntConsumer;
import java.util.logging.Level;

import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;

public class DatalogWindow extends Window implements InternalFrameListener, ChangeListener,
        MemoryFrameListener, ConnectionListener, GaugeSetListener {
    private JMenuBar menubar;
    private FileMenu fileMenu;

    private DatalogToolbar toolbar;
    private JTabbedPane tabbedPane;

    private Timer paintTimer;

    private List<DatalogPage> pages = new ArrayList<>();
    private DatalogPage activePage;
    private DatalogPage recordingPage;

    public DatalogWindow(Editor editor) {
        super(editor);
    }

    @Override
    protected void preInitComponent(JInternalFrame window) {
        super.preInitComponent(window);

        window.addInternalFrameListener(this);
        window.setDefaultCloseOperation(JInternalFrame.DO_NOTHING_ON_CLOSE);
        window.addInternalFrameListener(new InternalFrameAdapter() {
            @Override
            public void internalFrameClosing(InternalFrameEvent e) {
                if (pages.stream().noneMatch(DatalogPage::isDirty)) {
                    dispose();
                    return;
                }

                focus();

                if (JOptionPane.showConfirmDialog(getParent(),
                        "You have unsaved data logs. Do you want to close them?",
                        "Unsaved Data Logs",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
                    return;
                }

                pages.clear();
                dispose();
            }
        });

        Inputs.bind(this.getComponent().getRootPane(),
                "record",
                this::toggleRecording,
                KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this.getComponent().getRootPane(),
                "maximize",
                () -> {
                    DatalogPage page = getActivePage();
                    if (page != null) {
                        page.fitToScreen();
                    }
                },
                KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this.getComponent().getRootPane(),
                "zoomOut",
                () -> {
                    DatalogPage page = getActivePage();
                    if (page != null) {
                        page.zoomOut();
                    }
                },
                KeyStroke.getKeyStroke(KeyEvent.VK_O, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_O, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this.getComponent().getRootPane(),
                "zoomIn",
                () -> {
                    DatalogPage page = getActivePage();
                    if (page != null) {
                        page.zoomIn();
                    }
                },
                KeyStroke.getKeyStroke(KeyEvent.VK_I, InputEvent.CTRL_DOWN_MASK),
                KeyStroke.getKeyStroke(KeyEvent.VK_I, InputEvent.META_DOWN_MASK)); // OSX
        Inputs.bind(this.getComponent().getRootPane(),
                "left",
                () -> {
                    DatalogPage page = getActivePage();
                    if (page != null) {
                        page.moveLeft();
                    }
                },
                KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, 0)); // OSX
        Inputs.bind(this.getComponent().getRootPane(),
                "right",
                () -> {
                    DatalogPage page = getActivePage();
                    if (page != null) {
                        page.moveRight();
                    }
                },
                KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, 0)); // OSX
    }

    private JMenuBar initMenu() {
        JMenuBar menuBar = new JMenuBar();

        menuBar.add((fileMenu = new FileMenu(this)).getComponent());
        menuBar.add(new ViewMenu(this).getComponent());

        return menuBar;
    }

    public DatalogPage getRecordingPage() {
        return recordingPage;
    }

    public void setRecordingPage(DatalogPage page) {
        toolbar.setPaused(page == null);

        if (page == null && this.recordingPage != null) {
            // Recording stopped
            int index = tabbedPane.indexOfComponent(this.recordingPage);
            if (index >= 0) {
                tabbedPane.setIconAt(index, null);
            }
        }

        this.recordingPage = page;

        if (page != null) {
            // Recording started
            page.setPaused(false, false);

            int index = tabbedPane.indexOfComponent(page);
            if (index >= 0) {
                tabbedPane.setIconAt(index, Icons.get(CarbonIcons.RECORDING_FILLED, Color.RED));
            }
        }

        updateTitle();
    }

    public Optional<Connection> ensureConnection() {
        try {
            return getEditor().withWaitCursor(() ->
                    getParent().getConnectionManager().requireConnection(ConnectionFeature.DATALOG));
        } catch (Exception ex) {
            return Optional.empty();
        }
    }

    public DatalogPage getActivePage() {
        return activePage;
    }

    public void setActivePage(DatalogPage page) {
        if (this.activePage != page && this.activePage != null) {
            this.activePage.deactivated();
        }

        if (page != null) {
            page.activated();
        } else {
            toolbar.setT(0);
        }

        this.activePage = page;

        updateTitle();

        if (page != null) {
            page.revalidate();
            page.repaint();
        }
    }

    private void addPage(DatalogPage page) {
        pages.add(page);

        tabbedPane.addTab(page.getTitle(), Icons.get(CarbonIcons.CATALOG), page);
        tabbedPane.setSelectedComponent(page);

        tabbedPane.revalidate();
        tabbedPane.repaint();
    }

    public void deletePage(DatalogPage datalogPage) {
        int index = pages.indexOf(datalogPage);
        if (index < 0) {
            return;
        }

        if (recordingPage != null && !recordingPage.isPaused()) {
            if (JOptionPane.showConfirmDialog(getParent(),
                    "Do you want to stop recording?",
                    "Close Datalog",
                    JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
                return;
            }

            stopRecording();
        }

        tabbedPane.remove(index);
        pages.remove(datalogPage);

        tabbedPane.revalidate();
        tabbedPane.repaint();
    }

    public void updateTitle(DatalogPage datalogPage) {
        int index = pages.indexOf(datalogPage);
        if (index < 0) {
            return;
        }

        SwingUtilities.invokeLater(() -> {
            tabbedPane.setTitleAt(index, datalogPage.getTitle());
            tabbedPane.revalidate();
            tabbedPane.repaint();
        });
    }

    public void toggleRecording() {
        if (recordingPage != null) {
            stopRecording();
        } else {
            startRecording();
        }

        updateTitle();
    }

    public void startRecording() {
        if (isRecording()) {
            return;
        }

        ensureConnection().ifPresent(connection -> {
            String suggestedName = Instant.now().toString().replaceAll(":", "-");
            String newDatalogName = JOptionPane.showInputDialog(getParent(),
                    "Specify a name for this recording", suggestedName);
            if (newDatalogName == null || newDatalogName.isBlank()) {
                return;
            }

            DatalogPage page = new DatalogPage(this);
            page.setName(newDatalogName);
            addPage(page);
            setRecordingPage(page);
        });
    }

    public void stopRecording() {
        if (recordingPage != null) {
            DatalogPage page = recordingPage;
            setRecordingPage(null);
            tabbedPane.setSelectedComponent(page);
            page.setPaused(true, true);

            updateTitle();
        }
    }

    @Override
    protected void initComponent(JInternalFrame window) {
        window.setLayout(new BorderLayout());
        window.add((toolbar = new DatalogToolbar(this)).getComponent(), BorderLayout.NORTH);
        window.setJMenuBar(menubar = initMenu());


        tabbedPane = new JTabbedPane();
        tabbedPane.putClientProperty("JTabbedPane.tabClosable", true);
        tabbedPane.putClientProperty("JTabbedPane.tabIconPlacement", SwingConstants.TRAILING);
        tabbedPane.putClientProperty("JTabbedPane.tabCloseCallback",
                (IntConsumer) (i) -> deletePage(pages.get(i)));

        window.add(tabbedPane, BorderLayout.CENTER);

        setActivePage(null);
        setRecordingPage(null);

        updateTitle();

        tabbedPane.addChangeListener(this);
    }

    @Override
    public String getTitle() {
        DatalogPage active = getActivePage();
        if (active != null) {
            return "Data Logging - " + active.getName();
        } else {
            return "Data Logging";
        }
    }

    @Override
    public Icon getIcon() {
        if (isRecording()) {
            return Icons.get(CarbonIcons.RECORDING_FILLED, Color.RED);
        } else {
            return Icons.get(CarbonIcons.CHART_AVERAGE, getTextColor());
        }
    }

    @Override
    public void reload() {
        updateTitle();
    }

    public DatalogToolbar getToolbar() {
        return toolbar;
    }

    private void startTimer() {
        if (paintTimer == null) {
            Timer timer = new Timer("Update");
            timer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    if (DatalogWindow.this.activePage != null) {
                        tabbedPane.repaint();
                    }
                }
            }, 0L, 1000L / 40L);
        }
    }

    private void stopTimer() {
        if (paintTimer != null) {
            paintTimer.cancel();
            paintTimer.purge();
            paintTimer = null;
        }
    }

    @Override
    public void internalFrameOpened(InternalFrameEvent e) {
        startTimer();
    }

    @Override
    public void internalFrameClosing(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameClosed(InternalFrameEvent e) {
        stopTimer();
    }

    @Override
    public void internalFrameIconified(InternalFrameEvent e) {
        stopTimer();
    }

    @Override
    public void internalFrameDeiconified(InternalFrameEvent e) {
        startTimer();
    }

    @Override
    public void internalFrameActivated(InternalFrameEvent e) {
        startTimer();
    }

    @Override
    public void internalFrameDeactivated(InternalFrameEvent e) {
        stopTimer();
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        setActivePage((DatalogPage) tabbedPane.getSelectedComponent());
    }

    public boolean isRecording() {
        return recordingPage != null;
    }

    private static void writeCell(String value, Writer writer) throws IOException {
        String escaped = StringEscapeUtils.escapeCsv(value);
        writer.write("\"" +escaped + "\",");
    }

    private static void writeRow(Writer writer, String... cells) throws IOException {
        for (String string : cells) {
            writeCell(string, writer);
        }
        writer.write("\r\n");
    }

    public void saveDatalog(boolean includeAll) {
        DatalogPage page = getActivePage();
        if (page == null) {
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        FileNameExtensionFilter def = new FileNameExtensionFilter("Comma-separated value file (*.csv)", "csv");
        fileChooser.addChoosableFileFilter(def);
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
        fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("Log files (*.log)", "log"));
        fileChooser.setFileFilter(def);
        fileChooser.setSelectedFile(new File(page.getName() + ".csv"));
        fileChooser.setDialogTitle("Export Datalog");
        if (fileChooser.showSaveDialog(getParent()) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();

            Set<MemoryParameter> parameters = page.getParameters();

            try (FileWriter writer = new FileWriter(file)) {
                writeCell("Time", writer);
                for (MemoryParameter parameter : parameters) {
                    writeCell(parameter.getName(), writer);
                }
                writer.write("\r\n");

                for (MemoryFrame frame : Lists.reverse(page.getFrames())) { // Reversed for time order (asc. desired)
                    boolean inView = frame.getInstant().isAfter(page.getLeft()) &&
                            frame.getInstant().isBefore(page.getRight());

                    if (!inView && !includeAll) {
                        continue;
                    }

                    writeCell(frame.getInstant().toString(), writer);
                    for (MemoryParameter parameter : parameters) {
                        byte[] data = frame.getData(parameter);
                        if (data != null) {
                            writeCell(parameter.getScale().format(parameter.getValue(data)), writer);
                        } else {
                            writeCell("", writer);
                        }
                    }
                    writer.write("\r\n");
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            page.setDirty(false);

            Log.ui().log(Level.INFO, "Datalog exported to " + file.getPath());
        }
    }

    @Override
    public void onMemoryFrame(MemoryFrame frame) {
        DatalogPage recordingPage = getRecordingPage();
        if (recordingPage != null) {
            recordingPage.addFrame(frame);
        }
    }

    @Override
    public void onDisconnected(Connection connection) {
        stopRecording();
    }

    @Override
    public void onGaugeSetChanged(GaugeSet oldGaugeSet, GaugeSet newGaugeSet) {
        stopRecording();
    }

    @Override
    public void onGaugeSetModified(GaugeSet gaugeSet) {

    }
}
