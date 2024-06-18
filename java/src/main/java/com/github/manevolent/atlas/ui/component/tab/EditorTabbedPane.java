package com.github.manevolent.atlas.ui.component.tab;

import com.github.manevolent.atlas.settings.BooleanSetting;
import com.github.manevolent.atlas.settings.IntegerSetting;
import com.github.manevolent.atlas.settings.Setting;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.ZeroDividerSplitPane;
import com.github.manevolent.atlas.ui.component.EditorComponent;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.Arrays;

/**
 * A reusable tabbed pane in the Editor. These panes are typically docked to a side (N/S/E/W) and offer some
 * basic view manipulation like hiding and so forth.
 */
public class EditorTabbedPane extends EditorComponent<JTabbedPane> implements ChangeListener, AncestorListener {
    private final BooleanSetting minimizedState;

    private static final int minimumSize = 50;
    private final int anchor;

    private Dimension savedSize;
    private boolean minimized;

    private JButton minimizeButton;

    public EditorTabbedPane(Editor editor, int anchor, Tab... tabs) {
        super(editor);

        this.anchor = anchor;
        this.minimizedState = new BooleanSetting(true, EditorTabbedPane.class.getName(), anchor, "minimized");

        Integer lastSize = new IntegerSetting(EditorTabbedPane.class.getName(), anchor, "size").get();

        if (lastSize != null) {
            if (anchor == SwingUtilities.NORTH || anchor == SwingUtilities.SOUTH) {
                this.savedSize = new Dimension(Integer.MAX_VALUE, lastSize);
            } else {
                this.savedSize = new Dimension(lastSize, Integer.MAX_VALUE);
            }
        }

        Arrays.stream(tabs).forEach(this::addTab);
    }

    @Override
    protected JTabbedPane newComponent() {
        JTabbedPane tabbedPane = new JTabbedPane() { };
        tabbedPane.addChangeListener(this);
        tabbedPane.addAncestorListener(this);
        return tabbedPane;
    }

    @Override
    protected void initComponent(JTabbedPane component) {
        component.addChangeListener(e -> component.grabFocus());
    }

    @Override
    protected void postInitComponent(JTabbedPane tabbedPane) {
        Ikon icon;
        if (anchor == SwingUtilities.SOUTH) {
            icon = CarbonIcons.ARROW_DOWN;
        } else if (anchor == SwingUtilities.WEST) {
            icon = CarbonIcons.ARROW_LEFT;
        } else if (anchor == SwingUtilities.EAST) {
            icon = CarbonIcons.ARROW_RIGHT;
        } else if (anchor == SwingUtilities.NORTH) {
            icon = CarbonIcons.ARROW_UP;
        } else {
            icon = CarbonIcons.ERROR_FILLED; // Error
        }

        minimizeButton = Inputs.nofocus(Layout.emptyBorder(Inputs.button(icon, () -> setMinimized(true))));
        minimizeButton.setBackground(new JPanel().getBackground());
        minimizeButton.setToolTipText("Hide");
        minimizeButton.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                int width = minimizeButton.getWidth();
                int height = minimizeButton.getHeight();
                int size = Math.max(width, height);
                if (width != height) {
                    minimizeButton.setSize(new Dimension(size, size));
                    minimizeButton.setPreferredSize(new Dimension(size, size));
                    tabbedPane.revalidate();
                }
            }
        });

        JPanel trailingPanel = new JPanel(new BorderLayout());
        Layout.emptyBorder(2, 2, 2, 2, trailingPanel);

        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        tabbedPane.setTabPlacement(JTabbedPane.TOP);
        trailingPanel.add(minimizeButton, BorderLayout.EAST);

        // See: https://www.formdev.com/flatlaf/client-properties/ for documentation on these constants
        tabbedPane.putClientProperty("JTabbedPane.tabRotation", "auto");
        tabbedPane.putClientProperty("JTabbedPane.trailingComponent", trailingPanel);
        tabbedPane.putClientProperty("JTabbedPane.tabInsets", new Insets(0, 10, 0, 10));
        tabbedPane.putClientProperty("JTabbedPane.tabHeight", 24);
        tabbedPane.putClientProperty("JTabbedPane.tabsPopupPolicy", "asNeeded");
        tabbedPane.putClientProperty("JTabbedPane.scrollButtonsPolicy", "asNeeded");
    }

    public void addTab(Tab tab) {
        JTabbedPane tabbedPane = getComponent();
        tabbedPane.addTab(tab.getTitle(), tab.getIcon(), tab.getComponent());
        Rectangle bounds = tabbedPane.getUI().getTabBounds(tabbedPane, 0);

        if (anchor == SwingUtilities.NORTH || anchor == SwingUtilities.SOUTH) {
            tabbedPane.setMinimumSize(new Dimension(Integer.MAX_VALUE, (int) bounds.getHeight()));
        } else {
            tabbedPane.setMinimumSize(new Dimension((int) bounds.getWidth(), Integer.MAX_VALUE));
        }
    }

    protected JSplitPane getSplitPane() {
        JTabbedPane tabbedPane = getComponent();
        JSplitPane splitPane = null;
        Component parent = tabbedPane;
        while ((parent = parent.getParent()) != null) {
            if (parent instanceof JSplitPane) {
                splitPane = (JSplitPane) parent;
                break;
            } else if (parent instanceof Window || parent instanceof JInternalFrame) {
                return null;
            }
        }

        return splitPane;
    }

    public void setMinimized(boolean minimized) {
        if (this.minimized != minimized) {
            setMinimizedImpl(minimized);
        }
    }

    private void setMinimizedImpl(boolean minimized) {
        JTabbedPane tabbedPane = getComponent();

        this.minimized = minimized;
        Settings.set(minimizedState, minimized);
        minimizeButton.setVisible(!minimized);

        if (anchor == SwingConstants.WEST) {
            tabbedPane.setTabPlacement(minimized ? JTabbedPane.LEFT : JTabbedPane.TOP);
        } else if (anchor == SwingConstants.EAST) {
            tabbedPane.setTabPlacement(minimized ? JTabbedPane.RIGHT : JTabbedPane.TOP);
        }

        if (minimized) {
            minimize();
        } else {
            restore();
        }

        JSplitPane splitPane = getSplitPane();
        if (splitPane instanceof ZeroDividerSplitPane zdsp) {
            zdsp.setDividerEnabled(!minimized);
        }

        tabbedPane.revalidate();
        tabbedPane.repaint();
    }

    public boolean isMinimized() {
        return this.minimized;
    }

    private void updateSize() {
        JTabbedPane tabbedPane = getComponent();
        JSplitPane splitPane = getSplitPane();

        if (splitPane != null && isMinimized()) {
            Rectangle bounds = tabbedPane.getUI().getTabBounds(tabbedPane, 0);

            if (anchor == SwingConstants.SOUTH) {
                splitPane.setDividerLocation((int) (splitPane.getHeight() - bounds.getHeight() - splitPane.getDividerSize()));
                tabbedPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, (int) bounds.getHeight()));
                tabbedPane.setPreferredSize(new Dimension(Integer.MAX_VALUE, (int) bounds.getHeight()));
            } else if (anchor == SwingConstants.NORTH) {
                splitPane.setDividerLocation((int) (splitPane.getHeight()));
                tabbedPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, (int) bounds.getHeight()));
                tabbedPane.setPreferredSize(new Dimension(Integer.MAX_VALUE, (int) bounds.getHeight()));
            } else if (anchor == SwingConstants.WEST) {
                splitPane.setDividerLocation((int) (bounds.getWidth() + splitPane.getDividerSize()));
                tabbedPane.setMaximumSize(new Dimension((int) bounds.getWidth(), Integer.MAX_VALUE));
                tabbedPane.setPreferredSize(new Dimension((int) bounds.getWidth(), Integer.MAX_VALUE));
            } else if (anchor == SwingConstants.EAST) {
                splitPane.setDividerLocation((int) (splitPane.getWidth() - bounds.getWidth() - splitPane.getDividerSize()));
                tabbedPane.setMaximumSize(new Dimension((int) bounds.getWidth(), Integer.MAX_VALUE));
                tabbedPane.setPreferredSize(new Dimension((int) bounds.getWidth(), Integer.MAX_VALUE));
            } else {
                throw new UnsupportedOperationException();
            }
        }
    }

    private void minimize() {
        JTabbedPane tabbedPane = getComponent();
        savedSize = tabbedPane.getSize();
        tabbedPane.setSelectedIndex(-1);
        updateSize();
    }

    private void restore() {
        JTabbedPane tabbedPane = getComponent();

        if (anchor == SwingUtilities.NORTH || anchor == SwingUtilities.SOUTH) {
            tabbedPane.setMinimumSize(new Dimension(0, minimumSize));
            tabbedPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        } else {
            tabbedPane.setMinimumSize(new Dimension(minimumSize, 0));
            tabbedPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        }

        if (savedSize == null) {
            savedSize = tabbedPane.getPreferredSize();
        }

        tabbedPane.setSize(savedSize);
        tabbedPane.setPreferredSize(savedSize);

        savedSize = tabbedPane.getSize();

        JSplitPane splitPane = getSplitPane();
        if (splitPane != null) {
            double dividerLocation;
            if (anchor == SwingConstants.SOUTH) {
                dividerLocation = (splitPane.getHeight() - savedSize.getHeight() - splitPane.getDividerSize());
            } else if (anchor == SwingConstants.WEST) {
                dividerLocation = savedSize.getWidth() + splitPane.getDividerSize();
            } else if (anchor == SwingConstants.EAST) {
                dividerLocation = (splitPane.getWidth() - savedSize.getWidth() - splitPane.getDividerSize());
            } else {
                throw new UnsupportedOperationException();
            }

            splitPane.setDividerLocation((int) dividerLocation);
        }
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        JTabbedPane tabbedPane = getComponent();
        boolean showingTab = tabbedPane.getSelectedIndex() >= 0;
        if (showingTab) {
            setMinimized(false);
        }
    }

    @Override
    public void ancestorAdded(AncestorEvent event) {
        JSplitPane splitPane = getSplitPane();
        if (splitPane != null) {
            splitPane.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) {
                    updateSize();
                }
            });
        }

        setMinimizedImpl(Settings.get(minimizedState, false));
    }

    @Override
    public void ancestorRemoved(AncestorEvent event) {

    }

    @Override
    public void ancestorMoved(AncestorEvent event) {

    }
}
