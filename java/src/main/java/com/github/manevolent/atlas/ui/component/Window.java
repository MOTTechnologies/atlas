package com.github.manevolent.atlas.ui.component;

import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.behavior.EditHistory;

import javax.swing.*;
import javax.swing.event.InternalFrameAdapter;
import javax.swing.event.InternalFrameEvent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.beans.PropertyVetoException;

public abstract class Window extends EditorComponent<JInternalFrame> {
    private final EditHistory history = new EditHistory();
    private boolean iconified = false;

    protected Window(Editor editor) {
        super(editor);
    }

    public EditHistory getHistory() {
        return history;
    }

    @Override
    protected void preInitComponent(JInternalFrame component) {
        super.preInitComponent(component);
        component.setTitle(getTitle());
        component.addInternalFrameListener(new InternalFrameAdapter() {
            @Override
            public void internalFrameDeiconified(InternalFrameEvent e) {
                iconified = false;
            }

            @Override
            public void internalFrameIconified(InternalFrameEvent e) {
                iconified = true;
            }
        });
    }

    @Override
    protected void postInitComponent(JInternalFrame component) {
        if (!component.isVisible()) {
            component.pack();

            component.setPreferredSize(component.getPreferredSize());
            component.setSize(component.getPreferredSize());

            try {
                component.setMaximum(Settings.OPEN_WINDOWS_MAXIMIZED.get());
            } catch (PropertyVetoException e) {
                // Ignore
            }
        }

        updateTitle();

        if (component.isVisible()) {
            component.revalidate();
            component.repaint();
        }
    }

    public abstract String getTitle();

    public abstract Icon getIcon();

    public void updateTitle() {
        JInternalFrame internalFrame = getComponent();

        Icon icon = getIcon();
        if (icon != null) {
            internalFrame.setFrameIcon(icon);
        }

        internalFrame.setTitle(getTitle());
    }

    public abstract void reload();

    @Override
    protected JInternalFrame newComponent() {
        JInternalFrame internalFrame = new JInternalFrame() {
            @Override
            public void setTitle(String title) {
                super.setTitle(title);
                Window.this.getParent().getWindowMenu().update();
            }
        };

        internalFrame.setMinimumSize(new Dimension(300, 200));
        internalFrame.setPreferredSize(new Dimension(300, 200));

        internalFrame.setClosable(true);
        internalFrame.setMaximizable(true);
        internalFrame.setIconifiable(true);
        internalFrame.setResizable(true);

        internalFrame.addInternalFrameListener(new InternalFrameAdapter() {
            @Override
            public void internalFrameOpened(InternalFrameEvent e) {
                opened();
            }
        });

        return internalFrame;
    }

    protected void opened() {

    }

    public boolean isMinimized() {
        return iconified;
    }

    public void focus() {
        JDesktopPane desktop = getParent().getDesktop();
        JInternalFrame component = getComponent();

        if (component.getParent() != null && !component.getParent().equals(desktop)) {
            return;
        }

        try {
            component.setIcon(false);
        } catch (PropertyVetoException e) {
            throw new RuntimeException(e);
        }

        component.setVisible(true);
        desktop.moveToFront(component);
        component.grabFocus();

        try {
            component.setSelected(true);
        } catch (PropertyVetoException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Component getContent() {
        return getComponent().getContentPane();
    }

    @Override
    public String toString() {
        return getTitle();
    }

    public void dispose() {
        getComponent().dispose();
    }

    public boolean close() {
        JInternalFrame component = getComponent();
        component.doDefaultCloseAction();
        return component.isClosed();
    }
}
