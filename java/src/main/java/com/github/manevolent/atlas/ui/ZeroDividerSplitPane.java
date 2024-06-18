package com.github.manevolent.atlas.ui;

import com.formdev.flatlaf.ui.FlatSplitPaneUI;
import com.github.manevolent.atlas.settings.IntegerSetting;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import javax.swing.border.Border;

import javax.swing.plaf.SplitPaneUI;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.plaf.basic.BasicSplitPaneUI;
import javax.swing.text.JTextComponent;
import java.awt.*;

public class ZeroDividerSplitPane extends JSplitPane {
    private static final int dividerDragSize = 9;
    private static final int dividerDragOffset = 4;

    private boolean dividerEnabled = true;

    public ZeroDividerSplitPane() {
        getUI();
        setDividerSize(1);
        setContinuousLayout(true);
    }

    public ZeroDividerSplitPane(int orientation) {
        super(orientation);
        getUI();
        setDividerSize(1);
        setContinuousLayout(true);
    }

    private Integer get() {
        IntegerSetting setting = getLocationSetting();
        if (setting != null) {
            return setting.get();
        } else {
            return null;
        }
    }

    private void set(int value) {
        IntegerSetting setting = getLocationSetting();
        if (setting != null) {
            setting.set(value);
        }
    }

    @Override
    public void setName(String name) {
        super.setName(name);

        Integer dividerLocation = get();
        if (dividerLocation != null) {
            setDividerLocation(dividerLocation);
        }
    }

    public ZeroDividerSplitPane(int orientation, Component left, Component right) {
        super(orientation);
        getUI();
        setLeftComponent(left);
        setRightComponent(right);
        setDividerSize(1);
        setContinuousLayout(true);
    }

    public boolean isDividerEnabled() {
        return dividerEnabled;
    }

    public void setDividerEnabled(boolean dividerEnabled) {
        this.dividerEnabled = dividerEnabled;
    }

    @Override
    public int getDividerSize() {
        return super.getDividerSize();
    }

    @Override
    public void updateUI() {
        setUI(new FlatSplitPaneUI() {
            @Override
            public BasicSplitPaneDivider createDefaultDivider() {
                return new ZeroSizeDivider(this);
            }
        });
        revalidate();
    }

    @Override
    public void doLayout() {
        super.doLayout();

        SplitPaneUI ui = getUI();
        if (ui instanceof BasicSplitPaneUI basicSplitPaneUI) {
            BasicSplitPaneDivider divider = basicSplitPaneUI.getDivider();
            Rectangle bounds = divider.getBounds();
            divider.setBounds(recalculateBounds(bounds));
        }
    }

    private Rectangle recalculateBounds(Rectangle bounds) {
        if (orientation == HORIZONTAL_SPLIT) {
            bounds.x -= dividerDragOffset;
            bounds.width = dividerDragSize;
        } else {
            bounds.y -= dividerDragOffset;
            bounds.height = dividerDragSize;
        }

        return bounds;
    }

    protected IntegerSetting getLocationSetting() {
        String name = getName();
        if (name == null) {
            return null;
        }

        return new IntegerSetting(getClass().getName(), name, "location");
    }

    private class ZeroSizeDivider extends BasicSplitPaneDivider {
        public ZeroSizeDivider( BasicSplitPaneUI ui ) {
            super( ui );
            super.setBorder( null );
            setBackground(Color.gray.darker());
        }

        @NotNull
        @Override
        public Cursor getCursor() {
            if (isDividerEnabled()) {
                return super.getCursor();
            } else {
                return Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR);
            }
        }

        @Override
        public void setBorder( Border border ) {
            // ignore
        }

        @Override
        public boolean contains(int x, int y) {
            if (getDividerSize() <= 0 || !isDividerEnabled()) {
                return false;
            }

            Point location = getLocation();
            x += location.x;
            y += location.y;

            if (isTarget(getLeftComponent(), x, y) || isTarget(getRightComponent(), x, y)) {
                return false;
            }

            return getBounds().contains(x, y);
        }

        public boolean isTarget(Component search, int x, int y) {
            Component component = getRelativeComponent(search, x, y);
            return component instanceof JScrollBar
                    || component instanceof JButton
                    || component instanceof JCheckBox
                    || component instanceof JTextComponent;
        }

        public Component getRelativeComponent(Component search, int x, int y) {
            if (search instanceof Container container) {
                return container.findComponentAt(x - search.getX(), y - search.getY());
            } else {
                return search.getComponentAt(x - search.getX(), y - search.getY());
            }
        }

        @Override
        public void paint(Graphics g) {
            g.setColor(getBackground());
            if(orientation == HORIZONTAL_SPLIT) {
                g.drawLine(dividerDragOffset, 0, dividerDragOffset, getHeight() - 1 );
            } else {
                g.drawLine(0, dividerDragOffset, getWidth() - 1, dividerDragOffset);
            }
        }

        @Override
        protected void dragDividerTo(int location) {
            if (isDividerEnabled()) {
                super.dragDividerTo(location + dividerDragOffset);
            }
        }

        @Override
        protected void finishDraggingTo(int location) {
            if (isDividerEnabled()) {
                int offset = location + dividerDragOffset;
                super.finishDraggingTo(offset);
                set(getDividerLocation());
            }
        }
    }
}
