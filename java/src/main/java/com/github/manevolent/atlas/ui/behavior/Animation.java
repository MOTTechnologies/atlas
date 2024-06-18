package com.github.manevolent.atlas.ui.behavior;

import com.github.manevolent.atlas.logging.Log;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.logging.Level;

public abstract class Animation extends Thread {
    private final JComponent component;

    public Animation(JComponent component) {
        this.component = component;
    }

    public JComponent getComponent() {
        return component;
    }

    public abstract boolean isAnimating();

    protected abstract void update(JComponent component);

    protected void onUpdated() {
        component.repaint();
    }

    public void cancel() {
        interrupt();
    }

    @Override
    public void run() {
        while (!interrupted() && isAnimating()) {
            try {
                SwingUtilities.invokeAndWait(() -> {
                    update(component);
                    onUpdated();
                });
            } catch (InterruptedException  e) {
                break;
            } catch (Exception e) {
                Log.ui().log(Level.WARNING, "Problem updating animation for " + component, e);
            }
        }
    }
}
