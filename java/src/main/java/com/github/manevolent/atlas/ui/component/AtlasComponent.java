package com.github.manevolent.atlas.ui.component;

import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.ui.Editor;

import javax.swing.*;
import java.awt.*;
import java.util.logging.Level;

public abstract class AtlasComponent<T extends Component, E> {
    private final E parent;
    private final T component;

    private final ThreadLocal<Boolean> initializing = new ThreadLocal<>();
    private boolean initialized = false;

    protected AtlasComponent(E editor) {
        initializing.set(false);
        this.parent = editor;
        component = newComponent();
    }

    /**
     * Gets the currently active project model.
     * @return project instance.
     */
    public Project getProject() {
        return getEditor().getProject();
    }

    /**
     * Gets the main editor window.
     * @return editor instance.
     */
    public abstract Editor getEditor();

    /**
     * Called to construct a new component.
     * @return new component instance.
     */
    protected abstract T newComponent();

    public T getComponent() {
        Boolean initializingValue = initializing.get();
        if (!initialized && (initializingValue == null || !initializingValue)) {
            Log.ui().log(Level.FINER, "Initializing component " + getClass().getName() + "...");
            try {
                initializing.set(true);
                preInitComponent(getComponent());
                initComponent(getComponent());
                postInitComponent(getComponent());
                Log.ui().log(Level.FINER, "Initialized component " + getClass().getName() + ".");
            } finally {
                initializing.set(false);
            }

            initialized = true;
        }

        return component;
    }

    public E getParent() {
        return parent;
    }

    protected void preInitComponent(T component) { }
    protected abstract void initComponent(T component);
    protected void postInitComponent(T component) { }

    protected Component getContent() {
        return getComponent();
    }

    public void reinitialize() {
        T component = getComponent();

        Component content = getContent();
        if (component instanceof JComponent) {
            ((JComponent) content).removeAll();
        }

        initComponent(component);
        postInitComponent(component);

        content.revalidate();
        content.repaint();
    }

}
