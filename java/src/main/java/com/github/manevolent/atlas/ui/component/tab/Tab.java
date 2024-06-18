package com.github.manevolent.atlas.ui.component.tab;

import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.behavior.ModelChangeListener;
import com.github.manevolent.atlas.ui.component.EditorComponent;
import com.github.manevolent.atlas.ui.Editor;

import javax.swing.*;

public abstract class Tab extends EditorComponent<JPanel> implements ModelChangeListener {
    private JTabbedPane pane;

    protected Tab(Editor editor, JTabbedPane pane) {
        super(editor);

        this.pane = pane;
    }

    public abstract String getTitle();

    public abstract Icon getIcon();

    @Override
    public void onModelChanged(Model model, ChangeType changeType) {
        if (model == Model.PROJECT && changeType == ChangeType.ADDED) {
            reinitialize();
        }
    }

    protected JTabbedPane getPane() {
        return pane;
    }

    public void focus() {
        pane.setSelectedComponent(getComponent());
    }

    @Override
    public JPanel newComponent() {
        JPanel panel = new JPanel();
        return panel;
    }
}
