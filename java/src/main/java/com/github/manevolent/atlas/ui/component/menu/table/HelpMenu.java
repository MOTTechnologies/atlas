package com.github.manevolent.atlas.ui.component.menu.table;

import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.table.TableEditor;

import javax.swing.*;

public class HelpMenu extends TableEditorMenu {
    public HelpMenu(TableEditor editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JMenu menu) {
        menu.setText("Help");
    }
}
