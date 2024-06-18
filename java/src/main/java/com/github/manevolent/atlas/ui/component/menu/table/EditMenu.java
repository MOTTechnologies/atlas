package com.github.manevolent.atlas.ui.component.menu.table;

import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;

public class EditMenu extends TableEditorMenu {
    public EditMenu(TableEditor editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JMenu menu) {
        menu.setText("Edit");

        menu.add(Menus.item(CarbonIcons.DATA_TABLE, "Apply different table...", (e) -> getParent().applyTable()));
        menu.add(Menus.item(CarbonIcons.RESET, "Apply different calibration...", (e) -> getParent().applyCalibration()));
    }
}
