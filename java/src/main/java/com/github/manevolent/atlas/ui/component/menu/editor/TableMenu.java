package com.github.manevolent.atlas.ui.component.menu.editor;

import com.github.manevolent.atlas.ApplicationMetadata;
import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.model.storage.ProjectStorageType;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.NewRomForm;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Menus;
import com.github.manevolent.atlas.ui.util.Tools;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;

public class TableMenu extends EditorMenu {
    public TableMenu(Editor editor) {
        super(editor);
    }

    @Override
    protected void initComponent(JMenu menu) {
        menu.setText("Table");

        menu.add(Menus.item(CarbonIcons.DATA_TABLE_REFERENCE, Table.codeColor, "New Table...",
                e -> getEditor().newTable()));

        menu.addSeparator();

        menu.add(Menus.item(CarbonIcons.DATA_VIS_4, "Define Table by Address...",
                e -> Tools.defineTableByAddress(getEditor())));

        menu.add(Menus.item(CarbonIcons.SEARCH, "Find New Tables...",
                e -> Tools.findTables(getEditor())));

        menu.add(Menus.item(CarbonIcons.NETWORK_3, "Match Tables...",
                e -> Tools.matchTables(getEditor())));
    }
}
