package com.github.manevolent.atlas.ui.component.popupmenu.graph;

import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.graph.GraphEditor;
import com.github.manevolent.atlas.ui.component.popupmenu.PopupMenu;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;

public class GraphPopupMenu extends PopupMenu<GraphEditor> {
    public GraphPopupMenu(GraphEditor editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JPopupMenu menu) {
        GraphEditor window = getParent();

        JMenu newMenu = new JMenu("Create Node");
        newMenu.setIcon(Icons.get(CarbonIcons.ADD));
        newMenu.add(Menus.item(CarbonIcons.DATA_TABLE_REFERENCE, "Table...", e -> window.newTableNode()));
        newMenu.add(Menus.item(CarbonIcons.SUMMARY_KPI, "Parameter...", e -> window.newParameterNode()));
        newMenu.addSeparator();
        newMenu.add(Menus.item(CarbonIcons.INFORMATION_FILLED, "Documentation", e -> window.newDocumentationNode()));
        menu.add(newMenu);

        //menu.addSeparator();


    }

    public void update() {
        reinitialize();
    }
}
