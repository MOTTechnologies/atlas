package com.github.manevolent.atlas.ui.component.popupmenu.gauge;

import com.github.manevolent.atlas.model.MemoryParameter;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.gauge.UIGauge;
import com.github.manevolent.atlas.ui.component.popupmenu.PopupMenu;
import com.github.manevolent.atlas.ui.component.tab.GaugesTab;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.tree.TreeNode;

public class GaugePopupMenu extends PopupMenu<GaugesTab> {
    private final UIGauge ui;

    public GaugePopupMenu(GaugesTab tab, UIGauge ui) {
        super(tab);

        this.ui = ui;
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JPopupMenu menu) {
        JMenuItem header = new JMenuItem(ui.getGauge().toString());
        header.setEnabled(false);
        menu.add(header);
        menu.addSeparator();
        menu.add(Menus.item(CarbonIcons.EDIT, "Edit Gauge...", e -> getParent().editGauge(ui)));
        menu.add(Menus.item(CarbonIcons.COPY, "Copy Gauge...", e -> getParent().copyGauge(ui)));
        menu.addSeparator();
        menu.add(Menus.item(CarbonIcons.TRASH_CAN, "Delete Gauge", e -> getParent().deleteGauge(ui)));
        menu.addSeparator();

        MemoryParameter parameter = ui.getGauge().getParameter();
        menu.add(Menus.item(parameter.getTreeIcon(), "Edit Parameter...",
                e -> getEditor().openParameter(ui.getGauge().getParameter())));
    }
}
