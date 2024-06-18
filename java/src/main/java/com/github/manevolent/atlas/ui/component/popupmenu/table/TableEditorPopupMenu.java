package com.github.manevolent.atlas.ui.component.popupmenu.table;

import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.popupmenu.PopupMenu;

import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;

import java.awt.*;

public class TableEditorPopupMenu extends PopupMenu<TableEditor> {
    public TableEditorPopupMenu(TableEditor editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JPopupMenu menu) {
        TableEditor tableEditor = getParent();

        menu.addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
                JTable table = tableEditor.getJTable();
                Point mousePosition = table.getMousePosition();
                if (mousePosition == null) {
                    return;
                }

                int row = table.rowAtPoint(mousePosition);
                int col = table.columnAtPoint(mousePosition);

                if (!table.isCellSelected(row, col)) {
                    table.changeSelection(row, col, false, false);
                }
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {

            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {

            }
        });

        menu.add(Menus.item(FontAwesomeSolid.FILE_DOWNLOAD,  "Apply other table...",
                (e) -> getParent().applyTable()));

        menu.addSeparator();

        menu.add(Menus.item(FontAwesomeSolid.TIMES, "Multiply...",
                (e) -> getParent().scaleSelection()));
        menu.add(Menus.item(FontAwesomeSolid.DIVIDE, "Divide...",
                (e) -> getParent().divideSelection()));
        menu.add(Menus.item(FontAwesomeSolid.PLUS, "Add...",
                (e) -> getParent().addSelection()));
        menu.add(Menus.item(FontAwesomeSolid.PERCENTAGE, "Scale...",
                (e) -> getParent().scaleSelection()));
        menu.add(Menus.item(FontAwesomeSolid.EQUALS, "Average",
                (e) -> getParent().averageSelection()));
        menu.add(Menus.item(CarbonIcons.CONTAINER_SOFTWARE, "Interpolate",
                (e) -> getParent().interpolateSelection()));
    }
}
