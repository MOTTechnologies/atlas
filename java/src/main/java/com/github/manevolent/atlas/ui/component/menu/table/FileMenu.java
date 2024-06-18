package com.github.manevolent.atlas.ui.component.menu.table;

import com.github.manevolent.atlas.model.Table;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.table.TableEditor;
import com.github.manevolent.atlas.ui.settings.TableEditorSettingPage;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;

import static javax.swing.JOptionPane.QUESTION_MESSAGE;

public class FileMenu extends TableEditorMenu {
    public FileMenu(TableEditor editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JMenu menu) {
        menu.setText("File");

        JMenuItem saveTable = Menus.item(CarbonIcons.EXPORT, "Export Table...", e -> {
            TableEditor.exportTable(getEditor(), getParent().getTable(), getParent().getCalibration());
        });
        menu.add(saveTable);

        menu.addSeparator();

        JMenuItem editTable = Menus.item(CarbonIcons.CHART_CUSTOM, "Edit Table Definition", e -> {
            getEditor().openTableDefinition(getParent().getTable());
        });
        menu.add(editTable);

        JMenuItem copyTable = Menus.item(CarbonIcons.COPY, "Copy Table Definition...", e -> {
            Table table =  getParent().getTable();
            String newTableName = (String) JOptionPane.showInputDialog(getEditor(),
                    "Specify a name", table.getName(),
                    QUESTION_MESSAGE, null, null, table.getName() + " (Copy)");

            if (newTableName == null || newTableName.isBlank()) {
                return;
            }

            Table newTable = table.copy();
            newTable.setName(newTableName);
            getEditor().openTableDefinition(newTable);
        });
        menu.add(copyTable);

        menu.addSeparator();

        menu.add(Menus.item(CarbonIcons.SETTINGS, "Settings", (e) -> {
            getEditor().openEditorSettings(TableEditorSettingPage.class);
        }));

        menu.addSeparator();

        JMenuItem close = new JMenuItem("Close");
        close.addActionListener(e -> getParent().dispose());
        menu.add(close);
    }
}
