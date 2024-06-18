package com.github.manevolent.atlas.ui.component.menu.datalog;

import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.datalog.DatalogWindow;
import com.github.manevolent.atlas.ui.settings.DatalogSettingPage;
import com.github.manevolent.atlas.ui.settings.TableEditorSettingPage;
import com.github.manevolent.atlas.ui.util.Menus;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;

public class FileMenu extends DatalogMenu {
    public FileMenu(DatalogWindow editor) {
        super(editor);
    }

    @Override
    public Editor getEditor() {
        return getParent().getEditor();
    }

    @Override
    protected void initComponent(JMenu fileMenu) {
        fileMenu.setText("File");

        JMenuItem saveDatalog = new JMenuItem("Export Datalog...");
        saveDatalog.addActionListener(e -> {
            getParent().saveDatalog(true);
        });
        fileMenu.add(saveDatalog);

        JMenuItem saveVisible = new JMenuItem("Export Visible...");
        saveVisible.addActionListener(e -> {
            getParent().saveDatalog(false);
        });
        fileMenu.add(saveVisible);
        fileMenu.addSeparator();

        JMenuItem openDatalog = new JMenuItem("Open Datalog...");
        openDatalog.addActionListener(e -> {
        });
        fileMenu.add(openDatalog);

        fileMenu.addSeparator();

        fileMenu.add(Menus.item(CarbonIcons.SETTINGS, "Settings", (e) -> {
            getEditor().openEditorSettings(DatalogSettingPage.class);
        }));

        fileMenu.addSeparator();

        JMenuItem close = new JMenuItem("Close");
        close.addActionListener((e) -> {

        });

        JMenuItem exit = new JMenuItem("Exit");
        exit.addActionListener((e) -> getParent().getComponent().doDefaultCloseAction());
        fileMenu.add(exit);
    }
}
