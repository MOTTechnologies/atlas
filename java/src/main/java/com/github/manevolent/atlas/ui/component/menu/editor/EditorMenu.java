package com.github.manevolent.atlas.ui.component.menu.editor;

import com.formdev.flatlaf.util.SystemInfo;
import com.github.manevolent.atlas.ui.component.EditorComponent;
import com.github.manevolent.atlas.ui.Editor;
import org.kordamp.ikonli.swing.FontIcon;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

public abstract class EditorMenu extends EditorComponent<JMenu> {
    protected EditorMenu(Editor editor) {
        super(editor);
    }

    @Override
    protected JMenu newComponent() {
        return new JMenu();
    }

    @Override
    protected void initComponent(JMenu component) {

    }

    @Override
    protected void postInitComponent(JMenu component) {
        if (SystemInfo.isMacOS) {
            applyMenu(component, (item) -> {
                if (item != null && item.getIcon() instanceof FontIcon icon) {
                    icon.setIconColor(Color.WHITE);
                    item.setIcon(icon.toImageIcon());
                }
            });
        }
    }

    private void applyMenu(JMenu menu, Consumer<JMenuItem> consumer) {
        for (int i = 0; i < menu.getItemCount(); i ++) {
            JMenuItem menuItem = menu.getItem(i);
            consumer.accept(menuItem);
            if (menuItem instanceof JMenu subMenu) {
                applyMenu(subMenu, consumer);
            }
        }
    }
}
