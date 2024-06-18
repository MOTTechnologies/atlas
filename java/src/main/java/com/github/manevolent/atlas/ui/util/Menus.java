package com.github.manevolent.atlas.ui.util;

import com.formdev.flatlaf.util.SystemInfo;
import org.kordamp.ikonli.Ikon;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;

public class Menus {

    public static JMenuItem item(Ikon ikon, String text, ActionListener actionListener) {
        JMenuItem menuItem = new JMenuItem(text);

        Color color = menuItem.getForeground();
        menuItem.setIcon(Icons.get(ikon, color, menuItem.getFont().getSize()));
        menuItem.addActionListener(actionListener);
        return menuItem;
    }

    public static JMenuItem item(Ikon ikon, Color iconColor, String text, ActionListener actionListener) {
        JMenuItem menuItem = new JMenuItem(text);
        menuItem.setIcon(Icons.get(ikon, iconColor, menuItem.getFont().getSize()));
        menuItem.addActionListener(actionListener);
        return menuItem;
    }

    public static JMenuItem item(String text, ActionListener actionListener) {
        JMenuItem menuItem = new JMenuItem(text);
        menuItem.addActionListener(actionListener);
        return menuItem;
    }

}
