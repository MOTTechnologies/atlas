package com.github.manevolent.atlas.ui.util;

import org.kordamp.ikonli.Ikon;

import javax.swing.*;
import java.awt.*;

public class Labels {

    public static JLabel text(String text, Font font) {
        JLabel label = new JLabel(text);
        label.setFont(font);
        return label;
    }

    public static JLabel text(String text) {
        JLabel label = new JLabel(text);
        return label;
    }

    public static JLabel boldText(Ikon icon, String text) {
        return Fonts.bold(text(icon, text));
    }

    public static JLabel boldText(String text) {
        return Fonts.bold(text(text));
    }

    public static JLabel darkerText(String text) {
        JLabel label = new JLabel(text);
        label.setForeground(label.getForeground().darker());
        return label;
    }

    public static JLabel text(String text, Color color) {
        JLabel label = new JLabel(text);
        label.setForeground(color);
        return label;
    }

    public static JLabel text(String text, Color color, Font font) {
        JLabel label = new JLabel(text);
        label.setFont(font);
        label.setForeground(color);
        return label;
    }

    public static JLabel text(Ikon icon, String text, Color color) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, color));
        label.setForeground(color);
        return label;
    }

    public static JLabel text(Ikon icon, String text, Color color, String toolTipText) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, color));
        label.setForeground(color);
        label.setToolTipText(toolTipText);
        return label;
    }

    public static JLabel text(Ikon icon, String text, Font font, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(font);
        label.setIcon(Icons.get(icon, color));
        label.setForeground(color);
        return label;
    }


    public static JLabel text(Ikon icon, String text, Font font, Color color, String toolTipText) {
        JLabel label = new JLabel(text);
        label.setFont(font);
        label.setIcon(Icons.get(icon, color));
        label.setForeground(color);
        label.setToolTipText(toolTipText);
        return label;
    }

    public static JLabel text(Ikon icon, String text) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, label.getForeground()));
        return label;
    }

    public static JLabel text(Ikon icon, Font font, String text) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, label.getForeground()));
        label.setFont(font);
        return label;
    }

    public static JLabel text(Ikon icon, String text, String toolTipText) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, label.getForeground()));
        label.setToolTipText(toolTipText);
        return label;
    }

    public static JLabel text(Ikon icon, Color iconColor, String text, Color color) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, iconColor));
        label.setForeground(color);
        return label;
    }

    public static JLabel text(Ikon icon, Color iconColor, String text) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, iconColor));
        return label;
    }

    public static JLabel boldText(Ikon icon, Color iconColor, String text) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, iconColor));
        return Fonts.bold(label);
    }

    public static JLabel text(Ikon icon, Color iconColor, Font font, String text, Color color) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, iconColor));
        label.setFont(font);
        label.setForeground(color);
        return label;
    }

    public static JLabel text(Ikon icon, Color iconColor, Font font, String text, Color color, String toolTipText) {
        JLabel label = new JLabel(text);
        label.setIcon(Icons.get(icon, iconColor));
        label.setFont(font);
        label.setForeground(color);
        label.setToolTipText(toolTipText);
        return label;
    }

    public static JLabel icon(Ikon icon) {
        JLabel label = new JLabel();
        label.setIcon(Icons.get(icon));
        return label;
    }
}
