package com.github.manevolent.atlas.ui.util;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.Rectangle2D;
import java.util.Arrays;

public class Fonts {
    public static final Font VALUE_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private static final String defaultConsoleFont = "Courier New";

    public static Color getTextColor() {
        return new JLabel().getForeground();
    }

    public static Font getTextFont() {
        return new JLabel().getFont();
    }

    public static FontMetrics getFontMetrics(Font font) {
        Canvas c = new Canvas();
        return c.getFontMetrics(font);
    }

    public static String[] getAvailableFontFamilyNames() {
        GraphicsEnvironment environment = GraphicsEnvironment.getLocalGraphicsEnvironment();
        return environment.getAvailableFontFamilyNames();
    }

    public static boolean isFontAvailable(String familyName) {
        return Arrays.binarySearch(getAvailableFontFamilyNames(), familyName) >= 0;
    }

    public static String getConsoleFontFamilyName() {
        return defaultConsoleFont;
    }

    public static <T extends Component> T bold(T component) {
        component.setFont(component.getFont().deriveFont(Font.BOLD));
        return component;
    }

    public static Font bold(Font font) {
        return font.deriveFont(Font.BOLD);
    }

    /**
     * Resizes the provided font to fit within the given area.
     *
     * @param g2d Graphics instance to work with.
     * @param baseFont base Font instance to work with, sized to the largest size desired.
     * @param width area width
     * @param height area height
     * @param string String to use when determining the ideal font size.
     * @return derived font that is the largest size to fit within the provided area.
     */
    public static Font resizeFont(Graphics2D g2d, Font baseFont, int width, int height, String string) {
        Font derived = baseFont;
        Rectangle2D bounds;
        for (float size = baseFont.getSize2D(); size > 0; size -= 0.5f) {
            derived = baseFont.deriveFont(size);
            bounds = g2d.getFontMetrics(derived).getStringBounds(string, g2d);
            if (bounds.getHeight() <= height && bounds.getWidth() <= width) {
                break;
            }
        }
        return derived;
    }
}
