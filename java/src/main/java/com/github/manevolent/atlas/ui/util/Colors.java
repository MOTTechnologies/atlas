package com.github.manevolent.atlas.ui.util;

import java.awt.*;

public class Colors {
    public static Color withAlpha(Color color, int alpha) {
        return new Color(color.getRed(), color.getGreen(), color.getBlue(), alpha);
    }

    public static Color interpolate(float min, Color minColor, float max, Color maxColor, float value) {
        float red_a = minColor.getRed() / 255f;
        float green_a = minColor.getGreen() / 255f;
        float blue_a = minColor.getBlue() / 255f;

        float red_b = maxColor.getRed() / 255f;
        float green_b = maxColor.getGreen() / 255f;
        float blue_b = maxColor.getBlue() / 255f;

        float q = (value - min) / (max - min);
        if (Float.isNaN(q)) {
            q = 0f;
        }

        q = Math.min(1f, Math.max(q, 0f));

        float red = red_a + ((red_b - red_a) * q);
        float green = green_a + ((green_b - green_a) * q);
        float blue = blue_a + ((blue_b - blue_a) * q);
        return new Color(red, green, blue);
    }
}
