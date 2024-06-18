package com.github.manevolent.atlas.ui.component.gauge;

import com.github.manevolent.atlas.model.Gauge;

import com.github.manevolent.atlas.ui.util.Fonts;

import java.awt.*;
import java.awt.geom.Rectangle2D;

public class NumberUIGauge extends UIGaugeComponent {
    private static final int pointerSize = 5;

    public NumberUIGauge(Gauge gauge) {
        super(gauge);
    }

    @Override
    protected Point getLabelLocation(Rectangle2D bounds) {
        Point defaultLocation = super.getLabelLocation(bounds);
        return new Point(defaultLocation.x, (int) ((getHeight() / 2) + 5 + 5 + 5 + bounds.getHeight()));
    }

    @Override
    public void paint(Graphics g) {
        super.paint(g);

        int centerX = getWidth() / 2;
        int centerY = getHeight() / 2;

        float min = getScale().getMinimum(), max = getScale().getMaximum();
        float value = getValue();
        float clampedValue = Math.max(min, Math.min(max, value));
        float valueRatio = (clampedValue - getMinimumValue()) / (getMaximumValue() - getMinimumValue());
        valueRatio = Math.max(0f, Math.min(1f, valueRatio));

        Color interpolatedColor = getColor(clampedValue);

        Graphics2D g2d = (Graphics2D) g;

        String string = getScale().formatPreferred(value) + getUnit().getPreferredUnit().getText();
        Font font = Fonts.resizeFont(g2d, Fonts.VALUE_FONT.deriveFont(32f),
                getWidth() - getInsets().left - getInsets().right,
                32,
                string);

        g2d.setColor(Fonts.getTextColor());
        g2d.setFont(font);

        FontMetrics metrics = g2d.getFontMetrics(font);
        Rectangle2D bounds = metrics.getStringBounds(string, g);
        int width = metrics.stringWidth(string);
        g2d.drawString(
                string,
                centerX - (width / 2),
                (int) (centerY - (bounds.getHeight() / 2))
        );

        int barWidth = getWidth() - getInsets().right - getInsets().left;

        // Draw rectangle
        g2d.setPaint(Color.GRAY);
        g2d.fillRect(getInsets().left, centerY, barWidth, 5);

        g2d.setPaint(new GradientPaint(0, 0, getMinimumColor(), getWidth(), 0, getMaximumColor()));

        int valueWidth = Math.round(barWidth * valueRatio);
        g2d.fillRect(getInsets().left, centerY, valueWidth, 5);

        // Draw pointer (the little colored triangle under the value bar)
        g2d.setColor(interpolatedColor);

        Graphics sub = g2d.create();
        sub.translate(getInsets().left, 0);
        Polygon polygon = new Polygon();
        polygon.addPoint(valueWidth, centerY + 5);
        polygon.addPoint(valueWidth - pointerSize, centerY + 5 + pointerSize);
        polygon.addPoint(valueWidth + pointerSize, centerY + 5 + pointerSize);
        sub.fillPolygon(polygon);

        paintErrorMessage(g);
    }
}
