package com.github.manevolent.atlas.ui.component.gauge;

import com.github.manevolent.atlas.model.Gauge;

import com.github.manevolent.atlas.ui.util.Fonts;

import java.awt.*;

public class RPMUIGauge extends UIGaugeComponent {
    public RPMUIGauge(Gauge gauge) {
        super(gauge);
    }

    private Point getPoint(float angle, float distance) {
        double a = Math.toRadians(angle);
        return new Point((int) (Math.cos(a) * distance), (int) (Math.sin(a) * distance));
    }

    @Override
    public void paint(Graphics g) {
        super.paint(g);

        Graphics2D g2d = (Graphics2D) g;

        float min = getScale().getMinimum(), max = getScale().getMaximum();
        int size = getWidth() - getInsets().left - getInsets().right;
        int centerX = getWidth() / 2;
        int centerY = getHeight() / 2;

        // Draw tacks
        g2d.setColor(Color.GRAY);
        g2d.translate(centerX, centerY);
        for (int tackAngle = 0; tackAngle <= 270; tackAngle += 27) {
            Point far = getPoint(135 + tackAngle, size / 2f);
            Point near = getPoint(135 + tackAngle, (size / 2f) - 8);
            g2d.drawLine(near.x, near.y, far.x, far.y);
        }
        g2d.setColor(Color.GRAY.darker());
        for (float tackAngle = 27 / 2f; tackAngle <= 270; tackAngle += 27) {
            Point far = getPoint(135 + tackAngle, size / 2f);
            Point near = getPoint(135 + tackAngle, (size / 2f) - 5);
            g2d.drawLine(near.x, near.y, far.x, far.y);
        }
        g2d.translate(-centerX, -centerY);

        // Draw arcs
        g2d.setStroke(new BasicStroke(5, BasicStroke.CAP_SQUARE, BasicStroke.JOIN_MITER));

        g2d.setPaint(Color.GRAY);
        g.drawArc(getInsets().left, getInsets().top,
                getWidth() - getInsets().left - getInsets().right,
                getHeight() - getInsets().top - getInsets().bottom,
                180 + 45, -270);

        float value = getValue();
        float clampedValue = Math.max(min, Math.min(max, value));
        float valueRatio = (clampedValue - getMinimumValue()) / (getMaximumValue() - getMinimumValue());
        valueRatio = Math.max(0f, Math.min(1f, valueRatio));

        float angle = 270 * valueRatio;
        g2d.setPaint(new GradientPaint(0, 0, getMinimumColor(), getWidth(), 0, getMaximumColor()));
        g.drawArc(getInsets().left, getInsets().top,
                size,
                getHeight() - getInsets().top - getInsets().bottom,
                180 + 45, Math.round(-angle));

        // Draw pointer
        float pointerAngle = 135 + angle;
        Polygon pointer = new Polygon();
        Point left = getPoint(pointerAngle - 90, 4);
        pointer.addPoint(left.x, left.y);
        Point right = getPoint(pointerAngle + 90, 4);
        pointer.addPoint(right.x, right.y);

        g2d.setStroke(new BasicStroke(1, BasicStroke.CAP_SQUARE, BasicStroke.JOIN_MITER));

        Point tip = getPoint(pointerAngle, size / 2f);
        pointer.addPoint(tip.x, tip.y);

        g2d.setColor(Color.RED);
        g2d.translate(centerX, centerY);
        g2d.fill(pointer);
        g2d.translate(-centerX, -centerY);

        // Draw value text
        g2d.setColor(Fonts.getTextColor());
        g2d.setFont(Fonts.VALUE_FONT);

        String string = getScale().formatPreferred(value) + getUnit().getPreferredUnit().getText();
        FontMetrics metrics = g2d.getFontMetrics(g2d.getFont());
        int width = metrics.stringWidth(string);
        g2d.drawString(
                string,
                centerX - (width / 2),
                getHeight() - getInsets().bottom - metrics.getHeight()
        );

        paintErrorMessage(g);
    }
}
