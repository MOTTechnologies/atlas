package com.github.manevolent.atlas.ui.component.gauge;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.Gauge;
import com.github.manevolent.atlas.ui.util.Colors;
import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Labels;
import org.jetbrains.annotations.NotNull;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;

public abstract class UIGaugeComponent extends JComponent implements UIGauge {
    private static final Dimension size = new Dimension(128, 128);
    private static final Insets insets = new Insets(5, 5, 5, 5);

    private final Gauge gauge;
    private float value;

    private boolean demo;
    private boolean canHighlight = true;
    private boolean receivingData = false;

    private final Border normalBorder = BorderFactory.createEmptyBorder(1, 1, 1, 1);
    private final Border highlightedBorder = BorderFactory.createDashedBorder(Color.GRAY, 1, 2, 2, true);
    private Border activeBorder = normalBorder;

    private Calibration calibration;

    public UIGaugeComponent(Gauge gauge) {
        this.gauge = gauge;

        setBorder(BorderFactory.createCompoundBorder(
                new Border() {
                    @Override
                    public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
                        activeBorder.paintBorder(c, g, x, y, width, height);
                    }

                    @Override
                    public Insets getBorderInsets(Component c) {
                        return activeBorder.getBorderInsets(c);
                    }

                    @Override
                    public boolean isBorderOpaque() {
                        return activeBorder.isBorderOpaque();
                    }
                },
                BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));

        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                if (canHighlight) {
                    activeBorder = highlightedBorder;
                } else {
                    activeBorder = normalBorder;
                }
                repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                activeBorder = normalBorder;
                repaint();
            }
        });

        setMinimumSize(size);
        setPreferredSize(size);
        setSize(size);

        setDoubleBuffered(true);

        setToolTipText(gauge.getParameter().getName());

        value = getMinimumValue();
    }

    public boolean canHighlight() {
        return canHighlight;
    }

    public void setCanHighlight(boolean highlight) {
        this.canHighlight = highlight;
    }

    public boolean isDemo() {
        return demo;
    }

    public void setDemo(boolean demo) {
        if (this.demo != demo) {
            this.demo = demo;
        }
    }

    public void setReceivingData(boolean receivingData) {
        this.receivingData = receivingData;
    }

    public boolean isReceivingData() {
        return receivingData;
    }

    public void setCalibration(Calibration calibration) {
        this.calibration = calibration;
    }

    public Calibration getCalibration() {
        return calibration;
    }

    @Override
    public Gauge getGauge() {
        return gauge;
    }

    @Override
    public UIGaugeComponent getComponent() {
        return this;
    }

    /**
     * The render location for the gauge's label string (name).
     * @param bounds the bounds of the label string to render
     * @return center point, or null if no gauge label should be drawn.
     */
    protected Point getLabelLocation(Rectangle2D bounds) {
        return new Point((getWidth() / 2) - (int) (bounds.getWidth() / 2), getHeight() - getInsets().bottom);
    }

    @Override
    public void paint(Graphics g) {
        super.paint(g);

        Graphics2D g2d = (Graphics2D) g;

        g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g2d.setRenderingHint(RenderingHints.KEY_COLOR_RENDERING, RenderingHints.VALUE_COLOR_RENDER_QUALITY);
        g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        String text = getGauge().getParameter().getName();
        Font font = Fonts.resizeFont(
                g2d,
                Fonts.getTextFont().deriveFont(10f),
                getWidth() - getInsets().left - getInsets().right, getHeight(),
                text);

        FontMetrics fontMetrics = g.getFontMetrics(font);
        g.setFont(font);
        g.setColor(Fonts.getTextColor());

        Rectangle2D bounds = fontMetrics.getStringBounds(text, g2d);
        Point labelLocation = getLabelLocation(bounds);
        if (labelLocation != null) {
            g.drawString(text, labelLocation.x, labelLocation.y);
        }
    }

    protected void paintErrorMessage(Graphics g) {
        String errorMessage;
        if (demo) {
            errorMessage = null;
        } else if (calibration != null && !gauge.getParameter().isVariantSupported(calibration)) {
            errorMessage = "Variant unsupported";
        } else if (!receivingData) {
            errorMessage = "No data";
        } else {
            errorMessage = null;
        }

        if (errorMessage != null) {
            g.setColor(Colors.withAlpha(Color.GRAY, 0x32));
            g.fillRect(0, 0, getWidth(), getHeight());

            JLabel label = Labels.text(CarbonIcons.WARNING_ALT_FILLED, Color.RED, errorMessage, Color.RED);
            label.setVerticalAlignment(JLabel.TOP);
            label.setVerticalTextPosition(JLabel.TOP);
            label.setHorizontalAlignment(JLabel.CENTER);
            //label.setHorizontalTextPosition(JLabel.CENTER);
            label.setSize(getWidth(), getHeight());

            Graphics sub = g.create();
            sub.translate(0, insets.top);
            label.paint(g);
        }
    }

    @Override
    public float getValue() {
        return value;
    }

    @Override
    public void setValue(float value) {
        setReceivingData(true);

        if (this.value != value) {
            this.value = value;
            onValueChanged();
        }
    }

    protected void onValueChanged() {
        repaint();
    }

    @Override
    public void doLayout() {
        // Resize to a square
        setSize(getSize());

        // We explicitly call getSize() again as it could have been modified
        setPreferredSize(getSize());
        super.doLayout();
    }

    @Override
    public void setSize(@NotNull Dimension d) {
        double height = d.getHeight();
        height = Math.max(getMinimumSize().height, height);
        d.setSize(height, height);
        super.setSize(d);
    }
}
