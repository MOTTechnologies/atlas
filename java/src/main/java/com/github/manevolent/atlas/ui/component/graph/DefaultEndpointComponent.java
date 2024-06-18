package com.github.manevolent.atlas.ui.component.graph;

import com.github.manevolent.atlas.model.node.GraphNode;

import com.github.manevolent.atlas.model.node.NodeEndpoint;
import com.github.manevolent.atlas.model.node.NodeOutput;
import com.github.manevolent.atlas.ui.util.Colors;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.concurrent.atomic.AtomicBoolean;

public class DefaultEndpointComponent extends JPanel implements EndpointComponent {
    private final GraphNode graphNode;
    private final NodeEndpoint<?> endpoint;
    private final DefaultGraphRenderer renderer;

    private final JLabel label;
    private final JComponent anchor;

    public <T extends GraphNode> DefaultEndpointComponent(T graphNode,
                                                          NodeEndpoint<?> endpoint,
                                                          int orientation,
                                                          DefaultGraphRenderer renderer) {
        this.graphNode = graphNode;
        this.endpoint = endpoint;
        this.renderer = renderer;

        setOpaque(false);

        setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

        setLayout(new BoxLayout(this, BoxLayout.X_AXIS));

        label = createLabel();
        anchor = createAnchor();

        if (orientation == SwingConstants.LEFT) {
            add(anchor);
            add(Box.createHorizontalStrut(4));
            add(label);
        } else {
            add(label);
            add(Box.createHorizontalStrut(4));
            add(anchor);
        }
    }

    @Override
    public GraphNode getGraphNode() {
        return graphNode;
    }

    private JLabel createLabel() {
        JLabel label = new JLabel() {
            @Override
            public void paint(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.setColor(getBackground());
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                super.paint(g);
            }
        };

        label.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        label.setText(endpoint.getLabelUnchecked(graphNode));
        Color defaultColor = new Color(0xE0B020);
        Color preferredColor = endpoint instanceof NodeOutput<?> output ?
                output.getColorUnchecked(graphNode).darker() : defaultColor;
        label.setBackground(Colors.withAlpha(preferredColor, 0xA0));
        label.setForeground(Color.WHITE);
        label.setMaximumSize(label.getPreferredSize());

        return label;
    }

    private JComponent createAnchor() {
        AtomicBoolean mouseHovering = new AtomicBoolean();
        JComponent anchor = new JComponent() {
            @Override
            public void paint(Graphics g) {
                Graphics2D g2d = (Graphics2D) g;
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

                Color color = Color.GRAY;

                g2d.setColor(color.darker().darker());
                g2d.fillOval(2, 2, getWidth() - 4, getHeight() - 4);

                if (endpoint instanceof NodeOutput<?> output) {
                    color = output.getColorUnchecked(graphNode);
                }

                if (mouseHovering.get() || renderer.getPressedEndpoint() == DefaultEndpointComponent.this) {
                    g2d.setColor(color.brighter());
                } else {
                    g2d.setColor(color.darker());
                }

                g2d.setStroke(new BasicStroke(2f));
                g2d.drawOval(2, 2, getWidth() - 4, getHeight() - 4);
            }
        };

        anchor.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                renderer.setPressedEndpoint(DefaultEndpointComponent.this);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                renderer.setPressedEndpoint(null);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                mouseHovering.set(false);

                if (renderer.getHoveredEndpoint() == DefaultEndpointComponent.this) {
                    renderer.setHoveredEndpoint(null);
                } else {
                    renderer.repaint();
                }
            }

            @Override
            public void mouseEntered(MouseEvent e) {
                mouseHovering.set(true);

                if (!renderer.setHoveredEndpoint(DefaultEndpointComponent.this)) {
                    renderer.repaint();
                }
            }
        });

        anchor.addMouseMotionListener(new MouseAdapter() {
            @Override
            public void mouseDragged(MouseEvent e) {
                renderer.repaint();
            }
        });

        Dimension size = new Dimension(20, 20);
        anchor.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        anchor.setMinimumSize(size);
        anchor.setPreferredSize(size);
        anchor.setMaximumSize(size);

        return anchor;
    }

    @Override
    public NodeEndpoint<?> getEndpoint() {
        return endpoint;
    }

    @Override
    public Point getAnchorPoint() {
        Point location = anchor.getLocationOnScreen();
        return new Point(location.x + (anchor.getWidth() / 2), location.y + (anchor.getHeight() / 2));
    }
}
