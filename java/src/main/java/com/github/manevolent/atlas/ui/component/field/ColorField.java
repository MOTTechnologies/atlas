package com.github.manevolent.atlas.ui.component.field;

import com.github.manevolent.atlas.model.Color;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.ui.behavior.ClickListener;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

public class ColorField extends JPanel {
    private JPanel colorPanel;
    private JButton selectButton;

    private Color color;

    public ColorField(Component parent, Color existing, Consumer<Color> changed) {
        this.color = existing != null ? existing : Color.fromAwtColor(java.awt.Color.WHITE);

        setLayout(new BorderLayout());

        colorPanel = new JPanel();

        Runnable set = () -> {
            java.awt.Color newColor = JColorChooser.showDialog(parent, "Select a color", color.toAwtColor(), false);
            if (newColor == null) {
                return;
            }

            this.color = Color.fromAwtColor(newColor);
            changed.accept(Color.fromAwtColor(newColor));
            colorPanel.setBackground(newColor);
        };

        selectButton = Inputs.button(
                CarbonIcons.EYEDROPPER,
                new JLabel().getForeground(),
                set
        );

        Insets insets = selectButton.getInsets();

        colorPanel.setForeground(this.color.toAwtColor());
        colorPanel.setBackground(this.color.toAwtColor());
        colorPanel.setOpaque(true);
        Layout.matteBorder(1, 1, 1, 1, java.awt.Color.BLACK, colorPanel);

        colorPanel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        colorPanel.addMouseListener(new ClickListener(() -> {
            if (ColorField.this.isEnabled()) {
                set.run();
            }
        }));

        JPanel wrapped = Layout.wrap(new BorderLayout(), colorPanel, BorderLayout.CENTER);
        wrapped.setPreferredSize(new Dimension(80, selectButton.getHeight()));
        wrapped.setMaximumSize(new Dimension(80, selectButton.getHeight()));
        wrapped.setBorder(Layout.emptyBorder(insets));
        add(wrapped, BorderLayout.CENTER);

        selectButton.setToolTipText("Select color...");

        selectButton.setFocusable(false);

        add(selectButton, BorderLayout.EAST);
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        selectButton.setEnabled(enabled);
    }

    public Color getColor() {
        return color;
    }
}
