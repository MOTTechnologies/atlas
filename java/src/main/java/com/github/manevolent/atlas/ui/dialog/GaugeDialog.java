package com.github.manevolent.atlas.ui.dialog;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.behavior.Animation;
import com.github.manevolent.atlas.ui.behavior.ClickListener;
import com.github.manevolent.atlas.ui.behavior.TimedAnimation;
import com.github.manevolent.atlas.ui.component.field.ColorField;
import com.github.manevolent.atlas.ui.component.gauge.UIGauge;
import com.github.manevolent.atlas.ui.component.gauge.UIGaugeComponent;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.awt.Color;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.function.Consumer;

public class GaugeDialog extends JDialog {
    private final Editor editor;
    private final Gauge gauge;

    private JPanel content;
    private JComboBox<MemoryParameter> parameterComboBox;
    private JButton ok;

    private java.util.List<UIGauge> uis = new ArrayList<>();

    private boolean canceled;
    private Animation animation;
    private JComponent styleField;

    public GaugeDialog(Editor editor, Gauge gauge, String title) {
        super(editor, title, false);

        this.editor = editor;
        this.gauge = gauge;

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                canceled = true;
                super.windowClosing(e);
            }
        });

        setType(Type.NORMAL);
        initComponent();
        setResizable(true);
        setModalityType(ModalityType.APPLICATION_MODAL);
        setMinimumSize(new Dimension(600, getMinimumSize().height));
        setIconImage(Icons.getImage(CarbonIcons.METER, Color.WHITE).getImage());

        pack();
        setLocationRelativeTo(editor);
    }

    private void runGaugeSweep() {
        if (animation != null) {
            animation.interrupt();
            animation = null;
        }

        animation = new TimedAnimation(styleField, 0.6D) {
            @Override
            protected void update(double position, JComponent component) {
                uis.forEach(ui -> {
                    double pos = 1 - (position * 2);
                    pos = Math.abs(pos);
                    ui.setValue(ui.getMinimumValue() + ((ui.getMaximumValue()
                            - ui.getMinimumValue()) * pos));
                });
            }
        };

        animation.start();
    }

    public Gauge getGauge() {
        return gauge;
    }

    public Editor getEditor() {
        return editor;
    }

    public Project getProject() {
        return getEditor().getProject();
    }

    public boolean isCanceled() {
        return canceled;
    }

    private void accept() {
        gauge.setParameter((MemoryParameter) parameterComboBox.getSelectedItem());
        dispose();
        canceled = false;
    }

    private void cancel() {
        canceled = true;
        dispose();
    }

    private JComponent initValueField(float value,
                                      com.github.manevolent.atlas.model.Color color,
                                      Consumer<Float> valueChanged,
                                      Consumer<com.github.manevolent.atlas.model.Color> colorChanged) {
        JPanel inputPanel = new JPanel(new BorderLayout());
        Scale scale = getGauge().getParameter().getScale();

        float minimum = Math.min(scale.getMinimum(), scale.getMaximum());
        float maximum = Math.max(scale.getMinimum(), scale.getMaximum());

        if (Float.floatToIntBits(minimum) == 0x80000000) {
            minimum = 0;
        }

        if (Float.floatToIntBits(maximum) == 0x80000000) {
            maximum = 0;
        }

        if (Float.floatToIntBits(value) == 0x80000000) {
            value = 0;
        }

        float clampedValue = Math.max(Math.min(value, maximum), minimum);
        if (clampedValue != value) {
            valueChanged.accept(clampedValue);
        }

        SpinnerNumberModel model = new SpinnerNumberModel(clampedValue,
                minimum, maximum, scale.getPrecision());

        JSpinner spinner = new JSpinner(model);
        ((JSpinner.DefaultEditor)spinner.getEditor()).getTextField().setHorizontalAlignment(JTextField.LEFT);
        spinner.addChangeListener(e -> {
            Number number = (Number) spinner.getValue();
            valueChanged.accept(number.floatValue());
        });
        inputPanel.add(spinner, BorderLayout.CENTER);

        inputPanel.add(new ColorField(this, color, colorChanged), BorderLayout.EAST);

        return inputPanel;
    }

    private JComponent initStyleField(GaugeDisplayType displayType, Consumer<GaugeDisplayType> changed) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        uis.clear();

        for (GaugeDisplayType choice : GaugeDisplayType.values()) {
            JPanel outerPanel = new JPanel();
            MouseListener listener = new ClickListener(() -> changed.accept(choice));

            if (displayType == choice) {
                Layout.matteBorder(2, 2, 2, 2, Color.GRAY, outerPanel);
            } else {
                Layout.emptyBorder(2, 2, 2, 2, outerPanel);
            }

            Gauge testGauge = gauge.copy();
            testGauge.setDisplayType(choice);
            UIGauge ui = UIGauge.createUi(testGauge);
            ui.setValue(ui.getMaximumValue());
            if (ui instanceof UIGaugeComponent gaugeComponent) {
                gaugeComponent.setCanHighlight(displayType != choice);
            }

            uis.add(ui);

            JComponent component = ui.getComponent();

            component.addMouseListener(listener);
            component.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            outerPanel.add(component);
            panel.add(outerPanel);
        }

        return panel;
    }

    private void initComponent() {
        if (content != null) {
            throw new IllegalStateException();
        }

        content = Inputs.createEntryPanel();
        getContentPane().add(content);

        Inputs.createTextRow(content, 1, "Gauge Settings");

        Inputs.createEntryRow(content, 2, "Parameter", "The parameter to use for reporting values",
                parameterComboBox = Inputs.comboBox(
                        getProject().getParameters().stream().sorted(
                                Comparator.comparing(MemoryParameter::getName)).toList(),
                        gauge.getParameter(), false, parameter -> {
                    if (parameter != gauge.getParameter()) {
                        gauge.setParameter(parameter);

                        Scale scale = parameter.getScale();

                        float minimum = Math.min(scale.getMinimum(), scale.getMaximum());
                        float maximum = Math.max(scale.getMinimum(), scale.getMaximum());

                        gauge.setMinimum(minimum);
                        gauge.setMaximum(maximum);
                        reinitialize();
                    }
                }));

        // Align the gauge object with whatever the parameter combo-box selected
        if (gauge.getParameter() == null) {
            gauge.setParameter((MemoryParameter) parameterComboBox.getSelectedItem());
        }

        Inputs.createEntryRow(content, 3, "Minimum", "The minimum value and its associated color",
                initValueField(gauge.getMinimum(), gauge.getMinimumColor(),
                        value -> {
                            if (gauge.getMinimum() != value) {
                                gauge.setMinimum(value);
                                reinitialize();
                            }
                        },
                        color -> {
                            if (!gauge.getMinimumColor().equals(color)) {
                                gauge.setMinimumColor(color);
                                reinitialize();
                            }
                        }));

        Inputs.createEntryRow(content, 4, "Maximum", "The maximum value and its associated color",
                initValueField(gauge.getMaximum(), gauge.getMaximumColor(),
                        value -> {
                            if (gauge.getMaximum() != value) {
                                gauge.setMaximum(value);
                                reinitialize();
                            }
                        },
                        color -> {
                            if (!gauge.getMaximumColor().equals(color)) {
                                gauge.setMaximumColor(color);
                                reinitialize();
                            }
                        }));

        Inputs.createEntryRow(content, 5, "Style", "The style of this gauge",
                styleField = initStyleField(gauge.getDisplayType(), value -> {
                    if (gauge.getDisplayType() != value) {
                        gauge.setDisplayType(value);
                        reinitialize();
                    } else {
                        runGaugeSweep();
                    }
                }));

        if (ok == null) {
            ok = Inputs.button(CarbonIcons.CHECKMARK, "OK", null, this::accept);
        }

        JButton cancel = Inputs.button("Cancel", this::cancel);
        Inputs.createButtonRow(content, 6, ok, cancel);

        getRootPane().setDefaultButton(ok);

        runGaugeSweep();
    }

    private void reinitialize() {
        if (content != null) {
            getContentPane().remove(content);
            content = null;
        }

        initComponent();
        revalidate();
        repaint();
    }

    public static Gauge show(Editor editor, Gauge gauge, String title) {
        GaugeDialog dialog = new GaugeDialog(editor, gauge, title);
        dialog.setVisible(true);
        if (dialog.isCanceled()) {
            return null;
        } else {
            return gauge;
        }
    }

    public static Gauge show(Editor editor) {
        Gauge gauge = Gauge.builder().build();
        GaugeDialog dialog = new GaugeDialog(editor, gauge, "New Gauge");
        dialog.setVisible(true);
        if (dialog.isCanceled()) {
            return null;
        } else {
            return gauge;
        }
    }

    public static Gauge show(Editor editor, Gauge existing) {
        Gauge gauge = existing.copy();
        GaugeDialog dialog = new GaugeDialog(editor, gauge, "Edit Gauge");
        dialog.setVisible(true);
        if (dialog.isCanceled()) {
            return null;
        } else {
            return gauge;
        }
    }
}
