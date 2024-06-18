package com.github.manevolent.atlas.ui.util;

import com.github.manevolent.atlas.connection.ConnectionType;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.field.MemoryAddressField;
import com.github.manevolent.atlas.ui.dialog.BinaryInputDialog;
import com.github.manevolent.atlas.ui.settings.SettingPage;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;
import javax.swing.event.*;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URISyntaxException;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static java.awt.event.ItemEvent.DESELECTED;
import static java.awt.event.ItemEvent.SELECTED;
import static javax.swing.JOptionPane.QUESTION_MESSAGE;

public class Inputs {

    public static JButton button(Ikon icon, Runnable clicked) {
        JButton button = new JButton(Icons.get(icon, Fonts.getTextColor()));
        button.addActionListener(e -> clicked.run());
        return button;
    }

    public static JButton button(Ikon icon, java.awt.Color color, Runnable clicked) {
        JButton button = new JButton(Icons.get(icon, color));
        button.addActionListener(e -> clicked.run());
        return button;
    }

    public static JButton button(String title, Runnable clicked) {
        JButton button = new JButton(title);
        button.addActionListener(e -> clicked.run());
        return button;
    }

    public static JButton button(Ikon icon, String title, Runnable clicked) {
        JButton button = new JButton(title, Icons.get(icon, new JLabel().getForeground()));
        button.addActionListener(e -> clicked.run());
        return button;
    }

    public static JButton button(Ikon icon, String title, String toolTipText, Runnable clicked) {
        JButton button = new JButton(title, Icons.get(icon, new JLabel().getForeground()));
        if (toolTipText != null) {
            button.setToolTipText(toolTipText);
        }
        button.addActionListener(e -> clicked.run());
        return button;
    }

    public static JCheckBox checkbox(String title, boolean initial,
                                     Consumer<Boolean> changed) {
        JCheckBox checkBox = new JCheckBox(title);
        checkBox.setSelected(initial);
        checkBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED && e.getStateChange() != DESELECTED) {
                return;
            }
            changed.accept(checkBox.isSelected());
        });
        return checkBox;
    }

    public static JTextArea textArea(String defaultValue, Consumer<String> changed) {
        JTextArea textArea = new JTextArea();
        textArea.setText(defaultValue);

        textArea.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                changed.accept(textArea.getText());
            }
            @Override
            public void removeUpdate(DocumentEvent e) {
                changed.accept(textArea.getText());
            }
            @Override
            public void changedUpdate(DocumentEvent e) {
                changed.accept(textArea.getText());
            }
        });

        return textArea;
    }

    private static JTextField textField(String defaultValue, String toolTip,
                                        Font font, boolean editable, Consumer<String> changed) {

        JTextField textField = new JTextField();
        textField.setEditable(editable);

        if (defaultValue != null) {
            textField.setText(defaultValue);
        }

        if (toolTip != null) {
            textField.setToolTipText(toolTip);
        }

        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                changed.accept(textField.getText());
            }
            @Override
            public void removeUpdate(DocumentEvent e) {
                changed.accept(textField.getText());
            }
            @Override
            public void changedUpdate(DocumentEvent e) {
                changed.accept(textField.getText());
            }
        });

        return textField;
    }

    public static JTextField textField(String defaultValue, String toolTip,
                                       boolean editable, Consumer<String> changed) {
        return textField(defaultValue, toolTip, (Font) null, editable, changed);
    }

    public static JTextField textField(String defaultValue, String toolTip, Consumer<String> changed) {
        return textField(defaultValue, toolTip, true, changed);
    }

    public static JTextField textField(String defaultValue, Font font, Consumer<String> changed) {
        return textField(defaultValue, (String) null, font, true, changed);
    }

    public static JTextField textField(String defaultValue, Consumer<String> changed) {
        return textField(defaultValue, (String) null, changed);
    }

    public static JTextField textField(Consumer<String> changed) {
        return textField(null, changed);
    }

    public static MemoryAddressField memoryAddressField(Project project, Variant variant,
                                                        MemoryAddress existing,
                                                        EnumSet<MemoryType> memoryTypes,
                                                        Consumer<MemoryAddress> changed) {
        return new MemoryAddressField(project, variant, existing, memoryTypes, changed);
    }


    public static <T> JComboBox<T> comboBox(Collection<T> options, T intended,
                                            boolean allowNull,
                                            Consumer<T> valueChanged) {
        return comboBox(null, options, intended, allowNull, valueChanged);
    }

    public static <T> JComboBox<T> comboBox(String toolTip, Collection<T> options, T intended,
                                            boolean allowNull,
                                            Consumer<T> valueChanged) {
        List<T> list = options.stream()
                .sorted(Comparator.comparing(T::toString))
                .toList();

        Vector<T> vector = new Vector<>(list);

        JComboBox<T> comboBox = new JComboBox<>(vector);
        if (allowNull) {
            comboBox.insertItemAt(null, 0);
        }

        comboBox.setToolTipText(toolTip);
        comboBox.setSelectedItem(list.contains(intended) ? intended : null);

        if (comboBox.getSelectedItem() == null && !allowNull && !options.isEmpty()) {
            comboBox.setSelectedItem(list.getFirst());
        }

        comboBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED) {
                return;
            }

            //noinspection unchecked
            T value = (T) e.getItem();
            if (value == null && !allowNull) {
                return;
            }

            valueChanged.accept(value);
        });

        return comboBox;
    }

    public static <E extends Enum<E>> JComboBox<E> enumField(String toolTip, Class<E> type, E intended,
                                                             Consumer<E> valueChanged) {
        List<E> options = Arrays.stream(type.getEnumConstants()).toList();

        if (intended == null) {
            intended = type.getEnumConstants()[0];
            valueChanged.accept(intended);
        }

        return comboBox(toolTip, options, intended, false, valueChanged);
    }

    public static JComboBox<ConnectionType> connectionTypeField(String toolTip, ConnectionType intended,
                                                      Consumer<ConnectionType> valueChanged) {
        return enumField(toolTip, ConnectionType.class, intended, valueChanged);
    }

    public static JComboBox<Unit> unitField(String toolTip, Unit intended, Consumer<Unit> valueChanged) {
        Unit[] values = Arrays.stream(Unit.values())
                .sorted(Comparator.comparing(Unit::toString)).toArray(Unit[]::new);
        JComboBox<Unit> comboBox = new JComboBox<>(values);
        if (intended != null) {
            comboBox.setSelectedItem(intended);
        } else {
            comboBox.setSelectedItem(Unit.RPM);
        }
        comboBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED) {
                return;
            }
            valueChanged.accept((Unit) e.getItem());
        });
        return comboBox;
    }

    public static JComboBox<ArithmeticOperation> arithmeticOperationField(String toolTip,
                                                                          ScalingOperation operation,
                                                                          Consumer<ArithmeticOperation> valueChanged) {
        JComboBox<ArithmeticOperation> comboBox = new JComboBox<>(ArithmeticOperation.values());
        if (operation != null) {
            comboBox.setSelectedItem(operation.getOperation());
        } else {
            comboBox.setSelectedItem(ArithmeticOperation.ADD);
        }
        comboBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED) {
                return;
            }
            valueChanged.accept((ArithmeticOperation) e.getItem());
        });
        return comboBox;
    }

    public static JComboBox<MemorySection> memorySectionField(List<MemorySection> sections,
                                                              MemorySection value,
                                                              Consumer<MemorySection> changed) {
        JComboBox<MemorySection> comboBox = new JComboBox<>(sections.toArray(new MemorySection[0]));
        MemorySection intended = value == null ? sections.getFirst() : value;
        comboBox.setSelectedItem(intended);
        comboBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED) {
                return;
            }

            changed.accept((MemorySection)e.getItem());
        });
        return comboBox;
    }

    public static JComboBox<MemorySection> memorySectionField(Project project, MemorySection value,
                                                              Predicate<MemorySection> predicate,
                                                              Consumer<MemorySection> changed) {
        return memorySectionField(
                project.getSections().stream().filter(predicate).toList(),
                value,
                changed);
    }

    public static JSpinner memoryLengthField(Series series, Consumer<Integer> valueChanged) {
        SpinnerNumberModel model = new SpinnerNumberModel(
                series != null ? series.getLength() : 1,
                1, 1_024_000, 1);
        JSpinner spinner = new JSpinner(model);
        ((JSpinner.DefaultEditor)spinner.getEditor()).getTextField().setHorizontalAlignment(JTextField.LEFT);
        spinner.addChangeListener(e -> valueChanged.accept((int) spinner.getValue()));
        return spinner;
    }

    public static JComboBox<Scale> scaleField(Project project, Scale existing,
                                              String toolTip, Consumer<Scale> valueChanged) {
        Scale[] values = project.getScales().stream()
                .sorted(Comparator.comparing(Scale::toString)).toArray(Scale[]::new);
        JComboBox<Scale> comboBox = new JComboBox<>(values);
        comboBox.setSelectedItem(existing);
        comboBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED) {
                return;
            }
            valueChanged.accept((Scale)e.getItem());
        });
        return comboBox;
    }

    public static JComboBox<DataFormat> dataTypeField(String toolTip, DataFormat intended,
                                                      Consumer<DataFormat> valueChanged) {
        DataFormat[] values = Arrays.stream(DataFormat.values())
                .sorted(Comparator.comparing(DataFormat::toString)).toArray(DataFormat[]::new);
        JComboBox<DataFormat> comboBox = new JComboBox<>(values);
        if (intended != null) {
            comboBox.setSelectedItem(intended);
        } else {
            comboBox.setSelectedItem(DataFormat.UBYTE);
        }
        comboBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED) {
                return;
            }
            valueChanged.accept((DataFormat) e.getItem());
        });
        return comboBox;
    }

    public static <T extends JComponent> T nofocus(T component) {
        component.setFocusable(false);
        return component;
    }

    public static <T extends JComponent> T bg(java.awt.Color color, T component) {
        component.setOpaque(true);
        component.setBackground(color);
        return component;
    }

    public static JPanel createButtonRow(JPanel entryPanel, int row, JButton... buttons) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

        Arrays.stream(buttons).forEach(panel::add);

        entryPanel.add(panel,
                Layout.gridBagConstraints(
                        GridBagConstraints.SOUTHEAST, GridBagConstraints.NONE,
                        1, row, // pos
                        2, 1, // size
                        1, 1 // weight
                ));

        return panel;
    }

    public static JPanel createEntryPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        return panel;
    }

    public static JComponent createTextRow(JPanel entryPanel, int row, String label) {
        JLabel labelField = Labels.text(label);
        entryPanel.add(labelField, Layout.gridBagConstraints(
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE, 0, row, 2, 1, 0, 1
        ));

        Insets insets = new JTextField().getInsets();
        labelField.setBorder(BorderFactory.createEmptyBorder(
                insets.top,
                0,
                insets.bottom,
                insets.right
        ));

        return labelField;
    }

    public static JComponent createEntryRow(JPanel entryPanel, int row,
                                            String label, String helpText,
                                            JComponent input) {
        // Label
        JLabel labelField = Labels.darkerText(label);
        entryPanel.add(labelField, Layout.gridBagConstraints(
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE, 0, row, 0, 1
        ));

        // Entry
        input.setToolTipText(helpText);
        entryPanel.add(input,
                Layout.gridBagConstraints(GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL, 1, row, 1, 1));

        labelField.setVerticalAlignment(SwingConstants.TOP);

        Insets insets = new JTextField().getInsets();
        labelField.setBorder(BorderFactory.createEmptyBorder(
                insets.top,
                0,
                insets.bottom,
                insets.right
        ));
        labelField.setMaximumSize(new Dimension(
                Integer.MAX_VALUE,
                (int) input.getSize().getHeight()
        ));

        int height = Math.max(input.getHeight(), input.getPreferredSize().height);

        input.setPreferredSize(new Dimension(
                100,
                height
        ));
        input.setSize(
                100,
                height
        );

        return entryPanel;
    }

    public static void bind(Component component, String key, Runnable action, KeyStroke... strokes) {
        int when = JComponent.WHEN_FOCUSED;

        if (component instanceof JFrame frame) {
            component = frame.getRootPane();
            when = JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT;
        } else if (component instanceof JDialog dialog) {
            component = dialog.getRootPane();
            when = JComponent.WHEN_IN_FOCUSED_WINDOW;
        }

        bind(component, when, key, action, strokes);
    }

    public static void bind(Component component, int when, String key, Runnable action, KeyStroke... strokes) {
        Arrays.asList(strokes).forEach(stroke -> {
            ((JComponent)component).getInputMap(when).put(stroke, action);
        });

        ((JComponent)component).getActionMap().put(action, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    public static void customFileDialog(SettingPage settingPage) {

    }

    public static <T> T showOptionDialog(Frame parent, String title, String message, List<T> options) {
        JComboBox<T> comboBox = comboBox(options, null, false, (v) -> { /*ignored*/ });

        BorderLayout layout = new BorderLayout();
        JPanel topPanel = new JPanel(layout);
        JLabel label = new JLabel(message);
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        topPanel.add(label, BorderLayout.NORTH);
        JPanel centerPanel = new JPanel(new BorderLayout(5, 5));
        centerPanel.add(comboBox, BorderLayout.CENTER);
        topPanel.add(centerPanel);

        int res = JOptionPane.showConfirmDialog(parent, topPanel, title, JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            return (T) comboBox.getSelectedItem();
        } else {
            return null;
        }
    }

    public static Integer showSpinnerDialog(Frame parent, String title, String message, int value, int min, int max) {
        JSpinner spinner = new JSpinner(new SpinnerNumberModel(value, min, max, 1));

        BorderLayout layout = new BorderLayout();
        JPanel topPanel = new JPanel(layout);
        JLabel label = new JLabel(message);
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        topPanel.add(label, BorderLayout.NORTH);
        JPanel centerPanel = new JPanel(new BorderLayout(5, 5));
        centerPanel.add(spinner, BorderLayout.CENTER);
        topPanel.add(centerPanel);

        int res = JOptionPane.showConfirmDialog(parent, topPanel, title, JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            return (int) spinner.getValue();
        } else {
            return null;
        }
    }

    public static Object showRenameDialog(Frame parent, String message, String title, String initial) {
        JTextField renameField = new JTextField(initial);
        Layout.preferWidth(renameField, 400);

        BorderLayout layout = new BorderLayout();
        JPanel topPanel = new JPanel(layout);
        topPanel.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                renameField.grabFocus();

                int start = initial.lastIndexOf('-');
                while (true) {
                    char c = initial.charAt(start);
                    if (start < initial.length() - 1 && (c == ' ' || c == '-')) {
                        start ++;
                    } else {
                        break;
                    }
                }

                renameField.select(start, initial.length());
            }

            @Override
            public void ancestorRemoved(AncestorEvent event) {

            }

            @Override
            public void ancestorMoved(AncestorEvent event) {

            }
        });

        JLabel label = new JLabel(message);
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
        topPanel.add(label, BorderLayout.NORTH);
        JPanel centerPanel = new JPanel(new BorderLayout(5, 5));
        centerPanel.add(renameField, BorderLayout.CENTER);
        topPanel.add(centerPanel);

        int res = JOptionPane.showConfirmDialog(parent, topPanel, title, JOptionPane.OK_CANCEL_OPTION);
        if (res == JOptionPane.OK_OPTION) {
            return renameField.getText();
        } else {
            return null;
        }
    }
}
