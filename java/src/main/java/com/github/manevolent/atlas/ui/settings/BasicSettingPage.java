package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.uds.SecurityAccessProperty;
import com.github.manevolent.atlas.ui.settings.field.*;
import com.github.manevolent.atlas.ui.util.*;
import com.google.common.html.HtmlEscapers;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.awt.Color;

public abstract class BasicSettingPage extends AbstractSettingPage implements FieldChangeListener {
    private final Frame parent;
    private JPanel content;

    private java.util.List<SettingField> fields;

    public BasicSettingPage(Frame parent, Ikon icon, String name) {
        super(icon, name);

        this.parent = parent;
    }

    protected String getHelpText() {
        return null;
    }

    protected abstract java.util.List<SettingField> createFields();

    @Override
    public void onFieldChanged(SettingField field) {
        fireFieldChanged(field);
    }

    private java.util.List<SettingField> getFields() {
        if (this.fields == null) {
            this.fields = createFields();
            this.fields.forEach(field -> field.addChangeListener(this));
        }

        return this.fields;
    }

    private JComponent addHeaderRow(JPanel entryPanel, int row,
                                    Ikon icon, String label) {
        JPanel labelPanel = Layout.wrap(Layout.emptyBorder(5, 0, 5, 0, Fonts.bold(Labels.text(icon, label))));
        Layout.matteBorder(0, 0, 1, 0, Color.GRAY.darker(), labelPanel);
        labelPanel = Layout.emptyBorder(0, 0, 5, 0, Layout.wrap(labelPanel));

        entryPanel.add(labelPanel, Layout.gridBagConstraints(
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                0, row,
                2, 1,
                1, 0
        ));
        return labelPanel;
    }

    private JComponent addEntryRow(JPanel entryPanel, int row,
                                   String label, String helpText,
                                   JComponent input,
                                   int labelAlignment) {
        // Label
        JLabel labelField = Labels.darkerText(label);
        entryPanel.add(labelField, Layout.gridBagConstraints(
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                0, row,
                0, 0
        ));

        Insets insets = new JTextField().getInsets();

        // Entry
        if (input instanceof JLabel) {
            input.setBorder(BorderFactory.createEmptyBorder(
                    insets.top,
                    0,
                    insets.bottom,
                    insets.right
            ));
        }
        input.setToolTipText(helpText);


        entryPanel.add(input,
                Layout.gridBagConstraints(GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        1, row,
                        1, 0));

        labelField.setVerticalAlignment(labelAlignment);

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
        Layout.preferHeight(labelField, input);

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

    private void initComponent() {
        JPanel content = Layout.emptyBorder(5, 5, 5, 5, new JPanel());
        content.setLayout(new GridBagLayout());

        addHeaderRow(content, 0, getIcon(), getName());

        java.util.List<SettingField> elements = getFields();
        for (int row = 0; row < elements.size(); row ++) {
            SettingField element = elements.get(row);

            String title = element instanceof CheckboxSettingField ? "" : element.getName();

            addEntryRow(content, 1 + row,
                    title, element.getTooltip(),
                    element.getInputComponent(),
                    element.getLabelAlignment());
        }

        if (this.content == null) {
            this.content = new JPanel(new BorderLayout());
        }

        this.content.add(content, BorderLayout.NORTH);

        String helpText = getHelpText();
        if (helpText != null) {
            Color color = new Color(64, 168, 255);
            JLabel label = new JLabel();
            label.setVerticalAlignment(JLabel.TOP);
            label.setVerticalTextPosition(JLabel.TOP);
            label.setIcon(Icons.get(CarbonIcons.INFORMATION_FILLED, color));

            JPanel outerPanel = new JPanel(new BorderLayout());
            Layout.emptyBorder(5, 5, 5, 5, outerPanel);

            JPanel innerPanel = new JPanel(new BorderLayout());
            Layout.emptyBorder(5, 5, 5, 5, innerPanel);
            innerPanel.setBackground(Colors.withAlpha(color, 16));

            String escaped = HtmlEscapers.htmlEscaper().escape(helpText);
            escaped = escaped.replace("\r\n", "<br/>");
            label.setText("<html>" + escaped + "</html>");
            innerPanel.add(label);

            outerPanel.add(innerPanel);

            this.content.add(outerPanel, BorderLayout.SOUTH);
        }
    }

    @Override
    public JComponent getContent() {
        if (this.content == null) {
            initComponent();
        }

        return this.content;
    }

    public void reinitialize() {
        this.fields = createFields();
        JComponent content = getContent();
        content.removeAll();
        initComponent();

        content.revalidate();
        content.repaint();
    }

    @Override
    public boolean apply() {
        for (SettingField element : getFields()) {
            if (!element.apply()) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean isDirty() {
        return fields != null && fields.stream().anyMatch(SettingField::isDirty);
    }

    protected SettingField createSettingField(PropertyDefinition definition, KeySet keySet) {
        if (definition.getValueType().equals(SecurityAccessProperty.class)) {
            return new SecurityAccessPropertySettingField(parent, keySet, definition.getKey(),
                    definition.getName(), definition.getDescription());
        } else if (definition.getValueType().equals(KeyProperty.class)) {
            return new KeyPropertySettingField(parent, keySet, definition.getKey(),
                    definition.getName(), definition.getDescription());
        } else if (definition.getValueType().equals(AddressProperty.class)) {
            return new AddressPropertySettingField(parent, keySet, definition.getKey(),
                    definition.getName(), definition.getDescription());
        } else {
            throw new UnsupportedOperationException(definition.getValueType().getName());
        }
    }

}
