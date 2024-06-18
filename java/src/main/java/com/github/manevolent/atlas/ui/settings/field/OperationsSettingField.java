package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.model.Scale;
import com.github.manevolent.atlas.model.ScalingOperation;
import com.github.manevolent.atlas.ui.Editor;

import com.github.manevolent.atlas.ui.component.toolbar.Toolbar;
import com.github.manevolent.atlas.ui.dialog.BinaryInputDialog;
import com.github.manevolent.atlas.ui.dialog.ScalingOperationDialog;
import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Layout;

import com.github.manevolent.atlas.ui.util.Tools;
import org.kordamp.ikonli.fontawesome5.FontAwesomeSolid;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedList;

import static com.github.manevolent.atlas.ui.util.Layout.*;
import static com.github.manevolent.atlas.ui.util.Layout.topBorder;

public class OperationsSettingField extends AbstractSettingField {
    private final Scale scale;

    private JList<ScalingOperation> ops;
    private boolean dirty;

    public OperationsSettingField(String name, String tooltip, Scale scale) {
        super(name, tooltip);
        this.scale = scale;
    }

    private ListModel<ScalingOperation> getOperationsModel() {
        DefaultListModel<ScalingOperation> model = new DefaultListModel<>();
        scale.getOperations().forEach(model::addElement);
        return model;
    }

    private JList<ScalingOperation> initOperationsList() {
        JList<ScalingOperation> list = new JList<>(getOperationsModel());
        list = Layout.minimumWidth(list, 200);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer(new Renderer(Fonts.VALUE_FONT));
        return Layout.emptyBorder(list);
    }

    @Override
    public JComponent getInputComponent() {
        JPanel operationsPanel = emptyBorder(0, 5, 0, 5, new JPanel(new BorderLayout()));

        JPanel content = new JPanel(new BorderLayout());
        JPanel inner = new JPanel(new BorderLayout());

        inner.add(new FieldToolbar(this).getComponent(), BorderLayout.NORTH);

        inner.add(Layout.emptyBorder(scrollVertical(ops = initOperationsList())), BorderLayout.CENTER);

        content.add(matteBorder(1, 1, 1, 1, java.awt.Color.GRAY.darker(), inner), BorderLayout.CENTER);

        operationsPanel.add(topBorder(5, content), BorderLayout.CENTER);

        return operationsPanel;
    }

    @Override
    public boolean apply() {
        dirty = false;
        return true;
    }

    @Override
    public boolean isDirty() {
        return dirty;
    }

    @Override
    public int getLabelAlignment() {
        return SwingConstants.TOP;
    }

    public void deleteOperation() {
        ScalingOperation operation = ops.getSelectedValue();
        if (operation == null) {
            return;
        }

        if (JOptionPane.showConfirmDialog(null,
                "Are you sure you want to delete \"" + operation + "\"?",
                "Delete operation",
                JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
            return;
        }

        scale.removeOperation(operation);

        scaleChanged();
        updateOperationsList();
    }

    public void addOperation() {
        ScalingOperation operation = ScalingOperationDialog.show(null);
        if (operation == null) {
            return;
        }

        scale.addOperation(ops.getSelectedValue(), operation);

        scaleChanged();
        updateOperationsList();
    }

    public void editOperation() {
        ScalingOperation operation = ops.getSelectedValue();
        if (operation == null) {
            return;
        }

        operation = ScalingOperationDialog.show(null, operation);
        if (operation == null) {
            return;
        }

        scaleChanged();
        updateOperationsList();
    }

    public void moveDown() {
        ScalingOperation operation = ops.getSelectedValue();
        if (operation == null) {
            return;
        }

        scale.moveOperationDown(operation);
        scaleChanged();
        updateOperationsList();
    }

    public void moveUp() {
        ScalingOperation operation = ops.getSelectedValue();
        if (operation == null) {
            return;
        }

        scale.moveOperationUp(operation);
        scaleChanged();
        updateOperationsList();
    }

    public void updateOperationsList() {
        if (ops == null) {
            return;
        }

        ScalingOperation selected = ops.getSelectedValue();
        ops.setModel(getOperationsModel());
        ops.setSelectedValue(selected, true);
    }

    public void scaleChanged() {
        dirty = true;
        fireFieldChanged();
    }

    public void testOperation() {
        Tools.testOperation(null, scale);
    }

    private class FieldToolbar extends Toolbar<OperationsSettingField> {
        public FieldToolbar(OperationsSettingField settingField) {
            super(settingField);
        }

        @Override
        public Editor getEditor() {
            throw new UnsupportedOperationException();
        }

        @Override
        protected void preInitComponent(JToolBar toolbar) {
            super.preInitComponent(toolbar);

            toolbar.setOrientation(JToolBar.HORIZONTAL);
            toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.GRAY.darker()));
        }

        @Override
        protected void initComponent(JToolBar toolbar) {

            toolbar.add(makeSmallButton(FontAwesomeSolid.CARET_UP, "up", "Move operation up", e -> {
                moveUp();
            }));
            toolbar.add(makeSmallButton(FontAwesomeSolid.CARET_DOWN, "down", "Move operation down", e -> {
                moveDown();
            }));

            toolbar.addSeparator();

            toolbar.add(makeSmallButton(FontAwesomeSolid.EDIT, "edit", "Edit operation", e -> {
                editOperation();
            }));
            toolbar.add(makeSmallButton(FontAwesomeSolid.PLUS, "new", "Add operation", e -> {
                addOperation();
            }));
            toolbar.add(makeSmallButton(FontAwesomeSolid.TRASH, "delete", "Delete operation", e -> {
                deleteOperation();
            }));

            toolbar.addSeparator();

            toolbar.add(makeSmallButton(FontAwesomeSolid.VIAL, "test", "Test operations", e -> {
                testOperation();
            }));

        }
    }

    private static class Renderer extends DefaultListCellRenderer {
        private final Font font;

        private Renderer(Font font) {
            this.font = font;
        }

        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            Component component = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            component.setFont(font);
            return component;
        }
    }
}
