package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.Variant;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.toolbar.VariantToolbar;
import com.github.manevolent.atlas.ui.settings.field.FieldChangeListener;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.event.InternalFrameEvent;
import javax.swing.event.InternalFrameListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.util.Comparator;
import java.util.List;

import static javax.swing.JOptionPane.WARNING_MESSAGE;

public abstract class SettingsWindow<T extends SettingObject> extends Window
        implements InternalFrameListener, FieldChangeListener, ListSelectionListener {
    private final Ikon icon;
    private final String title;

    private final T real;
    private final T workingCopy;

    private JButton apply;

    private SettingPage settingPage;
    private Variant variant;
    private boolean dirty = false;
    private JList<Variant> variantList;

    private boolean showVariantList;
    private JPanel contentPanel;

    protected SettingsWindow(boolean showVariantList, Editor editor,
                             T object, Ikon icon, String title) {
        super(editor);

        this.showVariantList = showVariantList;

        this.icon = icon;
        this.title = title;

        this.real = object;
        this.workingCopy = createWorkingCopy(object);

        this.variant = pickVariant(editor);
    }

    public Variant pickVariant(Editor editor) {
        Variant active = editor.getVariant();
        if (isVariantSupported(active)) {
            return active;
        } else {
            return getSupportedVariants().getFirst();
        }
    }

    protected boolean isVariantSupported(Variant variant) {
        return true;
    }

    private List<Variant> getSupportedVariants() {
        return getProject().getVariants().stream()
                .filter(this::isVariantSupported)
                .sorted(Comparator.comparing(Variant::getName))
                .toList();
    }

    protected void addVariant(Variant variant) {
        reloadVariantList();
        setVariant(variant);
        setDirty(true);
    }

    protected void deleteVariant(Variant variant) {
        reloadVariantList();
        setVariant(getSupportedVariants().getFirst());
        setDirty(true);
    }

    @Override
    public String getTitle() {
        return title + (isDirty() ? "*" : "");
    }

    @Override
    public Icon getIcon() {
        return Icons.get(icon);
    }

    public T getItem() {
        return real;
    }

    public T getWorkingCopy() {
        return workingCopy;
    }

    @Override
    protected void preInitComponent(JInternalFrame frame) {
        super.preInitComponent(frame);

        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        frame.addInternalFrameListener(this);
    }

    /**
     * Creates a working copy for the supplied object.
     * @param object object to create a working copy for.
     * @return working copy instance.
     */
    protected T createWorkingCopy(T object) {
        return object.createWorkingCopy();
    }

    /**
     * Creates a new setting page for the window's content area.
     * @return new setting page instance.
     */
    protected SettingPage createSettingPage() {
        return new DefaultSettingPage(getParent(), CarbonIcons.SETTINGS, "Settings",
                getWorkingCopy().createFields(getProject(), getVariant()));
    }

    protected Variant getVariant() {
        return variant;
    }

    protected void onVariantChanged(Variant variant) {
        if (variantList.getSelectedValue() != variant) {
            variantList.setSelectedValue(variant, true);
        }

        reloadSettings();

        contentPanel.revalidate();
        contentPanel.repaint();
    }

    protected void setVariant(Variant variant) {
        if (variant == null) {
            return;
        }

        if (this.variant != variant) {
            this.variant = variant;

            onVariantChanged(variant);
        }
    }

    /**
     * Get the setting page associated with this window, or creates one if one does not exist.
     * @return setting page instance.
     */
    public SettingPage getSettingPage() {
        if (settingPage == null) {
            settingPage = createSettingPage();
            settingPage.addChangeListener(this);
        }

        return settingPage;
    }

    protected void reloadSettings() {
        this.settingPage = createSettingPage();
        this.contentPanel.removeAll();
        this.contentPanel.add(initSettings(), BorderLayout.CENTER);
    }

    protected JComponent initSettings() {
        return getSettingPage().getContent();
    }

    protected JComponent initFooter() {
        JPanel footer = new JPanel(new GridLayout(1, 2));

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT));

        footer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY.darker()),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ));

        buttonRow.add(Inputs.nofocus(Inputs.button("Close", this::cancel)));
        buttonRow.add(apply = Inputs.nofocus(Inputs.button("Save", this::apply)));
        apply.setEnabled(isDirty());

        getComponent().getRootPane().setDefaultButton(apply);

        footer.add(buttonRow);

        return footer;
    }

    private boolean isDirty() {
        return dirty;
    }

    public void setDirty(boolean dirty) {
        if (this.dirty != dirty) {
            apply.setEnabled(dirty);
            updateTitle();
        }
    }

    protected void onApplied() {
        updateTitle();
        getEditor().setDirty(true);
        apply.setEnabled(settingPage.isDirty());
    }

    private void apply() {
        getSettingPage().apply();
        real.applyWorkingCopy(workingCopy);
        onApplied();
    }

    private void cancel() {
        if (getSettingPage().isDirty()) {
            String message = "You have unsaved changes to your settings " +
                    "that will be lost. Save changes before closing?";

            focus();

            int answer = JOptionPane.showConfirmDialog(getParent(),
                    message,
                    "Unsaved changes",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    WARNING_MESSAGE
            );

            switch (answer) {
                case JOptionPane.CANCEL_OPTION:
                    return;
                case JOptionPane.YES_OPTION:
                    apply();
                case JOptionPane.NO_OPTION:
                    break;
            }
        }

        dispose();
    }

    private JToolBar initVariantToolbar() {
        return new VariantToolbar<>(this) {
            @Override
            protected List<Variant> getSupportedVariants() {
                return SettingsWindow.this.getSupportedVariants();
            }

            @Override
            protected Variant getCurrentVariant() {
                return SettingsWindow.this.getVariant();
            }

            @Override
            protected void addVariant(Variant variant) {
                SettingsWindow.this.addVariant(variant);
            }

            @Override
            protected void deleteVariant(Variant variant) {
                SettingsWindow.this.deleteVariant(variant);
            }

            @Override
            public Editor getEditor() {
                return SettingsWindow.this.getEditor();
            }
        }.getComponent();
    }

    private void reloadVariantList() {
        variantList.removeListSelectionListener(this);
        variantList.setModel(createVariantListModel());
        variantList.setSelectedValue(variant, true);
        variantList.addListSelectionListener(this);
    }

    protected ListModel<Variant> createVariantListModel() {
        DefaultListModel<Variant> model = new DefaultListModel<>();
        getSupportedVariants().forEach(model::addElement);
        return model;
    }

    private JList<Variant> initVariantList() {
        JList<Variant> list = new JList<>(createVariantListModel());
        Layout.emptyBorder(list);
        list.setBackground(new JPanel().getBackground());
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        Layout.preferWidth(list, 200);

        if (list.getModel().getSize() > 0) {
            list.setSelectedValue(variant, true);
        }

        list.addListSelectionListener(this);

        return list;
    }

    protected JPanel initVariantPanel() {
        JPanel variantPanel = new JPanel(new BorderLayout());
        Layout.matteBorder(0, 0, 0, 1, Color.GRAY.darker(), variantPanel);

        variantPanel.add(initVariantToolbar(), BorderLayout.NORTH);
        if (variantList == null) {
            variantList = initVariantList();
        } else {
            reloadVariantList();
        }
        JScrollPane scrollPane = new JScrollPane(variantList);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        variantPanel.add(scrollPane, BorderLayout.CENTER);

        return variantPanel;
    }

    @Override
    public void valueChanged(ListSelectionEvent e) {
        setVariant(variantList.getSelectedValue());
    }

    @Override
    protected void initComponent(JInternalFrame frame) {
        JPanel contentPanel = new JPanel(new BorderLayout());

        if (this.contentPanel == null) {
            this.contentPanel = new JPanel(new BorderLayout());
        }

        this.contentPanel.removeAll();
        this.contentPanel.add(initSettings(), BorderLayout.CENTER);

        if (showVariantList) {
            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, initVariantPanel(),
                    this.contentPanel);
            contentPanel.add(splitPane, BorderLayout.CENTER);
        } else {
            contentPanel.add(this.contentPanel, BorderLayout.CENTER);
        }

        contentPanel.add(initFooter(), BorderLayout.SOUTH);

        frame.setContentPane(contentPanel);
    }

    @Override
    public void reload() {

    }

    @Override
    public void onFieldChanged(SettingField field) {
        setDirty(true);
    }

    @Override
    public void internalFrameActivated(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameClosed(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameClosing(InternalFrameEvent e) {
        cancel();
    }

    @Override
    public void internalFrameDeactivated(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameDeiconified(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameIconified(InternalFrameEvent e) {

    }

    @Override
    public void internalFrameOpened(InternalFrameEvent e) {

    }
}
