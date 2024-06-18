package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.ui.ZeroDividerSplitPane;

import com.github.manevolent.atlas.ui.settings.field.FieldChangeListener;
import com.github.manevolent.atlas.ui.settings.field.SettingField;

import com.github.manevolent.atlas.ui.util.Layout;
import org.kordamp.ikonli.Ikon;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;

import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;

public abstract class ListSettingPage<T, P extends BasicSettingPage>
        extends AbstractSettingPage
        implements ListSelectionListener, FieldChangeListener {
    private JList<T> list;
    private JPanel settingsContent;
    private JComponent content;
    private P settingPage;

    private java.util.Map<T, T> workingCopies = new HashMap<>();
    private java.util.Map<T, P> settingPages = new HashMap<>();

    protected ListSettingPage(Ikon icon, String name) {
        super(icon, name);
    }

    protected P getSettingPage() {
        return settingPage;
    }

    protected abstract T createWorkingCopy(T real);

    protected abstract java.util.List<T> getList();

    protected String getName(T object) {
        return object.toString();
    }

    @Override
    public JComponent getContent() {
        if (content == null) {
            content = initComponent();
        }

        return content;
    }

    protected ListModel<T> createListModel() {
        DefaultListModel<T> model = new DefaultListModel<>();

        workingCopies.values()
                .stream().sorted(Comparator.comparing(this::getName))
                .forEach(model::addElement);

        return model;
    }

    private JList<T> initList() {
        JList<T> list = new JList<>(createListModel());
        Layout.emptyBorder(list);
        list.setBackground(new JPanel().getBackground());
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        Layout.preferWidth(list, 200);

        if (list.getModel().getSize() > 0) {
            list.setSelectedIndex(0);
        }

        list.addListSelectionListener(this);

        return list;
    }

    protected JToolBar initToolBar() {
        return null;
    }

    private JPanel initLeftPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        JToolBar toolBar = initToolBar();
        if (toolBar != null) {
            panel.add(toolBar, BorderLayout.NORTH);
        }

        panel.add(list = initList(), BorderLayout.CENTER);

        return panel;
    }

    private JPanel initRightPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        Layout.emptyBorder(panel);
        return panel;
    }

    private JComponent initComponent() {
        // Initialize all working copies
        getList().stream()
                .filter(t -> !workingCopies.containsKey(t))
                .forEach(t -> workingCopies.put(t, createWorkingCopy(t)));

        JScrollPane leftScrollPane = new JScrollPane(
                initLeftPanel(),
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        Layout.matteBorder(0, 0, 0, 1, Color.GRAY.darker(), leftScrollPane);
        Layout.minimumWidth(leftScrollPane, 200);

        JScrollPane rightScrollPane = new JScrollPane(
                settingsContent = initRightPanel(),
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED
        );
        Layout.emptyBorder(rightScrollPane);

        rightScrollPane.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                JScrollPane scrollPane = (JScrollPane) e.getComponent();
                settingsContent.setMaximumSize(new Dimension(0, Integer.MAX_VALUE));
                Dimension preferredSize = settingsContent.getLayout().minimumLayoutSize(settingsContent);
                settingsContent.setPreferredSize(new Dimension(
                        0,
                        (int) preferredSize.getHeight()
                ));
                settingsContent.revalidate();
            }
        });

        updateSettingContent();

        return new ZeroDividerSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftScrollPane, rightScrollPane);
    }

    protected void add(T real) {
        T workingCopy = createWorkingCopy(real);

        settingPages.put(workingCopy, createSettingPage(real, workingCopy));
        workingCopies.put(real, workingCopy);

        updateListModel();

        fireFieldChanged(null);
    }

    protected void remove(T workingCopy) {
        T real = getReal(workingCopy);

        // Remove from the model
        settingPages.remove(workingCopy);
        workingCopies.remove(real);

        // Update the model
        updateListModel();

        fireFieldChanged(null);
    }

    public T getReal(T workingCopy) {
        return workingCopies.keySet().stream()
                .filter(real -> workingCopies.get(real) == workingCopy)
                .findFirst().orElseThrow();
    }

    protected java.util.Map<T, T> getWorkingCopies() {
        return Collections.unmodifiableMap(workingCopies);
    }

    protected abstract P createSettingPage(T real, T workingCopy);

    protected P createSettingPage(T workingCopy) {
        return createSettingPage(getReal(workingCopy), workingCopy);
    }

    private void updateSettingContent() {
        settingsContent.removeAll();

        T selected = list.getSelectedValue();

        if (selected != null) {
            settingPage = settingPages.get(selected);

            if (settingPage == null) {
                settingPage = createSettingPage(selected);
                settingPage.addChangeListener(this);
                settingPages.put(selected, settingPage);
            }

            settingsContent.add(settingPage.getContent(), BorderLayout.CENTER);
        }

        settingsContent.revalidate();
        settingsContent.repaint();
    }

    protected void updateListModel() {
        SwingUtilities.invokeLater(() -> {
            int index = list.getSelectedIndex();
            list.setModel(createListModel());
            if (index >= 0) {
                list.setSelectedIndex(index);
            }
        });
    }

    @Override
    public boolean apply() {
        return settingPages.values().stream().allMatch(BasicSettingPage::apply);
    }

    @Override
    public void valueChanged(ListSelectionEvent e) {
        updateSettingContent();
    }

    @Override
    public boolean isScrollNeeded() {
        return false;
    }

    @Override
    public boolean isDirty() {
        java.util.List<T> list = getList();
        boolean pagesDirty = settingPages.values().stream().anyMatch(SettingPage::isDirty);
        boolean willDelete = list.stream().anyMatch(cal -> !getWorkingCopies().containsKey(cal));
        boolean willAdd = getWorkingCopies().keySet().stream().anyMatch(cal -> !list.contains(cal));
        return pagesDirty || willDelete || willAdd;
    }

    @Override
    public void onFieldChanged(SettingField field) {
        fireFieldChanged(field);
    }
}
