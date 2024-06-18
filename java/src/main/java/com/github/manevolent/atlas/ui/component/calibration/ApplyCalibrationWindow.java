package com.github.manevolent.atlas.ui.component.calibration;

import com.github.manevolent.atlas.model.Calibration;

import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.ZeroDividerSplitPane;
import com.github.manevolent.atlas.ui.behavior.ChangeType;
import com.github.manevolent.atlas.ui.behavior.ClickListener;
import com.github.manevolent.atlas.ui.behavior.Model;
import com.github.manevolent.atlas.ui.component.Window;
import com.github.manevolent.atlas.ui.component.tab.TreeTab;
import com.github.manevolent.atlas.ui.component.table.TableComparer;
import com.github.manevolent.atlas.ui.util.*;
import com.google.common.html.HtmlEscapers;
import org.kordamp.ikonli.Ikon;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.InternalFrameAdapter;
import javax.swing.event.InternalFrameEvent;

import java.awt.*;

import java.util.*;
import java.util.List;

import static com.github.manevolent.atlas.ui.util.Fonts.getTextColor;

public class ApplyCalibrationWindow extends Window {
    private final List<ComparedItem> comparedItems;
    private final Map<ComparedItem, JPanel> listItems = new HashMap<>();
    private final Set<ComparedItem> enabledItems = new HashSet<>();
    private final Calibration source, target;

    private ComparedItem selected;

    private JPanel listPanel;
    private JPanel rootPanel;
    private JPanel contentPanel;

    private JButton apply;

    public ApplyCalibrationWindow(Editor editor, Calibration source, Calibration target,
                                  List<ComparedItem> comparedItems) {
        super(editor);

        this.source = source;
        this.target = target;
        this.comparedItems = comparedItems;
    }

    @Override
    public String getTitle() {
        return "Apply " + source.getName() + " to " + target.getName();
    }

    @Override
    public Icon getIcon() {
        return Icons.get(CarbonIcons.FETCH_UPLOAD, getTextColor());
    }

    @Override
    public void reload() {

    }

    private void onSelectedItemChanged(ComparedItem old, ComparedItem item) {
        if (old != null) {
            Layout.emptyBorder(2, 2, 2, 2, listItems.get(old));
        }

        contentPanel.removeAll();

        if (item != null) {
            Layout.matteBorder(2, 2, 2, 2, Color.GRAY, listItems.get(item));
        } else {
            return;
        }

        JPanel panel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(new CompoundBorder(
                new MatteBorder(0, 0, 1, 0, Color.GRAY.darker()),
                new EmptyBorder(5, 5, 5, 5)
        ));

        topPanel.add(Labels.boldText(item.getItem().getTreeIcon(), item.getItem().getTreeIconColor(),
                item.getItem().getTreeName()));

        panel.add(topPanel, BorderLayout.NORTH);

        if (item instanceof ComparedTable comparedTable) {
            panel.add(new TableComparer(getEditor(),
                            comparedTable.getItem(), item.getSource(),
                            comparedTable.getItem(), item.getTarget(),
                            TableComparer.CompareOperation.SUBTRACT
                    ).getComponent().getContentPane(),
                    BorderLayout.CENTER);
        }

        listPanel.revalidate();
        listPanel.repaint();

        contentPanel.add(panel);

        contentPanel.revalidate();
        contentPanel.repaint();
    }

    private void setSelectedItem(ComparedItem newItem) {
        if (newItem != selected) {
            ComparedItem oldItem = selected;
            this.selected = newItem;
            onSelectedItemChanged(oldItem, newItem);
        }
    }

    private JPanel createRow(Ikon ikon, Color iconColor, CompareSeverity worst, String tableName,
                             ComparedItem compared, List<Comparison> comparisons) {
        JPanel outerPanel = new JPanel(new BorderLayout());
        Layout.emptyBorder(5, 5, 0, 5, outerPanel);

        JPanel borderPanel = new JPanel(new BorderLayout());
        Layout.emptyBorder(2, 2, 2, 2, borderPanel);
        listItems.put(compared, borderPanel);

        JCheckBox checkBox = new JCheckBox("", true) {
            @Override
            public void repaint() {
                super.repaint();
                if (listPanel != null) {
                    listPanel.repaint();
                }
            }
        };

        if (worst != null) {
            borderPanel.setBackground(Colors.withAlpha(worst.getColor(), 16));

            if (worst == CompareSeverity.ERROR || worst == CompareSeverity.MATCH) {
                checkBox.setSelected(false);
            }

            if (worst == CompareSeverity.ERROR) {
                checkBox.setEnabled(false);
            }
        } else {
            borderPanel.setBackground(Colors.withAlpha(Color.GRAY, 16));
        }

        if (checkBox.isSelected()) {
            enabledItems.add(compared);

            if (apply != null) {
                SwingUtilities.invokeLater(() -> {
                    apply.setEnabled(!enabledItems.isEmpty());
                });
            }
        }

        checkBox.addChangeListener((e) -> {
            if (checkBox.isSelected()) {
                enabledItems.add(compared);
            } else {
                enabledItems.remove(compared);
            }

            if (apply != null) {
                SwingUtilities.invokeLater(() -> {
                    apply.setEnabled(!enabledItems.isEmpty());
                });
            }
        });

        JPanel innerPanel = new JPanel();
        innerPanel.setLayout(new BoxLayout(innerPanel, BoxLayout.Y_AXIS));
        innerPanel.setOpaque(false);
        Layout.emptyBorder(3, 3, 3, 3, innerPanel);

        checkBox.setOpaque(false);
        borderPanel.add(checkBox, BorderLayout.WEST);

        JLabel titleLabel = new JLabel();
        titleLabel.setIcon(Icons.get(ikon, iconColor));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD));
        titleLabel.setText("<html>" + HtmlEscapers.htmlEscaper().escape(tableName) + "</html>");
        innerPanel.add(titleLabel);

        for (Comparison comparison : comparisons) {
            JLabel label = new JLabel();
            label.setIcon(comparison.getIcon());
            label.setText("<html>" + HtmlEscapers.htmlEscaper().escape(comparison.getText()) + "</html>");
            innerPanel.add(label);
        }

        borderPanel.add(innerPanel, BorderLayout.CENTER);
        outerPanel.add(borderPanel);

        return outerPanel;
    }

    private JPanel createRow(ComparedItem comparedItem, CompareSeverity worst, List<Comparison> comparisons) {
        TreeTab.Item item = comparedItem.getItem();
        return createRow(item.getTreeIcon(), item.getTreeIconColor(), worst,
                item.getTreeName(), comparedItem, comparisons);
    }

    private JPanel initList() {
        JPanel listPanel = new JPanel();
        listPanel.setLayout(new GridBagLayout());

        int row = 0;
        for (; row < comparedItems.size(); row ++) {
            ComparedItem comparedItem = comparedItems.get(row);

            CompareSeverity worst = comparedItem.getComparisons().stream()
                    .map(Comparison::getSeverity)
                    .max(Comparator.comparing(CompareSeverity::getOrdinal))
                    .orElse(null);

            JPanel rowPanel = createRow(comparedItem, worst, comparedItem.getComparisons());

            if (worst != CompareSeverity.ERROR) {
                rowPanel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
                rowPanel.addMouseListener(new ClickListener(() -> setSelectedItem(comparedItem)));
            }

            listPanel.add(rowPanel, Layout.gridBagConstraints(GridBagConstraints.NORTH,
                    GridBagConstraints.HORIZONTAL, 0, row, 1, 0));
        }

        return listPanel;
    }

    @Override
    protected void preInitComponent(JInternalFrame frame) {
        frame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        frame.addInternalFrameListener(new InternalFrameAdapter() {
            @Override
            public void internalFrameClosing(InternalFrameEvent e) {
                cancel();
            }
        });
    }

    @Override
    protected void initComponent(JInternalFrame frame) {
        apply = Inputs.button("Apply", this::apply);
        listPanel = initList();

        JScrollPane scrollPaneLeft = new JScrollPane(listPanel,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPaneLeft.setBorder(BorderFactory.createEmptyBorder());

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(scrollPaneLeft, BorderLayout.CENTER);

        JPanel finishPanel = new JPanel(new BorderLayout());
        finishPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Color.GRAY.darker()),
                BorderFactory.createEmptyBorder(4, 4, 4, 4)
        ));
        JPanel finishButtonRow = new JPanel();
        finishButtonRow.setLayout(new BoxLayout(finishButtonRow, BoxLayout.X_AXIS));
        finishButtonRow.add(Inputs.button("Cancel", this::cancel));

        apply.setEnabled(false);
        frame.getRootPane().setDefaultButton(apply);
        finishButtonRow.add(apply);

        SwingUtilities.invokeLater(() -> {
            apply.setEnabled(!enabledItems.isEmpty());
        });

        finishPanel.add(finishButtonRow, BorderLayout.EAST);
        leftPanel.add(finishPanel, BorderLayout.SOUTH);

        contentPanel = new JPanel(new BorderLayout());

        JSplitPane splitPane = new ZeroDividerSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                leftPanel, contentPanel);

        if (rootPanel == null) {
            rootPanel = new JPanel(new BorderLayout());
        } else {
            rootPanel.removeAll();
        }

        rootPanel.add(splitPane, BorderLayout.CENTER);

        frame.add(rootPanel);

        setSelectedItem(comparedItems.getFirst());
    }

    private void apply() {
        if (JOptionPane.showConfirmDialog(getEditor(),
                "Are you sure you want to apply " + enabledItems.size() + " item(s) from "
                        + source.getName() + " to " + target.getName() + "?",
                "Apply Calibration",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        getEditor().executeWithProgress("Applying Calibration",
                "Applying " + source.getName() + " to " + target.getName() + "...",
                (dialog) -> {
                    List<ComparedItem> filteredItems = enabledItems.stream().toList();

                    int i = 0;
                    for (; i < filteredItems.size(); i ++) {
                        ComparedItem comparedItem = filteredItems.get(i);

                        dialog.updateProgress("Applying " + comparedItem.getItem().getTreeName() + "...",
                                (float) i / (float) comparedItems.size());

                        try {
                            comparedItem.apply();
                        } catch (Throwable ex) {
                            Errors.show(getEditor(), "Apply Failed", "Failed to apply " +
                                    comparedItem.getItem().getTreeName(), ex);
                            return;
                        }

                        if (comparedItem instanceof ComparedTable) {
                            getEditor().fireModelChange(Model.TABLE, ChangeType.MODIFIED);
                        }
                    }

                    ApplyCalibrationWindow.this.close();

                    JOptionPane.showConfirmDialog(getComponent(),
                            "Successfully applied " + i + " item(s) from " + source.getName() + " to "
                                    + target.getName() + ".",
                            "Apply Successful",
                            JOptionPane.OK_CANCEL_OPTION);
                });
    }

    private void cancel() {
        if (JOptionPane.showConfirmDialog(getEditor(),
                "Are you sure you want to cancel?",
                "Cancel",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        dispose();
    }

}
