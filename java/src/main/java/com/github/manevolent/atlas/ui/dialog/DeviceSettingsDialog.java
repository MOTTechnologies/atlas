package com.github.manevolent.atlas.ui.dialog;

import com.github.manevolent.atlas.ApplicationMetadata;
import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.protocol.j2534.*;
import com.github.manevolent.atlas.ui.util.*;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;
import java.util.logging.Level;

import static java.awt.event.ItemEvent.SELECTED;

public class DeviceSettingsDialog extends JDialog {
    private JComboBox<J2534DeviceType> deviceTypeField;
    private JComboBox<J2534DeviceDescriptor> deviceField;

    private J2534DeviceDescriptor defaultDevice;
    private J2534DeviceType deviceType;

    public DeviceSettingsDialog(JFrame parent) {

        setMinimumSize(new Dimension(350, 150));
        setType(Type.POPUP);
        setIconImage(Icons.getImage(CarbonIcons.TOOL_BOX, Color.WHITE).getImage());
        initComponent();
        pack();
        setResizable(false);
        setModal(true);
        setLocationRelativeTo(parent);
        setTitle(ApplicationMetadata.getName() + " - Device Settings");
    }

    private JComboBox<J2534DeviceType> deviceTypeField(J2534DeviceType existing,
                                                       Consumer<J2534DeviceType> valueChanged) {
        J2534DeviceType[] values = Arrays.stream(J2534DeviceType.values())
                .sorted(Comparator.comparing(J2534DeviceType::toString)).toArray(J2534DeviceType[]::new);
        JComboBox<J2534DeviceType> comboBox = new JComboBox<>();

        comboBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED) {
                return;
            }

            valueChanged.accept((J2534DeviceType)e.getItem());
        });

        comboBox.setModel(new DefaultComboBoxModel<>(values));
        comboBox.setSelectedItem(existing);

        return comboBox;
    }

    private void updateDeviceModel(J2534DeviceProvider<?> provider) {
        if (deviceField == null) {
            return;
        }

        List<J2534DeviceDescriptor> devices;

        try {
            devices = provider.getAllDevices().stream().map(x -> (J2534DeviceDescriptor) x).toList();

            // Make mutable
            devices = new ArrayList<>(devices);
        } catch (Throwable e) {
            String message = "Problem getting devices";
            Log.can().log(Level.SEVERE, message, e);
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(getParent(),
                                message + "!\r\n"
                                + e.getMessage() + "\r\n"
                                + "See console output (F12) for more details.",
                        "Device Error",
                        JOptionPane.ERROR_MESSAGE);
            });

            devices = new ArrayList<>();
        }

        J2534DeviceDescriptor defaultDescriptor;

        try {
            defaultDescriptor = provider.getDefaultDevice();
        } catch (DeviceNotFoundException ex) {
            defaultDescriptor = new MissingJ2534DeviceDescriptor(ex.getName());
            devices.add(defaultDescriptor);
        } catch (Exception ex) {
            if (devices.isEmpty()) {
                defaultDescriptor = null;
            } else {
                defaultDescriptor = devices.getFirst();
            }
        }

        J2534DeviceDescriptor[] values = devices.stream()
                .sorted(Comparator.comparing(J2534DeviceDescriptor::toString))
                .toArray(J2534DeviceDescriptor[]::new);

        deviceField.setModel(new DefaultComboBoxModel<>(values));

        deviceField.setSelectedItem(defaultDescriptor);

        deviceField.revalidate();
        deviceField.repaint();
    }

    private static JComboBox<J2534DeviceDescriptor> deviceField(Consumer<J2534DeviceDescriptor> valueChanged) {
        JComboBox<J2534DeviceDescriptor> comboBox = new JComboBox<>();
        Color defaultColor = comboBox.getForeground();
        comboBox.setRenderer(new Renderer());
        comboBox.addItemListener(e -> {
            if (e.getStateChange() != SELECTED) {
                return;
            }

            if (e.getItem() instanceof MissingJ2534DeviceDescriptor) {
                comboBox.setForeground(Color.RED);
            } else {
                comboBox.setForeground(defaultColor);
            }

            valueChanged.accept((J2534DeviceDescriptor) e.getItem());
        });
        return comboBox;
    }

    private void initComponent() {
        JPanel frame = new JPanel();
        frame.setLayout(new GridBagLayout());
        frame.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        frame.add(Layout.emptyBorder(0, 0, 10, 0, Labels.boldText("Device Settings")),
                Layout.gridBagConstraints(GridBagConstraints.NORTHWEST,
                        GridBagConstraints.NONE,
                        0, 0,
                        2, 1,
                        1, 1));

        Inputs.createEntryRow(frame, 1, "Type", "The type of J2534 device to establish a vehicle connection with",
                deviceTypeField = deviceTypeField(Devices.getType(), (newDeviceType) ->{
                    updateDeviceModel(newDeviceType.getProvider());
                    deviceType = newDeviceType;
                }));

        deviceType = (J2534DeviceType) deviceTypeField.getSelectedItem();

        Inputs.createEntryRow(frame, 2, "Device", "The type of J2534 device to establish a vehicle connection with",
                deviceField = deviceField((newDevice) ->{
                    this.defaultDevice = newDevice;
                }));

        updateDeviceModel(Devices.getProvider());

        JButton ok;
        frame.add(ok = Inputs.button(CarbonIcons.CHECKMARK, "OK", this::accept),
                Layout.gridBagConstraints(GridBagConstraints.SOUTHEAST,
                        GridBagConstraints.NONE,
                        0, 3,
                        2, 1,
                        1, 1)
        );
        getRootPane().setDefaultButton(ok);

        add(frame);
    }

    public void accept() {
        if (deviceType != null) {
            Devices.setType(deviceType);
        } else {
            return;
        }

        if (defaultDevice instanceof MissingJ2534DeviceDescriptor) {
            dispose();
            return;
        }

        try {
            deviceType.getProvider().setDefaultDevice(defaultDevice);
            dispose();
        } catch (Exception ex) {
            Errors.show(this, "Device change failed", "Problem setting default device", ex);
        }
    }

    private static class MissingJ2534DeviceDescriptor implements J2534DeviceDescriptor {
        private final String name;

        private MissingJ2534DeviceDescriptor(String name) {
            this.name = name;
        }

        @Override
        public J2534Device createDevice(Project project) throws IOException {
            throw new UnsupportedEncodingException();
        }

        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            return name + " (missing)";
        }
    }

    private static class Renderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            Component component = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);

            if (value instanceof MissingJ2534DeviceDescriptor) {
                if (component instanceof JLabel label) {
                    label.setForeground(Color.RED);
                }
            }

            return component;
        }
    }

}
