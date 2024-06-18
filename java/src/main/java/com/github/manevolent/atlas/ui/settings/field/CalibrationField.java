package com.github.manevolent.atlas.ui.settings.field;

import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.ui.dialog.BinaryInputDialog;
import com.github.manevolent.atlas.ui.settings.BasicSettingPage;
import com.github.manevolent.atlas.ui.settings.DefaultSettingPage;
import com.github.manevolent.atlas.ui.settings.SettingPage;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Layout;
import org.checkerframework.checker.units.qual.A;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.*;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;

import static javax.swing.JOptionPane.WARNING_MESSAGE;

public class CalibrationField extends AbstractSettingField {
    private final Calibration calibration;

    private final Project project;
    private boolean dirty;
    private JButton export;
    private final JPanel buttonRow;

    public CalibrationField(String name, Calibration calibration, Runnable changed, Project project) {
        super(name, null);
        this.calibration = calibration;
        this.project = project;

        buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT));

        buttonRow.add(Inputs.button(CarbonIcons.FOLDER, "Open ROM...", () -> {
            if (calibration.getSection() == null) {
                return;
            }

            if (calibration.hasData()) {
                if (JOptionPane.showConfirmDialog(null,
                        "WARNING!\r\n" + calibration.getName() + " already has ROM binary data.\r\n" +
                                "Changing this data will PERMANENTLY remove any table data associated with this calibration in Atlas.\r\n" +
                                "Proceed with replacing existing data with a new ROM file?",
                        "Overwrite Calibration",
                        JOptionPane.YES_NO_OPTION,
                        WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
                    return;
                }
            }

            AtomicReference<Boolean> decryptRom = new AtomicReference<>(true);
            SettingPage settingPage = new DefaultSettingPage(null, CarbonIcons.SETTINGS, "Options",
                    SettingField.create(Boolean.class, "Decrypt ROM", "Decrypt the opened ROM data with the " +
                            "vendor-specific algorithm and key material.", decryptRom));

            FileNameExtensionFilter def = new FileNameExtensionFilter("Binary files", "bin");
            JFileChooser fileChooser = settingPage.newFileChooser();
            fileChooser.addChoosableFileFilter(def);
            fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("ROM files", "rom"));
            fileChooser.setFileFilter(def);
            fileChooser.setDialogTitle("Open ROM file - " + calibration.getName());
            if (fileChooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) {
                return;
            }

            File file = fileChooser.getSelectedFile();
            byte[] data;
            try (FileInputStream inputStream = new FileInputStream(file)) {
                data = inputStream.readAllBytes();
            } catch (Exception e) {
                Log.can().log(Level.SEVERE, "Problem opening ROM file " + file.getAbsolutePath(), e);
                JOptionPane.showMessageDialog(null, "Problem opening ROM file!\r\n" +
                                e.getMessage() + "\r\n" +
                                "See console output (F12) for more details.",
                        "Open ROM failed",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            int offset = 0x0;
            int length = calibration.getSection().getDataLength();

            if (data.length < calibration.getSection().getDataLength()) {
                JOptionPane.showMessageDialog(null,
                        "The ROM file you provided is too short: it is " +
                                data.length + " bytes long, but the " +
                                calibration.getSection().getName() + " memory region is " +
                                calibration.getSection().getDataLength() + " bytes long.",
                        "Open ROM failed",
                        JOptionPane.ERROR_MESSAGE);
                return;
            } else if (data.length > calibration.getSection().getDataLength()) {
                if (JOptionPane.showConfirmDialog(null,
                        "The ROM file you provided is " + data.length + " bytes long, but the " +
                        calibration.getSection().getName() + " memory region is " +
                                calibration.getSection().getDataLength() + " bytes long. " +
                        "An byte offset in \"" + file.getName() + "\" will be required to inform Atlas" +
                                " where the corresponding start of the memory region is located.\r\nWould you like to provide an offset?",
                        "Offset Required",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.QUESTION_MESSAGE) != JOptionPane.OK_OPTION) {
                    return;
                }

                Long answer = BinaryInputDialog.show(null,
                        calibration.getSection().getBaseAddress(),
                        0, 0xFFFFFFFFL);

                if (answer == null) {
                    return;
                }

                offset = (int) (long) answer;
            }

            if (!decryptRom.get()) {
                try {
                    calibration.getSection().getEncryptionType().getFactory().create().encrypt(calibration, data);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            calibration.updateSource(data, offset, length);
            dirty = true;
            fireFieldChanged();

            export.setEnabled(calibration.hasData());
        }));

        buttonRow.add(export = Inputs.button(CarbonIcons.EXPORT, "Export ROM...", () -> {
            if (calibration.getSection() == null) {
                return;
            }

            if (!calibration.hasData()) {
                return;
            }

            //TODO correct checksum
            AtomicReference<Boolean> encryptRom = new AtomicReference<>(true);
            SettingPage settingPage = new DefaultSettingPage(null, CarbonIcons.SETTINGS, "Options",
                    SettingField.create(Boolean.class, "Encrypt ROM", "Encrypt the saved ROM data with the " +
                            "vendor-specific algorithm and key material.", encryptRom));

            JFileChooser fileChooser = settingPage.newFileChooser();
            FileNameExtensionFilter def = new FileNameExtensionFilter("Binary files", "bin");
            fileChooser.addChoosableFileFilter(def);
            fileChooser.addChoosableFileFilter(new FileNameExtensionFilter("ROM files", "rom"));
            fileChooser.setFileFilter(def);
            fileChooser.setDialogTitle("Export ROM data - " + calibration.getName());
            if (fileChooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) {
                return;
            }

            File file = fileChooser.getSelectedFile();

            byte[] data;
            try {
                data = calibration.readFully();

                if (encryptRom.get()) {
                    calibration.getSection().getEncryptionType().getFactory().create().encrypt(calibration, data);
                }
            } catch (Exception e) {
                Log.can().log(Level.SEVERE, "Problem exporting ROM data to file " + file.getAbsolutePath(), e);
                JOptionPane.showMessageDialog(null, "Problem exporting ROM data!\r\n" +
                                e.getMessage() + "\r\n" +
                                "See console output (F12) for more details.",
                        "Export ROM data failed",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            try (FileOutputStream outputStream = new FileOutputStream(file)) {
                outputStream.write(data);
            } catch (Exception e) {
                Log.can().log(Level.SEVERE, "Problem exporting ROM data to file " + file.getAbsolutePath(), e);
                JOptionPane.showMessageDialog(null, "Problem exporting ROM data!\r\n" +
                                e.getMessage() + "\r\n" +
                                "See console output (F12) for more details.",
                        "Export ROM data failed",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
        }));

        export.setEnabled(calibration.hasData());
    }

    @Override
    public JComponent getInputComponent() {
        return buttonRow;
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
}
