package com.github.manevolent.atlas.ui.dialog;

import com.github.manevolent.atlas.model.ArithmeticOperation;
import com.github.manevolent.atlas.model.DataFormat;
import com.github.manevolent.atlas.model.Precision;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.component.field.BinaryInputField;
import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Inputs;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.HexFormat;
import java.util.function.Consumer;

import static com.github.manevolent.atlas.ui.util.Inputs.memorySectionField;

public class BinaryInputDialog extends JDialog {
    private final long defaultValue;
    private final long minValue, maxValue;

    private BinaryInputField binaryInputField;

    private boolean canceled = false;

    public BinaryInputDialog(Frame parent, long defaultValue, long minValue, long maxValue) {
        super(parent, "Enter Data Value", true);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
            canceled = true;
            super.windowClosing(e);
            }
        });

        this.defaultValue = defaultValue;
        this.minValue = minValue;
        this.maxValue = maxValue;

        setType(Type.POPUP);
        initComponent();
        pack();
        setLocationRelativeTo(parent);
        setResizable(false);
        setModal(true);
        setMinimumSize(new Dimension(300, getMinimumSize().height));
        setIconImage(Icons.getImage(CarbonIcons.MATRIX, Color.WHITE).getImage());

        binaryInputField.grabFocus();
    }

    private BinaryInputField createDataInputField(Consumer<Boolean> inputValid, Runnable enter) {
        binaryInputField = new BinaryInputField(Precision.WHOLE_NUMBER, (double) defaultValue,
                inputValid, (field) -> enter.run(), this::cancel);

        binaryInputField.setMin(minValue);
        binaryInputField.setMax(maxValue);

        return binaryInputField;
    }

    private void accept() {
        dispose();
        canceled = false;
    }

    private void cancel() {
        canceled = true;
        dispose();
    }

    private void initComponent() {
        JPanel content = Inputs.createEntryPanel();
        JButton ok = Inputs.button(CarbonIcons.CHECKMARK, "OK", null, this::accept);
        getRootPane().setDefaultButton(ok);

        BinaryInputField dataInputField = createDataInputField(ok::setEnabled, this::accept);
        Inputs.createEntryRow(content, 1, "Value", "The data value",
                dataInputField);

        JButton cancel = Inputs.button("Cancel", this::cancel);
        Inputs.createButtonRow(content, 2, ok, cancel);

        getContentPane().add(content);
        dataInputField.transferFocus();
    }

    public Long getValue() {
        if (!canceled) {
            return binaryInputField.getLongValue();
        } else {
            return null;
        }
    }


    public static Number show(Editor parent, DataFormat format) {
        switch (format) {
            case UBYTE -> {
                return (long) show(parent, 0, 255);
            }
            case SBYTE -> {
                return (long) show(parent, 0, 65535).byteValue();
            }
            case USHORT -> {
                return (long) show(parent, 0, 65535);
            }
            case SSHORT -> {
                return (long) show(parent, 0, 65535).shortValue();
            }
            case UINT -> {
                return (long) show(parent, 0L, (long) Math.pow(2, 32) - 1);
            }
            case SINT -> {
                return (long) show(parent, 0, (long) Math.pow(2, 32) - 1).intValue();
            }
            case FLOAT -> {
                return (float) Float.intBitsToFloat(show(parent, 0, (long) Math.pow(2, 32) - 1).intValue());
            }
            default -> throw new UnsupportedOperationException(format.name());
        }
    }

    public static Long show(Frame parent, long minValue, long maxValue) {
        return show(parent, 0L, minValue, maxValue);
    }

    public static Long show(Frame parent, long defaultValue, long minValue, long maxValue) {
        BinaryInputDialog dialog = new BinaryInputDialog(parent, defaultValue, minValue, maxValue);
        dialog.setVisible(true);
        return dialog.getValue();
    }
}
