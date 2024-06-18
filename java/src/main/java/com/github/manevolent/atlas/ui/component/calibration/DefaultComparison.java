package com.github.manevolent.atlas.ui.component.calibration;

import com.github.manevolent.atlas.ui.util.Icons;
import org.kordamp.ikonli.Ikon;

import javax.swing.*;

public class DefaultComparison implements Comparison {
    private final CompareSeverity severity;
    private final Icon icon;
    private final String text;

    public DefaultComparison(CompareSeverity severity, Icon icon, String text) {
        this.severity = severity;
        this.icon = icon;
        this.text = text;
    }

    public DefaultComparison(CompareSeverity severity, Ikon icon, String text) {
        this.severity = severity;
        this.icon = Icons.get(icon, severity.getColor());
        this.text = text;
    }

    @Override
    public CompareSeverity getSeverity() {
        return severity;
    }

    @Override
    public Icon getIcon() {
        return icon;
    }

    @Override
    public String getText() {
        return text;
    }

}
