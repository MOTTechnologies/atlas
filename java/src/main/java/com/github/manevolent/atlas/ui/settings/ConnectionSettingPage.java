package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.connection.ConnectionFeature;
import com.github.manevolent.atlas.connection.ConnectionType;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.ui.settings.field.EnumSettingField;
import com.github.manevolent.atlas.ui.settings.field.LabelSettingField;
import com.github.manevolent.atlas.ui.settings.field.ListSettingField;
import com.github.manevolent.atlas.ui.settings.field.SettingField;
import com.github.manevolent.atlas.ui.settings.validation.ValidationSeverity;
import com.github.manevolent.atlas.ui.settings.validation.ValidationState;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Jobs;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ConnectionSettingPage extends BasicSettingPage {
    private final Project project;
    private final Frame parent;

    private ConnectionType connectionType;

    public ConnectionSettingPage(Frame parent, Project project) {
        super(parent, CarbonIcons.PLUG, "Connection");

        this.parent = parent;
        this.project = project;
        this.connectionType = project.getConnectionType();
    }

    @Override
    protected List<SettingField> createFields() {
        List<SettingField> elements = new ArrayList<>();

        elements.add(new EnumSettingField<>(
                "Connection Type",
                "The communication type for connections to this vehicle",
                ConnectionType.class,
                connectionType,
                t -> {
                    ConnectionType existing = project.getConnectionType();
                    if (t != existing) {
                        if (existing != null && JOptionPane.showConfirmDialog(null,
                                "Are you sure you want to change the project connection type?\r\n" +
                                        "Doing so will interrupt any established connections.",
                                "Warning",
                                JOptionPane.YES_NO_OPTION,
                                JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
                            return false;
                        }

                        Jobs.fork(() -> {
                            project.setConnectionType(t);
                        });
                    }

                    return true;
                },
                (connectionType) -> {
                    this.connectionType = connectionType;
                    reinitialize();
                }));

        elements.add(new ListSettingField<>(
                "Key Set",
                "The key set to use when authorizing with the vehicle or encrypting/decrypting data.",
                project.getKeySets(),
                project.getActiveKeySet(),
                (v) -> true,
                v -> {
                    project.getKeySets().forEach(k -> k.setActive(false));
                    v.setActive(true);
                }));

        // List support features
        elements.add(new LabelSettingField("Supported Features", Arrays.stream(ConnectionFeature.values())
                .map(feature -> {
                    JLabel label = new JLabel(feature.getName());

                    boolean supported = connectionType.getFactory().getSupportedFeatures().contains(feature);
                    label.setIcon(supported ? Icons.get(CarbonIcons.CHECKMARK_FILLED, Color.GREEN) :
                            Icons.get(CarbonIcons.ERROR_FILLED, Color.RED)
                    );

                    return label;
                }).toList()));

        return elements;
    }

    @Override
    public void validate(ValidationState state) {
        if (connectionType == ConnectionType.DEBUG) {
            state.add(this, ValidationSeverity.WARNING, "Connection type is currently set to debug. " +
                    "Are you sure this correct?");
        }
    }

    @Override
    public boolean isDirty() {
        return super.isDirty() || project.getConnectionType() != connectionType;
    }
}
