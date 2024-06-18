package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.connection.ConnectionType;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryption;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionFactory;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.settings.field.*;
import com.github.manevolent.atlas.ui.util.Labels;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class KeySetSettingPage extends BasicSettingPage {
    private final Frame parent;
    private final Project project;

    private final KeySet real;
    private final KeySet keySet;

    public KeySetSettingPage(Frame parent, Project project,
                             KeySet real, KeySet keySet) {
        super(parent, CarbonIcons.PASSWORD, "Key Set - " + keySet.getName());

        this.project = project;
        this.parent = parent;
        this.real = real;
        this.keySet = keySet;
    }

    public KeySet getRealKeySet() {
        return real;
    }

    public KeySet getWorkingKeySet() {
        return keySet;
    }

    @Override
    protected String getHelpText() {
        return "A key set is a list of settings specific to the connection type selected. Typically, the keys entered " +
                "will be used to authenticate with the ECU. Define multiple key sets to " +
                "support different calibrations and their associated vendor-specific keys.";
    }

    @Override
    protected List<SettingField> createFields() {
        List<SettingField> elements = new ArrayList<>();

        elements.add(new StringSettingField(
                "Name", "The name of this key set.",
                keySet.getName(),
                v -> true,
                keySet::setName
        ));

        elements.add(new CheckboxSettingField(
                "Confidential", "Check if this key set should never be shared in a shared project.",
                keySet.isConfidential(),
                v -> true,
                keySet::setConfidential
        ));

        ConnectionType connectionType = project.getConnectionType();

        for (PropertyDefinition parameter : connectionType.getFactory().getPropertyDefinitions()) {
            elements.add(createSettingField(parameter, keySet));
        }

        return elements;
    }

    @Override
    public boolean isDirty() {
        return !project.getKeySets().contains(real) || super.isDirty();
    }
}
