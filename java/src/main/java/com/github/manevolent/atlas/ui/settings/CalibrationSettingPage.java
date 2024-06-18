package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.logic.OS;
import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.ui.settings.field.*;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

public class CalibrationSettingPage extends BasicSettingPage {
    private final Frame parent;
    private final Project project;

    private final Calibration real;
    private final Calibration calibration;

    public CalibrationSettingPage(Frame parent, Project project,
                                  Calibration real, Calibration calibration) {
        super(parent, CarbonIcons.CATALOG, "Calibration - " + calibration.getName());

        this.project = project;
        this.parent = parent;
        this.real = real;
        this.calibration = calibration;
    }

    @Override
    protected String getHelpText() {
        return "A calibration is a specific map or tune that you can define which can be flashed to the vehicle. You can " +
                "define multiple calibrations: for example, one for 97 octane, one for E85, and one for a track day.";
    }

    public Calibration getRealSection() {
        return real;
    }

    public Calibration getWorkingSection() {
        return calibration;
    }

    @Override
    protected List<SettingField> createFields() {
        List<SettingField> elements = new ArrayList<>();

        elements.add(new CalibrationField(
                "",
                calibration,
                () -> {},
                project
        ));

        elements.add(new StringSettingField(
                "Name", "The name of this calibration",
                calibration.getName(),
                v -> true,
                calibration::setName
        ));

        elements.add(new ListSettingField<>(
                "Variant", "The platform variant of this calibration",
                project.getVariants(),
                calibration.getVariant(),
                v -> true,
                calibration::setVariant
        ));

        elements.add(new CheckboxSettingField(
                "Read-only", "Check if this calibration should never be edited in any table editors, etc.",
                calibration.isReadonly(),
                v -> true,
                calibration::setReadonly
        ));

        elements.add(new CheckboxSettingField(
                "Confidential", "Check if this calibration should never be shared in a shared project.",
                calibration.isConfidential(),
                v -> true,
                calibration::setConfidential
        ));

        MemorySection section = calibration.getSection();
        MemoryEncryptionType encryptionType = section.getEncryptionType();
        if (section.getMemoryType() == MemoryType.CODE) {
            if (calibration.getVariant().getOSType() != null) {
                OS os;
                try {
                    os = calibration.getOS();
                } catch (IOException e) {
                    Log.ui().log(Level.WARNING, "Problem loading OS for calibration " + calibration.getName(), e);
                    os = null;
                }

                if (os != null) {
                    for (PropertyDefinition parameter : os.getPropertyDefinitions()) {
                        elements.add(createSettingField(parameter, calibration.getKeySet()));
                    }
                }
            }

            if (encryptionType != null) {
                for (PropertyDefinition parameter : encryptionType.getFactory().getPropertyDefinitions()) {
                    elements.add(createSettingField(parameter, calibration.getKeySet()));
                }
            }
        }

        return elements;
    }

    @Override
    public boolean isDirty() {
        return !project.getCalibrations().contains(real) || super.isDirty();
    }
}
