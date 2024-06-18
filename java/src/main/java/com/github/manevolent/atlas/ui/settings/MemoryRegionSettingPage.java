package com.github.manevolent.atlas.ui.settings;

import com.github.manevolent.atlas.model.*;
import com.github.manevolent.atlas.model.crypto.MemoryEncryption;
import com.github.manevolent.atlas.model.crypto.MemoryEncryptionType;
import com.github.manevolent.atlas.ui.settings.field.*;
import com.github.manevolent.atlas.ui.util.Labels;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class MemoryRegionSettingPage extends BasicSettingPage {
    private final Frame parent;
    private final Project project;

    private final MemorySection real;
    private final MemorySection section;

    public MemoryRegionSettingPage(Frame parent, Project project,
                                   MemorySection real, MemorySection section) {
        super(parent, CarbonIcons.CHIP, "Memory Region - " + section.getName());

        this.project = project;
        this.parent = parent;
        this.real = real;
        this.section = section;
    }

    public MemorySection getRealSection() {
        return real;
    }

    public MemorySection getWorkingSection() {
        return section;
    }

    @Override
    protected String getHelpText() {
        return "A memory region is a known segment of memory in the ECU. Add a code region to tell Atlas where a " +
                "calibration file (ROM) should exist and be flashed to, or add a RAM region to instruct Atlas how to " +
                "read variables in memory for gauges and data-logging.";
    }


    @Override
    protected List<SettingField> createFields() {
        List<SettingField> elements = new ArrayList<>();

        elements.add(new StringSettingField(
                "Name", "The name of this memory region",
                section.getName(),
                v -> true,
                section::setName
        ));

        elements.add(new EnumSettingField<>(
                "Type",
                "The memory type of this region",
                MemoryType.class,
                section.getMemoryType(),
                v -> true,
                section::setMemoryType
        ));

        elements.add(new AddressSettingField(
                "Base Address", "The base address of this memory region",
                section.getBaseAddress(),
                v -> true,
                section::setBaseAddress
        ));

        elements.add(new IntegerSettingField(
                "Length", "The data length of this memory region",
                section.getDataLength(),
                0,
                Integer.MAX_VALUE,
                v -> true,
                section::setDataLength
        ));

        elements.add(new EnumSettingField<>(
                "Byte Order",
                "The byte order for data in this region",
                MemoryByteOrder.class,
                section.getByteOrder(),
                v -> true,
                section::setByteOrder
        ));

        elements.add(new EnumSettingField<>(
                "Encryption Type",
                "The encryption type for data in this region",
                MemoryEncryptionType.class,
                section.getEncryptionType(),
                v -> {
                    section.setup(project);
                    return true;
                },
                v -> {
                    section.setEncryptionType(v);
                    reinitialize();
                }));

        MemoryEncryptionType encryptionType = section.getEncryptionType();
        if (encryptionType != null && encryptionType != MemoryEncryptionType.NONE) {
            MemoryEncryption encryption = section.getEncryptionType().getFactory().create();
            elements.add(new LabelSettingField("Cipher Info",
                    Labels.text(CarbonIcons.APPLICATION, "Block size: " + (encryption.getBlockSize() * 8) + " bits"),
                    Labels.text(CarbonIcons.PASSWORD, "Key size: " + (encryption.getKeySize() * 8) + " bits")
            ));
        }

        return elements;
    }

    @Override
    public boolean isDirty() {
        return !project.getSections().contains(real) || super.isDirty();
    }
}
