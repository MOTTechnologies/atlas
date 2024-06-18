package com.github.manevolent.atlas.ghidra;

import com.github.manevolent.atlas.model.Calibration;

import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;

public class AtlasCodeBlock extends AtlasMemoryBlock {
    public AtlasCodeBlock(Calibration calibration, Program program, AddressSpace addressSpace) {
        super(calibration.getSection(), program, addressSpace);
    }
}
