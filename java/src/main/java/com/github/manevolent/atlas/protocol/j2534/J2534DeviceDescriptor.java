package com.github.manevolent.atlas.protocol.j2534;

import com.github.manevolent.atlas.model.Project;

import java.io.IOException;

public interface J2534DeviceDescriptor {

    J2534Device createDevice(Project project) throws IOException;

}
