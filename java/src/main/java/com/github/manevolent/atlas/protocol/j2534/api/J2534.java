package com.github.manevolent.atlas.protocol.j2534.api;

import com.sun.jna.Library;

public interface J2534 extends Library {
    int PassThruOpen();
}
