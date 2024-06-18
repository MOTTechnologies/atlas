package com.github.manevolent.atlas;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.TimeoutException;

public interface FrameReader<T extends Frame>  extends Closeable {
    T read() throws IOException, TimeoutException;
}
