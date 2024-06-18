package com.github.manevolent.atlas.connection;

import java.io.IOException;

public class FlashException extends IOException {
    private final FlashResult result;
    private final String message;

    public FlashException(FlashResult result, String message, Exception thrown) {
        super(message, thrown);

        this.message = message;
        this.result = result;
    }

    public FlashException(FlashResult.State state, String message, Exception thrown) {
        super(message, thrown);

        this.message = message;
        this.result = new FlashResult(state, 0);
    }

    public FlashException(FlashResult result, String message) {
        super(message);

        this.message = message;
        this.result = result;
    }

    public FlashException(FlashResult.State state, String message) {
        super(message);

        this.message = message;
        this.result = new FlashResult(state, 0);
    }

    public FlashResult getResult() {
        return result;
    }
}
