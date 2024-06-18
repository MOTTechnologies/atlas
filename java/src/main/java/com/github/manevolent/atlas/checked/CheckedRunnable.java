package com.github.manevolent.atlas.checked;

public interface CheckedRunnable<E extends Exception> extends Runnable {

    @Override
    default void run() {
        try {
            runChecked();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    void runChecked() throws E;

}
