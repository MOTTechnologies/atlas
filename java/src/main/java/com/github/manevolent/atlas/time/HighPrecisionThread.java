package com.github.manevolent.atlas.time;

import com.github.manevolent.atlas.logging.Log;

import java.util.function.Supplier;
import java.util.logging.Level;

public class HighPrecisionThread extends Thread {
    private final Runnable runnable;
    private final Object lock = new Object();
    private final IntervalTimer timer;

    private boolean canceled = false;

    public HighPrecisionThread(long queueResetLength, Supplier<Integer> freqeuencySupplier, Runnable runnable) {
        this.runnable = runnable;
        this.timer = new IntervalTimer(freqeuencySupplier, queueResetLength, lock);

        setName("High Precision Timer");
        setDaemon(true);
        setDefaultUncaughtExceptionHandler((t, ex) -> {
            Log.can().log(Level.SEVERE, t.getName() + " crashed", ex);
        });
    }

    public boolean isCanceled() {
        return canceled;
    }

    public void cancel() {
        synchronized (lock) {
            canceled = true;
            lock.notifyAll();
        }
    }

    @Override
    public void run() {
        final long start = System.nanoTime();
        synchronized (lock) {
            while (!canceled) {
                try {
                    timer.sleep();
                } catch (InterruptedException e) {
                    break;
                }

                runnable.run();
            }
        }
    }
}
