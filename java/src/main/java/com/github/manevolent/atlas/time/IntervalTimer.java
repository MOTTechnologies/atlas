package com.github.manevolent.atlas.time;

import com.github.manevolent.atlas.logging.Log;

import java.util.function.Supplier;

public class IntervalTimer {
    private final Supplier<Integer> interval;
    private final long maximumMissed;
    private final Object lock;
    private long wake, time, wait;

    public IntervalTimer(Supplier<Integer> interval, long maximumMissed, Object lock) {
        this.interval = interval;
        this.maximumMissed = maximumMissed;
        this.lock = lock;
        this.time = wake = System.nanoTime();
    }

    public IntervalTimer(Supplier<Integer> interval, long maximumMissed) {
        this(interval, maximumMissed, new Object());
    }

    public synchronized void sleep() throws InterruptedException {
        long interval = (long) ((1d / (double)this.interval.get()) * 1_000D * 1_000_000);

        // Get timestamp
        time = System.nanoTime();

        // Find the time we need to wake up at
        wake += interval;

        long maxDelay = time - (interval * maximumMissed);
        if (wake < maxDelay) {
            /*Log.get().warning(getClass().getSimpleName() + " falling behind: " + ((maxDelay - wake) / 1_000_000D)
                    + "ms behind; abruptly resetting timer..."
            );*/

            wake = time;
        }

        // Calculate how long we will need to wait
        wait = (wake - time);

        // Wait until the specified time
        sleepFor(wait);

        while (wake > System.nanoTime()) {
            ; //consume cycles
        }
    }

    private void sleepFor(long nanos) throws InterruptedException {
        if (nanos > 0) {
            long elapsed = 0, t0, waitMillis;
            double waitTime;
            int waitNanos;

            while (elapsed < nanos) {
                t0 = System.nanoTime();
                waitTime = nanos / 1_000_000D;
                waitMillis = (long) Math.floor(waitTime);
                waitNanos = (int) ((waitTime - waitMillis) * 1_000_000);

                lock.wait(waitMillis, waitNanos);

                elapsed += System.nanoTime() - t0;
            }
        }
    }
}