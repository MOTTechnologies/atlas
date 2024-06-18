package com.github.manevolent.atlas.ui.behavior;

import javax.swing.*;

public abstract class TimedAnimation extends Animation {
    private final double duration;
    private long start = 0L;

    public TimedAnimation(JComponent component, double duration) {
        super(component);

        this.duration = duration;
    }

    @Override
    public boolean isAnimating() {
        return getPosition() <= 1d && isAlive();
    }

    protected double getPosition() {
        return ((System.nanoTime() - start) / 1_000_000_000D) / duration;
    }

    @Override
    protected void update(JComponent component) {
        double position = Math.max(0D, Math.min(1D, getPosition()));
        update(position, component);
    }

    protected abstract void update(double position, JComponent component);

    @Override
    public void cancel() {
        super.cancel();
        finish();
    }

    protected void onComplete() {

    }

    private void finish() {
        update(1D, getComponent());
        onComplete();
    }

    @Override
    public void run() {
        start = System.nanoTime();
        try {
            super.run();
        } finally {
            finish();
        }
    }
}
