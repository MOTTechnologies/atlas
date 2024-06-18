package com.github.manevolent.atlas.ui.dialog;

import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import com.github.manevolent.atlas.ui.util.Inputs;
import com.github.manevolent.atlas.ui.util.Labels;
import com.github.manevolent.atlas.ui.util.Layout;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ProgressDialog extends JDialog implements ProgressListener {
    private Instant start = Instant.now();

    private final String message;
    private final boolean cancellable;
    private final AtomicBoolean canceled = new AtomicBoolean(false);

    private float lastProgress = 0f;
    private Instant lastUpdate = start;
    private JProgressBar progressBar;
    private JLabel statusText;
    private JLabel etaText;

    private Runnable cancelCallback;

    public ProgressDialog(Frame parent, String title, String message, boolean cancellable) {
        super(parent, title, true);

        this.message = message;
        this.cancellable = cancellable;

        initComponents();

        setResizable(false);

        if (!cancellable) {
            setUndecorated(true);
        }

        pack();

        setMinimumSize(new Dimension(getWidth() + 100, getPreferredSize().height));
        setPreferredSize(new Dimension(getWidth() + 100, getPreferredSize().height));

        setLocationRelativeTo(parent);

        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                close();
            }
        });

        if (cancellable) {
            Inputs.bind(this, "cancel", this::close, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0x00));
        }
    }

    private void close() {
        if (!cancellable) {
            return;
        }

        if (canceled.get()) {
            return;
        }

        if (JOptionPane.showConfirmDialog(getParent(),
                "Are you sure you want to cancel the operation?",
                "Cancel",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) {
            return;
        }

        updateProgress("Canceling...", (float) progressBar.getPercentComplete());
        canceled.set(true);

        if (cancelCallback != null) {
            cancelCallback.run();
        }
    }

    public void setCancelCallback(Runnable callback) {
        this.cancelCallback = callback;
    }

    public boolean isCanceled() {
        return cancellable && canceled.get();
    }

    private void initComponents() {
        JPanel frame = new JPanel();
        frame.setLayout(new GridLayout(4, 1));
        frame.setBorder(BorderFactory.createEmptyBorder(20, 20, 10, 20));

        frame.add(Layout.emptyBorder(0, 0, 10, 0, Labels.boldText(message)));

        frame.add(Layout.emptyBorder(10, 0, 10, 0,
                statusText = Labels.text("")));
        statusText.setForeground(statusText.getForeground().darker());

        frame.add(Layout.emptyBorder(10, 0, 10, 0, progressBar = new JProgressBar()));

        JPanel pushRight = new JPanel(new BorderLayout());
        pushRight.add(etaText = Layout.alignRight(Labels.text("")), BorderLayout.EAST);
        frame.add(Layout.emptyBorder(pushRight));
        etaText.setForeground(etaText.getForeground().darker());

        progressBar.setValue(0);
        progressBar.setMaximum(1000);

        add(frame);
    }

    @Override
    public void updateProgress(String message, float progress) {
        if (canceled.get()) {
            return;
        }

        if (progress < lastProgress) {
            start = Instant.now();
        }

        lastProgress = progress;

        Instant now = Instant.now();
        SwingUtilities.invokeLater(() -> {
            long millisElapsed = ChronoUnit.MILLIS.between(start, now);
            float multiplier = 1f / progress;
            long millisToGo = (long) (multiplier * millisElapsed) - millisElapsed;
            int number;
            String unit;
            if (millisToGo < 60_000) {
                number = (int) Math.ceil((double)millisToGo / 1000D);
                unit = "second";
            } else {
                number = (int) Math.ceil((double)millisToGo / 1000D / 60D);
                unit = "minute";
            }
            if (number > 1) {
                unit += "s"; //pluralize
            }


            if (number > 0 && number < Integer.MAX_VALUE) {
                etaText.setText(number + " " + unit + " left");
                lastUpdate = now;
            }

            progressBar.setValue((int) (progress * progressBar.getMaximum()));
            statusText.setText(message);

            statusText.revalidate();
            statusText.repaint();

            progressBar.revalidate();
            progressBar.repaint();
        });
    }
}