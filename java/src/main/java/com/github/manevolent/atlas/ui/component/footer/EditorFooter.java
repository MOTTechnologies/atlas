package com.github.manevolent.atlas.ui.component.footer;

import com.github.manevolent.atlas.ApplicationMetadata;
import com.github.manevolent.atlas.connection.ConnectionFeature;
import com.github.manevolent.atlas.ui.util.Fonts;
import com.github.manevolent.atlas.ui.util.Icons;
import com.github.manevolent.atlas.ui.util.Labels;
import com.github.manevolent.atlas.ui.Editor;
import com.github.manevolent.atlas.ui.util.Separators;
import org.kordamp.ikonli.carbonicons.CarbonIcons;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.TimerTask;

public class EditorFooter extends Footer<Editor> {
    private JLabel statusLabel;
    private Instant statusInstant;
    private String statusString;

    private JLabel connectionLabel;

    private java.util.Timer timer;

    public EditorFooter(Editor editor) {
        super(editor);

        this.statusInstant = Instant.now();
        this.statusString = "Initialized";
    }

    @Override
    public Editor getEditor() {
        return getParent();
    }

    @Override
    protected void preInitComponent(JPanel footerBar) {
        footerBar.setLayout(new BorderLayout());
        footerBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0,
                Color.GRAY.darker()));
    }

    /**
     * Can be reinitialized
     * @param footerBar footer bar
     */
    @Override
    protected void initComponent(JPanel footerBar) {
        Font smallFont = Fonts.getTextFont().deriveFont(11f);
        Color color = Fonts.getTextColor().darker();

        JPanel left = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        footerBar.add(left, BorderLayout.WEST);
        left.add(statusLabel = Labels.text("", color, smallFont));

        JPanel right = new JPanel(new FlowLayout(FlowLayout.LEFT));
        footerBar.add(right, BorderLayout.EAST);

        connectionLabel = Labels.icon(CarbonIcons.PLUG_FILLED);
        connectionLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                getParent().getConnectionManager().requireConnection(ConnectionFeature.DATALOG);
            }
        });

        setConnected(getParent().getConnectionManager().isConnected());
        right.add(connectionLabel);

        right.add(Separators.horizontal());

        String applicationName = ApplicationMetadata.getName() + " " + ApplicationMetadata.getVersion();
        right.add(Labels.text(applicationName, color, smallFont));
    }

    @Override
    protected void postInitComponent(JPanel component) {
        timer = new java.util.Timer("Status");
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                SwingUtilities.invokeLater(() -> {
                    updateStatus();
                });
            }
        }, 1000, 1000);
    }

    public void updateStatus() {
        String timeString;
        Instant now = Instant.now();
        long minutes = ChronoUnit.MINUTES.between(statusInstant, now);
        long seconds = ChronoUnit.SECONDS.between(statusInstant, now);
        if (minutes == 1) {
            timeString = "a minute ago";
        } else if (minutes > 1) {
            timeString = minutes + " minutes ago";
        } else {
            timeString = "moments ago";
        }

        statusLabel.setText(statusString + " (" + timeString + ")");
    }

    public void setStatus(String status) {
        this.statusInstant = Instant.now();
        this.statusString = status;

        updateStatus();
    }

    public void setConnected(boolean connected) {
        connectionLabel.setIcon(Icons.get(CarbonIcons.PLUG_FILLED,
                connected ? Color.GREEN.darker() : Color.GRAY));
        connectionLabel.revalidate();
        connectionLabel.repaint();

        if (connected) {
            connectionLabel.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
            connectionLabel.setToolTipText("Connected to vehicle");
        } else {
            connectionLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            connectionLabel.setToolTipText("Disconnected");
        }
    }
}