package com.github.manevolent.atlas.ui;

import com.github.manevolent.atlas.ApplicationMetadata;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;

import static java.awt.Font.SANS_SERIF;

public class SplashForm extends JFrame {
    private final BufferedImage splashImage;
    private final Font headerFont;
    private final Timer timer;

    private float progress;
    private String status = "Loading...";

    public SplashForm() throws IOException, FontFormatException {
        splashImage = ImageIO.read(SplashForm.class.getResource("/splash2.png"));

        setIgnoreRepaint(false);
        setUndecorated(true);
        setBackground(new Color(0, 0, 0, 0));
        setResizable(false);
        setType(Type.UTILITY);

        timer = new Timer(250, (e) -> {
            if (isVisible()) {
                SplashForm.this.repaint();
            }
        });

        Font font = Font.createFont(Font.TRUETYPE_FONT,
                getClass().getResourceAsStream("/fonts/splash_header.otf"));

        this.headerFont = font.deriveFont(Font.BOLD, 40);

        String applicationName = ApplicationMetadata.getName();
        String applicationVersion = ApplicationMetadata.getVersion();

        JPanel backgroundImage = new JPanel() {
            @Override
            public void paintComponent(Graphics g) {
                super.paintComponent(g);

                if (g instanceof Graphics2D) {
                    ((Graphics2D) g).setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON);
                }

                // Draw the background image.
                g.drawImage(splashImage, 0, 0, getWidth(), getHeight(), this);
                g.setFont(headerFont);
                g.setColor(Color.WHITE);
                g.drawString(applicationName, 40, 50 + 20);

                Font versionFont = new Font(SANS_SERIF, Font.BOLD, 20);
                g.setColor(Color.WHITE.darker());
                g.setFont(versionFont);
                g.drawString(applicationVersion,
                        40,
                        50 + 20 + 30
                );

                int progressHeight = 5;
                g.setColor(Color.GRAY);
                g.fillRect(0, getHeight() - progressHeight, getWidth(), getHeight());

                String progressString = status;

                // Get the FontMetrics
                Font statusFont = new Font(SANS_SERIF, Font.BOLD, 14);
                FontMetrics metrics = g.getFontMetrics(statusFont);

                // Determine the X coordinate for the text
                g.setColor(Color.WHITE);
                int x = (getWidth() / 2) - (metrics.stringWidth(progressString) / 2);

                if (progress > 0f) {
                    g.setFont(statusFont);
                    g.drawString(progressString, x, getHeight() - progressHeight - 16);
                }

                g.setColor(Color.GREEN.darker());
                g.fillRect(0, getHeight() - progressHeight, (int) (getWidth() * progress), getHeight());
            }
        };

        backgroundImage.setDoubleBuffered(true);
        backgroundImage.setSize(getPreferredSize());
        backgroundImage.setBackground(Color.BLACK);

        add(backgroundImage);

        pack();
        setLocationRelativeTo(null);

        timer.start();
    }

    @Override
    public void dispose() {
        setVisible(false);

        super.dispose();

        timer.stop();
    }

    public void setProgress(float progress, String status) {
        this.progress = progress;
        this.status = status;
        java.awt.EventQueue.invokeLater(() -> {
            revalidate();
            repaint();
        });
    }

    @Override
    public Dimension getPreferredSize() {
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        double width = screenSize.getWidth();
        double height = screenSize.getHeight();

        height /= 3;

        float imageAspectRatio = (float)splashImage.getWidth() / (float)splashImage.getHeight();

        width = height * imageAspectRatio;

        return new Dimension((int)Math.round(width), (int)Math.round(height));
    }


    @Override
    public void paint(Graphics g) {
        super.paint(g);
    }
}
