package com.github.manevolent.atlas.ui.behavior;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * TLDR: Swing is weird about click events. Make sure clicking works as most people expect.
 *
 * If you press down on the mouse, move it, and release, that's technically a drag event.  The action of releasing the
 * mouse after the pointer has moved will mute the click event, which makes using the interface very frustrating.
 *
 * To solve this, this class will hook to mouseReleased(MouseEvent) as well and watch for any left button releases.
 * That corrects the problem and makes the interface feel more responsive, rather than "clicks" doing nothing. It's
 * important to do this, since end-users likely will use the application on a laptop with a track pack/some sort of
 * finger tracking device that slip the mouse ever so slightly when you click (i.e. Mac).
 */
public class ClickListener extends MouseAdapter {
    /**
     * The action to fire when a click is detected.
     */
    private final Runnable action;

    /**
     * The last pressed location of the mouse on the screen.
     */
    private Point lastPressedLocation;

    /**
     * Click action listener.
     */
    private boolean clicking = false;

    /**
     * Creates a new click listener with a specified action to run when a click event takes place.
     * @param action action to run.
     */
    public ClickListener(Runnable action) {
        this.action = action;
    }

    /**
     * Sets if the mouse is pressed on this component.
     */
    public void setClicking(boolean clicking) {
        this.clicking = clicking;
    }

    /**
     * Checks if the mouse was pressed on this component, but no mouse release event has been received.
     * @return true if the mouse is in a clicking state in regard to this component.
     */
    public boolean isClicking() {
        return clicking;
    }

    /**
     * Gets the last pressed location of the mouse cursor in screen coordinates.
     * @return last pressed location, or null if no mouse press is currently occurring.
     */
    protected Point getLastPressedLocation() {
        return lastPressedLocation;
    }

    /**
     * Gets the maximum threshold of mouse movement during a drag event before a click event will not be fired.
     * @return movement threshold, in pixels.
     */
    protected double getMovementThreshold() {
        return Double.MAX_VALUE;
    }

    /**
     * Used by the drag event listener to determine if a "click" has taken place.
     * @param e mouse event to inspect
     * @return true if the event represents a click (i.e. MouseEvent.BUTTON1 is actuated), false otherwise.
     */
    protected boolean isClickButton(MouseEvent e) {
        return e.getButton() == MouseEvent.BUTTON1;
    }

    /**
     * Used by the drag event listener to determine if a "click" has taken place in a manner that implies the desired
     * component is clicked. For example, if you first press the mouse down then drag off the component and release the
     * mouse, ideally the click action should not be fired. This method will return "false" by default to ensure that
     * behavior.
     * @param e mouse event to inspect
     * @return true if the component is considered clicked by the provided event, false otherwise.
     */
    protected boolean isComponentClicked(MouseEvent e) {
        Component component = e.getComponent();
        if (component == null) {
            return false;
        }
        return component.contains(e.getPoint());
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        if (clicking) {
            setClicking(false);
            action.run();
        }
    }

    @Override
    public void mousePressed(MouseEvent e) {
        if (isClickButton(e)) {
            lastPressedLocation = e.getLocationOnScreen();
            setClicking(true);
        }
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        Point lastLocation = lastPressedLocation;

        if (lastLocation != null) {
            Point location = e.getLocationOnScreen();
            double distance = location.distance(lastLocation);
            if (distance < getMovementThreshold() && isClickButton(e) && isComponentClicked(e) && clicking) {
                setClicking(false);
                action.run();
            }

            lastPressedLocation = null;
        }
    }
}
