package com.github.manevolent.atlas.protocol.uds;

public interface UDSListener {

    /**
     * Called when a UDS frame is read, but has not been handled yet
     * @param frame frame
     */
    default void onUDSFrameRead(UDSFrame frame) { }

    /**
     * Called when a UDS frame is written successfully, but has not been answered yet
     * @param frame UDS frame that was sent
     */
    default void onUDSFrameWrite(UDSFrame frame) { }

    /**
     * Called when the listener's parent is closed
     * @param session session closed
     */
    default void onDisconnected(UDSSession session) { }

}
