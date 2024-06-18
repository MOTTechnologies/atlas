#!/bin/sh
# SteamOS/Arch launcher script that checks if the current user has permissions to access /dev/ttyACM devices

# zenity dialog without gtk warnings
zen_nospam() {
  zenity 2> >(grep -v 'Gtk' >&2) --title="Atlas Serial Config" --width=300 --height=100 "$@"
}

# execute atlas
atlas() {
  jre/bin/java --enable-preview --add-exports java.base/java.lang=ALL-UNNAMED --add-exports java.desktop/sun.awt=ALL-UNNAMED --add-exports java.desktop/sun.java2d=ALL-UNNAMED -cp "lib/*" com.github.manevolent.atlas.ui.Atlas
}

# zenity dialogs for adding user to the approriate group
change() {
  setup=$(zen_nospam --question --text="User: $USER does not have serial device permissions.\nUpdate permissions?")
  if [ $? -eq 0 ]; then
    # prompt user for sudo password
    PASS=$(zen_nospam --entry --hide-text --text="Enter your sudo/admin password:")
    if [ $? -eq 0 ]; then
      # add user to group
      echo "$PASS" | sudo -S usermod -a -G "$SERIAL_GROUP" "$USER"
      # create temp file indicating restart needed
      touch /tmp/restartrequired.status
      if groups "$USER" | grep -q "$SERIAL_GROUP"; then
          if [ $DISTRO == "steamos" ]; then
            # prompt for restart on SteamOS
            setup=$(zen_nospam --question --text="Permissions applied successfully.\nSteam Deck restart required.\nRestart now?")
            if [ $? -eq 0 ]; then
              # restart steam deck
              echo "$PASS" | sudo -S shutdown -r now
            else
              zen_nospam --warning --text="Restart aborted.\nRestart required to apply permissions."
            fi
          else
            # assume the user knows how to use a computer
            zen_nospam --info --text="Permissions set successfully.\nPlease log out and log back in to apply changes."
          fi
      else
        zen_nospam --warning --text="Failed to set user serial permissions.\nManual execution of \"sudo usermod -a -G $SERIAL_GROUP $USER\" may resolve this."
      fi
    else
      zen_nospam --warning --text="Canceled."
    fi
  else
    zen_nospam --warning --text="Canceled permissions change."
  fi
}

# detect linux distro
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${ID}"
elif type lsb_release >/dev/null 2>&1; then
    DISTRO=$(lsb_release -i -s)
elif [ -f /etc/redhat-release ]; then
    DISTRO='centos'
else
    DISTRO=$(uname -s)
fi

# specify the appropriate user group
case "$DISTRO" in
    "ubuntu" | "debian")
        SERIAL_GROUP="dialout"
        ;;
    "fedora" | "centos" | "rhel")
        SERIAL_GROUP="dialout"
        ;;
    "arch")
        SERIAL_GROUP="uucp"
        ;;
    "steamos")
        SERIAL_GROUP="uucp"
        ;;
    "gentoo")
        SERIAL_GROUP="uucp"
        ;;
    "suse" | "opensuse")
        SERIAL_GROUP="uucp"
        ;;
    *)
        SERIAL_GROUP="dialout"
        ;;
esac

if groups "$USER" | grep -q "$SERIAL_GROUP"; then
  if [ -f "/tmp/restartrequired.status" ]; then
    if [ $DISTRO == "steamos" ]; then
      # prompt for restart on SteamOS
      zen_nospam --warning --text="A restart is required.\nRestart and try again."
    else
      # warn user that changes may not be applied but start atlas anyway
      zen_nospam --info --text="Serial permissions may not have been applied.\nAtlas will not be able detect Tactrix\nPlease log out and log back in to apply changes."
      atlas
    fi
  else
    # launch atlas
    atlas
  fi
else
  # start change permission function
  change
fi
