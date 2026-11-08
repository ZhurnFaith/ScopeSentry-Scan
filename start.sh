#!/bin/bash

# Enter working directory
cd /apps

# Check whether UPDATE file exists
if [ -f "/apps/UPDATE" ]; then
    echo "UPDATE file exists, start processing update..."

    # Back up the existing ScopeSentry executable
    if [ -f "/apps/ScopeSentry" ]; then
        echo "Back up the existing ScopeSentry file..."
        mv /apps/ScopeSentry /apps/ScopeSentry.bak || { echo "Backup failed"; exit 1; }
    fi

    # Read the ZIP file's URL
    zip_url=$(cat /apps/UPDATE)

    if [ -z "$zip_url" ]; then
        echo "ERROR: UPDATE no URL found in file"
        exit 1
    fi

    # Download ZIP file to /tmp/main.zip
    echo "Download the ZIP file from $zip_url..."
    curl -o /tmp/main.zip "$zip_url" || { echo "ERROR: ZIP file download failed"; mv /apps/ScopeSentry.bak /apps/ScopeSentry || exit 1; exit 1; }

    # Extract the ZIP file to the /apps directory
    echo "Extract ZIP file to /apps..."
    unzip -o /tmp/main.zip -d /apps || { echo "ERROR: extraction failed"; mv /apps/ScopeSentry.bak /apps/ScopeSentry || exit 1; exit 1; }

    # Clean up temporary files
    rm -f /tmp/main.zip

    # Delete UPDATE file
    rm -f /apps/UPDATE
else
    echo "UPDATE file does not exist, skip update and start the application..."
fi

# Ensure the new ScopeSentry file exists and is executable
if [ -f "/apps/ScopeSentry" ]; then
    chmod +x /apps/ScopeSentry
    # Run the new ScopeSentry executable
    echo "Run new ScopeSentry..."
    /apps/ScopeSentry
else
    echo "ERROR: ScopeSentry file does not exist, restore backup and start..."
    if [ -f "/apps/ScopeSentry.bak" ]; then
        mv /apps/ScopeSentry.bak /apps/ScopeSentry
        chmod +x /apps/ScopeSentry
        /apps/ScopeSentry
    else
        echo "ERROR: no backup file, unable to start the application"
        exit 1
    fi
fi
