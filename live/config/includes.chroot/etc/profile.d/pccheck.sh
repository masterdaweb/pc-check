export PYTHONPATH=/opt/pccheck
if [ "$(id -u)" = 0 ] && [ -t 1 ]; then
    echo
    echo "  Master da Web PC-Check live system. The burn-in runs on tty1 (Alt+F1)."
    echo "  Commands:  pccheck status [--watch]   |   pccheck abort   |   pccheck report <session-dir>"
    echo "  Results:   /mnt/pccheck/pccheck/sessions/"
    echo
fi
