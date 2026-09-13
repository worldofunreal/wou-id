#!/bin/sh

# Host-side control for the wou-id jail.
# `service wou_id start|stop|restart|status` drives the jail, so the deploy
# pipeline keeps using the same command it always used.
#
# At boot the generic jail service already starts every jail in jail.conf,
# including this one, so start is idempotent: if the jail is up we only
# confirm the service answers.

# PROVIDE: wou_id
# REQUIRE: LOGIN cleanvar jail
# KEYWORD: shutdown

. /etc/rc.subr

name="wou_id"
rcvar="wou_id_enable"

load_rc_config "${name}"

: ${wou_id_enable:="NO"}
: ${wou_id_jail:="wou-id"}
: ${wou_id_health_url:="http://127.0.0.1:25570/health"}
: ${wou_id_health_timeout:="40"}

pidfile="/var/run/jail_${wou_id_jail}.pid"

start_cmd="wou_id_jail_start"
stop_cmd="wou_id_jail_stop"
restart_cmd="wou_id_jail_restart"
status_cmd="wou_id_jail_status"
extra_commands="status"

wou_id_jid()
{
	/usr/sbin/jls -j "${wou_id_jail}" jid 2>/dev/null
}

wou_id_wait_healthy()
{
	i=0
	while [ "${i}" -lt "${wou_id_health_timeout}" ]; do
		if /usr/local/bin/curl -sf -m 2 "${wou_id_health_url}" >/dev/null 2>&1; then
			echo "wou-id jail healthy."
			return 0
		fi
		i=$((i + 1))
		sleep 1
	done
	echo "wou-id jail did not answer ${wou_id_health_url} within ${wou_id_health_timeout}s" >&2
	return 1
}

wou_id_jail_start()
{
	if [ -n "$(wou_id_jid)" ]; then
		echo "${wou_id_jail} already running (jid $(wou_id_jid))."
	else
		/usr/sbin/service jail start "${wou_id_jail}" || return 1
	fi
	wou_id_wait_healthy
}

wou_id_jail_stop()
{
	if [ -z "$(wou_id_jid)" ]; then
		echo "${wou_id_jail} already stopped."
		return 0
	fi
	/usr/sbin/service jail stop "${wou_id_jail}"
}

wou_id_jail_restart()
{
	wou_id_jail_stop
	sleep 1
	/usr/sbin/service jail start "${wou_id_jail}" || return 1
	wou_id_wait_healthy
}

wou_id_jail_status()
{
	if [ -n "$(wou_id_jid)" ]; then
		echo "${wou_id_jail} is running (jid $(wou_id_jid))."
		return 0
	fi
	echo "${wou_id_jail} is not running."
	return 1
}

run_rc_command "$1"
