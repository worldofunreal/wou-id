#!/bin/sh

# PROVIDE: wou_id
# REQUIRE: LOGIN valkey stalwart
# KEYWORD: shutdown

. /etc/rc.subr

name="wou_id"
rcvar="wou_id_enable"

load_rc_config "${name}"

: ${wou_id_enable:="NO"}
: ${wou_id_env_file:="/usr/local/etc/wou-id/wou-id.env"}

pidfile="/var/run/${name}.pid"
child_pidfile="/var/run/${name}.child.pid"
proc="/usr/local/libexec/wou-server"
required_files="${proc} ${wou_id_env_file}"

command="/usr/sbin/daemon"
command_args="-f -P ${pidfile} -p ${child_pidfile} -r -R 2 -H -o /var/log/wou-id/server.log -T ${name} -u sowdb ${proc}"

start_precmd="${name}_prestart"

wou_id_prestart()
{
	set -a
	. "${wou_id_env_file}"
	set +a

	install -d -o sowdb -g sow -m 0750 /var/db/wou-id
	install -d -o sowdb -g sow -m 0750 /var/log/wou-id
}

run_rc_command "$1"
