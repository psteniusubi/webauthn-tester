#!/bin/bash

export ServerRoot=/etc/apache2
export ModulesDir=/usr/lib/apache2/modules
export InstanceRoot="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
export ErrorLog="$InstanceRoot/logs/error.log"

if [ ! -d "$InstanceRoot/logs" ]; then 
	mkdir "$InstanceRoot/logs"
fi
if [ -f "$ErrorLog" ]; then
	rm -f "$ErrorLog"
fi

exec /usr/sbin/apache2 -X -d "$ServerRoot" -f "$InstanceRoot/conf/httpd.conf" -E "$ErrorLog" -DLinux $*
