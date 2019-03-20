function addOptions(select, options) {
	for(var i in options) {
		var o = $("<option>")
			.attr({"value":options[i]})
			.text(options[i]);
		select.append(o);
	}
	return select;
}

function createCredentialsList(select, settings) {
	select.empty();
	select.append("<option>");
	select.append(
		$("<option>")
			.attr({"value":"*"})
			.text("All")
	);
	for(var i in settings.credentials) {
		var cred = settings.credentials[i];
		var text = cred.instant + " - " + cred.user.name + " (" + cred.user.displayName + ")";
		var o = $("<option>")
			.attr({"value":cred.id})
			.text(text);
		select.append(o);		
	}
	return select;
}

function addCredential(settings, user, id, publicKey) {
	settings.credentials[id] = {
		"instant":new Date().toISOString(),
		"user":{
			"name":user.name,
			"id":user.id,
			"displayName":user.displayName,
		},
		"id":id,
		"credentialPublicKey":credentialPublicKey,
	};
	saveSettings(settings);
}

function getCredential(settings, id) {
	var cred = settings.credentials[id];
	return (cred != undefined) ? Promise.resolve(cred) : Promise.reject("PublicKey not found: " + id);
}

function readSettings() {
	var settings;
	var s = window.localStorage.getItem("settings");
	if(s) {
		settings = JSON.parse(s);
		if(settings.rp) {
			delete settings.rp;
		}
		if(settings.user) {
			delete settings.user;
		}
	} else {
		settings = {
			"credentials": {},
		};
	}
	return settings;
}

function saveSettings(settings) {
	if(settings) {
		window.localStorage.setItem("settings", JSON.stringify(settings, replacer, 2));
	} else {
		window.localStorage.removeItem("settings");
	}
}
