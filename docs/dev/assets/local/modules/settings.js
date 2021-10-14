import { jsonToString, } from "./utils.js";

function addOptions(select, options) {
	for(var i in options) {
		var o = $("<option>")
			.attr({"value":options[i]})
			.text(options[i]);
		select.append(o);
	}
	return select;
}

export function createCredentialsList(select, settings) {
	select.innerHTML = "";

	let option = document.createElement("option");
	option.setAttribute("value", "");
	option.setAttribute("selected", "selected");
	option.innerText = "";
	select.appendChild(option);

	option = document.createElement("option");
	option.setAttribute("value", "*");
	option.innerText = "All";
	select.appendChild(option);

	for(const id in settings.credentials) {
		const cred = settings.credentials[id];
		const text = cred.instant + " - " + cred.user.name + " (" + cred.user.displayName + ")";
		option = document.createElement("option");
		option.setAttribute("value", cred.id);
		option.innerText = text;
		select.appendChild(option);		
	}
	return select;
}

export function addCredential(settings, user, id, credentialPublicKey) {
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

export function getCredential(settings, id) {
	const cred = settings.credentials[id];
	return cred;
}

export function readSettings() {
	let settings;
	const s = window.localStorage.getItem("settings");
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

export function saveSettings(settings) {
	if(settings) {
		window.localStorage.setItem("settings", jsonToString(settings));
	} else {
		window.localStorage.removeItem("settings");
	}
}
