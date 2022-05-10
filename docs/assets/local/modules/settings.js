import { jsonToString } from "./utils.js";
import { notEmpty, notNull } from "./common.js";

export function createCredentialsList(select, settings, id) {
	select.innerHTML = "";

	let option = document.createElement("option");
	option.setAttribute("value", "");
	option.innerText = "";
	select.appendChild(option);

	let selected = option;

	option = document.createElement("option");
	option.setAttribute("value", "*");
	option.innerText = "All";
	select.appendChild(option);

	for (const i in settings.credentials) {
		const cred = settings.credentials[i];
		//const text = cred.instant + " - " + cred.user.name + " (" + cred.user.displayName + ")";
		const text = `${cred.instant} - ${cred.user.name} (${cred.user.displayName})`
		option = document.createElement("option");
		option.setAttribute("value", cred.id);
		option.innerText = text;
		select.appendChild(option);
		if (notEmpty(id) && (cred.id === id)) {
			selected = option;
		}
	}

	selected.setAttribute("selected", "selected");

	return select;
}

export function addCredential(settings, user, id, credentialPublicKey, response) {
	if (notEmpty(id)) {
		settings.credentials[id] = {
			"instant": new Date().toISOString(),
			"user": {
				"name": user.name,
				"id": user.id,
				"displayName": user.displayName,
			},
			"id": id,
			"credentialPublicKey": credentialPublicKey,
			"response": response,
		};
		saveSettings(settings);
	}
}

export function getCredential(settings, id) {
	const cred = settings.credentials[id];
	return cred;
}

export function readSettings() {
	let settings = {
		"credentials": {},
	};
	const s = window.localStorage.getItem("settings");
	if (notEmpty(s)) {
		try {
			settings = JSON.parse(s);
		} catch {
		}
		if ("rp" in settings) {
			delete settings.rp;
		}
		if ("user" in settings) {
			delete settings.user;
		}
		if (!("credentials" in settings)) {
			settings.credentials = {};
		}
	}
	return settings;
}

export function saveSettings(settings) {
	if (notNull(settings)) {
		window.localStorage.setItem("settings", jsonToString(settings));
	} else {
		window.localStorage.removeItem("settings");
	}
}
