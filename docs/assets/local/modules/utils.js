import { encodeArray } from "./base64.js";

export function replacer(k, v) {
    if (v instanceof ArrayBuffer) {
        return encodeArray(v);
    }
    if (v instanceof Uint8Array) {
        return encodeArray(v);
    }
    return v;
}

export function jsonToString(obj) {
    return JSON.stringify(obj, replacer, 2);
}

export function toggle_section(id, visible) {
    const section = document.getElementById(id);
    section.querySelector(":scope > input[type='checkbox']").checked = visible == false;
}

export function clear_error(id) {
    const section = document.getElementById(id);
    section.querySelectorAll(".error").forEach(e => e.classList.remove("error"));
}
