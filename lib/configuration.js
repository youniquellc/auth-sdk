"use strict";
let extend = require("extend");
let file = require("./leo-auth-sdk-config.js");
module.exports = function (data) {
	let doValidation = true;
	if (typeof data === "boolean") {
		doValidation = data;
		data = undefined;
	}

	let configuration = {
		update: function (newConfig) {
			let config;
			var resources = {
				resources: process.env.Resources && JSON.parse(process.env.Resources) || {}
			};
			if ("leoauthsdk" in process.env) {
				resources = JSON.parse(process.env["leoauthsdk"]);
			}
			let profile = (typeof newConfig === "string" ? newConfig : null) || process.env.LEO_DEFAULT_PROFILE || "default";


			if (!file[profile] && profile != "default" && doValidation) {
				throw new Error(`Profile "${profile}" does not exist!`);
			}
			config = extend(true, {}, file[profile] || {}, resources, typeof newConfig === "object" ? newConfig : {});
			update(this, config);
			return this;
		},
		validate: function () {},
		setProfile: function (profile) {
			return this.update(profile);
		}
	};
	configuration.update(data);


	if (doValidation) {
		configuration.validate();
	}

	return configuration;
};


function update(config, newConfig) {
	newConfig = extend(true, {}, newConfig);
	if (!newConfig.region && newConfig.resources) {
		newConfig.region = newConfig.resources.Region;
	}
	let u = newConfig.update;
	delete newConfig.update;
	extend(true, config, newConfig);
	newConfig.update = u;
}