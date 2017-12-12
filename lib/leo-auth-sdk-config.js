"use strict";

let homeDir = require('os').homedir();
let path = require("path");
let fs = require("fs");
let configPath = path.resolve(`${homeDir}/.leo`, "leo-auth-sdk-config.json");

module.exports = {};
if (fs.existsSync(configPath)) {
	let config = buildConfig(process.cwd());
	var sdkConfigData = {};
	sdkConfigData = require(configPath);

	if (config.profiles) {
		let profiles = config.profiles;
		let tmp = {};
		config.profiles.map((p => {
			tmp[p] = sdkConfigData[p];
		}))
		sdkConfigData = tmp;
		sdkConfigData.default = sdkConfigData.default || sdkConfigData[config.defaultProfile] || sdkConfigData[config.profiles[0]];
	}
	module.exports = sdkConfigData;
}

function buildConfig(rootDir) {
	let config = {
		profiles: undefined,
		defaultProfile: undefined
	};
	let paths = [];
	do {
		paths.push(rootDir);

		var lastDir = rootDir;
		rootDir = path.resolve(rootDir, "../");
	} while (rootDir != lastDir);
	paths.slice(0).reverse().forEach(function (dir) {
		let packageFile = path.resolve(dir, "package.json");
		if (fs.existsSync(packageFile)) {
			var pkg = require(packageFile);
			if (pkg.config && pkg.config.leo) {
				config.profiles = pkg.config.leo.profiles || config.profiles;
				config.defaultProfile = pkg.config.leo.defaultProfile || config.defaultProfile;
				if (config.type == "system") {}
			}
		}
	});

	return config;
}