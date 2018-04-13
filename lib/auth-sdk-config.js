'use strict';

let homeDir = require('os').homedir();
let path = require('path');
let fs = require('fs');
let configPath = path.resolve(`${homeDir}/.auth-sdk`, 'config.json');

module.exports = {};
if (fs.existsSync(configPath)) {
  let config = buildConfig(process.cwd());
  var sdkConfigData = {};
  sdkConfigData = require(configPath);

  if (config.profiles) {
    let tmp = {};
    config.profiles.map((p => {
      tmp[p] = sdkConfigData[p];
    }));
    sdkConfigData = tmp;
    sdkConfigData.default = sdkConfigData.default || sdkConfigData[config.defaultProfile] || sdkConfigData[config.profiles[0]];
  }
  sdkConfigData.default = sdkConfigData.default || sdkConfigData[config.defaultProfile] || sdkConfigData[Object.keys(sdkConfigData)[0]];
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
    rootDir = path.resolve(rootDir, '../');
  } while (rootDir != lastDir);

  let systemDirectory;

  paths.slice(0).reverse().forEach(function (dir) {
    let packageFile = path.resolve(dir, 'package.json');
    if (fs.existsSync(packageFile)) {
      var pkg = require(packageFile);
      if (pkg.config && pkg.config.leo) {
        config.profiles = pkg.config.leo.profiles || config.profiles;
        config.defaultProfile = pkg.config.leo.defaultProfile || config.defaultProfile;
        if (pkg.config.leo.type == 'system') {
          systemDirectory = dir;
        }
      }
    }
  });

  if (systemDirectory && config.defaultProfile && config.defaultProfile.match(/^!/)) {
    var env = process.env.LEO_ENV == 'undefined' ? null : process.env.LEO_ENV || null;
    var region = process.env.LEO_REGION == 'undefined' ? null : process.env.LEO_REGION || null;

    var variableDir = path.resolve(systemDirectory, 'config/variables');

    var vDir = `${variableDir}/${region}_${env == 'local' ? 'dev' : env}`;
    var variables = {};
    if (fs.existsSync(vDir)) {
      fs.readdirSync(vDir).forEach((file) => {
        let vPath = path.resolve(vDir, file);
        if (fs.existsSync(vPath) && file.match(/\.json$/)) {
          let name = file.replace(/\.json$/, '').toLowerCase();
          var d = JSON.parse(fs.readFileSync(vPath, {
            encoding: 'utf-8'
          }));
          Object.keys(d).forEach(k => {
            variables[`${name}.${k}`] = d[k];
          });
        }
      });
    }


    var ref = config.defaultProfile.replace(/^\\?!/, '');
    config.defaultProfile = variables[ref.toLowerCase()];
  }

  return config;
}