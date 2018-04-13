'use strict';
let extend = require('extend');
let file = require('./auth-sdk-config.js');

module.exports = function (data) {
  let doValidation = true;
  if (typeof data === 'boolean') {
    doValidation = data;
    data = undefined;
  }

  let configuration = {
    update: function (newConfig) {
      let config;

      let hasValidEnv = true;
      ['AUTH_AWS_REGION', 'AUTH_IDENTITES_TABLE', 'AUTH_ROLE_POLICIES_TABLE', 'AUTH_POLICIES_TABLE', 'AUTH_ROLE_POLICY_MAP_TABLE'].forEach((variable) => {
        if (!(variable in process.env)) {
          hasValidEnv = false;
        }
      });

      // The default is to get all the necessary configuration out of the env.
      if (hasValidEnv) {
        update(this, {
          region: process.env.AUTH_AWS_REGION,
          profile: process.env.AUTH_AWS_PROFILE,
          resources: {
            IdentitiesTable: process.env.AUTH_IDENTITES_TABLE,
            RolePoliciesTable: process.env.AUTH_ROLE_POLICIES_TABLE,
            PoliciesTable: process.env.AUTH_POLICIES_TABLE,
            RolePolicyMapTable: process.env.AUTH_ROLE_POLICY_MAP_TABLE,
          }
        });
        return this;
      } else {
        var resources = {
          resources: process.env.Resources && JSON.parse(process.env.Resources) || {}
        };
        if ('authsdk' in process.env) {
          resources = JSON.parse(process.env['authsdk']);
        }

        // If the variables don't exist in the env then we will get them out of the ~/.auth-sdk/config.json file
        let profile = (typeof newConfig === 'string' ? newConfig : null) || process.env.AWS_DEFAULT_PROFILE || 'default';

        if (!file[profile] && profile != 'default' && doValidation) {
          throw new Error(`Profile "${profile}" does not exist!`);
        }
        config = extend(true, {}, file[profile] || {}, resources, typeof newConfig === 'object' ? newConfig : {});
        update(this, config);
        return this;
      }
    },
    validate: function () { },
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