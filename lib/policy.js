const conditions = require('./conditions.js');

module.exports = {
  contextify: function(variables, policies) {
    var flatContext = {};
    this.flattenRequest(variables, flatContext, '.');

    const getVar = (name) => {
      var matches = name.match(/^(")?\$\{([^}]*)\}/);
      var v = matches[2];
      var hasQuotes = matches[1] == '"';

      if (v in flatContext) {
        var val = flatContext[v];
        var outVar = null;

        if (typeof val === 'function') {
          outVar = val();
        } else {
          outVar = val;
        }
        if (Array.isArray(outVar)) {
          if (hasQuotes) {
            return '"' + outVar.join('","') + '"';
          } else {
            return outVar.join(',');
          }
        } else {
          if (hasQuotes) {
            return '"' + outVar + '"';
          } else {
            return outVar;
          }
        }
      } else {
        throw new Error(`Unknown variable ${v}`);
      }
    };


    return policies.map((policy) => {
      var matches = policy.match(/"?\$\{[^}]*\}"?/g);
      if (matches) {
        matches.forEach((match) => {
          if (match[0] != '"') {
            match = match.replace(/"$/, '');
          }
          policy = policy.replace(match, getVar(match));
        });
      }
      return JSON.parse(policy);
    });
  },
  flattenRequest: function(obj, out, separator, prefix) {
    prefix = prefix || '';
    separator = separator || ':';
    Object.keys(obj).forEach((k) => {
      var v = obj[k];
      if (typeof v === 'object' && !(Array.isArray(v)) && v !== null) {
        this.flattenRequest(v, out, separator, prefix + k.toLowerCase() + separator);
      } else {
        out[prefix + k.toLowerCase()] = v;
      }
    });
  },
  /**
   * Check if the current policy contains an Action and that it matches the action specified in the request.
   * @param {Object} policy The policy to match against the request.
   * @param {Object} flatRequest The flattened request to be matched against.
   */
  containsApplicableAction: function(policy, flatRequest) {
    return ('Action' in policy && conditions['StringLike'](flatRequest, 'action', policy.Action));
  },
  /**
   * Check if the current policy contains a NotAction and that it doesn't match the action specified in the request.
   * @param {Object} policy The policy to match against the request.
   * @param {Object} flatRequest The flattened request to be matched against.
   */
  containsApplicableNotAction: function(policy, flatRequest) {
    return ('NotAction' in policy && conditions['StringNotLike'](flatRequest, 'action', policy.NotAction));
  },
  /**
   * Check if the current policy contains a Resource and that it matches the Resource specified in the request.
   * @param {Object} policy The policy to match against the request.
   * @param {Object} flatRequest The flattened request to be matched against.
   */
  containsApplicableResource: function(policy, flatRequest) {
    return ('Resource' in policy && conditions['StringLike'](flatRequest, 'lrn', policy.Resource));
  },
  /**
   * Check if the current policy contains a NotResource and that it doesn't match the Resource specified in the request.
   * @param {Object} policy The policy to match against the request.
   * @param {Object} flatRequest The flattened request to be matched against.
   */
  containsApplicableNotResource: function(policy, flatRequest) {
    return ('NotResource' in policy && conditions['StringNotLike'](flatRequest, 'lrn', policy.NotResource));
  },
  /**
   * Policies may have conditions attached to them. This will check that all the conditions are valid or not.
   * @param {Object} policy The policy to match against the request.
   * @param {Object} flatRequest The flattened request to be matched against.
   */
  checkPolicyConditions: function (policy, flatRequest) {
    if (policy.Condition) {
      for (let conditional in policy.Condition) {
        let condition = policy.Condition[conditional];
        for (let field in condition) {
          let result = conditions[conditional](flatRequest, field.toLowerCase(), condition[field]);
          if (!result) {
            return true;
          }
        }
      }
    }

    return false;
  },
  /**
   * Validate that the statements found for the user give the user access to the requested resource and action.
   * @param {Object} request The incoming request.
   * @param {array<Object>} statements Any statements that apply to the current user based on their roles.
   */
  validate: function(request, statements) {
    var flatRequest = {};
    this.flattenRequest(request, flatRequest, ':');

    //First we want to check if they are explicitly denied in anyway
    denyloop: for (var i = 0; i < statements.length; i++) {
      let policy = statements[i];
      let type = policy.Effect.toLowerCase().trim();
      if (type !== 'deny') {
        continue;
      }

      if (this.containsApplicableAction(policy, flatRequest) || this.containsApplicableNotAction(policy, flatRequest)) {
        if (this.containsApplicableResource(policy, flatRequest) || this.containsApplicableNotResource(policy, flatRequest)) {
          // We know the Action/NotAction and Resource/NotResource match, so now we can check the policy conditions.
          if (this.checkPolicyConditions(policy, flatRequest)) {
            // We didn't match this deny request, so move onto the next one
            continue denyloop;
          }

          return {
            auth: false,
            reason: 'denied by policy'
          };
        }
      }
    }

    //Check this policy, to see if the lrns match
    allowloop: for (let i = 0; i < statements.length; i++) {
      let policy = statements[i];
      let type = policy.Effect.toLowerCase().trim();
      if (type !== 'allow') {
        continue;
      }

      if (this.containsApplicableAction(policy, flatRequest) || this.containsApplicableNotAction(policy, flatRequest)) {
        if (this.containsApplicableResource(policy, flatRequest) || this.containsApplicableNotResource(policy, flatRequest)) {
          // We know the Action/NotAction and Resource/NotResource match, so now we can check the policy conditions.
          if (this.checkPolicyConditions(policy, flatRequest)) {
            // This policy isn't going to grant them anything
            continue allowloop;
          }

          // We found one that gave them all the permissions they needed
          return {
            auth: true,
            reason: 'Matched policy'
          };
        }
      }
    }

    // Nothing matched so they aren't authorized.
    return {
      auth: false,
      reason: 'Did not match any statements'
    };
  }
};
