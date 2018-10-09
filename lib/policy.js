const conditions = require('./conditions.js');

module.exports = {
  contextify: function(variables, policies) {
    var flatContext = {
      'date.year_month': () => {
        return '2016 June';
      }
    };
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
  validate: function(request, statements) {
    console.log('statements', JSON.stringify(statements));
    var flatRequest = {};
    this.flattenRequest(request, flatRequest, ':');
    // console.log("\n\n\n\nNew Request---------------------------------\n", flatRequest, "\n---------------------------------------------\n\n");

    console.log(flatRequest);

    //First we want to check if they are explicitly denied in anyway
    denyloop: for (var i = 0; i < statements.length; i++) {
      let policy = statements[i];
      let type = policy.Effect.toLowerCase().trim();
      if (type !== 'deny') {
        continue;
      }

      //If it has the right action
      if (('Action' in policy && conditions['StringLike'](flatRequest, 'action', policy.Action)) ||
        ('NotAction' in policy && conditions['StringNotLike'](flatRequest, 'action', policy.NotAction))) {
        if (('Resource' in policy && conditions['StringLike'](flatRequest, 'lrn', policy.Resource)) ||
          ('NotResource' in policy && conditions['StringNotLike'](flatRequest, 'lrn', policy.NotResource))
        ) {
          // console.log("Deny: This policy matches and should be validated\n\n");
          if (policy.Condition) {
            for (let conditional in policy.Condition) {
              let condition = policy.Condition[conditional];
              for (let field in condition) {
                let result = conditions[conditional](flatRequest, field.toLowerCase(), condition[field]);
                // console.log("Result: ", result, " Params: ", policy.Effect, conditional, field, condition[field], "\n");
                if (!result) {
                  continue denyloop; //We didn't match this deny request, so move onto the next one
                }
              }
            }
          }
          // console.log("\n\n\nDenying to deny policy with conditions", policy.Action, policy.Resource, policy.Condition);
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
      //If it has the right action
      if (('Action' in policy && conditions['StringLike'](flatRequest, 'action', policy.Action)) ||
        ('NotAction' in policy && conditions['StringNotLike'](flatRequest, 'action', policy.NotAction))) {
        //Great, does it have the right lrn?
        if (('Resource' in policy && conditions['StringLike'](flatRequest, 'lrn', policy.Resource)) ||
          ('NotResource' in policy && conditions['StringNotLike'](flatRequest, 'lrn', policy.NotResource))
        ) {
          // console.log("ALLOW: This policy matches and should be validated\n\n");
          if (policy.Condition) {
            for (let conditional in policy.Condition) {
              let condition = policy.Condition[conditional];
              for (let field in condition) {
                let result = conditions[conditional](flatRequest, field.toLowerCase(), condition[field]);
                if (!result) {
                  continue allowloop; //This policy isn't going to grant them anything
                }
              }
            }
          }
          //We found one that gave them all the permissions they needed
          // console.log("\n\n\nGranted permissions through this policy", policy.Action, policy.Resource, policy.Condition);
          return {
            auth: true,
            reason: 'Matched policy'
          };
        }
      }
    }
    // console.log("Denied due to lack of matching statements");
    return {
      auth: false,
      reason: 'Did not match any statements'
    };
  }
};
