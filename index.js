const policy = require('./lib/policy');
const dynamoUtil = require('./lib/dynamodb_util');

const IDENTITIES_TABLE = process.env.AUTH_IDENTITES_TABLE;
const ROLE_POLICIES_TABLE = process.env.AUTH_ROLE_POLICIES_TABLE;

let authConfig = {};

/**
 * Add the authorize function to the user object.
 * @param {object} user The user object which will have the authorize function added to it.
 * @returns The modified user object.
 */
const addAuthorizeToUser = (user) => {
  /**
   * Check the users authorization against the found policies.
   * @param {object} event The event received by the lambda function.
   * @param {object} resource The provided resource that the user is authorized against.
   * @returns The user if the user is authorized.
   * @throws 'Access Denied' if the user is not authorized.
   */
  user.authorize = async (event, resource) => {
    // Merge the event and resource together into a request.
    var request = createRequest(event, resource);
    user.cognitoId = request.cognito.id;
    let statements = [];
    if (authConfig.statements) {
      // Every user is part of the '*' role, so add it and gather the statements for all roles belonging to the user.
      // In this case the statements come from the bootstrap function.
      user.roles.concat('*').map(id => {
        statements = statements.concat(authConfig.statements[id]);
      });
    } else {
      // Every user is part of the '*' role, so add it and gather the statements for all roles belonging to the user.
      // In this case the statements are read out of dynamo.
      let data = await dynamoUtil.queryAll(ROLE_POLICIES_TABLE, 'role', user.roles.concat('*'), {});

      if (!resource.context) {
        resource.context = [];
      }

      if (!Array.isArray(resource.context)) {
        resource.context = [resource.context];
      }

      // Loop over each role name. I.E. "*" and "role/user"
      Object.keys(data).forEach((id) => {
        const policies = data[id].policies;
        // Gather all the statements that apply to this user.
        Object.keys(policies).forEach((name) => {
          statements = statements.concat(policies[name]);
        });

        // The roles may have additional context attached to them. If requested that data may be pulled into the users record.
        // I.E. If a role "*" has an additional attribute otherdata: { "some": "context" } and the resource has context: ["otherdata"]
        // then the user record will come back as user: { context: { "otherdata": { "some": "context" } } }
        resource.context.map((contextItem) => {
          user.context[contextItem] = Object.assign(user.context[contextItem] || {}, data[id][contextItem]);
        });
      });
    }

    // Now we can check if the user has the necessary statements/permissions to access the resource requested.
    var result = policy.validate(request, policy.contextify(user.context, statements));

    // If not then throw an error.
    if (result.auth !== true) {
      throw 'Access Denied';
    }

    return user;
  };
  return user;
};

/**
 * Merge the received event and the requested resource together to create the request to authorize.
 * @param {object} event The event received by the lambda function.
 * @param {object} resource The provided resource that the user is authorized against.
 * @returns {object} The merged request data.
 */
const createRequest = (event, resource) => {
  var lrn = resource.lrn;

  if (authConfig.resourcePrefix && !lrn.match(/^lrn/)) {
    lrn = authConfig.resourcePrefix + lrn;
  }

  var matches = lrn.match(/lrn:([^:]*):([^:]*)/);
  var system = matches[2];
  var params = resource[system];

  // If a system is provided and then replace any data found in the lrn with data from that system.
  // I.E.
  // resource = {
  //   lrn: 'lrn:company:project:::{resource}',
  //   action: 'list',
  //   project: { resource: 'items' }
  // }
  // Will replace the lrn with lrn:company:project:::items
  // Notice that the key "project" matches with the third item in the lrn "project".
  for (var key in params) {
    var val = params[key];
    if (val && val.replace) {
      val = val.replace(/:/g, '');
      lrn = lrn.replace(new RegExp('{' + key + '}', 'g'), val);
    }
  }

  return {
    id: event.requestContext.requestId,
    time: Date.now(),
    action: system + ':' + resource.action,
    lrn: lrn,
    aws: Object.assign({}, event.requestContext.identity, event.requestContext),
    [system]: resource[system],
    cognito: {
      id: event.requestContext.identity.cognitoIdentityId,
      provider: event.requestContext.identity.cognitoAuthenticationProvider,
      type: event.requestContext.identity.cognitoAuthenticationType,
      poolId: event.requestContext.identity.cognitoIdentityPoolId
    }
  };
};


module.exports = {
  /**
   * A helper function for writing policies. This will return the flattened request as it
   * would be received by the policies and can be used to determine what fields and values
   * are available for use with the policy conditions.
   * @param {Object} event The event received by the lambda function.
   * @param {Object} resource The provided resource that the user is authorized against.
   */
  getFlattenedRequest: function(event, resource) {
    const request = createRequest(event, resource);
    const flatContext = {
      'date.year_month': () => {
        return '2016 June';
      }
    };

    policy.flattenRequest(request, flatContext);

    return flatContext;
  },
  /**
   * Get the user, context, and roles from dynamo based on the provided id.
   * @param {string} id The id of the user who made the request.
   */
  getUser: async function(id) {
    if (id && id.requestContext) {
      id = id.requestContext;
    }

    if (!id) {
      // If there is no logged in user then return a blank user.
      return addAuthorizeToUser({
        context: {},
        identity_id: id,
        roles: []
      });
    } else if (id && id.identity && !id.identity.cognitoIdentityId && id.identity.caller) {
      // If there is no cognito identity ID then the user is using and aws key and secret directly.
      return addAuthorizeToUser({
        identity_id: 'aws_key',
        context: {
          key: id.identity.caller
        },
        roles: ['role/aws_key']
      });
    } else {
      // Otherwise, the user made the request through cognito and we can use their information.
      if (id && id.identity) {
        id = id.identity.cognitoIdentityId || '*';
      }

      // Attempt to get the user from the identites table.
      return dynamoUtil.get(IDENTITIES_TABLE, 'identity_id', id)
        .then(data => {
          // If there was no data in dynamo then we will return an anonymous user.
          if (!data || data.identity_id !== id) {
            return addAuthorizeToUser({
              context: {},
              identity_id: id,
              roles: []
            });
          } else {
            // Support older ones where the context was stored as a string.
            if (typeof data.context == 'string') {
              data.context = JSON.parse(data.context);
            }

            // Now we can return the ready to use user.
            return addAuthorizeToUser(data);
          }
        });
    }
  },
  /**
   * Here we will get the user and check if the user has the proper permissions
   * to access the resource and action requested.
   *
   * @param {Object} event The event received by the lambda function.
   * @param {Object} resource The provided resource that the user is authorized against.
   * @param {Object} user The user accessing the resource. If one is not provided then it will be retrieved.
   */
  authorize: async function(event, resource, user = null) {
    // If the user is provided then we can authorize against the provided user.
    if (user) {
      if (!('authorize' in user)) {
        addAuthorizeToUser(user);
      }
      return user.authorize(event, resource);
    } else {
      // Otherwise, we will need to get the user and authorized against the retrieved user.
      return this.getUser(event.requestContext).then(user => user.authorize(event, resource));
    }
  },
  /**
   * If desired we can provide our own statements rather than querying dynamo for it.
   *
   * @param {object} config The policies and statements used to bypass the request to dynamo. (See README.md for a complete example)
   */
  bootstrap: function(config) {
    if (config.actions) {
      let actionPrefix = config.actions;
      let resourcePrefix = config.resource;
      let parts = resourcePrefix.split(':').filter(e => e.length != 0);
      if (!resourcePrefix || parts.length < 3) {
        throw new Error('You have not defined a valid resource prefix. It must exist and have at least three parts separated by colons (:). I.E. lrn:<company>:<project>');
      }
      // If there are less than 5 parts then add empty strings to the array until it is 5 parts long.
      while (parts.length <= 5) {
        parts.push('');
      }
      // This will get the correct number of colons on the end of the resource to get it to 5 identitfiers separated by colons(:).
      resourcePrefix = parts.join(':');
      let statements = {};
      // The old API would merge the roles and statements and store the merged results.
      // This mimic that by merging the roles and statements for each identity here.
      Object.keys(config.identities).map(id => {
        let p = config.identities[id];
        statements[id] = [];
        p.map(policy => {
          // stringify it so it matches the old way of doing it for now
          statements[id] = statements[id].concat(config.policies[policy].map(p => {
            if (p.Action && !p.Action.match(/:/)) {
              p.Action = actionPrefix + ':' + p.Action;
            }

            if (p.Resource && !p.Resource.match(/^lrn/)) {
              p.Resource = resourcePrefix + p.Resource;
            }

            // To make it compatible with the data stored in dynamo we must stringify the results.
            return JSON.stringify(p);
          }));
        });
      });
      authConfig = {
        actionPrefix: actionPrefix,
        resourcePrefix: resourcePrefix,
        statements: statements
      };
    } else {
      throw new Error('You have not defined an action prefix');
    }
  }
};
