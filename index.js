let config = require("leo-config");
var policy = require("./lib/policy");
let dynamodb = require("leo-aws").dynamodb;

let IDENTITIES_TABLE = process.env.AUTH_IDENTITES_TABLE;
let ROLE_POLICIES_TABLE = process.env.AUTH_ROLE_POLICIES_TABLE;


let authConfig = {};

function wrapUser(user) {
  user.authorize = async function(event, resource) {
    var request = createRequest(event, resource);
    user.cognitoId = request.cognito.id;
    let statements = [];
    if (authConfig.statements) {
      user.roles.concat('*').map(id => {
        statements = statements.concat(authConfig.statements[id]);
      });
    } else {
      let data = await dynamodb.batchGetHashkey(ROLE_POLICIES_TABLE, "roles", user.roles.concat('*'), {});
      if (!resource.context) {
        resource.context = [];
      }
      if (!Array.isArray(resource.context)) {
        resource.context = [resource.context];
      }
      for (var id in data) {
        for (var name in data[id].policies) {
          statements = statements.concat(data[id].policies[name]);
        }
        resource.context.map(c => {
          user.context[c] = Object.assign(user.context[c] || {}, data[id][c])
        });
      }
    }
    var result = policy.validate(request, policy.contextify(user.context, statements));
    if (result.auth !== true) {
      throw "Access Denied";
    }
    return user;
  };
  return user;
}

function createRequest(event, resource) {
  var lrn = resource.lrn;

  if (authConfig.resourcePrefix && !lrn.match(/^lrn/)) {
    lrn = authConfig.resourcePrefix + lrn;
  }

  var matches = lrn.match(/lrn:([^:]*):([^:]*)/);
  var system = matches[2];
  var params = resource[system];

  for (var key in params) {
    var val = params[key];
    if (val && val.replace) {
      val = val.replace(/:/g, '');
      lrn = lrn.replace(new RegExp("{" + key + "}", 'g'), val);
    }
  }
  var request = {
    id: event.requestContext.requestId,
    time: Date.now(),
    action: system + ":" + resource.action,
    lrn: lrn,
    aws: Object.assign({}, event.requestContext.identity, event.requestContext),
    cognito: {
      id: event.requestContext.identity.cognitoIdentityId,
      provider: event.requestContext.identity.cognitoAuthenticationProvider,
      type: event.requestContext.identity.cognitoAuthenticationType,
      poolId: event.requestContext.identity.cognitoIdentityPoolId
    }
  };
  request[system] = resource[system];
  return request;
};


module.exports = {
  getUser: async function(id) {
    if (id && id.requestContext) {
      id = id.requestContext;
    }

    if (!id) {
      return wrapUser({
        context: {},
        identity_id: id,
        roles: []
      });
    } else if (id && id.identity && !id.identity.cognitoIdentityId && id.identity.caller) {
      return wrapUser({
        identity_id: "aws_key",
        context: {
          key: id.identity.caller
        },
        roles: ["role/aws_key"]
      });
    } else {
      if (id && id.identity) {
        id = id.identity.cognitoIdentityId || '*';
      }

      return dynamodb.get(IDENTITIES_TABLE, id, {
        id: "identity_id"
      }).then(data => {
        if (!data || data.identity_id !== id) {
          return wrapUser({
            context: {},
            identity_id: id,
            roles: []
          });
        } else {
          //Support older ones where it was stored as a string
          if (typeof data.context == "string") {
            data.context = JSON.parse(data.context);
          }
          return wrapUser(data);
        }
      });
    }
  },
  authorize: async function(event, resource, user = null) {
    if (user) {
      if (!(authorize in user)) {
        wrapUser(user);
      }
      return user.authorize(event, resource);
    } else {
      return this.getUser(event.requestContext).then(user => user.authorize(event, resource));
    }
  },
  /**
   * If necessary we can provide some data to the function rather than retrieving it from dynamo.
   *
   * The config object takes the shape of the following:
   *
   * config = {
   *  actions: 'looks',
   *  resource: 'lrn:younique:looks',
   *  identities: {
   *    '*': [
   *      'search_admin',
   *    ],
   *    'role/admin': [
   *      'search_admin',
   *    ],
   *    'role/user': [
   *      'search_admin',
   *    ],
   *  },
   *  policies: {
   *    'search_admin': [
   *      {
   *        Effect: "Allow",
   *        Action: "*",
   *        Resource: "*",
   *        Condition: {
   *          "IpAddress": {
   *            "aws:sourceip": [
   *              "67.207.37.24/29",
   *              "50.225.58.224/29",
   *              "50.225.58.226/32",
   *              "162.218.222.188/32",
   *              "67.207.40.96/32"
   *            ]
   *          }
   *        }
   *      }
   *    ]
   *  }
   */
  bootstrap: function(config) {
    if (config.actions) {
      let actionPrefix = config.actions;
      let resourcePrefix = config.resource;
      let parts = resourcePrefix.split(':').filter(e => e.length != 0);
      if (!resourcePrefix || parts.length < 3) {
        throw new Error("You have not defined a valid resource prefix. It must exist and have at least three parts separated by colons (:). I.E. lrn:<company>:<project>");
      };
      // If there are less than 5 parts then add empty strings to the array until it is 5 parts long.
      while (parts.length <= 5) {
        parts.push('');
      }
      // This will get the correct number of colons on the end of the resource to get it to 5 identitfiers separated by colons(:).
      resourcePrefix = parts.join(':');
      let statements = {};
      Object.keys(config.identities).map(id => {
        let p = config.identities[id];
        statements[id] = [];
        p.map(policy => {
          //stringify it so it matches the old way of doing it for now
          statements[id] = statements[id].concat(config.policies[policy].map(p => {
            if (p.Action && !p.Action.match(/:/)) {
              p.Action = actionPrefix + ":" + p.Action;
            }
            if (p.Resource && !p.Resource.match(/^lrn/)) {
              p.Resource = resourcePrefix + p.Resource;
            }
            return JSON.stringify(p);
          }));
        });
      });
      authConfig = {
        actionPrefix: actionPrefix,
        resourcePrefix: resourcePrefix,
        statements: statements
      }
    } else {
      throw new Error("You have not defined an action prefix");
    }
  }
};
