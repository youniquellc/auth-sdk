var policy = require('./policy');
var configure = require('./configuration.js')();
var dynamodb = require('./dynamodb.js')(configure);

let IDENTITIES_TABLE = configure.resources.IdentitiesTable;
let ROLE_POLICIES_TABLE = configure.resources.RolePoliciesTable;

function wrapUser(user) {
  user.authorize = (event, resource, callback) => {
    var request = module.exports.createRequest(event, resource);
    user.cognitoId = request.cognito.id;
    dynamodb.batchGetHashkey(ROLE_POLICIES_TABLE, 'role', user.roles.concat('*'), {}, function (err, data) {
      var statements = [];
      for (var id in data) {
        for (var name in data[id].policies) {
          statements = statements.concat(data[id].policies[name]);
        }
      }
      var result = policy.validate(request, policy.contextify(user.context, statements));
      if (result.auth !== true) {
        callback('Access Denied', result);
      } else {
        callback(null, user);
      }
    });
  };
  return user;
}

module.exports = {
  configuration: configure,
  dynamodb: dynamodb,
  getUser: function (id, callback) {
    if (!id) {
      callback(null, wrapUser({
        context: {},
        identity_id: id,
        roles: []
      }));
    } else if (id && id.identity && !id.identity.cognitoIdentityId && id.identity.caller) {
      callback(null, wrapUser({
        identity_id: 'aws_key',
        context: {
          key: id.identity.caller
        },
        roles: ['role/aws_key']
      }));
    } else {
      configure.registry = {};
      if (id && id.identity) {
        id = id.identity.cognitoIdentityId || '*';
      }
      if (configure.registry.user && configure.registry.user.identity_id == id) {
        callback(null, wrapUser(configure.registry.user));
      } else {
        dynamodb.docClient.get({
          TableName: IDENTITIES_TABLE,
          Key: {
            identity_id: id
          },
          'ReturnConsumedCapacity': 'TOTAL'
        }, function (err, data) {
          if (err) {
            callback(err);
          } else if (!data || !data.Item || data.Item.identity_id !== id) {
            configure.registry.user = {
              identity_id: id,
              context: {},
              roles: []
            };
            callback(null, wrapUser(configure.registry.user));
          } else {
            data.Item.context = JSON.parse(data.Item.context);
            configure.registry.user = data.Item;
            callback(null, wrapUser(configure.registry.user));
          }
        });
      }
    }
  },
  createRequest: function (event, resource) {
    var lrn = resource.lrn;

    var matches = lrn.match(/lrn:([^:]*):([^:]*)/);
    var system = matches[2];
    var params = resource[system];

    for (var key in params) {
      var val = params[key];
      if (val && val.replace) {
        val = val.replace(/:/g, '');
        lrn = lrn.replace(new RegExp('{' + key + '}', 'g'), val);
      }
    }

    // The first thing after the lrn will be the entity or entities we are wishing to perform the action on.
    // I.E. lrn:younique:looks:::look:create then the entity will be a look
    // OR lrn:younique:looks:::looks:list then the entities will be looks
    var entity = lrn.split(':::')[1];
    entity = entity.split(':')[0];

    var request = {
      id: event.requestContext.requestId,
      time: Date.now(),
      action: entity + ':' + resource.action,
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
  },
  authorize: function (event, resource, callback) {
    this.getUser(event.requestContext, function (err, user) {
      if (err) {
        callback(err);
      } else {
        user.authorize(event, resource, callback);
      }
    });
  }
};