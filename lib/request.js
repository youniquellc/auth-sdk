var policy = require("./policy");
var configure = require("./configuration.js")();
var dynamodb = require("./dynamodb.js")(configure);

let USER_TABLE = configure.resources.LeoAuthUser;
let AUTH_TABLE = configure.resources.LeoAuth;

function wrapUser(user) {
	user.authorize = (event, resource, callback) => {
		var request = module.exports.createRequest(event, resource);
		user.cognitoId = request.cognito.id;
		dynamodb.batchGetHashkey(AUTH_TABLE, "identity", user.identities.concat('*'), {}, function (err, data) {
			var statements = [];
			for (var id in data) {
				for (var name in data[id].policies) {
					statements = statements.concat(data[id].policies[name]);
				}
			}
			var result = policy.validate(request, policy.contextify(user.context, statements));
			if (result.auth !== true) {
				callback("Access Denied", result);
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
				identities: []
			}));
		} else if (id && id.identity && !id.identity.cognitoIdentityId && id.identity.caller) {
			callback(null, wrapUser({
				identity_id: "aws_key",
				context: {
					key: id.identity.caller
				},
				identities: ["role/aws_key"]
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
					TableName: USER_TABLE,
					Key: {
						identity_id: id
					},
					"ReturnConsumedCapacity": 'TOTAL'
				}, function (err, data) {
					if (err) {
						callback(err);
					} else if (!data || !data.Item || data.Item.identity_id !== id) {
						configure.registry.user = {
							context: {},
							identity_id: id,
							identities: []
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

// if (configure._meta.env == "local" && configure.test) {
// 	var user;
// 	if (configure.test.user) {
// 		user = configure.test.users[configure.test.user];
// 	} else {
// 		user = configure.test.users.default;
// 	}
// 	var auth = user.auth;

// 	if (auth) {
// 		module.exports.getUser = function (id, callback) {
// 			console.log("overridden user", JSON.stringify(auth, null, 2));
// 			callback(null, wrapUser(auth));
// 			return auth;
// 		};
// 	}
// }