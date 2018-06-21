let config = require("leo-config");
var policy = require("./lib/policy");
let dynamodb = require("leo-aws").dynamodb;

let USER_TABLE = config.leoauth.LeoAuthUser;
let AUTH_TABLE = config.leoauth.LeoAuth;


let authConfig = {};

function wrapUser(user) {
	user.authorize = async function(event, resource) {
		var request = createRequest(event, resource);
		user.cognitoId = request.cognito.id;
		let statements = [];
		if (authConfig.statements) {
			user.identities.concat('*').map(id => {
				statements = statements.concat(authConfig.statements[id]);
			});
		} else {
			let data = await dynamodb.batchGetHashkey(AUTH_TABLE, "identity", user.identities.concat('*'), {});
			for (var id in data) {
				for (var name in data[id].policies) {
					statements = statements.concat(data[id].policies[name]);
				}
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


module.exports = function(config = {}) {
	if (config.actions) {
		let actionPrefix = config.actions;
		if (!actionPrefix) {
			throw new Error("You have not defined an action prefix");
		}
		let resourcePrefix = config.resource;
		let parts = resourcePrefix.split(/:/).filter(e => e.length != 0);
		if (!resourcePrefix || parts.length < 3) {
			throw new Error("You have not defined an action prefix");
		};
		while (parts.length <= 5) {
			parts.push('');
		}
		resourcePrefix = parts.join(":");
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
	}
	return {
		getUser: async function(id) {
			if (id && id.requestContext) {
				id = id.requestContext;
			}

			if (!id) {
				return wrapUser({
					context: {},
					identity_id: id,
					identities: []
				});
			} else if (id && id.identity && !id.identity.cognitoIdentityId && id.identity.caller) {
				return wrapUser({
					identity_id: "aws_key",
					context: {
						key: id.identity.caller
					},
					identities: ["role/aws_key"]
				});
			} else {
				if (id && id.identity) {
					id = id.identity.cognitoIdentityId || '*';
				}

				return dynamodb.get(USER_TABLE, id, {
					id: "identity_id"
				}).then(data => {
					if (!data || !data.Item || data.Item.identity_id !== id) {
						return wrapUser({
							context: {},
							identity_id: id,
							identities: []
						});
					} else {
						//Support older ones where it was stored as a string
						if (typeof data.Item.context == "string") {
							data.Item.context = JSON.parse(data.Item.context);
						}
						return wrapUser(data.Item);
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
		}
	}
};
