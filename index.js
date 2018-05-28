var policy = require("./lib/policy");
var config = require("leo-config");
let dynamodb = config.leoaws.dynamodb;

if (!config.leoauth || !config.leoauth.resources) {
	console.log("Please define your LeoAuth Settings");
	process.exit();
}


let USER_TABLE = config.leoauth.resources.LeoAuthUser;
let AUTH_TABLE = config.leoauth.resources.LeoAuth;

function wrapUser(user) {
	user.authorize = async function(event, resource) {
		var request = createRequest(event, resource);
		user.cognitoId = request.cognito.id;

		let data = await dynamodb.batchGetHashkey(AUTH_TABLE, "identity", user.identities.concat('*'), {});
		var statements = [];
		for (var id in data) {
			for (var name in data[id].policies) {
				statements = statements.concat(data[id].policies[name]);
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
	authorize: async function(event, resource) {
		return this.getUser(event.requestContext).then(user => user.authorize(event, resource));
	}
};
