# Younique Auth-SDK

This module will retrieve and authorize a user who is logged in via cognito and makes a request to an endpoint.

It has two modes. The first mode will connect to the Users tables in AWS and retrieve the policy information from those tables. The second mode allows the developer to code the policies directly into their project and save a few requests to dynamo.

## Requirements

This library is only supported for NodeJS v8+. It uses async/await and arrow functions heavily.

## Configuration

Two environment variables must be set in order for this library to work correctly.

AUTH_IDENTITES_TABLE
  - The preferred way is to import the value from CloudFormation **Fn::ImportValue "Users-IdentitiesTable"**
  - If you are using serverless you can use **${cf:Users.IdentitiesTable}**

AUTH_ROLE_POLICIES_TABLE
  - The preferred way is to import the value from CloudFormation **Fn::ImportValue "Users-RolePoliciesTable"**
  - If you are using serverless you can use **${cf:Users.RolePoliciesTable}**

During development you'll need to manually provide the environment variables, unless you are using serverless. If using serverless and the variables above then the environment will be populated automatically. Since this is a public repo, you'll need to look up the variables in the Users stack of the dev AWS account.

## Process

What happens when a user makes a request via API Gateway to a function that is using @youniquellc/auth-sdk? First the cognito id is matched against the identity stored in the identities table. This will give us any identifying information about this user. This means that we will get any context for the user as well as any roles that the user belongs to.

The response will look similar to the following.

```json
{
  "identity_id": "us-west-2:798e54b5-ee77-4fe2-8c5e-f66e211c0652",
  "context": "{\"user\":{\"id\":\"123123123\"},\"presenter\":{\"id\":12341234}}",
  "roles": [
    "role/user",
    "role/presenter"
  ]
}
```

The context is any data that we decide to store along with the user. The roles are how we match policy statements to a specific user.

This user for example would have access to any policies that belong to the "role/user" and "role/presenter" roles.

Another user might get the following response if they are only logged in as an admin user.

```json
{
  "identity_id": "us-west-2:243d4845-bc77-4982-9c52-cf17f84bc2ee",
  "context": "{\"user\":{\"id\":\"123123123\"}}",
  "roles": [
    "role/admin"
  ]
}
```

Meaning that this user has access to any policies that belong to the "role/admin" role.

## Bootstrapping

If you'd like to provide the policies yourself, rather than update the dynamodb tables in production and development, then you can use the bootstrapping method below to provide the policies.

```js
const auth = require('@youniquellc/auth-sdk');
const policy = require('./auth_policy');
auth.bootstrap(policy);
```

The policies are written the same way as they would be put into the dynamo tables. The following is an example.

```js
module.exports = {
  actions: 'looks',
  resource: 'lrn:younique:looks',
  identities: {
    '*': [
      'count_looks',
      'list_looks',
    ],
    'role/user': [
      'create_look',
      'delete_look',
    ],
    'role/presenter': [
      'create_look',
      'delete_look',
    ],
    'role/admin': [
      'looks_admin',
    ],
  },
  policies: {
    'count_looks': [
      {
        Effect: "Allow",
        Action: "looks:counts",
        Resource: "lrn:younique:looks:::*",
      },
    ],
    'list_looks': [
      {
        Effect: "Allow",
        Action: "looks:list",
        Resource: "lrn:younique:looks:::*",
      },
    ],
    'create_look': [
      {
        Effect: "Allow",
        Action: "look:create",
        Resource: "lrn:younique:looks:::*",
      },
    ],
    'delete_look': [
      {
        Effect: "Allow",
        Action: "look:delete",
        Resource: "lrn:younique:looks:::*",
      },
    ],
    'looks_admin': [
      {
        Effect: "Allow",
        Action: "looks:admin",
        Resource: "lrn:younique:looks:::*"
        Condition: {
          "IpAddress": {
            "aws:sourceip": [
              "123.456.789.101/29",
              "123.456.789.102/29",
              "123.456.789.103/29",
              "123.456.789.104/29",
              "123.456.789.105/29",
            ],
          },
        },
      },
    ],
  },
};
```

In the policy above the role/user and role/presenter roles both have the same policy names underneath them. This allows you to write the policy only once and then attach it to as many roles as is necessary.

This is the easiest way and does not required a dev ops ticket to implement. Otherwise you'll have to write the policy, test it in dev, and then submit the policy to dev ops to have the policy added to the production dynamo tables.

## Writing policies

There are a few ways to write policies. You can either write Allow policies (all the policies in the example above are allow policies) or you can write Deny policies. Both types of policies accept conditions.

The following is a list of the available conditions:
- StringLike: Matches a string allowing you to use the glob operator (*) for wildcard matches.
- StringNotLike: Makes sure that the value doesn't match the value, allows you to use the glob operator (*) for wildcard matches.
- StringEquals: Makes sure that the field value exactly matches.
- StringNotEquals: Makes sure that the field value doesn't exactly match.
- Null: Makes sure that the fields is not null, undefined, or an empty string.
- IPAddress: Makes sure that the field matches with an ip address.

All if an array is provided to the condition then all the values are treated as AND's meaning that every value must be true for the condition in order for the policy to be applied. NOTE: This is not true for IPAddress which is treated as an OR, in which case only one must be true for the policy to be applied.

In the policy above you can see that the IpAddress condition is an object that maps fields to the conditions. These are compared against the flattened request and if the conditions do not match then the policy will be ignored for this request.

An interesting IPAddress example is provided below which will give you access to do anything within your resources when you are connecting to your API's locally.

```js
module.exports = {
  actions: 'looks',
  resource: 'lrn:younique:looks',
  identities: {
    '*': [
      'localhost',
    ],
  },
  policies: {
    'localhost': [
      {
        Effect: 'Allow',
        Action: '*',
        Resource: '*',
        Condition: {
          "IpAddress": {
            "aws:sourceip": [
              "127.0.0.1/24"
            ],
          },
        },
      },
    ],
  }
};
```

In order to determine what options are available for the fields I've made a helper function where you can pass in your event and request and see what the flattened request will look like. You can then use these fields in your policy conditions.

```js
const auth = require('@youniquellc/auth-sdk');
const policy = require('./auth_policy');

exports.handler = async (event) => {
  const request = {
    lrn: 'lrn:younique:looks:::{resource}',
    action: 'list',
    // The following line is not necessary if you don't want to use replacement. You may just put the resource in the lrn above.
    looks: { resource: 'looks' }
  };

  console.log('flattenedRequest', auth.getFlattenedRequest(event, request));
};
```

## Authorizing the request

Now that we have the policies available to use we can authorize the user. The event here is the event that was received by a lambda function. The event will contain the cognito id of the user that made the request or if the request was made by an unauthenticated entity. Depending on your policies the user will either be matched and returned in the `then` or an error will be thrown and returned in the `catch`.

```js
const auth = require('@youniquellc/auth-sdk');
const policy = require('./auth_policy');

exports.handler = async (event) => {
  const request = {
    lrn: 'lrn:younique:looks:::{resource}',
    action: 'list',
    // The following line is not necessary if you don't want to use replacement. You may just put the resource in the lrn above.
    looks: { resource: 'looks' }
  };

  auth.bootstrap(policy);
  auth.authorize(event, request)
    .then((user) => {
      console.log('user', JSON.stringify(user));
    })
    .catch((authErr) => {
      console.log('authErr', authErr);
    });
};
```

The request above will generate the following resource: `lrn:younique:looks:::looks` and the following action `looks:list`. These will be matched against the policy you've provided in either the `bootstrap` function or in dynamo.

Go forth and authorize.
