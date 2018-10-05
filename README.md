# Younique Auth-SDK

This module will retrieve and authorize a user who is logged in via cognito and makes a request to an endpoint.

It has two modes. The first mode will connect to the Users tables in AWS and retrieve the policy information from those tables. The second mode allows the developer to code the policies directly into their project and save a few requests to dynamo.

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

What happens when a user makes a request via API Gateway to a function that is using auth-sdk? First the cognito id is matched against the identity stored in the identities table. This will give us any identifying information about this user. This means that we will get any context for the user as well as any roles that the user belongs to.

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

If you'd like to provide the policies yourself, rather than updating the dynamodb tables in production and development, then you can use the bootstrapping method below to provide the policies.

```js
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
    ]
    'list_looks': [
      {
        Effect: "Allow",
        Action: "looks:list",
        Resource: "lrn:younique:looks:::*",
      },
    ]
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

This is the easiest way and does not required a dev ops ticket to implement. Otherwise you'll have to write the policy, test it in dev, and then submit the policy to dev ops to have the policy added to the production dynamo tables.

## Authorizing the request

Now that we have the policies available to use we can authorize the user. The event here is the event that was received by a lambda function. The event will contain the cognito id of the user that made the request, or if the request was made by an unauthenticated entity. Depending on your policies the user will either be matched and returned in the `then` or an error will be thrown and returned in the `catch`.

```js
exports.handler = async (event) => {
  auth.authorize(event, {
    lrn: 'lrn:younique:looks:::{resource}',
    action: 'list',
    // The following line is not necessary if you don't want to use replacement. You may just put the resource in the lrn above.
    looks: { resource: 'looks' }
  })
    .then((user) => {
      console.log('user', JSON.stringify(user));
    })
    .catch((authErr) => {
      console.log('authErr', authErr);
    });
};
```

Go forth and authorize.