// Load the SDK for JavaScript
const AWS = require('aws-sdk');
// Set the region
AWS.config.update({region: process.env.AUTH_AWS_REGION});

// Create DynamoDB service object
const ddb = new AWS.DynamoDB({apiVersion: '2012-08-10'});

module.exports = {
  /**
   * Get a single item from dynamo.
   * @param {string} table The table to get the item from.
   * @param {string} attribute The attribute to match the id with.
   * @param {*} id The id to get.
   */
  get: async function(table, attribute, id) {
    const marshalledId = AWS.DynamoDB.Converter.marshall({ id });
    var params = {
      TableName: table,
      Key: {
        [attribute] : marshalledId.id,
      },
    };

    // Call DynamoDB to read the item from the table
    const result = await ddb.getItem(params).promise();
    return AWS.DynamoDB.Converter.unmarshall(result.Item);
  },
  /**
   *
   * @param {string} table The table to get the items from.
   * @param {string} attribute The attribute to match the ids with.
   * @param {*[]} ids The ids to get
   */
  queryAll: async function(table, attribute, ids) {
    const allResponses = {};
    // Setup the initial request by mapping all the id's to their dynamo marshalled version.
    const mappedIds = ids.map((id) => ({
      [attribute]: AWS.DynamoDB.Converter.marshall({ id }).id,
    }));
    let batchParams = {
      RequestItems: {
        [table]: {
          Keys: mappedIds
        },
      },
    };

    do {
      const response = await ddb.batchGetItem(batchParams).promise();
      // Assign the unmarshalled response data to the allResponses object with the response key as the key in the allResponses object.
      response.Responses[table].map((response) => {
        const unmarshalledResponse = AWS.DynamoDB.Converter.unmarshall(response);
        allResponses[unmarshalledResponse[attribute]] = unmarshalledResponse;
      });

      // As long as there are unprocessed keys we will continue the loop.
      batchParams = response.UnprocessedKeys;
    } while(Object.keys(batchParams).length);

    return allResponses;
  }
};
