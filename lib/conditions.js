var netmask = require('netmask').Netmask;

function matchify(expected, allowGlob) {
  if (!Array.isArray(expected)) {
    expected = [expected];
  }
  return expected.map(function (e) {
    e = e.toString().replace(/[^a-zA-Z0-9_\-*?: ./]/g, '').replace(/\./, '\\.');
    if (allowGlob) {
      return new RegExp('^' + e.replace(/\*/g, '.*').replace(/\/\.\*/, '.*') + '$');
    } else {
      return new RegExp('^' + e + '$');
    }
  });
}

function runMatch(actual, expected) {
  for (var i = 0; i < expected.length; i++) {
    // console.log(actual, expected[i]);
    if (actual.match(expected[i])) {
      return true;
    }
  }
  return false;
}

var conditions = {
  'StringLike': function (request, field, expected) {
    if (!(field in request) || request[field] === undefined || request[field] === null) {
      return false;
    }
    return runMatch(request[field].toString(), matchify(expected, true));
  },
  'StringNotLike': function (request, field, expected) {
    if (!(field in request)) {
      return false;
    }
    return !runMatch(request[field].toString(), matchify(expected, true));
  },
  'StringEquals': function (request, field, expected) {
    if (!(field in request) || request[field] === undefined || request[field] === null) {
      return false;
    }
    return runMatch(request[field].toString(), matchify(expected, false));
  },
  'StringNotEquals': function (request, field, expected) {
    if (!(field in request)) {
      return false;
    }
    return !runMatch(request[field].toString(), matchify(expected, false));
  },
  'Null': function (request, field, expected) {
    if (expected === true) {
      if (field in request) {
        return false;
      } else {
        return true;
      }
    } else if (expected === false) {
      if (field in request) {
        var val = request[field];
        if (val === undefined || val === null || val.toString().trim() === '') {
          return false;
        } else {
          return true;
        }
      } else {
        return false;
      }
    } else {
      throw new Error('Unknown Null expectation');
    }
  },
  'IpAddress': function (request, field, expected) {
    if (!(field in request)) {
      return false;
    }
    for (var i = 0; i < expected.length; i++) {
      var mask = new netmask(expected[i]);
      if (mask.contains(request[field])) {
        return true;
      }
    }
    return false;
  }

};

//Lets add Looping
Object.keys(conditions).forEach(function (condition) {
  conditions['ForAllValues:' + condition] = function (request, field, expected) {
    var actual = request[field];
    if (!actual || !Array.isArray(actual) || !actual.length) {
      return false;
    }
    for (var i = 0; i < actual.length; i++) {
      // console.log(actual[i], expected, conditions[condition](actual, i, expected));
      if (!conditions[condition](actual, i, expected)) {
        // console.log("all values is false");
        return false;
      }
    }
    return true;
  };
  conditions['ForAnyValues:' + condition] = conditions['ForAnyValue:' + condition] = function (request, field, expected) {
    var actual = request[field];
    if (!actual || !Array.isArray(actual) || !actual.length) {
      return false;
    }
    for (var i = 0; i < actual.length; i++) {
      // console.log(actual[i], expected, conditions[condition](actual, i, expected));
      if (conditions[condition](actual, i, expected)) {
        // console.log("any values is true");
        return true;
      }
    }
    return false;
  };
});

conditions.createMessage = function (conditional, flatRequest, field, expected) {
  var message = '';
  message = `Failed assertion for ${field}(${flatRequest[field]})`;
  if (conditional == 'Null' && expected === true) {
    message += 'to be Null';
  } else if (conditional == 'Null' && expected === false) {
    message += 'to be NotNull';
  } else {
    message += `to match ${expected}`;
  }
  return message;
};
// console.log(conditions);
module.exports = conditions;