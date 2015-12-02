'use strict';

/**
 * @module
 * This module contains the authentication functionality that implements the
 * application side logic for the Login with Amazon OAUTH authentication
 * using a authorization code flow with extensions to support device registration
 * for Alexa Voice Services. It is also extended to show how to work with devices.
 * The sample assumes that device serial numbers are unique across all devices.
 * See the README.md file for details on sequence of interactions.
 */
const crypto = require('crypto');
const https = require('https');
const _ = require('lodash');
const config = require('./config/config.json');

const auth = {};

// Maps stateCode => regCode
const pendingStateToRegCode = {};

// Temporary until registration is over
// Maps regCode => { productId, dsn, expires, deviceSecret }
const pendingRegCodeToDevice = {};

// Temporary until registration is over
// Maps productId:dsn => regCode
const pendingDeviceToRegCode = {};

// "Permanent" information about the device
// Maps productId:dsn => { deviceSecret, tokens: { access, refresh, expires } }
const deviceInformation = {};

// Queue of regCodes
const pendingRegistrationQueue = [];

var oAuthServer = 'https://' + config.lwaRedirectHost + '/ap/oa';
var lwaProdAuthUrl = oAuthServer + '?client_id=' + config.clientId +
  '&response_type=code&redirect_uri=' + config.redirectUrl;

// whitelisted urls - these will allow requests without being authenticated.
var whitelistUrls = [
  /^\/authresponse\?code=/,
  /^\/device\/register/,
  /^\/device\/regcode/,
  /^\/device\/accesstoken/,
  /^\/favicon.ico/,
  /^\/public/,
];

var intervalTimer = null;

var MAX_REG_SECONDS = 900;          // the time in seconds a registration code is valid
var MIN_POLL_RATE = 1000;           // The maximum rate in ms between polls for a token
var MAX_PENDING_REG = 50000;
var EXPIRE_CHECK_INTERVAL = 5000;   // time in ms to check check for expired reg codes.

var PRODUCT_MAX_LENGTH = 384;
var PRODUCT_MIN_LENGTH = 1;
var DSN_MIN_LENGTH = 1;

var STATE_NUM_BYTES = 32;
var REG_NUM_BYTES = 12;

// Simple wrapper function for generating an unauthorized error message.
function unauthorizedError(next, msg) {
  var err = new Error();
  err.name = 'UnauthorizedError';
  err.message = msg;
  err.status = 401;
  next(err);
}

// Simple wrapper function for generating an error message.
function error(name, msg, status) {
  var err = new Error();
  err.name = name;
  err.message = msg;
  err.status = status;
  return err;
}

/**
 * @api private
 *  Given the device information, initiates the redirect of a browser to the
 *  LWA endpoint that will perform authentication.  Adds in scope information
 *  for the Alexa service including device registration information.
 */
function redirectToDeviceAuthenticate(deviceInfo, regCode, res, next) {
  console.log('entering redirectToDeviceAuthenticate');
  res.statusCode = 302;
  crypto.randomBytes(STATE_NUM_BYTES, function (err, buf) {
    if (err) {
      console.error('RedirectToAuthentication: failure generating random string:',err);
      next(error('InternalError', 'Unknown failure', 500));
    } else {
      var state = buf.toString('hex');

      var productScope = {productID:deviceInfo.product, productInstanceAttributes:{deviceSerialNumber:deviceInfo.dsn}};
      var scopeData = {};
      scopeData['alexa:all'] = productScope;

      var scopeDataStr = '&scope=' + encodeURIComponent('alexa:all') + '&state=' + encodeURIComponent(state) + '&scope_data=' + encodeURIComponent(JSON.stringify(scopeData));
      var authUrl = lwaProdAuthUrl + scopeDataStr;

      pendingStateToRegCode[state] = regCode;
      res.setHeader('Location', authUrl);
      res.end();
    }
  });
}

/**
 * @api private
 *  Gets the options for posting a message to LWA.
 */
function getLwaPostOptions(urlPath) {
  return {
    host: config.lwaApiHost,
    path: urlPath,
    method: 'POST',
    port: 443,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    },
    rejectUnauthorized: config.validateCertChain
  };
}

/**
 * @api private
 *  Checks if the url provided is white listed.
 */
function checkWhiteList(url) {
  for (var i = 0; i < whitelistUrls.length; i++) {
    if (whitelistUrls[i].test(url)) {
      return true;
    }
  }
  return false;
}

/**
 * @api private
 *
 */
function isValidDevice(product, dsn) {
  if (product.length >= PRODUCT_MIN_LENGTH &&
      product.length <= PRODUCT_MAX_LENGTH &&
        dsn.length >= DSN_MIN_LENGTH &&
          config.products[product] &&
            config.products[product].indexOf(dsn) >= 0) {
    return true;
  }

  return false;
}

/**
 * @api private
 * Removes pending device information from collections tracking its state.
 */
function removePendingDevice(regCode) {
  if (pendingRegCodeToDevice[regCode]) {
    var dsn = pendingRegCodeToDevice[regCode].dsn;
    var product = pendingRegCodeToDevice[regCode].product;
    delete pendingRegCodeToDevice[regCode];
    delete pendingDeviceToRegCode[product + ':' + dsn];
  }
}

/**
 * @api private
 * Checks the pending registration queue, expiring any registrations that have exceeded their expire time.
 */
function checkExpire() {
  var curtime = new Date().getTime();
  var expired = 0;

  while (pendingRegistrationQueue.length > 0) {
    var regCode = pendingRegistrationQueue[0];

    if (regCode in pendingRegCodeToDevice) {
      if (curtime > pendingRegCodeToDevice[pendingRegistrationQueue[0]].expires) {
        console.log('Expiring pending registration for: ', pendingRegCodeToDevice[regCode].product,
                    ':', pendingRegCodeToDevice[regCode].dsn);
                    removePendingDevice(regCode);
                    expired++;
      } else {
        // Since pendingRegistrations get pushed onto pendingRegistrationQueue in order we can stop processing once we reach one registration that is not expired
        break;
      }
    } else {
      // If regCode is not in pendingRegCodeToDevice then it may have already been registered, so just let this one get shifted away
    }

    pendingRegistrationQueue.shift();
  }

  if (expired > 0) {
    console.log('expired: ', expired, ' pending registrations');
  }
}

/**
 * @api private
 *  Adds a pending registration to the list.  Caps list to max to prevent out of memory.  Typically
 *  in production environment this will be stored in a permanent store like Amazon DynamoDB rather than in memory
 */
function addPendingRegistration(regCode, deviceSecret, product, dsn) {
  var err = null;

  if (pendingRegCodeToDevice.length >= MAX_PENDING_REG) {
    console.log('request dropped as a result of max pending requests, product: ', product, ', dsn: ', dsn);
    err = error('Throttle', 'Try again later', 503 );
  } else if (!(product + ':' + dsn in pendingDeviceToRegCode)) {
    var curtime = new Date().getTime();
    var expires = curtime + (1000 * MAX_REG_SECONDS);
    pendingRegCodeToDevice[regCode] = {
      product: product,
      dsn: dsn,
      deviceSecret: deviceSecret,
      expires: expires
    };

    pendingDeviceToRegCode[product + ':' + dsn] = regCode;
    pendingRegistrationQueue.push(regCode);

    if (intervalTimer === null) {
      intervalTimer = setInterval(checkExpire, EXPIRE_CHECK_INTERVAL);
    }
  } else {
    err = error('PendingRegistration', 'This device already has a registration pending', 403);
  }
  return err;
}

/**
 * A call back function for all url's access to determine if
 * the access is permitted, registered with app.use for paths to be secured.
 * There is a set of whitelisted url's that can't require authentication.
 * Raises an authorization error if not permitted and stops route callbacks.
 *
 * @param req [Request] - standard request object.
 * @param res [Response] - standard response object.
 * @param next [callback] - callback to stop or continue next callback action
 *
 * @example Validate all paths
 *   app.use('/*', auth.validate);
 */
auth.validate = function (req, res, next) {
  //'whitelist' certain service urls...
  if (checkWhiteList(req.originalUrl) === true) {     // allow stuff in the public folder.
    console.log('auth.validate matched whitelisted url');
    return next();
  } else {
    // you can add your own authentication here for other pages if you want
    // to authenticate the user coming into your site before you go through
    // the LWA registration flow.  In this case rejecting all.
    unauthorizedError(next, 'no authentication');
    console.log('auth.validate UnauthorizedError...');
  }
};

/**
 * Gets a registration code for a device, which initiates the registration flow.
 * The device provides its product type and serial number (dsn) information.
 * This is cryptographically generated random number.  You can decide how long
 * you want the code to be by altering the first parameter into the randomBytes call.
 *
 * @callback callback function(err, regCode)
 *   @param err [Error] an error or null if no error occurred.
 *   @param regCode [String] The registration code to use
 * @example Getting a regCode
 *   auth.getregCode('speaker', '12345', function(err, regCode) {
 *            // process code.
 *        });
 */
auth.getRegCode = function(product, dsn, callback) {
  if (!isValidDevice(product, dsn)) {
    console.log('Invalid product and dsn combination');
    callback(error('BadRequest', 'The provided product and dsn do not match valid values', 400));
    return;
  }

  crypto.randomBytes(REG_NUM_BYTES, function(err, regCodeBuffer) {
    if (err) {
      console.log('failed on generate bytes', err);
      callback(error('InternalError', 'Failure generating code', 500));
      return;
    } else {
      crypto.randomBytes(REG_NUM_BYTES, function(err, deviceSecretBuffer) {
        if (err) {
          console.log('failed on generate bytes', err);
          callback(error('InternalError', 'Failure generating code', 500));
          return;
        } else {
          var regCode = regCodeBuffer.toString('hex');
          var deviceSecret = deviceSecretBuffer.toString('hex');

          var reply = null;
          var registrationError = addPendingRegistration(regCode, deviceSecret, product, dsn);

          if (registrationError === null) {
            reply = {
              regCode: regCode,
              deviceSecret: deviceSecret,
              expires: pendingRegCodeToDevice[regCode].expires,
            };
          } else {
            reply = {
              regCode: regCode
            };
          }

          callback(registrationError, reply);
        }
      });
    }
  });
};

/**
 * Invoked from a request to register from an end user browser.
 * If the registration code has been generated, then pulls device
 * device information from registration process, and redirects the
 * browser to the LWA login page, and the callback is not invoked.
 * If an error occurs, the redirect does not happen, and the callback
 * is invoked with the error code.
 *
 * @callback callback function(err)
 *   @param err [Error] the error message
 * @example Registering
 *   auth.register('f719d373d4aa0b9ee7a14d2e', res, next, function(err) {
 *   });
 */
auth.register = function (regCode, res, next, callback) {
  if (regCode.length != REG_NUM_BYTES*2 || !pendingRegCodeToDevice[regCode]) {
    console.log('regCode not found');
    callback(error('InvalidRegistrationCode', 'Registration code is invalid', 401));
  } else {
    var prodInfo = pendingRegCodeToDevice[regCode];
    var curtime = new Date().getTime();

    if (prodInfo.expires > curtime) {
      redirectToDeviceAuthenticate(prodInfo, regCode, res, next);
    } else {
      console.log('regCode was expired');
      callback(error('ExpiredRegistrationCode', 'Registration code expired', 401));
      removePendingDevice(regCode);
    }
  }
};

/**
 * Retrieves the tokens from the oauth service after the redirect occurred,
 * and associates the retrieved token with the device being registered.
 *
 * @param authcode (String) - the authorization code to retrieve tokens from LWA
 * @param state (String) - the state info passed back from the LWA service.
 *      this is the same state value passed to LWA in the original redirect.
 * @callback callback function(err)
 *   @param err [Error] the error, null if no error occurred.
 *   @param message [String] - result message to send end user.
 * @example Retrieving a token
 *   auth.retrieveToken('auth1234', 'abcde', function(err, msg) {
 *             ....
 *    });
 */
auth.retrieveTokens = function (authcode, stateCode, callback) {
  console.log('entering auth.retrieveToken');

  if (stateCode.length != STATE_NUM_BYTES*2 || pendingStateToRegCode[stateCode]) {
    var regCode = pendingStateToRegCode[stateCode];
    delete pendingStateToRegCode[stateCode];         // delete to prevent reuse.

    var curtime = new Date().getTime();
    if (pendingRegCodeToDevice[regCode] && pendingRegCodeToDevice[regCode].expires > curtime) {
      var options = getLwaPostOptions('/auth/o2/token');
      var reqGrant = 'grant_type=authorization_code&code=' + authcode +
        '&redirect_uri=' + config.redirectUrl + '&client_id=' + config.clientId +
        '&client_secret=' + config.clientSecret;

      var req = https.request(options, function (res) {
        var resultBuffer = null;

        res.on('end', function () {
          console.log('retrieveToken: completed request get token');
          if (res.statusCode === 200 && resultBuffer !== null) {
            var result = JSON.parse(resultBuffer);

            var product = pendingRegCodeToDevice[regCode].product;
            var dsn = pendingRegCodeToDevice[regCode].dsn;
            var deviceSecret = pendingRegCodeToDevice[regCode].deviceSecret;

            deviceInformation[product + ':' + dsn] = {
              deviceSecret: deviceSecret,
              tokens: {
                access: result.access_token,
                refresh: result.refresh_token,
                expires: result.expires_in,
              }
            };

            console.log(result.access_token);

            // The device is no longer pending registration
            removePendingDevice(regCode);
            callback(null, 'device tokens ready');
          } else {
            console.error('Failure retrieving tokens, status code: ', res.statusCode);
            callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', res.statusCode));
          }
        });

        res.on('data', function (data) {
          if (res.statusCode === 200) {
            if (resultBuffer === null) {
              resultBuffer = data;
            } else {
              resultBuffer = Buffer.concat([resultBuffer, data]);
            }
          } else {
            console.error('Failure retrieving tokens, status code: ', res.statusCode, ' data:', data);
            callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', res.statusCode));
          }
        });
      });

      req.on('error', function (e) {
        console.error('Failed to post request: ' + e.message);
      });

      req.write(reqGrant);
      req.end();
    } else {
      removePendingDevice(regCode);
      console.error('Registration code expired when token retrieved');
      callback(error('ExpiredRegistrationCode', 'Registration code expired', 401));
    }
  } else {
    console.log('state not found for code: ', stateCode);
    callback(error('InvalidState', 'Invalid state', 401));
  }
};

/**
 * Gets an access token given a refresh token and device serial number.
 *
 * @param dsn (String) - the device identifer (serial number)
 * @param refreshToken (String) - the refresh token provided by the device
 * @callback callback function(err, accessToken)
 *   @param err [Error] the error, null if no error occurred.
 *   @param accessToken [String] - The access token issued.
 * @example Getting an access token
 *   auth.getAccessToken('1234', 'abcde', function(err, accessToken) {
 *     ...
 *   });
 */
auth.getAccessToken = function (product, dsn, deviceSecret, callback) {
  console.log('entering auth.getAccessToken');

  if (!isValidDevice(product, dsn)) {
    console.log('Invalid product and dsn combination');
    callback(error('BadRequest', 'The provided product and dsn do not match valid values', 400));
    return;
  }

  var productDsn = product + ':' + dsn;

  if (productDsn in pendingDeviceToRegCode) {
    var regCode = pendingDeviceToRegCode[productDsn];
    var regInfo = pendingRegCodeToDevice[regCode];
    var curtime = new Date().getTime();

    if (regInfo.expires > curtime) {
      if (regInfo.product === product && regInfo.dsn === dsn) {
        // Give some backoff information if necessary
        var backoffStatus;
        var interval = 0;

        if (regInfo.lastCall === 0) {   // first call?
          interval = MIN_POLL_RATE + 1;
        } else {
          interval = curtime - regInfo.lastCall;
        }

        regInfo.lastCall = curtime;

        if (interval < MIN_POLL_RATE) {
          backoffStatus = 'slowdown';
        } else {
          backoffStatus = 'waiting';
        }
        callback(null, { poll_status: backoffStatus });
      } else {
        callback(error('InvalidProductInformation', 'The provided product and dsn do not match the provided deviceSecret.', 401));
      }
    } else {
      callback(error('ExpiredDeviceSecret', 'Registration was not completed in time for this deviceSecret. Please restart the process.', 401));
    }
  } else {
    if (deviceInformation[productDsn] && deviceSecret.length == REG_NUM_BYTES*2 && deviceInformation[productDsn].deviceSecret === deviceSecret) {
      // You would put any revocation checking logic here.

      var options = getLwaPostOptions('/auth/o2/token');
      var reqGrant = 'grant_type=refresh_token&refresh_token=' + deviceInformation[productDsn].tokens.refresh +
        '&client_id=' + config.clientId + '&client_secret=' + config.clientSecret;

      var req = https.request(options, function (res) {
        var resultBuffer = null;

        res.on('end', function () {
          if (res.statusCode === 200 && resultBuffer !== null) {
            var result = JSON.parse(resultBuffer);

            // Update the information locally
            deviceInformation[productDsn].tokens.access = result.access_token;
            deviceInformation[productDsn].tokens.expires = result.expires_in;

            // Craft the response to the device
            var reply = {
              access: result.access_token,
              expires: result.expires_in
            };
            callback(null, reply);
          } else {
            console.error('Failure retrieving tokens, status code: ', res.statusCode, ' data:', data);
            callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', res.statusCode));
          }
        });

        res.on('data', function (data) {
          if (res.statusCode === 200) {
            if (resultBuffer === null) {
              resultBuffer = data;
            } else {
              resultBuffer = Buffer.concat([resultBuffer, data]);
            }
          } else {
            console.error('Failure retrieving tokens, status code: ', res.statusCode, ' data:', data);
            callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', res.statusCode));
          }
        });
      });

      req.on('error', function (e) {
        console.log('Failure posting request: ' + e.message);
        callback(error('TokenRetrievalFailure', 'Unexpected failure while retrieving tokens.', 500));
      });

      req.write(reqGrant);
      req.end();
    } else {
      callback(error('InvalidDeviceSecret', 'This deviceSecret is either invalid, or register was not completed in time for this deviceSecret. Please restart the process.', 401));
    }
  }
};

module.exports = auth;
