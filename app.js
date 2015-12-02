'use strict';

/**
 * @module
 * This application module defines the REST services and web endpoints for
 * implementing a SAMPLE flow of LWA OAUTH authentication for authorization code
 * flow with extensions to support device registration for Alexa Voice Services.
 * It is also extended to show how to work with devices.  See the README.md file
 * for details on sequence of interactions.
 */

const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const auth = require('./authentication.js');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// This hook validates access for all pages.  See authenticate.js for implementation.
app.use('/*', auth.validate);

/**
 * Starts the authentication process by creating a registration code.
 *
 * This is the first resource that a device should call. The registration code should be
 * displayed in some form to the user for them to access the /device/register/:regcode route.
 * A device secret is also returned. This is not to be shared and is to be passed back to
 * request accessTokens. Along with the registration code and device secret will be an expires
 * key which gives a time-to-live for the two codes.
 *
 * @param {string} product - The productId of the device
 * @param {string} dsn - The device serial number
 * @return {Object} regcode, deviceSecret, expires
 */
app.get('/device/regcode/:product/:dsn', function (req, res) {
  console.log('entering get regcode');

  auth.getRegCode(req.params.product, req.params.dsn, function (err, reply) {
    if (err) {
      console.log('Failure: regcode failure:', err);
      res.status(500);
      res.send({
        error: err.name,
        message: err.message,
        extras: {
          regCode: reply.regCode
        }
      });
    } else {
      res.send(reply);
    }
  });
});

/**
 * Redirects the user to Amazon to login and give consent.
 *
 * This is the main page that a customer using this service would see. Once a customer has logged
 * into Amazon they will be redirected to the /authresponse route which will have an authorization
 * code that can be used to exchange for accessTokens.
 *
 * @param {string} regcode - The registration code shown on the device
 */
app.get('/device/register/:regcode', function (req, res, next) {
  console.log('entering register');

  auth.register(req.params.regcode, res, next, function (err) {
    // on success gets redirect so wont return to a callback.
    console.log('Failure: registering device: ', err);
    res.status(err.status);
    next(err);
  });
});

/**
 * Accepts a redirect from Login With Amazon (LWA) after the customer has logged in and consented to shared
 * information with our application
 *
 * After the customer logs in and accepts the consent form LWA will redirect them to this URI along with an
 * authorization code. That authorization code, along with the client_id and client_secret, are exchanged with
 * the LWA service for an accessToken and a refreshToken.
 */
app.get('/authresponse', function (req, res) {
  console.log('entering authresponse');

  auth.retrieveTokens(req.query.code, req.query.state, function (err, message) {
    if (err) {
      console.log('Failure: error on token retrieval: ', err);
      res.status(err.status);
      res.send({ error: err.name, message: err.message });
    } else {
      res.send(message);
    }
  });
});

/**
 * Used by a device to get an accessToken once the customer has finished authentication with Amazon
 *
 * Once a device displays the registration code to the customer it should begin polling this route every few seconds
 * until an access token is returned. Between the time when the registration code is displayed and the customer actually
 * authenticates with Amazon this route will return an object composed of a "poll_status" key with either value:
 * "slowdown" or "waiting". If a "slowdown" is received then the device is polling too often and should back off.
 *
 * @param {string} product - The productId of the device
 * @param {string} dsn - The device serial number
 * @param {string} deviceSecret - The device secret sent along with the registration code
 * @return {Object} accessToken, expires
 */
app.get('/device/accesstoken/:product/:dsn/:deviceSecret', function (req, res) {
  console.log('entering accesstoken');

  auth.getAccessToken(req.params.product, req.params.dsn, req.params.deviceSecret, function (err, reply) {
    if (err) {
      console.log('Failure: accesstoken:', err);
      res.status(err.status);
      res.send({ error: err.name, message: err.message });
    } else {
      res.send(reply);
    }
  });
});

// standard error handling functions.
app.use(function (req, res, next) {
  const err = new Error('Not Found');
  err.status = 404;
  next(err);
});

app.use(function (err, req, res, next) {
  console.log('error: ', err);
  res.status(err.status || 500);
  res.send(`error: ${err.message}`);
});

module.exports = app;
