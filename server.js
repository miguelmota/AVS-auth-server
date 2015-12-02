'use strict';

const app = require('./app');
const https = require('https');
const fs = require('fs');
const config = require('./config/config.json');
const port = process.env.PORT || config.port;

app.set('port', port);

const options = {
  key: fs.readFileSync('./ssl/server.key'),
  cert: fs.readFileSync('./ssl/server.crt'),
  passphrase: 'echo',
  requestCert: true,
  rejectUnauthorized: false
};

const server = https.createServer(options, app);

server.listen(port);
server.on('error', onError);
server.on('listening', onListening);

function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }

  const bind = typeof port === 'string'
    ? 'Pipe ' + port
    : 'Port ' + port;

  if (error.code === 'EACCES') {
    console.error(`${bind} requires elevated privileges`);
    process.exit(1);
  } else if (error.code === 'EADDRINUSE') {
    console.error(`${bind} is already in use`);
    process.exit(1);
  } else {
    throw error;
  }
}

function onListening() {
  const addr = server.address();
  const bind = typeof addr === 'string'
    ? 'pipe ' + addr
    : 'port ' + addr.port;

  console.log(`Listening on ${bind}`);
}
