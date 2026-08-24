'use strict';

const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const CURRENT_LEVEL = LEVELS[process.env.LOG_LEVEL] ?? LEVELS.info;

function ts() {
  return new Date().toISOString();
}

function fmt(level, scope, msg, extra) {
  const base = `[${ts()}] [${level.toUpperCase()}] [${scope}] ${msg}`;
  return extra !== undefined ? `${base} ${JSON.stringify(extra)}` : base;
}

function makeLogger(scope) {
  return {
    debug: (msg, extra) => LEVELS.debug >= CURRENT_LEVEL && console.debug(fmt('debug', scope, msg, extra)),
    info: (msg, extra) => LEVELS.info >= CURRENT_LEVEL && console.log(fmt('info', scope, msg, extra)),
    warn: (msg, extra) => LEVELS.warn >= CURRENT_LEVEL && console.warn(fmt('warn', scope, msg, extra)),
    error: (msg, extra) => LEVELS.error >= CURRENT_LEVEL && console.error(fmt('error', scope, msg, extra)),
  };
}

module.exports = { makeLogger };
