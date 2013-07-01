/* Externs file for closure compiler. */

/** @const */
var module = {};

var process = {
  stdout: {
    /**
    @param {string} bytes
    */
    write: function(bytes) {}
  }
};

/**
@param {string} name
@return {?}
*/
function require(name) {}

/** @const */
var console = {
  /**
  @param {*} output
  @param {...*} var_args
  */
  log: function(output, var_args) {}
};

/**
@constructor
@param {string} value
@param {number} base
*/
function BigInteger(value, base) {}

var forge = {};
forge.random.getBytes = function(n) {};
forge.pki = {};
forge.pki.rsa = {};
forge.pki.rsa.createKeyPairGenerationState = function(n) {};
forge.pki.rsa.stepKeyPairGenerationState = function(generator, n) {};
