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

var forge = {};
forge.random.getBytes = function(n) {};
forge.pki = {};
forge.pki.rsa = {};
/**
@return {{keys: {privateKey}}} RSA key generation state
*/
forge.pki.rsa.createKeyPairGenerationState = function(n) {};
forge.pki.rsa.stepKeyPairGenerationState = function(generator, n) {};

forge.jsbn = {};
/**
@constructor
@param {string} value
@param {number} base
*/
forge.jsbn.BigInteger = function(value, base) {};
