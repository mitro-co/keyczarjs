/*
Copyright 2003 Lectorius, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
