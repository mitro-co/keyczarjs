module.exports.runTests = function(tests) {
    for (var i = 0; i < tests.length; i++) {
        tests[i]();
        process.stdout.write('.');
    }
    console.log('success');
};
