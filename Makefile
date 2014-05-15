CLOSURE_COMPILER=java -jar $(HOME)/Downloads/compiler.jar --language_in ECMASCRIPT5_STRICT --warning_level VERBOSE --compilation_level ADVANCED_OPTIMIZATIONS --externs externs/forge.js --externs externs/globals.js --jscomp_error=missingProperties
BUILD_DIR=build

all: $(BUILD_DIR)/keyczar_util.js $(BUILD_DIR)/keyczar.js $(BUILD_DIR)/keyczar_util_test.js $(BUILD_DIR)/keyczar_test.js $(BUILD_DIR)/roundtripper.js

clean:
	$(RM) -r $(BUILD_DIR)

$(BUILD_DIR)/keyczar_util.js: keyczar_util.js
	mkdir -p $(dir $@)
	$(CLOSURE_COMPILER) --js $^ --js_output_file $@

$(BUILD_DIR)/keyczar.js: keyczar_util.js keyczar.js
	mkdir -p $(dir $@)
	$(CLOSURE_COMPILER) --js $^ --js_output_file $@

$(BUILD_DIR)/keyczar_util_test.js: keyczar_util.js test_util.js keyczar_util_test.js
	mkdir -p $(dir $@)
	$(CLOSURE_COMPILER) --externs externs/assert.js --js $^ --js_output_file $@

$(BUILD_DIR)/keyczar_test.js: keyczar_util.js keyczar.js test_util.js keyczar_test.js
	mkdir -p $(dir $@)
	$(CLOSURE_COMPILER) --externs externs/assert.js --externs externs/fs.js --js $^ --js_output_file $@

$(BUILD_DIR)/roundtripper.js: keyczar_util.js keyczar.js roundtripper.js
	mkdir -p $(dir $@)
	$(CLOSURE_COMPILER) --externs externs/assert.js --externs externs/fs.js --js $^ --js_output_file $@
