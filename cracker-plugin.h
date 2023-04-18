#ifndef _CRACKER_PLUGIN_H
#define _CRACKER_PLUGIN_H

#define INIT_FUNC_NAME "crackerPluginInit"
#define DECRYPT_FUNC_NAME "crackerPluginDecrypt"
#define FINALIZE_FUNC_NAME "crackerPluginFinalize"

/** 
 * Handle any initialization the plugin needs
*/
typedef void *(*crackerPluginInitFunc)(const char * const plugin_args);
/** Attempts to decrypt the loaded data file with the given password.
 *  @returns true iff decryption successful
*/
typedef bool (*crackerPluginDecryptFunc)(const char * const pass, void *state);
/** Handles any cleanup that's needed when we're done using this plugin
 *  @returns true iff it succeeds
*/
typedef bool (*crackerPluginFinalizeFunc)(void *state);

// Define the functions so when the implementation is encountered, it uses C name mangling (not C++)
// extern "C" crackerPluginInitFunc crackerPluginInit;
// extern "C" crackerPluginDecryptFunc crackerPluginDecrypt;
// extern "C" crackerPluginFinalizeFunc crackerPluginFinalize;

#endif