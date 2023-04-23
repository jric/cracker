/*! \file cracker.cc
## LICENSE
 Licensed under Creative Commons 4.0:  https://creativecommons.org/licenses/by-sa/4.0/

## AUTHOR
 Written by jric < j r i c j r 4 AT g m a i l DOT com >

## CREDITS
 Bidirectional pipes code adapted from Mr.Ree and Peter Mortensen at
   https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po

 String split copied from Arafat Hasan at
   https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c

## DESCRIPTION
 I use this tool to crack a password that I have mistyped so that I can recover the encrypted data.

 Main idea is to crack the password with minimum CPU power, so I do not attempt a brute-force search, but instead do
   a breadth-first search with minimal Damerau–Levenshtein edits, starting from the password I suspect was used but
   mistyped.

 The vast majority of mistyped passwords are only off by one character or position!  In my case, I had
   forgotten two characters when I had typed my password, and it took about 5 minutes to "crack" the password
   starting with a password that was off by two.  Note that the more edits are required to get back to the correct
   password, the runtime will increase exponentially.  For two edits and password about 10 characters long, it 
   took my macbook pro about 5 minutes to crack the password.  Mileage will vary.

## ALGORITHM
 I try every combination deleting characters, substituting characters, twiddling characters, and adding
   characters to the seed password to generate a new candidate password.

 I check the passwords one at a time, pipe them into the password checker, and when I find one that
   works, print it out and stop.

## USAGE

See `README.md`

## FUTURE

### Fragments
People often add or forget entire words or other character combinations when typing a password.  Therefore,
instead of editing character by character, we could also allow the user to type in common things they put
into their passwords, e.g. a date, a word, or punctuation sequence, and try adding or substituting in those
entire phrases, in addition to single characters.  We could also automatically identify fragments in
seed password based on character classes.  E.g. a SEED_PWD like `2,CapitalInvestments` could be tokenized
into '2', ',', 'Capital', and 'Investments'.  Since the first two tokens are only one character long anyway,
it doesn't help to tokenize them, but we could try swapping in or out the other two words, whole word at a
time.

### Restart
 I should be able to stop the program and continue near where I left off in case I need to restart
   the computer, etc., before the target password is found.  When the program is halted
   prematurely, it should write current progress to stderr or elsewhere that it can be used.
*/
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h> // for O_CLOEXEC
#include <sys/wait.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <exception>
#include <sstream>
#include <dlfcn.h>
#include "cracker-plugin.h"

#define DEBUG 1
#define MAX_PWD_LEN 100 // we will check passwords up to this length
#define BUFFER_SIZE 100 // size of buffer for inter-process-communication
#define SEED_PWD_VAR_NAME "SEED_PWD"
#define RETURN_CODE_PLUGIN_INIT 4 // code to exit with if plugin fails to initialize

#define OUTPUT(stuff, level) { std::cerr << __FILE__ << ':' << __LINE__ << ": " << level << ": " << stuff << std::endl;  }
#define ERR(stuff) { OUTPUT(stuff, "ERROR") }
#define WARN(stuff) { OUTPUT(stuff, "WARN") }
#define INFO(stuff) { OUTPUT(stuff, "INFO") }
#if DEBUG > 0
#define DBG1(stuff) OUTPUT(stuff, "DEBUG1")
#else
#define DBG1(stuff) { } // noop
#endif
#if DEBUG > 1
#define DBG2(stuff) OUTPUT(stuff, "DEBUG2")
#else
#define DBG2(stuff) { } // noop
#endif
#define ABORT(stuff) { ERR("FATAL: " << stuff); exit(2); }
#define ASSERT_NOT(x, y) { if (x == y) ABORT(x) }
#define ASSERT_IS(x, y) { if (x != y) ABORT(x << " != " << y) }
#define USAGE(msg) { if (msg) ERR(msg) ERR(\
   "usage: /cracker --checker \"command to check password\""\
   "         --match \"string to match that lets us know the password worked\""\
   "         [--distance <unsigned>] default all, check passwords with this number of mutations only"\
   "         [--dryrun] default false; don't check password, just print passwords that would be checked"\
   "./cracker --checker \"argument(s) to plugin, e.g. filepath\""\
   "         --plugin <filename> instead of running a command with --match, use an in-memory"\
   "             function call to make things faster; --checker becomes argument(s) to the plugin"\
   "             see ## PLUGIN below"\
   "         [--distance <unsigned>] default all, check passwords with this number of mutations only"\
   "         [--dryrun] default false; don't check password, just print passwords that would be checked") \
  exit(msg ? 3 : 0); }

enum PIPE_FILE_DESCRIPTERS
{
  READ_FD  = 0,
  WRITE_FD = 1
};

typedef struct _ChildDescriptor {
    int read_fd;
    int write_fd;
    pid_t pid;
    int err_no;
} ChildDescriptor;

// throw this exception when we find a matching password!
struct FoundPwd : public std::exception {
    const char * pwd;
    FoundPwd() : pwd("NOT_FOUND") {}
    FoundPwd(const char * pwd) : pwd(pwd) {}
   const char * what () const throw () {
      return pwd;
   }
};

// The command to run to try the password
static std::string checkCmdOriginal; // as passed on the commandline
static char **checkCmd = nullptr;
static char **pwdField = nullptr; // will set to one of the entries in checkCmd if it is PWD or new ptr for plugin mode
// Output from checkCmd that indicates success
static std::string match;
static std::string plugin;
static void *pluginState = nullptr;
// Edit distance to try
static int distance = -1; // -1 means try more and more edits
static bool dryrun = false;

static const char *seedPwd = getenv(SEED_PWD_VAR_NAME); // the password we expected to work; typo from this one
static unsigned seedPwdLen; // length of the seedPwd - compute once for efficiency

crackerPluginInitFunc crackerPluginInit = nullptr;
crackerPluginDecryptFunc crackerPluginDecrypt = nullptr;
crackerPluginFinalizeFunc crackerPluginFinalize = nullptr;

// splits a string by delimeter
std::vector<std::string> split (const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss (s);
    std::string item;

    while (std::getline (ss, item, delim)) {
        result.push_back (item);
    }

    return result;
}

// Executes the given command and returns descriptor that can be used to interact with it.
// Stdout and stderr are collected in the same file descriptor.
// @param commandAndArgs should have a null pointer to indicate no more args
// @param sendData should be true if a second pipe is needed to write to STDIN on the subprocess
// Make sure to read and write from/to the file descriptors at the right times to avoid deadlocking, else use
//   non-blocking calls (select?)
// Make sure to close the file descriptors when done with them so the pipes behave correctly.
// Make sure to free the descriptor object when done with it to avoid memory leak.
ChildDescriptor *execute(char **commandAndArgs, bool sendData) {
    ChildDescriptor *ret = (ChildDescriptor *)malloc(sizeof(ChildDescriptor));
    ASSERT_NOT(nullptr, ret);
    int parentToChild[2]; // parent writes to [1], child reads from [0]
    int childToParent[2]; // child writes to [1], parent reads from [0]
    int execCheck[2]; // pipe descriptors to be auto-closed on successful exec, get error otherwise

    if (sendData)
        ASSERT_IS(0, pipe(parentToChild));
    ASSERT_IS(0, pipe(childToParent));
    ASSERT_IS(0, pipe(execCheck));
    ASSERT_NOT(-1, fcntl(execCheck[0], F_SETFD, FD_CLOEXEC));
    ASSERT_NOT(-1, fcntl(execCheck[1], F_SETFD, FD_CLOEXEC));

    ret->read_fd = childToParent[READ_FD];
    ret->write_fd = sendData ? parentToChild[WRITE_FD] : -1;
    ret->err_no = 0;

    switch (ret->pid = fork()) {
        case -1: ABORT("failed to fork")
        case 0: // child
            if (sendData)
                ASSERT_IS(0, close(parentToChild [WRITE_FD]));
            ASSERT_IS(0, close(childToParent [READ_FD]));
            ASSERT_IS(0, close(execCheck[READ_FD]));
            if (sendData)
                ASSERT_NOT(-1, dup2(parentToChild[READ_FD], STDIN_FILENO));
            ASSERT_NOT(-1, dup2(childToParent[WRITE_FD], STDOUT_FILENO));
            ASSERT_NOT(-1, dup2(childToParent[WRITE_FD], STDERR_FILENO));
            execv(commandAndArgs[0], commandAndArgs);
            write(execCheck[WRITE_FD], &errno, sizeof(errno)); // let parent know what error
            ABORT("failed to exec")
        default: // parent
            if (sendData)
                ASSERT_IS(0, close(parentToChild [READ_FD]));
            ASSERT_IS(0, close(childToParent [WRITE_FD]));
            ASSERT_IS(0, close(execCheck[WRITE_FD]));
            read(execCheck[READ_FD], &ret->err_no, sizeof(ret->err_no));
            ASSERT_IS(0, close(execCheck[READ_FD]));
    }

    return ret;
}

// Executes the prepared check command and returns stdout & stderr from the command; inline for extra speed
inline std::string execAndCapture() {
    if (dryrun) {
        INFO(*pwdField);
        return "";
    }

    ChildDescriptor *checker = execute(checkCmd, false /* sendData */);
    if (checker->err_no != 0) ABORT(strerror(checker->err_no) << " when executing " << checkCmdOriginal)
    char buffer[BUFFER_SIZE];
    std::string data;
    int numInterrupts = 0;
    while (true) {
        ssize_t charsRead = read(checker->read_fd, buffer, BUFFER_SIZE);
        if (charsRead == 0) break;
        if (charsRead < 0) {
            if (errno == EINTR) {
                if (numInterrupts++ < 50) continue;
            }
            WARN("read from subprocess failed: " << strerror(errno) << "; data is: " << data);
            break;
        }
        data.append(buffer, charsRead);
    }
    ASSERT_IS(0, close(checker->read_fd));
    int status;
    ASSERT_NOT(-1, waitpid(checker->pid, &status, 0)); // need to wait for forked process to free resources
    free(checker);
    return data;
}

// Returns true iff the current password unlocks the file
inline bool testMatch() {
    if (checkCmd) {
        DBG1("checking on command line")
        if (execAndCapture().find(match) != std::string::npos) return true;
    } else {
        DBG1("checking with plugin")
        if (crackerPluginDecrypt(*pwdField, pluginState)) {
            DBG1("plugin returned true for " << *pwdField);
            return true;
        }
    }
    return false;
}

// Iterates all the different ways to delete a char from the pwd string
// Assumption, dels <= strlen(pwdMutated)
// @throw FoundPwd if the password is found
inline void searchIterateDels(char *pwdMutated, unsigned dels) {
    char *delsArr[MAX_PWD_LEN]; // where to delete a char
    char savedArr[MAX_PWD_LEN]; // chars we deleted

    if (!dels) {
        if (testMatch())
                throw FoundPwd(pwdMutated);
        return;
    }
    // initial values in delsArr
    for (int delsNum = 0; delsNum < dels; delsNum++)
        delsArr[delsNum] = pwdMutated + delsNum;

    // movePos is most significant (leftward) place currently being modified as we wind through all combos,
    //  highest pointer first
    for (int movePos = dels - 1; movePos >= 0; ) {
        // delete all the characters
        for (int delPos = dels - 1; delPos >= 0; delPos--) {
            savedArr[delPos] = *delsArr[delPos];
            memmove(delsArr[delPos], delsArr[delPos] + 1, strlen(delsArr[delPos] + 1) + 1);
        }
        //DBG1("saved str: " << std::string(savedArr, dels))
        if (testMatch())
            throw FoundPwd(pwdMutated);
        // put all the characters back
        for (int delPos = 0; delPos < dels; delPos++) {
            memmove(delsArr[delPos] + 1, delsArr[delPos], strlen(delsArr[delPos]) + 1);
            *delsArr[delPos] = savedArr[delPos];
        }
        //DBG1("restored str: " << pwdMutated)

        // shift one position, but "carry over" to more significant movePos as appropriate
        movePos = dels - 1;
        if (!*(++delsArr[movePos])) {
            while (--movePos >= 0 && ++delsArr[movePos] + 1 >= delsArr[movePos + 1]);
            for (int fixPos = movePos + 1; fixPos < dels; fixPos++)
                delsArr[fixPos] = fixPos ? delsArr[fixPos - 1] + 1 : pwdMutated;
        }
    }
}

// if arr contains ptrs in original pwd for each pos being mutated, return ptr to pos where the added char is (string
//   shifts as chars are added)
#define MUTATED_POS(arr, pos) ( arr[pos] + pos )
// Use 1 for normal operation, 20 for faster debugging; must always be < 127
#define CHAR_STEPS 1

// helper for debugging searchIterateAdds()
inline void showPositionsBeingIterated(char ** addsArr, unsigned addsArrLen, char * stringStart) {
    std::stringstream s;
    s << addsArr[0] - stringStart;
    for (int i = 1; i < addsArrLen; i++) s << ", " << addsArr[i] - stringStart;
    DBG1("iterating chars at positions: " << s.str())
}

// helper for searchIterateAdds() : tries every combination of characters at the given insertion points
inline void searchIterateAtInsertions(int adds, int dels, char *pwdMutated, char **insertionPoints) {
    int iterPos; // which of the points are we iterating currently? 0...adds-1
    while (true) {
        iterPos = adds - 1;
        searchIterateDels(pwdMutated, dels);
        if ('~' < static_cast<unsigned char>(*MUTATED_POS(insertionPoints, iterPos) += CHAR_STEPS)) { // too big, iterate next left
            DBG2("too big, moving left");
            while (--iterPos >= 0 && '~' < static_cast<unsigned char>(*MUTATED_POS(insertionPoints, iterPos) += CHAR_STEPS));
            for (int resetPos = iterPos + 1; resetPos < adds; resetPos++)
                *MUTATED_POS(insertionPoints, resetPos) = ' ';
        }
        DBG2("iterPos: " << iterPos);
        if (iterPos < 0) break;
    }
}

// Iterates all the different ways to add "adds" num of chars into the pwd string and then iterates deletions
// @throw FoundPwd if the password is found
inline void searchIterateAdds(char *pwdMutated, int adds, int dels) {
    char *addsArr[adds]; // where to add a char; each entry points into pwdMutated
    const int pwdMutatedLen = strlen(pwdMutated);

    if (!adds)
        return searchIterateDels(pwdMutated, dels);

    if (adds + pwdMutatedLen >= MAX_PWD_LEN)
        return; // we cannot add the given number of characters -- exceeds max pwd length; skip this op

    // initial values in addsArr; all insertion points start at the end of pwdMutated
    for (int addsNum = 0; addsNum < adds; addsNum++)
        addsArr[addsNum] = pwdMutated + pwdMutatedLen;

    // try each insertion point combo; our stop condition is when our leftmost insertion point would be beyond start of string
    for ( ; addsArr[0] >= pwdMutated; ) {
        // make space for new chars in pwdMutated and initialize
        for (int addPos = adds - 1; addPos >= 0; addPos--)
            memmove(addsArr[addPos] + 1, addsArr[addPos], strlen(addsArr[addPos]) + 1);
        for (int addPos = adds - 1; addPos >= 0; addPos--)
            *MUTATED_POS(addsArr, addPos) = ' ';
#if 0   // DEBUGING OUTPUT
        showPositionsBeingIterated(addsArr, adds, pwdMutated);
#endif
        // iterate all combinations of chars
        searchIterateAtInsertions(adds, dels, pwdMutated, addsArr);
        // restore the string
        for (int addPos = adds - 1; addPos >= 0; addPos--)
            memmove(MUTATED_POS(addsArr, addPos), MUTATED_POS(addsArr, addPos) + 1, strlen(MUTATED_POS(addsArr, addPos) + 1) + 1);
        // iterate position(s) for new char insertion
        // movePos is most significant (leftward) index point that was moved
        int movePos = adds - 1;
        while (true) {
            --addsArr[movePos];
            if (movePos == 0) break;
            if (addsArr[movePos] < addsArr[movePos  - 1]) --movePos;
            else break;
        }
        DBG2("movePos: " << movePos);
        if (movePos < adds - 1) // reset all rightward insertion points to end of string
            for (int resetPos = movePos + 1; resetPos < adds; resetPos++)
                addsArr[resetPos] = pwdMutated + pwdMutatedLen;
    }
}

// Iterates all the different ways to transliterate the pwd string and then iterate other mutation types
// @throw FoundPwd if the password is found
inline void searchIterateTrans(char * pwdMutated, int trans, int adds, int dels) {
    char *transArr[MAX_PWD_LEN]; // where to transpose chars

    if (!trans)
        searchIterateAdds(pwdMutated, adds, dels);
    else
        for (int transNum = 0; transNum < trans; transNum++) {
            for (char *transPos = transNum ? transArr[transNum - 1] + 1 : pwdMutated;
                *transPos && *(transPos + 1); transPos++) {
                transArr[transNum] = transPos;
                char tmp = *transPos;
                *transPos = *(transPos + 1);
                *(transPos + 1) = tmp;
                searchIterateAdds(pwdMutated, adds, dels);
                *(transPos + 1) = *transPos; // swap the characters back the way they were
                *transPos = tmp;
            }
        }

}

// Runs the search, generating variations of the seed password, trying them with or plugin.
// Starts by checking the seed password, then tries checking all variations at edit distance of 1, then 2, 
//   etc. until the program runs out of life or finds the matching password.
// Limitation:  I try char swap first, then transposition, then additions, then deletions.  If the  
//   operations are done in a different order, they could produce results we never "see".
// @param editDistance
// @return the password if found, else returns string "NOT_FOUND" after trying all passwords within edit
//   distance equal to the length of the seed password.
std::string search(unsigned editDistance) {
    if (seedPwdLen > MAX_PWD_LEN / 2)
        ABORT("seed password is too long; more than " << MAX_PWD_LEN / 2);
    char pwdMutated[MAX_PWD_LEN * 2 + 1]; // allows up to seedPwdLen additions
    char *editsArr[MAX_PWD_LEN]; // where edits made
    char savedArr[MAX_PWD_LEN]; // original characters in each edit position

    *pwdField = pwdMutated; // updates checkCmd
    if (editDistance == 0 && distance <= 0) {
        memcpy(pwdMutated, seedPwd, seedPwdLen + 1);
        if (testMatch()) return std::string(pwdMutated);
    }
    // These first four for loops select all the combinations of various numbers of mutation for each type possible
    try {
        for (int edits = 0; edits <= editDistance; edits++) {
            for (int trans = 0; trans + edits <= editDistance; trans++) {
                for (int adds = 0; adds + trans + edits <= editDistance; adds++) {
                    int dels = editDistance - adds - trans - edits;
                    DBG1("(edits, trans, adds, dels): (" << edits << ", " << trans << ", " << adds << ", " << dels << ')')
                    memcpy(pwdMutated, seedPwd, seedPwdLen + 1);
                    if (!edits)
                        searchIterateTrans(pwdMutated, trans, adds, dels);
                    else {
                        for (int editNum = 0; editNum < edits; editNum++) {
                            editsArr[editNum] = editNum ? editsArr[editNum - 1] + 1 : pwdMutated;
                            savedArr[editNum] = *editsArr[editNum];
                            *editsArr[editNum] = ' ';
                        }
                        // try all combinations of edit position, moving the last one forward to the end, then
                        //  moving the next-to-last, etc.; last position moves the fastest
                        for (bool allTried = false; !allTried; ) {
                            // wind forward like a clock, starting with first position (moves fastest)
                            for (bool notAtEnd = true; notAtEnd; ) { // at end when we've tried all combinations of edits
                                searchIterateTrans(pwdMutated, trans, adds, dels);
                                // wind these forward like a clock
                                bool bumpNext = true;
                                for (int pos = 0; bumpNext; ) {
                                    bumpNext = false;
                                    if (++(*editsArr[pos]) > '~') {
                                        *editsArr[pos++] = ' ';
                                        if (pos < edits)
                                            bumpNext = true;
                                        else
                                            notAtEnd = false;
                                    }
                                }
                            }
                            for (int editNum = 0; editNum < edits; editNum++) {
                                *editsArr[editNum] = savedArr[editNum];
                            }
                            bool bumpNext = true;
                            int pos = edits - 1;
                            for (; bumpNext; ) {
                                bumpNext = false;
                                if (*(++(editsArr[pos])) == 0) {
                                    if (--pos >= 0)
                                        bumpNext = true;
                                    else
                                        allTried = true;
                                }
                            }
                            if (pos >= 0) {
                                // initialize values & reset the position pointers after first one that moved
                                savedArr[pos] = *editsArr[pos];
                                *editsArr[pos] = ' ';
                                for (int i = pos + 1; i < edits; i++) {
                                    editsArr[i] = editsArr[i - 1] + 1;
                                    savedArr[i] = *editsArr[i];
                                    *editsArr[i] = ' ';
                                }
                            }
                        }
                    }
                }
            }
        }
    } catch (const FoundPwd &e) {
        return std::string(e.what());
    }
    if (editDistance < seedPwdLen && distance < 0) {
        INFO("password not found with " << editDistance << " edits; trying " << editDistance + 1);
        return search(editDistance + 1);
    }
    return "NOT_FOUND";
}

int main(int argc, const char **argv) {
    // Parse commandline arguments
    for (int i = 1; i < argc; i++) {
        if (!strcmp("--checker", argv[i])) {
            if (i + 1 >= argc) ABORT("missing argument for --checker");
            checkCmdOriginal = argv[++i];
        } else if (!strcmp("--match", argv[i])) {
            if (i + 1 >= argc) ABORT("missing argument for --match");
            if (!plugin.empty()) ABORT("Can't specify both --match and --plugin");
            match = argv[++i];
        } else if (!strcmp("--plugin", argv[i])) {
            if (i + 1 >= argc) ABORT("missing argument for --plugin");
            if (!match.empty()) ABORT("Can't specify both --match and --plugin");
            plugin = argv[++i];
        } else if (!strcmp("--dryrun", argv[i])) {
            dryrun = true;
        } else if (!strcmp("--distance", argv[i])) {
            if (i + 1 >= argc) ABORT("missing argument for --distance");
            distance = atoi(argv[++i]);
        } else {
            USAGE("Unexpected argument");
        }
    }
    if (match.empty() && plugin.empty()) USAGE("Must specify one of --match or --plugin")

    if (!match.empty()) { // doing a commandline check
        DBG1("checking passwords via the commandline")
        std::vector<std::string> commandAndArgs = split(checkCmdOriginal, ' ');
        checkCmd = static_cast<char **>(malloc(sizeof(char *) * commandAndArgs.size() + 1));
        int i = 0;
        for ( ; i < commandAndArgs.size(); i++) {
            checkCmd[i] = strdup(commandAndArgs[i].c_str());
            if (!strcmp(checkCmd[i], "PWD"))
                pwdField = checkCmd + i; // this it the command arg that will dynamically change
        }
        checkCmd[i] = nullptr;
        if (checkCmd == nullptr) USAGE("required argument --checker missing")
    } else { // doing a plugin check
        DBG1("checking passwords via plugin " << plugin)
        // Load the plugin
        void *handle = dlopen(plugin.c_str(), RTLD_LAZY);
        if (!handle) ABORT("Unable to load plugin " << plugin << " due to " << dlerror());
        // Load the functions
        crackerPluginInit = reinterpret_cast<crackerPluginInitFunc>(dlsym(handle, INIT_FUNC_NAME));
        if (!crackerPluginInit)
            ABORT("Unable to load " << INIT_FUNC_NAME << " from " << checkCmdOriginal << "; check available symbols");
        crackerPluginDecrypt = reinterpret_cast<crackerPluginDecryptFunc>(dlsym(handle, DECRYPT_FUNC_NAME));
        if (!crackerPluginDecrypt)
            ABORT("Unable to load " << DECRYPT_FUNC_NAME << " from " << checkCmdOriginal << "; check available symbols");
        crackerPluginFinalize = reinterpret_cast<crackerPluginFinalizeFunc>(dlsym(handle, FINALIZE_FUNC_NAME));
        if (!crackerPluginFinalize)
            ABORT("Unable to load " << FINALIZE_FUNC_NAME << " from " << checkCmdOriginal << "; check available symbols");

        pluginState = crackerPluginInit(checkCmdOriginal.c_str());
        if (!pluginState) {
            ABORT("Unable to initialize plugin");
            return RETURN_CODE_PLUGIN_INIT;
        }

        char *currPwd;       // a place to keep track of the curr passwd being checked
        pwdField = &currPwd;
    }

    if (nullptr == seedPwd) ABORT("environment variable not set: " << SEED_PWD_VAR_NAME);
    seedPwdLen = strlen(seedPwd);

    if (CHAR_STEPS > 1) WARN("char steps is " << CHAR_STEPS << "; not all passwords will be checked");

    std::string pwd = search(distance < 0 ? 0 : distance);
    std::cout << "Password is: \'" << pwd << '\'' << std::endl;

    if (pluginState) crackerPluginFinalize(pluginState);

    return pwd == std::string("NOT_FOUND") ? 1 : 0;
}