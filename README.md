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
   a breadth-first search starting with the correct password that I believe was mistyped, and make one, two, then three, etc.
   "edits" to immitate common typing mistakes, and try all possible combinations of those mistakes at every possible position
   in the "correct" password.  The "mistakes" attempted are Damerau–Levenshtein edits, meaning:
   
    * drop a character,
    * add a character,
    * substitute a character, or
    * twiddle two characters.
   
 The vast majority of mistyped passwords are only off by one character or position!  In my case, I had
   forgotten two characters when I had typed my password, and it took about 5 minutes to "crack" the password
   starting with a password that was off by two.  Note that the runtime will increase exponentially as the
   number of edits increases that are required to get back to the correct password.  For two edits and password
   about 10 characters long, it took my macbook pro about 5 minutes to crack the password.  Mileage will vary.

## ALGORITHM
 I try every combination deleting characters, substituting characters, twiddling characters, and adding
   characters to the seed password to generate a new candidate password.

 I check the passwords one at a time, pipe them into the password checker, and when I find one that
   works, print it out and stop.

## USAGE

 Usage:
 ```
   export SEED_PWD=XXXXX
   ./cracker --checker "command to check password"
             --match "string to match that lets us know the password worked"
             [--distance <unsigned>] default all, check passwords with this number of mutations only
             [--dryrun] default false; don't check password, just print passwords that would be checked
   ./cracker --checker "argument(s) to plugin, e.g. filepath"
             --plugin <filename> instead of running a command with --match, use an in-memory
                function call to make things faster; --checker args become arguments to the plugin
                see ## PLUGIN below
             [--distance <unsigned>] default all, check passwords with this number of mutations only
             [--dryrun] default false; don't check password, just print passwords that would be checked
```

 If "command to check password" contains an argument "PWD", that argument is varied with each password
    attempt.  My sample command is:
   `/usr/local/bin/gpg --batch --passphrase PWD --decrypt /my/file/name`

The full command would be:
```
   SEED_PWD=XXXXX ./cracker --checker '/usr/local/bin/gpg --batch --passphrase PWD --decrypt /my/file/name' \
      --match string-I-know-is-in-my-encrypted-file
```

## PLUGIN

We can load a dynamic library and use it to check the passwords.  The dynamic library must implement the
interface in `cracker-plugin.h`.  Sample full command would be:
```
   SEED_PWD=XXX cracker --checker '/my/file/name' --plugin './libcrackerplugin_gpg.so.1.0.0'
```

## LIMITATIONS

File name and path of file to decrypt cannot contain spaces.  If they do, rename the file first.

## RETURNS

0 if pwd is found
1 if pwd is not found
other on error

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
   the computer, it crashes, or etc.  When the program is halted prematurely, it should write current progress
   to stderr or elsewhere.
   
### Parallelism
I could add multi-threading or cluster-computing to allow running the algorithm faster.
