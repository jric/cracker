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

 Usage:
 ```
   export SEED_PWD=XXXXX
   ./cracker --checker "command to check password"
             --match "string to match that lets us know the password worked"
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
