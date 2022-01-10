# What it does
Checks a given Keepass database file for leaked passwords.
It does so by querying the "haveibeenpwnd" online API with a (partial) hash.
This is described in more detail here : 
    https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange

# How to use it
Just pass it the Keepass database file when running it.
It will ask for the password.

Example: java -jar kbc-full-1.0.0.jar mypasswords.kdbx

# How to build
Clone the repository and execute the maven target "package".

# Important Notice
This software utilizes third party code. The author of KeePassBreachChecker is not responsible for the code of any third party library nor any builds of them.
Use at own risk. If you are paranoid, use the tool only if the machine executing it is not connected 
to the internet.
Inspect my code and the code of the utilized third party libs and do a build of the tool and the third
party library on your own if you don't trust my code or the code of the utilized third party libraries.
By using this software you submit to those conditions.