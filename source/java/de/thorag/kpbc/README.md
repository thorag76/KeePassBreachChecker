# What it does
Checks a given Keepass database file for vulnerable passwords.
It does so by querying the online API with a (partial) hash.
This is described in more detail here : 
    https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange

# How to use it
Just pass it the Keepass database file when running it.
It will ask for the password.

Example: java -jar kbc-full-1.0.0.jar mypasswords.kdbx

# How to build
Clone the repository and just call the maven target "package".