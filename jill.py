import argparse
import hashlib

#Define our function "plunder_password" and pass two paremeters in `filename` for wordlist.txt and `file_compare` for the passwords.txt file which has the passwords we are trying to steal.
def plunder_password(filename, file_compare):
    #Open both files to be read.
    file = open(filename, 'r')
    passwords = open(file_compare, 'r')

    #Once we have opened the file we want to use the `readline()` function to read all the lines in the files and return them as strings.
    pass_lines = passwords.readlines()
    lines = file.readlines()

    #In this `for loop` we iterate over the lines in the passwords.txt file assigned to the varible `pass_lines`.
    for password in pass_lines:
            
            #Split the strings at the colon to divide the usernames and passwords.
            password = password.split(':')

            #The hashed password we are looking for is the last index represented by [-1] while the first index represented by [0] is the username of the person the password belongs to.
            usr_pass = password[-1].strip()
            username = password[0]

            #The 2nd `for loop` is used to hash the passwords from our dictionary `wordlist.txt` to match with the hashed passwords from `passwords.txt`.
            for line in lines: 
                    
                    #Strip any whitespace.
                    clean_pass = line.strip()

                    #Hash the passwords into sha256. 
                    hash_passwords = hashlib.sha256(clean_pass.encode()).hexdigest()

                    #Use an `if statement` to check and see if the hashed passwords in passwords.txt match the hashed passwords in the dictionary wordlist.txt.
                    if usr_pass == hash_passwords:

                        #Print the user's username and their password.
                        print(f'{username}:' + clean_pass)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='All contents hashed in the file.')

    #For the script I add arguments for the two parameters `filename` and `file_compare`.
    parser.add_argument('file_compare', help='Host usernames')
    parser.add_argument('filename', help='Original unhashed passwords')
    args = parser.parse_args()

    #To complete the script I call the function `plunder_password` with the two arguments `filename` and `file_compare`.
    plunder_password(args.filename, args.file_compare)

    