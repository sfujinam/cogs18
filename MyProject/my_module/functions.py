"""A collection of function for doing my project."""
import random
import string
import getpass
from my_module.classes import EzpzpwMenu
#from IPython.display import clear_output

MASTER_KEY = 3

def exit():
    """Exits menu
    
    Parameters
    ----------
    None
    
    Returns
    -------
    None
    
    """
    print('Good Bye')

def main_menu():
    """Prompts user for options.
    
    Parameters
    ----------
    None
    
    Returns
    -------
    None
    """
    
    # While choice is not valid, show menu again
    valid = False
    
    while valid == False:
             
        print('Please select one of the following:')
        
        # Shows user the choices and prompts for input
        choice = input('1. Log in \n2. New user \n3. Change EZ-PZ-PW password \n4. Exit\n')
        # Create dict of functions to call
        options = {'1':log_in, '2':new_username, '3':change_password, '4':exit}
        
        #Inform user of choices
        if choice not in options:
            print('Invalid choice. Please enter 1, 2, or 3')
            
        else:
            valid = True
    # Calls function based on user input
    options[choice]()

def log_in():
    """Logs in user and goes to EZ-PZ-PW menu.
    
    Parameters
    ----------
    None
    
    Returns
    -------
    None
    """
    
    # Confirms log in authentication, and log in username
    login_check, username = auth()
    
    # Go to EZ-PZ-PW menu if user is authenticated
    if login_check == True:
        # Create EZ-PZ-PW account menu object
        ezpzpw_login = EzpzpwMenu(username)

        # Call user menu function
        ezpzpw_login.user_menu()
    
    # If log in fails, go back to main menu
    else:
        main_menu()
    
    
def auth(username1 = None):
    """Authenticates user log in information.
    
    Parameters
    ----------
    username1 : str
        optional, authenticates with specific username
    
    Returns
    -------
    pw_check : boolean
        checks if username and password are in database and match
    username : str
        returns the username that was used to authenticate password
    """
    
    # Set max number of attempts allowed
    MAX_ATTEMPTS = 5
    
    # Set password checker to false
    pw_check = False
    
    # Empty list check
    empty = True
    
    # Loop log in screen for incorrect inputs and set log in attempts counter to 0
    attempts = 0
    while pw_check == False:
        
        # Increase attempts number each time user enters username and password
        attempts += 1
        
        # Set username checker to false
        username_check = False
        
        # If no username was passed into the function, ask for one, otherwise use given username
        if username1 == None:
            username = input('Username: ')
        else:
            username = username1
        # Prompts for password
        password = getpass.getpass('Password: ')

        # If file needs to be created, open file using write function. Write function creates a blank file
        try:
            accounts = open('ezpzpw.txt')
        except FileNotFoundError:
            accounts = open('ezpzpw.txt', 'w+')
            accounts.close()
            accounts = open('ezpzpw.txt')
        
        # Searches file for username, then checks password
        for line in accounts: 
            
            empty = False
            
            # Decode line from file
            plain_text = decrypt(line)

            # Pull username and password from file and split into list of strings
            file_line = plain_text.split()

            file_username = file_line[0]
            file_password = file_line[1]

            # Make input username and file username lowercase
            if username.lower() == file_username.lower():

                # Set username check to true
                username_check = True

                if password == file_password:
                    pw_check = True


                # If password is wrong, exit for loop    
                elif pw_check == False:
                    print('Invalid password')
                    print(file_password)

                    break

        if empty == True:
            print('No accounts found.')
            return pw_check, None

        # If username is wrong, exit for loop    
        if username_check == False:
            print('Invalid username')
                                                               
        # Check number of attempts and warn user
        if pw_check == False:
           
            if attempts > (MAX_ATTEMPTS - 3) and attempts < MAX_ATTEMPTS:
                print('Beware! Too many unsuccessful log ins! ' + str(MAX_ATTEMPTS - attempts) + ' tries left.')
            elif attempts == MAX_ATTEMPTS:
                print('Too many unsuccessful log ins.')
                
                # Waits for user input before continuing and clears screen
                input('Press enter to continue')
                #clear_output()
                
                # Close file to free memory and allow to open in different mode
                accounts.close()

                return pw_check, None
        
    # If username and password is correct, proceed to log in, and show user menu
    if pw_check == True:
        # Close file to free memory and allow to open in different mode
        accounts.close()
        print('Authentication successful')
        # Waits for user input before continuing and clears screen
        input('Press enter to continue')
        #clear_output()
 
        return pw_check, username
        
def new_username(is_new = True):
    """Creates a new username.
     Parameters
    ----------
    is_new : boolean
        checks if user is creating a new account, or changing an old username, default is creating new account
    
    Returns
    -------
    None
    """
    
    print('Create a new account. ')
    
    # Set loop condition, so loop doesn't exit early
    taken = True
    
    # Check if list is empty
    empty = True
    
    while taken == True:
        
        # Prompt user for new username, and checks if it is taken from accounts and passwords file
        new_name = input('Enter new username: ')
                
        # If file needs to be created, open file using write function. Write function creates a blank file
        try:
            accounts = open('ezpzpw.txt')
        except FileNotFoundError:
            accounts = open('ezpzpw.txt', 'w+')
            accounts.close()
            accounts = open('ezpzpw.txt')
                  
        # Search through file
        for line in accounts:
          
            # If line can be ready, file not empty
            empty = False
            
            # Decode line from file
            plain_text = decrypt(line)

            # Pull username and password from file and split into list of strings
            file_line = plain_text.split()

            file_username = file_line[0]

            # Tell user name has been taken
            if new_name.lower() == file_username.lower():
                print('Username is already taken')

                taken = True
                break

            else: 
                taken = False
        
        if empty == True:
            taken = False
        # Close file to free memory and allow to open in different mode
        accounts.close()

    # New name is not taken
    if taken == False:
        
        # Call function to set new password if user needs is creating a new account
        if is_new == True:
            password = new_password(new_name)
    
    # Open accounts file in append mode and append new account info
    accounts = open(r'ezpzpw.txt', 'a+')
    encrypted = encrypt(new_name + ' ' + password + ' ')
    accounts.write(encrypted+'\n')

    # Close file to free up memory, and allow it to be opened later
    accounts.close()
    
    print('New account created.')
    
    # Waits for user input before continuing and clears screen
    input('Press enter to continue')
    #clear_output()

    # Go back to main menu
    main_menu()
    
            
def new_password(username):
    """Creates a new password for a specific username.
     Parameters
    ----------
    username : str
        username that password is linked to
    
    Returns
    -------
    new_pass : str
        returns the new password that was entered if it matches all the requirements
    """
    
    MAX_CONF_ATTEMPTS = 5
  
    # Set loop condition for password requirements
    req_met = False
    confirm = False
    
    # Set counter for confirmation attempts
    conf_attempts = 0
    
    print('Set a new password. ')
    
    # Give user password requirements for EZ-PZ-PW
    print('Password must contain at least one uppercase letter, one lowercase letter, '+\
          'and one number and be at least 7 characters long.')
    
    # Loop until password with requirements is entered
    while req_met == False:
        
        
        new_pass = getpass.getpass('Enter new password: ')
        
        # Check if password has a numeric character in it
        if new_pass.isalpha():
            print('Password must contain a number.')
        # Check if password has a letter in it
        if new_pass.isdigit():
            print('Password must contain a letter.')
        # Check if password has an uppercase in it
        if new_pass.islower():
            print('Password must contain an uppercase letter.')
        # Check if password has a lowercase in it
        if new_pass.isupper():
            print('Password must contain a lowercase letter.')
        #Check if password has whitespace 
        if new_pass.isspace():
            print('Password can not contain spaces.')
        #Check if password is long enough
        if len(new_pass) < 7:
            print('Password must be at least 7 characters long.')
            
        # If all requirements are set, exit loop, and confirm new password
        if not new_pass.isalpha() and not new_pass.isupper() and not new_pass.isdigit()\
        and not new_pass.islower() and not new_pass.isspace() and not (len(new_pass) < 7):
            req_met = True
    
    
    
    # Have user confirm new password
    while confirm == False:
        confirm_pass = getpass.getpass('Confirm new password: ')
        if confirm_pass == new_pass:
            confirm = True
            print('New password has been set!')

            return new_pass
        else:
            print('Please confirm again')
            conf_attempts += 1
            
            if conf_attempts == MAX_CONF_ATTEMPTS:
                print('Max number of attempts reached, try again.')
    
                # Restarts new password process
                new_password(username)
            
def change_password():
    """Authenticates user, changes password, and writes to file.
     Parameters
    ----------
    None
    
    Returns
    -------
    None
    """
    
    # Authenticates user before changing password
    login_check, username = auth()
    
    if login_check == True:
        new_pass = new_password(username)
        
        # If file needs to be created, open file using write function. Write function creates a blank file
        try:
            accounts = open('ezpzpw.txt')
        except FileNotFoundError:
            accounts = open('ezpzpw.txt', 'w')
        
        # Loop through file and create temp list of list with username and password
        temp_list = []
        for line in accounts:

            # Decode line from file
            plain_text = decrypt(line)

            # Pull username and password from file and split into list of strings
            file_line = plain_text.split()
            
            # Make temp list of list of strings
            temp_list.append(file_line)

        # Search for username in new temp list
        for list_of_usernames in temp_list:
            
            # Find given username, and update password
            if list_of_usernames[0] == username:
                list_of_usernames[1] = new_pass
                break
                
        # Close file so it can be opened later in write mode
        accounts.close()
        
        # Rewrite file with updated list, this complete rewrites entire file
        accounts = open(r'ezpzpw.txt', 'w')
       
        for list_of_usernames in temp_list:
            
            # Space between each piece of information is important for differentiating each piece of info, order is also important
            # Must have new line character after each account piece
            
            encrypted = encrypt(list_of_usernames[0] + ' ' + list_of_usernames[1] + ' ')
            accounts.write(encrypted+'\n')
           
            
        # Close file to free up memory, and allow it to be opened later
        accounts.close()
        
    # Waits for user input before continuing and clears screen
    input('Press enter to continue')
    #clear_output()
    
    # Go back to main menu
    main_menu()
        
def encrypt(plain):
    """Encodes password using algorithm.
    Parameters
    ----------
    plain : str
        plain text to be encoded
    
    Returns
    -------
    encoded : str
        returns the new encoded version 
    """
    
    # Use simple encoder from A2-Ciphers
    encoded = ''
    
    # Use global master key
    key = MASTER_KEY
    
    for char in plain:
        encoded = encoded + chr(ord(char) + key)

    return encoded
        
def decrypt(encoded):
    """Decodes password using algorithm.
    Parameters
    ----------
    encoded : str
        input the encoded version of the password
    
    Returns
    -------
    plain : str
        returns the plain text version 
    """
        
    # Use simple decoder from A2-Ciphers    
    decoded = ''
    
    # User global master key
    key = MASTER_KEY

    for char in encoded:
        decoded = decoded + chr(ord(char) - key)

    return decoded
