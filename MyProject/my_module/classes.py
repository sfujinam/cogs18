import random
import string
import getpass
from IPython.display import clear_output

MASTER_KEY = 3

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

class ListOfAccounts():
    """ListOfAccounts stores usernames, site/application the username is for, and the password for that account.
    
    Parameters
    ----------
    ezpzpw_name : str
        EZ-PZ-PW username that list of accounts stored under
    n_accounts : int
        number of accounts stored for specific EZ-PZ-PW account
    accounts : list
        list of dict with each accounts information
    
    Attributes
    ----------
    
    Methods
    -------
    
    """
    
    
    # Initialize list of accounts, taken from A4-ArtificialAgnets "__init__" function
    def __init__(self, ezpzpw_name):
        self.ezpzpw_name = ezpzpw_name
        self.n_accounts = 0
        self.accounts = []
        # Populates list of accounts for given user
        self.populate()
        
    # Add account to list of accounts, taken from A4-ArtificialAgnets "add_car" function
    def add_account(self, username, site, password):
        """Adds a new account to list of accounts
        
        Parameters
        ----------
        username : str
            username of new account
        site : str
            name of the site the username logs in to
        password : str
            password for the username 

        Returns
        -------
        added : boolean
            confirms that account was added
        """
        # Set return boolean to false before account gets added
        added = False
        
        # Check to make sure previous account is not overwritten
        exists = False
        for accnt in self.accounts:
            
            if username.lower() == accnt.get('username').lower() and site == accnt.get('site').lower():
                exists = True
                print('Account already exists.')
               
                return added
        
        # Add new account if it does not already exist, and update return boolean
        if exists == False:
            new_account = {'username' : username, 'site' : site, 'password': password}
            self.accounts.append(new_account)
            self.n_accounts += 1
            added = True

        return added
        
    def populate(self):
        """Reads file and populates list of accounts with stored list from file. Only run ONCE or it will not add properly.
        
        Parameters
        ----------
        ezpzpw_name : str
            EZ-PZ-PW username that list of accounts stored under
        
        Returns
        -------
        None
      
        """
        
        # Opens file specific to the user's account with stored account information
        file_name = self.ezpzpw_name.lower()
        
        # If file needs to be created, open file using write function. Write function creates a blank file
        try:
            list_accounts = open(file_name+'.txt')
        except FileNotFoundError:
            list_accounts = open(file_name+'.txt', 'w+')
        
        # Fill up list of accounts with each account 
        for line in list_accounts:
            
            plain_text = decrypt(line)
            
            file_line = plain_text.split()
            self.add_account(file_line[0], file_line[1], file_line[2])
            
        # Close file to free up memory, and allow it to be opened later
        list_accounts.close()
    
    def recall_pw(self, username, site):
        """Recalls a password for a specific account.
         
        Parameters
        ----------
        username : str
            username of account to retreive password for
        site : str
            site of username that user is searching for

        Returns
        -------
        password : str
            returns the password from the account as a string
        """
        # Set return password to None
        password = None
        
        # Search for given username and then get password for that username
        found = False
        for accnt in self.accounts:
            
            if accnt.get('username').lower() == username.lower() and accnt.get('site').lower() == site.lower():
                found = True
                password = accnt.get('password')
                # Exit loop after username and password is found
                break
                
        # Inform user that no username was found after search loop
        if found == False:
            print('Username not found.')
            
        
        # Return password that was found, returns None if not found
        return password
        
    def change_pw(self, username, site):
        """Changes the password of an existing account within the EZ-PZ-PW user's account database.
         
        Parameters
        ----------
        username : str
            username of account that is linked to password to be changed

        Returns
        -------
        changed : boolean
            confirms password has been changed
        """
        
        MAX_CONF_ATTEMPTS = 5
        
        # Set changed to false before password is changed
        changed = False
  
        # Set loop condition for password confirmation
        confirm = False

        # Set counter for confirmation attempts
        conf_attempts = 0
        
        # Search for username in list of accounts
        found = False
        for accnt in self.accounts:
            
            if accnt.get('username').lower() == username.lower() and accnt.get('site').lower() == site.lower():
                found = True
                break
                
        # Inform user that no username was found after search loop
        if found == False:
            print('Username not found.')
        
        
        # Prompt for new password if username was found
        if found == True:
            
            # Ask user if they want a randomly generated password
            new_pass = self.password_generator_menu()
            
            # If new password was generated, update password for account
            if new_pass != None:
                # Find account again in list of accounts and update password
                for accnt in self.accounts:

                    if accnt.get('username') == username:
                        accnt['password'] = new_pass
                        print('New password has been set!')
                        changed = True
                        break

                return changed
            
            #If user did generate one, have them enter one
            if new_pass == None:
            
                # Prompt user to change password
                new_pass = getpass.getpass('Please enter new password: ')
                # Have user confirm new password, and loop if confirmation is incorrect
                while confirm == False:
                    confirm_pass = getpass.getpass('Confirm new password: ')
                    if confirm_pass == new_pass:
                        confirm = True

                        # Find account again in list of accounts and update password
                        for accnt in self.accounts:

                            if accnt.get('username') == username:
                                accnt['password'] = new_pass
                                print('New password has been set!')
                                changed = True
                                break

                        return changed

                    else:
                        print('Please confirm again')
                        conf_attempts += 1
                        if conf_attempts == MAX_CONF_ATTEMPTS:
                            print('Max number of attempts reached.')

                            return changed

    def list_accounts(self):
        """Prints a list the usernames and site it is linked to of the user's stored accounts within EZ-PZ-PW
        
        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        
        # Inform user if there are no accounts stored
        if self.n_accounts == 0:
            
            print('There are no accounts stored.')
        
        # Print each account username and site 
        for accnt in self.accounts:
            
            print('Username:', accnt.get('username'), 'Site:', accnt.get('site'), '\n')
        
    def update_file(self):
        """Updates file with user's list of accounts information
        
        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        
        # Opens file specific to the user's account with stored account information in write mode
        file_name = self.ezpzpw_name.lower()
        list_accounts = open(file_name+'.txt','w+')
        
        # Write to file for each account information
        for accnt in self.accounts:
            
            # Space between each piece of information is important for differentiating each piece of info, order is also important
            # Must have new line character after each account piece
            encrypted = encrypt(accnt.get('username') + ' ' + accnt.get('site') + ' ' + accnt.get('password') + ' ')            
            list_accounts.write(encrypted+'\n')
           
            
        # Close file to free up memory, and allow it to be opened later
        list_accounts.close()
        
    def password_generator(self, min_length = 0, max_length = 0):
        """Generates a random password of given length. 
        
        Parameters
        ----------
        min_len : int
            minimum length of password to generate, default set to 8
        max_len : int
            maximum length of password to generate, default set to 12
            
        Returns
        -------
        password : str
            randomly generated password
        """
        # Check minimum and maximum inputs, set to default if 0
        if min_length == 0:
            min_length = 8
        if max_length == 0:
            max_length = 12
        
        # Generate random length of password between min and max
        n = random.randint(min_length, max_length)
        
        # Return string made up of upper and lower case letters and numbers of length n
        return ''.join(random.choices(string.ascii_letters + string.digits, k=n))
    
    def password_generator_menu(self):
        """Prompts user if they would like to generate a password
        Parameters
        ----------
        None

        Returns
        -------
        password : str
            random password that was generator, None if chose not to generate
        """
        # Set password to None until generated
        password = None
        
        # Input checking boolean
        check = True
        
        while check == True:
        
            answer = input('Would you like a secure randomly generated password? (y/n): ')

            #Convert user's choice to boolean
            choice = {'yes': True, 'y': True, 'no': False, 'n': False}

            # Check if user entered valid choice
            if answer.lower() in choice:

                # If choice is yes, then create password
                if choice[answer.lower()] == True:

                    min_input = input('Minimum password length (0 will use default): ')
                    max_input = input('Maximum password length (0 will use default): ')

                    # Check user input, if valid, change to int
                    if min_input == '':
                        min_length = 0
                    else:
                        min_length = int(min_input)

                    # Check user input, if valid, change to int
                    if max_input == '':
                        max_length = 0
                    else:
                        max_length = int(max_input)

                    # Loop if inputs are incorrect
                    if (min_length >= max_length or min_length < 0 or max_length > 30) and min_length != 0 and max_length != 0:
                        print('Invalid input. Will use defaults.')
                        min_length = 0
                        max_length = 0

                    # Call random password generator function
                    password = self.password_generator(min_length, max_length)

                    # Inform user new password has been generated
                    print('New password has been generated.')
                    
                    # End loop condition
                    check = False

                    return password              

                # If user does not want to generate a password, return password as None
                if choice[answer.lower()] == False:
                    
                    # End loop condition
                    check = False

                    return password 
            else: 
                print('Invalid choice. Input yes or no.')
            
class EzpzpwMenu():
    """EZ-PZ-PW user menu to organize user function after they have logged in, and use global variables 
    such as the user's EZ-PZ-PW username.
    
    Parameters
    ----------
    ezpzpw_name : str
        user's EZ-PZ-PW username
    accnt_list : ListOfAccounts
        user's list of accounts object
    
    Attributes
    ----------
    
    Methods
    -------
    
    """
    def __init__(self, ezpzpw_name):
        # EZ-PZ-PW username variable for all functions to use
        self.ezpzpw_name = ezpzpw_name
        
        # Create list of accounts class for given user
        self.accnt_list = ListOfAccounts(self.ezpzpw_name) 
    
    def user_menu(self):
        """Gives user options for their account.
         Parameters
        ----------
        None

        Returns
        -------
        None
        """
        print('Welcome to EZ-PZ-PW', self.ezpzpw_name + '.')

        # Loop to continue to show menu if choice is invalid
        valid = False
        while valid == False:
            print('Please select one of the following:')

            # Shows user the choices and prompts for input
            choice = input('1. Add account \n2. Retrieve Password \n3. Change Password \n4. List Accounts \n5. Log Out\n')
            # Create dict of functions to call
            options = {'1':self.add_account, '2':self.recall_pw, '3':self.change_pw, '4':self.list_accounts, '5':self.log_out}

            #Inform user of choices
            if choice not in options:
                print('Invalid choice. Please enter a number 1 through 5.')
                #clear_output(True)

            else:
                valid = True
        # Calls function based on user input
        options[choice]()
        
    def add_account(self):
        """Prompts user to create a new account to store password for.
        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        
        MAX_CONF_ATTEMPTS = 5
        
        conf_attempts = 0
        
        # Get user account info, and set variables
        username = input('Please enter username of new account: ')
        site = input('Please enter site that username logs in to: ')
        
                              
        # Ask user if they want a randomly generated password
        password = self.accnt_list.password_generator_menu()
                              
        # If password was generated, update password
        if password != None:
            added = self.accnt_list.add_account(username, site, password)
            if added == True:
                print('New account added.')

            # Waits for user input before continuing back to user menu
            input('Press enter to continue')
            clear_output()
                                                    
        # If user did not generate one, have them enter one
        if password == None:                      
            password = getpass.getpass('Please enter password for account: ')

            # Have user confirm new password, and loop if confirmation is incorrect
            confirm = False
            while confirm == False:
                confirm_pass = getpass.getpass('Confirm new password: ')
                if confirm_pass == password:
                    confirm = True

                    # Call list of accounts function and confirms if it was added 
                    added = self.accnt_list.add_account(username, site, password)
                    if added == True:
                        print('New account added.')
                        
                        # Waits for user then clears screen
                        input('Press enter to continue')
                        clear_output()

                    # Waits for user input before continuing and clears screen
                    #input('Press enter to continue')
                    #clear_output()

                else:
                    print('Please confirm again.')
                    conf_attempts += 1

                    if conf_attempts == MAX_CONF_ATTEMPTS:

                        print('Max number of attempts reached.')

                        # Waits for user input before continuing and clears screen
                        input('Press enter to continue')
                        clear_output()
        
        # Go back to menu
        self.user_menu()

    def recall_pw(self):
        """Prompts user for username of password to retreive.
        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        
        # Get user's username and the site for that username
        username = input('Please enter username of account: ')
        site = input('Please enter site that username logs in to: ')
        
        # Get password from list of accounts object
        password = self.accnt_list.recall_pw(username, site)
        
        # Returns password if account was found
        if password != None:
            print('Password is:', password)
        
        # Waits for user input before continuing and clears screen
        input('Press enter to continue')
        clear_output()
        
        # Go back to menu
        self.user_menu()
        
        
    def change_pw(self):
        """Prompts user for password change option.
        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        
        # Prompt user for username of account to change pw for
        username = input('Please enter username to change password for: ')
        site = input('Please enter site that username logs in to: ')
        
        # Call change pw func from users list of account object and confirms if it was changed 
        changed = self.accnt_list.change_pw(username, site)
        
        # If password is not successfully changed, inform user
        if changed == False:
            print('Password change unsuccessful')
        
        # Waits for user input before continuing and clears screen
        input('Press enter to continue')
        clear_output()
        
        # Go back to user menu    
        self.user_menu()

    def list_accounts(self):
        """Just calls user's list of accounts list accounts function. 
        ----------
        None

        Returns
        -------
        None
        """
        self.accnt_list.list_accounts()
        
        # Waits for user input before continuing and clears screen
        input('Press enter to continue')
        clear_output()
        
        # Go back to the menu
        self.user_menu()

    def log_out(self):
        """Logs user out of their EZ-PZ-PW account, and writes updated list of accounts to file
        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        print('Logging out...')
        
        # Writes list of accounts to file
        self.accnt_list.update_file()
        
        # Waits for user input before continuing and clears screen
        input('Press enter to continue')
        clear_output()

        from my_module.functions import main_menu
        main_menu()

