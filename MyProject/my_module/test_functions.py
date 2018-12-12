"""Test for my functions.

Note: because these are 'empty' functions (return None), here we just test
  that the functions execute, and return None, as expected.
"""

from my_module.functions import *
from my_module.classes import *

##
##

def test_1():

    assert callable(main_menu)
    
def test_2():
    
    assert callable(encrypt)
    
def test_3():
    
    assert callable(decrypt)
    
def test_4():
    
    test_string = 'Hello World'
    encrypted = encrypt(test_string)
    assert test_string != encrypted
    decrypted = decrypt(encrypted)
    assert decrypted == test_string
    
def test_5():

    assert callable(new_password)